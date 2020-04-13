//! Routines for creating and manipulating 4-level x86_64 page tables

#![no_std]

use core::alloc::Layout;
use core::mem::size_of;

pub const PAGE_PRESENT: u64 = 1 <<  0;
pub const PAGE_WRITE:   u64 = 1 <<  1;
pub const PAGE_USER:    u64 = 1 <<  2;
pub const PAGE_SIZE:    u64 = 1 <<  7;
pub const PAGE_NX:      u64 = 1 << 63;

/// The state of a page table mapping. Contains the information about every
/// level of the translation. Also contains information about whether the
/// page is final
#[derive(Debug, Clone, Copy)]
pub struct Mapping {
    pml4e: Option<PhysAddr>,
    pdpe:  Option<PhysAddr>,
    pde:   Option<PhysAddr>,
    pte:   Option<PhysAddr>,

    /// Actual address of the base of the page and the offset into it
    page: Option<(PhysAddr, u64)>,
}

impl Mapping {
    /// Compute the base virtual address of this page, if the page exists
    pub fn virt_base(&self) -> Option<VirtAddr> {
        // Page is not mapped
        if self.page.is_none() { return None; }

        /// Size of a page table entry
        const ES: u64 = core::mem::size_of::<u64>() as u64;

        Some(VirtAddr(cpu::canonicalize_address(
            ((self.pml4e.unwrap_or(PhysAddr(0)).0 & 0xfff) / ES) << 39 |
            ((self.pdpe .unwrap_or(PhysAddr(0)).0 & 0xfff) / ES) << 30 |
            ((self.pde  .unwrap_or(PhysAddr(0)).0 & 0xfff) / ES) << 21 |
            ((self.pte  .unwrap_or(PhysAddr(0)).0 & 0xfff) / ES) << 12
        )))
    }

    /// Get the size of this page
    pub fn size(&self) -> Option<PageType> {
        // Page is not mapped
        if self.page.is_none() { return None; }

        // Determine the level which was the end of the mapping, and that
        // reflects the page size.
        if self.pde.is_none() { return Some(PageType::Page1G); }
        if self.pte.is_none() { return Some(PageType::Page2M); }
        Some(PageType::Page4K)
    }
}

/// A strongly typed physical address. This is effectively just an integer but
/// we have strongly typed it to make code clarity a bit higher.
/// This may represent a host physical address, or a guest physical address.
/// The meaning will vary based on context.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct PhysAddr(pub u64);

/// A strongly typed virtual address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct VirtAddr(pub u64);

pub trait PhysMem {
    /// Provide a virtual address to memory which contains the raw physical
    /// memory at `paddr` for `size` bytes
    unsafe fn translate(&mut self, paddr: PhysAddr, size: usize) -> *mut u8;
   
    /// Allocate physical memory with a requested layout
    fn alloc_phys(&mut self, layout: Layout) -> PhysAddr;

    /// Free physical memory
    fn free_phys(&mut self, paddr: PhysAddr, size: u64);

    /// Same as `alloc_phys` but the memory will be zeroed
    fn alloc_phys_zeroed(&mut self, layout: Layout) -> PhysAddr {
        // Create an allocation
        let alc = self.alloc_phys(layout);

        // Zero it out
        unsafe {
            let bytes = self.translate(alc, layout.size());
            core::ptr::write_bytes(bytes, 0, layout.size());
        }

        alc
    }
}

/// Different page sizes for 4-level x86_64 paging
#[repr(u64)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PageType {
    Page4K = 4096,
    Page2M = 2 * 1024 * 1024,
    Page1G = 1 * 1024 * 1024 * 1024,
}

/// A 64-bit x86 page table 
#[repr(C)]
pub struct PageTable {
    /// The physical address of the top-level page table. This is typically
    /// the value in `cr3`, without the VPID bits.
    table: PhysAddr,
}

impl PageTable {
    /// Create a new empty page table
    pub fn new<P: PhysMem>(phys_mem: &mut P) -> PageTable {
        // Allocate the root level table
        let table = phys_mem.alloc_phys_zeroed(
            Layout::from_size_align(4096, 4096).unwrap());

        PageTable {
            table,
        }
    }

    /// Get the address of the page table
    pub fn table(&self) -> PhysAddr {
        self.table
    }

    /// Create a page table entry at `vaddr` for `size` bytes in length,
    /// `page_type` as the page size. `read`, `write`, and `exec` will be used
    /// as the permission bits.
    pub fn map<P: PhysMem>(&mut self, 
            phys_mem: &mut P, vaddr: VirtAddr, page_type: PageType,
            size: u64, read: bool, write: bool, exec: bool) -> Option<()> {
        self.map_init(phys_mem,
            vaddr, page_type, size, read, write, exec, None::<fn(u64) -> u8>)
    }

    /// Create a page table entry at `vaddr` for `size` bytes in length,
    /// `page_type` as the page size. `read`, `write`, and `exec` will be used
    /// as the permission bits.
    ///
    /// If the virtual memory is already mapped or the virtual address at any
    /// point over the range is non-canonical, this will return `None` and the
    /// page table will not be modified.
    ///
    /// If `init` is `Some`, it will be invoked with the current offset into
    /// the mapping, and the return value from the closure will be used to
    /// initialize that byte.
    pub fn map_init<F, P: PhysMem>(
                &mut self, phys_mem: &mut P,
                vaddr: VirtAddr, page_type: PageType,
                size: u64, _read: bool, write: bool, exec: bool,
                init: Option<F>) -> Option<()>
            where F: Fn(u64) -> u8 {
        // Get the raw page size in bytes and the mask
        let page_size = page_type as u64;
        let page_mask = page_size - 1;

        // Save off the original virtual address
        let orig_vaddr = vaddr;

        // Make sure that the virtual address is aligned to the page size
        // request
        if size <= 0 || (vaddr.0 & page_mask) != 0 {
            return None;
        }

        // Compute the end virtual address of this mapping
        let end_vaddr = vaddr.0.checked_add(size - 1)?;

        // Go through each page in this mapping
        for vaddr in (vaddr.0..=end_vaddr).step_by(page_size as usize) {
            // Allocate the page
            let page = phys_mem.alloc_phys(
                Layout::from_size_align(page_size as usize,
                                        page_size as usize).unwrap());

            // Create the page table entry for this page
            let ent = page.0 | PAGE_PRESENT |
                if write { PAGE_WRITE } else { 0 } |
                if exec  { 0 } else { PAGE_NX } |
                if page_type != PageType::Page4K { PAGE_SIZE } else { 0 };

            if let Some(init) = &init {
                // Translate the page
                let sliced = unsafe {
                    let bytes = phys_mem.translate(page, page_size as usize);

                    // Get access to the memory we just allocated
                    core::slice::from_raw_parts_mut(
                        bytes, page_size as usize)
                };

                for (off, byte) in sliced.iter_mut().enumerate() {
                    *byte = init(vaddr - orig_vaddr.0 + off as u64);
                }
            }

            // Add this mapping to the page table
            unsafe {
                if self.map_raw(phys_mem, VirtAddr(vaddr),
                        page_type, ent).is_none() {
                    // Failed to map, undo everything we have done so far
                    let mapped = vaddr - orig_vaddr.0;

                    if mapped > 0 {
                        // Free everything that we mapped up until the failure
                        self.free(phys_mem, orig_vaddr, mapped)
                            .expect("Failed to free what we just mapped");
                    }

                    return None;
                }
            }
        }

        Some(())
    }

    /// Free the virtual memory region indicated by `vaddr` and `size`. All
    /// pages used to back the allocation will be freed, and any intermediate
    /// page tables which no longer contain any mappings will be unlinked from
    /// the table and also freed.
    pub unsafe fn free<P: PhysMem>(&mut self, phys_mem: &mut P,
                                   vaddr: VirtAddr, size: u64) -> Option<()> {
        // Determine the end of the mapping
        let end = vaddr.0.checked_add(size.checked_sub(1)?)?;

        // Amount of virtual memory that will be freed by this operation
        // (in bytes)
        let mut to_free = 0u64;

        // We go through the memory range twice. The first time we validate
        // that all virtual memory in the range requested is present and valid.
        //
        // The second time, we actually perform the frees
        for &validate in &[true, false] {
            // Translate the initial page
            let mut cur_page = self.translate(phys_mem, vaddr)?;
            
            loop {
                // Check to see if we're on the validate pass
                if validate {
                    // Return failure if the page is not present
                    if cur_page.page.is_none() { return None; }

                    // Accumulate the amount of virtual memory we're going to
                    // free
                    to_free += cur_page.size()? as u64;
                } else {
                    // We should not return failure anywhere inside of this
                    // stage. We must panic if we cannot do something we want.
                    // Otherwise we violate the semantics of all-or-none frees.

                    let page_vaddr = cur_page.virt_base().unwrap();
                    let page_size  = cur_page.size().unwrap();
                    
                    // Get the physical address of the page table entries for
                    // the entry we're about to free
                    let mut table_entries = [PhysAddr(0); 4];
                    let table_entries = match page_size {
                        PageType::Page4K => {
                            table_entries[0] = cur_page.pml4e.unwrap();
                            table_entries[1] = cur_page.pdpe.unwrap();
                            table_entries[2] = cur_page.pde.unwrap();
                            table_entries[3] = cur_page.pte.unwrap();
                            &table_entries[..4]
                        }
                        PageType::Page2M => {
                            table_entries[0] = cur_page.pml4e.unwrap();
                            table_entries[1] = cur_page.pdpe.unwrap();
                            table_entries[2] = cur_page.pde.unwrap();
                            &table_entries[..3]
                        }
                        PageType::Page1G => {
                            table_entries[0] = cur_page.pml4e.unwrap();
                            table_entries[1] = cur_page.pdpe.unwrap();
                            &table_entries[..2]
                        }
                    };

                    // Go up the page table listing
                    for entry in table_entries.iter().rev() {
                        // Get the index of the table entry for this level
                        let idx = (entry.0 & 0xfff) as usize /
                            core::mem::size_of::<u64>();

                        // Get the base for the entire 512-entry table for this
                        // level
                        let ptable = PhysAddr(entry.0 & !0xfff);

                        // Convert the table into a vitrual address
                        let vad = phys_mem.translate(ptable, 4096);

                        // Convert the page table into a mutable Rust slice
                        let table = core::slice::from_raw_parts_mut(
                            vad as *mut u64, 512);

                        // Overwrite the entry with a zero
                        table[idx] = 0;

                        // Check to see if anyone is still using this table
                        let in_use = table.iter().any(|x| {
                            (x & PAGE_PRESENT) != 0
                        });

                        if in_use {
                            // We cannot do anything more
                            break;
                        }

                        // Prevent ourselves from freeing the root level of
                        // the page table.
                        if ptable != self.table() {
                            // Nobody is using this table itself, we can free
                            // it!
                            phys_mem.free_phys(ptable, 4096);
                        }
                    }

                    // Free the page
                    phys_mem.free_phys(
                        cur_page.page.unwrap().0, page_size as u64);

                    // Invalidate the TLB for this page as we have converted
                    // something from present to non-present.
                    cpu::invlpg(page_vaddr.0 as usize);
                }

                // Compute the address of the next page. This can overflow on
                // the final page
                let next_page = cur_page.virt_base()?.0
                    .checked_add(cur_page.size()? as u64);

                // If we made it to the end of all virtual memory, or we made
                // it to the end of the free request
                if next_page.is_none() || next_page.unwrap() > end {
                    break;
                }

                // Otherwise, we've got more to do!
                cur_page =
                    self.translate(phys_mem, VirtAddr(next_page.unwrap()))?;
            }

            // If we're going to free more virtual memory space than the user
            // requested, we're going to have problems.
            if validate && size != to_free {
                return None;
            }
        }

        Some(())
    }

    /// Translate a virtual address in the `self` page table into its
    /// components. This will include entries for every level in the table as
    /// well as the final page result if the page is mapped and present.
    pub fn translate<P: PhysMem>(&mut self, phys_mem: &mut P,
                                 vaddr: VirtAddr) -> Option<Mapping> {
        // Start off with an empty mapping
        let mut ret = Mapping {
            pml4e: None,
            pdpe:  None,
            pde:   None,
            pte:   None,
            page:  None,
        };
        
        // Check that the address is canonical
        if cpu::canonicalize_address(vaddr.0) != vaddr.0 {
            return None;
        }
        
        // Get the components of the address
        let indicies = [
            (vaddr.0 >> 39) & 0x1ff,
            (vaddr.0 >> 30) & 0x1ff,
            (vaddr.0 >> 21) & 0x1ff,
            (vaddr.0 >> 12) & 0x1ff,
        ];
        
        // Get the address of the page table
        let mut table = self.table;

        for (depth, &index) in indicies.iter().enumerate() {
            // Get the physical address of the page table entry
            let ptp = PhysAddr(table.0 + index * size_of::<u64>() as u64);

            // Fill in the address of the entry we are decoding
            match depth {
                0 => ret.pml4e = Some(ptp),
                1 => ret.pdpe  = Some(ptp),
                2 => ret.pde   = Some(ptp),
                3 => ret.pte   = Some(ptp),
                _ => unreachable!(),
            }

            // Get a virtual address for this entry
            let vad = unsafe { phys_mem.translate(ptp, size_of::<u64>()) };
            let ent = unsafe { core::ptr::read(vad as *mut u64) };

            // Check if this page is present
            if (ent & PAGE_PRESENT) == 0 {
                // Page is not present, break out and stop the translation
                break;
            }

            // Update the table to point to the next level
            table = PhysAddr(ent & 0xffffffffff000);

            // Check if this is the page mapping and not pointing to a table
            if depth == 3 || (ent & PAGE_SIZE) != 0 {
                // Page size bit is not valid (reserved as 0) for the PML4E,
                // return out the partially walked table
                if depth == 0 { break; }

                // Determine the mask for this page size
                let page_mask = match depth {
                    1 => PageType::Page1G as u64 - 1,
                    2 => PageType::Page2M as u64 - 1,
                    3 => PageType::Page4K as u64 - 1,
                    _ => unreachable!(),
                };

                // At this point, the page is valid, mask off all bits that
                // arent part of the address
                let page_paddr = table.0 & !page_mask;

                // Compute the offset in the page for the `vaddr`
                let page_off = vaddr.0 & page_mask;

                // Store the page and offset
                ret.page = Some((PhysAddr(page_paddr), page_off));

                // Translation done
                break;
            }
        }

        Some(ret)
    }

    /// Map a `vaddr` to a raw page table entry `raw`. This will use the page
    /// size specified by `page_type`.
    ///
    /// If the mapping already exists, or the virtual address is non-canonical
    /// then this returns `None`. In this case, no modifications were made to
    /// the page table.
    ///
    /// * `vaddr`     - Virtual address to create the mapping at
    /// * `page_type` - The page size to be used for the entry
    /// * `raw`       - The raw page table entry to use
    pub unsafe fn map_raw<P: PhysMem>(
            &mut self, phys_mem: &mut P, vaddr: VirtAddr, page_type: PageType,
            raw: u64) -> Option<()> {
        // We're mapping a non-present page or we're mapping a large page
        // without the page size bit set, this page will _never_ be valid so
        // just return fail.
        if (raw & PAGE_PRESENT) == 0 ||
                (page_type != PageType::Page4K && (raw & PAGE_SIZE) == 0) {
            return None;
        }

        // Determine the state of the existing mapping
        let mapping = self.translate(phys_mem, vaddr)?;

        // Page already mapped
        if mapping.page.is_some() {
            return None;
        }

        // Get all of the current mapping states
        let mut entries = [
            mapping.pml4e,
            mapping.pdpe,
            mapping.pde,
            mapping.pte,
        ];
        
        // Get the length of the entries array based on the page type
        let depth = match page_type {
            PageType::Page1G => 2,
            PageType::Page2M => 3,
            PageType::Page4K => 4,
        };

        // Check to see if a table is currently mapped at the location we want
        // to insert a large page. This will disallow us from mapping a large
        // page over a table which contains smaller pages.
        if entries.get(depth).map_or(false, |x| x.is_some()) {
            return None;
        }
        
        // After this point, we should never return partial success. We should
        // either panic or return success!

        // This should never happen. This means the page table doesn't even
        // exist.
        assert!(mapping.pml4e.is_some(), "Whoa, how is there no PML4E");

        // Get the components of the address
        let indicies = [
            (vaddr.0 >> 39) & 0x1ff,
            (vaddr.0 >> 30) & 0x1ff,
            (vaddr.0 >> 21) & 0x1ff,
            (vaddr.0 >> 12) & 0x1ff,
        ];

        // Create page tables as needed while walking to the final page
        for ii in 1..depth {
            // Check if there is a table along the path
            if entries[ii].is_none() {
                // Allocate a new empty table
                let table = phys_mem.alloc_phys_zeroed(
                    Layout::from_size_align(4096, 4096).unwrap());

                // Convert the address of the page table entry where we need
                // to insert the new table
                let ptr = phys_mem.translate(entries[ii - 1].unwrap(),
                    core::mem::size_of::<u64>());

                // Insert the new table at the entry in the tabe above us
                core::ptr::write(ptr as *mut u64,
                    table.0 | PAGE_USER | PAGE_WRITE | PAGE_PRESENT);

                // Update the mapping state as we have changed the tables
                entries[ii] = Some(PhysAddr(
                    table.0 + indicies[ii] * core::mem::size_of::<u64>() as u64
                ));
            }
        }

        // At this point, the tables have been created, and the page doesn't
        // already exist. Thus, we can write in the mapping!
        let ptr = phys_mem.translate(entries[depth - 1].unwrap(),
            core::mem::size_of::<u64>());
        core::ptr::write(ptr as *mut u64, raw);

        Some(())
    }
}

