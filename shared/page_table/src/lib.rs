//! Routines for creating and manipulating 4-level x86_64 page tables

#![no_std]

extern crate alloc; 

use core::mem::size_of;
use core::alloc::Layout;
use alloc::boxed::Box;

/// Page table flag indicating the entry is valid
pub const PAGE_PRESENT: u64 = 1 << 0;

/// Page table flag indiciating this page or table is writable
pub const PAGE_WRITE: u64 = 1 << 1;

/// Page table flag indiciating this page or table is accessible in user mode
pub const PAGE_USER: u64 = 1 << 2;

/// Page table flag indiciating that accesses to the memory described by this
/// page or table should be strongly uncached
pub const PAGE_CACHE_DISABLE: u64 = 1 << 4;

/// Page has been accessed
pub const PAGE_ACCESSED: u64 = 1 << 5;

/// Page has been dirtied
pub const PAGE_DIRTY: u64 = 1 << 6;

/// Page table flag indicating that this page entry is a large page
pub const PAGE_SIZE: u64 = 1 << 7;

/// Page table flag indicating the page or table is not to be executable
pub const PAGE_NX: u64 = 1 << 63;

/// The state of a page table mapping. Contains the information about every
/// level of the translation. Also contains information about whether the
/// page is final
#[derive(Debug, Clone, Copy)]
pub struct Mapping {
    /// Physical address of the PML4 entry which maps the translated address
    /// `None` if there is no table present at this level
    pub pml4e: Option<PhysAddr>,
    
    /// Physical address of the PDP entry which maps the translated address
    /// `None` if there is no table present at this level
    pub pdpe: Option<PhysAddr>,
    
    /// Physical address of the PD entry which maps the translated address
    /// `None` if there is no table present at this level
    pub pde: Option<PhysAddr>,
    
    /// Physical address of the PT entry which maps the translated address
    /// `None` if there is no table present at this level
    pub pte: Option<PhysAddr>,

    /// Actual address of the base of the page and the offset into it
    pub page: Option<(PhysAddr, u64)>,
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

/// A trait that allows generic access to physical memory
///
/// This allows the user of the page table to handle the physical to virtual
/// translations that the page table uses during walks.
///
/// This also allows the user to provide mechanisms for the page table code
/// to allocate and free physical memory such that page tables and pages can
/// be freed when they are unmapped.
///
/// A user can control the physical translations such that this can be used to
/// perform nested paging lookups given the `PhysMem` implementation for the
/// guest `cr3` correctly uses the EPT for the VM to provide guest physical to
/// host physical translations.
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

    /// Tracks which tables and pages can be written to
    /// Type for the `VirtAddr` is `Box<[u64; 512 / 64 + 512]>`
    tracking: Option<VirtAddr>,
}

impl PageTable {
    /// Create a new empty page table
    pub fn new<P: PhysMem>(phys_mem: &mut P) -> PageTable {
        // Allocate the root level table
        let table = phys_mem.alloc_phys_zeroed(
            Layout::from_size_align(4096, 4096).unwrap());

        PageTable {
            table,
            tracking: None,
        }
    }
    
    /// Create a new page table which tracks which pages are writable
    pub fn new_tracking<P: PhysMem>(phys_mem: &mut P) -> PageTable {
        // Allocate the root level table
        let table = phys_mem.alloc_phys_zeroed(
            Layout::from_size_align(4096, 4096).unwrap());

        PageTable {
            table,
            tracking: Some(VirtAddr(
                Box::into_raw(Box::new([0; 512 / 64 + 512])) as u64)),
        }
    }

    /// Get the address of the page table
    #[inline]
    pub fn table(&self) -> PhysAddr {
        self.table
    }

    /// Create a page table entry at `vaddr` for `size` bytes in length,
    /// `page_type` as the page size. `read`, `write`, and `exec` will be used
    /// as the permission bits.
    pub fn map<P: PhysMem>(&mut self, 
            phys_mem: &mut P, vaddr: VirtAddr, page_type: PageType,
            size: u64, read: bool, write: bool, exec: bool, user: bool)
                -> Option<()> {
        self.map_init(phys_mem,
            vaddr, page_type, size, read, write, exec, user,
            None::<fn(u64) -> u8>)
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
                size: u64, _read: bool, write: bool, exec: bool, user: bool,
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
                if user  { PAGE_USER  } else { 0 } |
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
                        self.free(phys_mem, orig_vaddr, mapped);
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
                                   vaddr: VirtAddr, size: u64) {
        assert!(self.tracking.is_none(),
            "Frees for tracking page tables not yet supported");
        // Determine the end of the mapping
        let end = vaddr.0.checked_add(
            size.checked_sub(1).expect("Virtual free of zero bytes"))
            .expect("Integer overflow on virtual free range");

        // Accumulate the number of bytes that have been freed
        let mut freed = 0u64;

        // Translate the initial page
        let mut cur_page = self.translate(phys_mem, vaddr).unwrap();
        
        loop {
            // Get the virtual address and size of this page
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
            'next_level: for (ii, &entry) in
                    table_entries.iter().enumerate().rev() {
                // Convert the table entry into a virtual address
                let vad = phys_mem.translate(
                    entry, core::mem::size_of::<u64>());

                // Unmap this entry as it is no longer used
                core::ptr::write(vad as *mut u64, 0);
                
                if ii > 0 {
                    // If there is a table level above us, then check
                    // to see how many pages are being described at
                    // this level. If there are no more mapped pages
                    // after updated the number of pages, then we can
                    // free the table itself.
                
                    // Get the table above us to get the number of
                    // pages mapped in that entry
                    let next_entry = table_entries[ii - 1];

                    // Get the virtual address of the next entry
                    let nvad = phys_mem.translate(
                        next_entry, core::mem::size_of::<u64>());

                    // Read the next entry
                    let nent = core::ptr::read(nvad as *const u64);

                    // Get the number of pages in use at this level.
                    // Stored as metadata in the ignored bits of the
                    // page table entry.
                    let in_use = (nent >> 52) & 0x3ff;

                    if in_use == 1 {
                        // We're about to decrement this to zero, thus
                        // free the table itself, and go to the next
                        // level as we might want to free the table
                        // that contains this table!

                        // Free the current page table
                        phys_mem.free_phys(PhysAddr(entry.0 & !0xfff),
                                           4096);
                        
                        // Continue on freeing tables as we just freed
                        // one which may have made the level above us
                        // contain no more active tables.
                        continue 'next_level;
                    } else {
                        // Update number of entries this table
                        // references
                        
                        assert!(in_use > 0 && in_use <= 512,
                            "Whoa, ref counts broken on page");

                        // Update the reference count
                        let nent = (nent & !0x3ff0_0000_0000_0000) |
                            ((in_use - 1) << 52);

                        // Write in the new entry
                        core::ptr::write(nvad as *mut u64, nent);
                        break 'next_level;
                    }
                } else {
                    // Stop freeing table entries as we reached the
                    // top level table.
                    break 'next_level;
                }
            }

            // Free the page
            phys_mem.free_phys(
                cur_page.page.unwrap().0, page_size as u64);
            
            // Accumulate the amount of virtual memory we're freeing
            freed += cur_page.size().unwrap() as u64;

            // Compute the address of the next page. This can overflow on
            // the final page
            let next_page = page_vaddr.0.checked_add(page_size as u64);

            // If we made it to the end of all virtual memory, or we made
            // it to the end of the free request
            if next_page.is_none() || next_page.unwrap() > end {
                break;
            }

            // Otherwise, we've got more to do!
            cur_page =
                self.translate(phys_mem, VirtAddr(next_page.unwrap()))
                .expect("Failed to translate virtual address during free");
        }

        // Make sure the caller understood exactly how much virtual memory
        // would be freed by this request. This effectively enforces the
        // alignment and page-size awareness such that if a user requests to
        // free 1 byte, but it's a 4 KiB page, that this will panic because we
        // freed more than the user expected.
        assert!(freed == size,
                "Virtual free request freed more bytes than requested");
       
        // Check to see if we're modifying the active page table. If we are
        // we have to invalidate mappings.
        let cur_cr3 = cpu::read_cr3();
        if (cur_cr3 & !0xfff) == self.table().0 {
            // Invalidate the non-global TLB entries. We don't use global pages
            // at all thus we can safely do a non-global invalidation. On our
            // Coffee Lake machine, a write-to-cr3 cost about 200 cycles, where
            // an `invlpg` costs 150 cycles. Though the full TLB invalidation
            // will have a runtime performance hit due to TLBs needing to be
            // repopulated for _all_ page table entries, it seems this will be
            // much faster overall than invalidating every single page that we
            // freed.
            //
            // In theory, for up to ~10 page frees it's probably faster to
            // `invlpg` each individual page. But this margin is so small that
            // we just always issue a write-to-cr3 instead. This dramaticially
            // reduces the cost of invalidating many pages. For example,
            // unmapping a ~1 MiB allocation.
            cpu::write_cr3(cpu::read_cr3());
        }
    }

    /// Translate a virtual address in the `self` page table into its
    /// components. This will include entries for every level in the table as
    /// well as the final page result if the page is mapped and present.
    pub fn translate<P: PhysMem>(&self, phys_mem: &mut P,
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
            let ent = unsafe { core::ptr::read(vad as *const u64) };

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
        // Only allow 4K pages in tracked mappings
        if page_type != PageType::Page4K && self.tracking.is_some() {
            return None;
        }

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

        // Track the level into the tracking table
        let mut tracking = self.tracking;

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

                if ii >= 2 {
                    // Get access to the entry with the reference count of the
                    // table we're updating
                    let ptr = phys_mem.translate(entries[ii - 2].unwrap(),
                        core::mem::size_of::<u64>());
                    
                    // Read the entry
                    let nent = core::ptr::read(ptr as *const u64);

                    // Update the reference count
                    let in_use = (nent >> 52) & 0x3ff;
                    let nent = (nent & !0x3ff0_0000_0000_0000) |
                        ((in_use + 1) << 52);

                    // Write in the new entry
                    core::ptr::write(ptr as *mut u64, nent);
                }

                if let Some(ttbl) = tracking {
                    // Convert the tracking table into it's underlying type
                    let ttbl = &mut *(ttbl.0 as *mut [u64; 512 / 64 + 512]);

                    let bit = indicies[ii - 1] % 64;
                    let idx = indicies[ii - 1] / 64;
                    
                    // Set that there is a table at this index
                    ttbl[idx as usize] |= 1 << bit;

                    // Create a new bit index table
                    let nxt =
                        Box::into_raw(Box::new([0u64; 512 / 64 + 512])) as u64;
                    ttbl[512 / 64 + indicies[ii - 1] as usize] = nxt;
                }

                // Insert the new table at the entry in the table above us
                core::ptr::write(ptr as *mut u64,
                    table.0 | PAGE_USER | PAGE_WRITE | PAGE_PRESENT);

                // Update the mapping state as we have changed the tables
                entries[ii] = Some(PhysAddr(
                    table.0 + indicies[ii] * core::mem::size_of::<u64>() as u64
                ));
            }

            // Traverse the tracking table regardless of if we created a new
            // page or not.
            if let Some(ttbl) = tracking {
                // Convert the tracking table into it's underlying type
                let ttbl = &mut *(ttbl.0 as *mut [u64; 512 / 64 + 512]);
                let nxt = ttbl[512 / 64 + indicies[ii - 1] as usize];
                tracking = Some(VirtAddr(nxt));
            }
        }
        
        {
            // Get access to the entry with the reference count of the
            // table we're updating with the new page
            let ptr = phys_mem.translate(entries[depth - 2].unwrap(),
                core::mem::size_of::<u64>());
            
            // Read the entry
            let nent = core::ptr::read(ptr as *const u64);

            // Update the reference count
            let in_use = (nent >> 52) & 0x3ff;
            let nent = (nent & !0x3ff0_0000_0000_0000) |
                ((in_use + 1) << 52);

            // Write in the new entry
            core::ptr::write(ptr as *mut u64, nent);
        }

        if let Some(ttbl) = tracking {
            // Convert the tracking table into it's underlying type
            let ttbl = &mut *(ttbl.0 as *mut [u64; 512 / 64 + 512]);

            let bit = indicies[depth - 1] % 64;
            let idx = indicies[depth - 1] / 64;
            
            // Set that there is a table at this index
            ttbl[idx as usize] |= 1 << bit;
        }

        // At this point, the tables have been created, and the page doesn't
        // already exist. Thus, we can write in the mapping!
        let ptr = phys_mem.translate(entries[depth - 1].unwrap(),
            core::mem::size_of::<u64>());
        core::ptr::write(ptr as *mut u64, raw);

        Some(())
    }

    /// Invoke a closure on every dirtied page
    #[inline]
    pub unsafe fn for_each_dirty_page<P, F>(&mut self, phys_mem: &mut P,
                                            mut callback: F)
            where P: PhysMem,
                  F: FnMut(VirtAddr, PhysAddr) {
        // Track the level into the tracking table
        let tracking =
            &*(self.tracking.unwrap().0 as *mut [u64; 512 / 64 + 512]);
        let mut bit = [0u64; 4];
        Self::for_each_dirty_page_int(phys_mem, &mut callback, tracking,
                                      &mut bit, 0, self.table());
    }

    /// An function that simplifies recursion to walk dirty pages
    unsafe fn for_each_dirty_page_int<P, F>(
        phys_mem: &mut P, callback: &mut F,
        tracking: &[u64; 512 / 64 + 512],
        bit: &mut [u64; 4], rec: usize, pt: PhysAddr)
            where P: PhysMem,
                  F: FnMut(VirtAddr, PhysAddr) {

        /// Accessed and present
        const AP: u64 = PAGE_PRESENT | PAGE_ACCESSED;

        /// Accessed and dirty
        const AD: u64 = PAGE_ACCESSED | PAGE_DIRTY;

        /// Dirty and present
        const DP: u64 = PAGE_PRESENT | PAGE_DIRTY;

        let table = phys_mem.translate(pt, 4096) as *mut u64;

        for (ii, &bits) in tracking[..512 / 64].iter().enumerate() {
            let mut bits: u64 = bits;
            while bits != 0 {
                let tz = bits.trailing_zeros() as u64;
                bits &= !(1 << tz);

                // Compute the page index
                let pfn = ii as u64 * 64 + tz;

                // Get the page table entry
                let pte = table.offset(pfn as isize);

                if rec == 3 {
                    // Skip the entry if it's not both dirty and
                    // present
                    if (*pte & DP) != DP { continue; }
                } else {
                    // Skip the entry if it's not both accessed and
                    // present
                    if (*pte & AP) != AP { continue; }
                }

                // Clear the accessed and dirty bits
                *pte &= !AD;

                bit[rec] = pfn;
                if rec == 3 {
                    let vaddr = VirtAddr(bit[0] << 39 |
                                         bit[1] << 30 |
                                         bit[2] << 21 |
                                         bit[3] << 12);
                    callback(vaddr, pt);
                } else {
                    let tracking =
                        &*(tracking[512 / 64 + bit[rec] as usize] as
                           *mut [u64; 512 / 64 + 512]);
                    // Compute the physical address of the table/page
                    let next_table = PhysAddr(*pte & 0xffffffffff000);

                    Self::for_each_dirty_page_int(
                        phys_mem, callback, tracking,
                        bit, rec + 1, next_table);
                }
            }
        }
    }
}

