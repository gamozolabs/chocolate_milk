//! Routines for creating and mapping extended page tables

use core::mem::size_of;
use core::alloc::Layout;
use alloc::boxed::Box;

use crate::mm;

use page_table::{PhysMem, VirtAddr, PhysAddr, Mapping, PageType};

/// Write back memory type for EPT pages
pub const EPT_MEMTYPE_WB: u64 = 6 << 3;

/// Page is readable
pub const EPT_READ: u64 = 1 << 0;

/// Page is writable
pub const EPT_WRITE: u64 = 1 << 1;

/// Page is executable
pub const EPT_EXEC: u64 = 1 << 2;

/// A large EPT page
pub const EPT_PAGE_SIZE: u64 = 1 << 7;

/// Page has been accessed
pub const EPT_ACCESSED: u64 = 1 << 8;

/// Page has been dirtied
pub const EPT_DIRTY: u64 = 1 << 9;

/// Page has executable as userland (only used when "mode-based execute control
/// for EPT" set in the VM execution controls)
pub const EPT_USER_EXEC: u64 = 1 << 10;

/// EPT is acessible in some way (it's present)
pub const EPT_PRESENT: u64 = EPT_READ | EPT_WRITE | EPT_EXEC | EPT_USER_EXEC;

/// A root level extended page table
pub struct Ept {
    /// Physical address of the root level of the page table
    table: PhysAddr,

    /// Tracks which tables and pages can be written to
    /// Type for the `VirtAddr` is `Box<[u64; 512 / 64 + 512]>`
    tracking: VirtAddr,
}

impl Ept {
    /// Create a new empty extended page table
    pub fn new() -> Option<Self> {
        let mut pmem = mm::PhysicalMemory;

        // Allocate the root level table
        let table = pmem.alloc_phys_zeroed(
            Layout::from_size_align(4096, 4096).unwrap())?;

        Some(Ept {
            table,
            tracking: VirtAddr(
                Box::into_raw(Box::new([0; 512 / 64 + 512])) as u64),
        })
    }
    
    /// Get the address of the page table
    #[inline]
    pub fn table(&self) -> PhysAddr {
        self.table
    }

    /// Create a page table entry at `gpaddr` for `size` bytes in length,
    /// `page_type` as the page size. `read`, `write`, and `exec` will be used
    /// as the permission bits.
    pub fn map(&mut self, gpaddr: PhysAddr, page_type: PageType,
            size: u64, read: bool, write: bool, exec: bool, exec_user: bool)
                -> Option<()> {
        self.map_init(gpaddr, page_type, size, read, write, exec, exec_user,
            None::<fn(u64) -> u8>)
    }

    /// Create a page table entry at `gpaddr` for `size` bytes in length,
    /// `page_type` as the page size. `read`, `write`, and `exec` will be used
    /// as the permission bits.
    ///
    /// If the guest physical memory is already mapped this will return `None`
    /// and the page table will not be modified.
    ///
    /// If `init` is `Some`, it will be invoked with the current offset into
    /// the mapping, and the return value from the closure will be used to
    /// initialize that byte.
    pub fn map_init<F>(
                &mut self, gpaddr: PhysAddr, page_type: PageType,
                size: u64, read: bool, write: bool, exec: bool,
                exec_user: bool, init: Option<F>) -> Option<()>
            where F: Fn(u64) -> u8 {
        // Make sure some permission is set
        assert!(read || write || exec || exec_user,
                "No permissions set for EPT mapping");

        // Get access to physical memory
        let mut phys_mem = mm::PhysicalMemory;

        // Get the raw page size in bytes and the mask
        let page_size = page_type as u64;
        let page_mask = page_size - 1;

        // Save off the original guest physical address
        let orig_gpaddr = gpaddr;

        // Make sure that the guest physical address is aligned to the page
        // size request
        if size <= 0 || (gpaddr.0 & page_mask) != 0 {
            return None;
        }

        // Compute the end guest physical address of this mapping
        let end_gpaddr = gpaddr.0.checked_add(size - 1)?;

        // Go through each page in this mapping
        for gpaddr in (gpaddr.0..=end_gpaddr).step_by(page_size as usize) {
            // Allocate the page
            let page = phys_mem.alloc_phys(
                Layout::from_size_align(page_size as usize,
                                        page_size as usize).unwrap())?;

            // Create the page table entry for this page
            let ent = page.0 | EPT_MEMTYPE_WB |
                if read       { EPT_READ      } else { 0 } |
                if write      { EPT_WRITE     } else { 0 } |
                if exec       { EPT_EXEC      } else { 0 } |
                if exec_user  { EPT_USER_EXEC } else { 0 } |
                if page_type != PageType::Page4K { EPT_PAGE_SIZE } else { 0 };

            if let Some(init) = &init {
                // Translate the page
                let sliced = unsafe {
                    let bytes = phys_mem.translate_mut(
                        page, page_size as usize)?;

                    // Get access to the memory we just allocated
                    core::slice::from_raw_parts_mut(
                        bytes, page_size as usize)
                };

                for (off, byte) in sliced.iter_mut().enumerate() {
                    *byte = init(gpaddr - orig_gpaddr.0 + off as u64);
                }
            }

            // Add this mapping to the page table
            unsafe {
                if self.map_raw(PhysAddr(gpaddr),
                        page_type, ent).is_none() {
                    // Failed to map, undo everything we have done so far
                    let mapped = gpaddr - orig_gpaddr.0;

                    if mapped > 0 {
                        // Free everything that we mapped up until the failure
                        self.free(orig_gpaddr, mapped);
                    }

                    return None;
                }
            }
        }

        Some(())
    }

    /// Free the guest physical memory region indicated by `gpaddr` and `size`.
    /// All pages used to back the allocation will be freed, and any
    /// intermediate page tables which no longer contain any mappings will be
    /// unlinked from the table and also freed.
    pub unsafe fn free(&mut self, _gpaddr: PhysAddr, _size: u64) {
        unimplemented!();
    }

    /// Translate a guest physical address in the `self` page table into its
    /// components. This will include entries for every level in the table as
    /// well as the final page result if the page is mapped and present.
    pub fn translate(&self, gpaddr: PhysAddr) -> Option<Mapping> {
        unsafe {
            (*(self as *const Self as *mut Self)).translate_int(gpaddr, false)
        }
    }
    
    /// Translate a guest physical address in the `self` page table into its
    /// components. This will include entries for every level in the table as
    /// well as the final page result if the page is mapped and present.
    ///
    /// If `dirty` is set to `true`, then the accessed and dirty bits will be
    /// set during the page table walk.
    pub fn translate_dirty(&mut self, gpaddr: PhysAddr, dirty: bool)
            -> Option<Mapping> {
        unsafe {
            self.translate_int(gpaddr, dirty)
        }
    }

    /// Translate a guest physical address in the `self` page table into its
    /// components. This will include entries for every level in the table as
    /// well as the final page result if the page is mapped and present.
    ///
    /// If `dirty` is set to `true`, then the accessed and dirty bits will be
    /// set during the page table walk.
    pub unsafe fn translate_int(&mut self, gpaddr: PhysAddr, dirty: bool)
            -> Option<Mapping> {
        // Get access to physical memory
        let mut phys_mem = mm::PhysicalMemory;

        // Start off with an empty mapping
        let mut ret = Mapping {
            pml4e: None,
            pdpe:  None,
            pde:   None,
            pte:   None,
            page:  None,
        };
        
        // Get the components of the address
        let indicies = [
            (gpaddr.0 >> 39) & 0x1ff,
            (gpaddr.0 >> 30) & 0x1ff,
            (gpaddr.0 >> 21) & 0x1ff,
            (gpaddr.0 >> 12) & 0x1ff,
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

            // Get a mapped virtual address for this entry
            let vad = phys_mem.translate_mut(ptp, size_of::<u64>())?;
            let ent = core::ptr::read(vad as *const u64);

            // Check if this page is present
            if (ent & EPT_PRESENT) == 0 {
                // Page is not present, break out and stop the translation
                break;
            }

            // Update dirty bits if requested
            if dirty {
                core::ptr::write_volatile(vad as *mut u64,
                    ent | EPT_DIRTY | EPT_ACCESSED);
            }

            // Update the table to point to the next level
            table = PhysAddr(ent & 0xffffffffff000);

            // Check if this is the page mapping and not pointing to a table
            if depth == 3 || (ent & EPT_PAGE_SIZE) != 0 {
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

                // Compute the offset in the page for the `gpaddr`
                let page_off = gpaddr.0 & page_mask;

                // Store the page and offset
                ret.page = Some((PhysAddr(page_paddr), page_off));

                // Translation done
                break;
            }
        }

        Some(ret)
    }

    /// Map a `gpaddr` to a raw page table entry `raw`. This will use the page
    /// size specified by `page_type`.
    ///
    /// If the mapping already exists, this returns `None`. In this case, no
    /// modifications were made to the page table.
    ///
    /// * `gpaddr`    - Guest physical address to create the mapping at
    /// * `page_type` - The page size to be used for the entry
    /// * `raw`       - The raw page table entry to use
    pub unsafe fn map_raw(&mut self, gpaddr: PhysAddr, page_type: PageType,
            raw: u64) -> Option<()> {
        // Only allow 4K pages in tracked mappings
        if page_type != PageType::Page4K {
            return None;
        }

        // Get access to physical memory
        let mut phys_mem = mm::PhysicalMemory;

        // We're mapping a non-present page or we're mapping a large page
        // without the page size bit set, this page will _never_ be valid so
        // just return fail.
        if (raw & EPT_PRESENT) == 0 ||
                (page_type != PageType::Page4K && (raw & EPT_PAGE_SIZE) == 0) {
            return None;
        }

        // Determine the state of the existing mapping
        let mapping = self.translate(gpaddr)?;

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
            (gpaddr.0 >> 39) & 0x1ff,
            (gpaddr.0 >> 30) & 0x1ff,
            (gpaddr.0 >> 21) & 0x1ff,
            (gpaddr.0 >> 12) & 0x1ff,
        ];

        // Track the level into the tracking table
        let mut tracking = self.tracking;

        // Create page tables as needed while walking to the final page
        for ii in 1..depth {
            // Check if there is a table along the path
            if entries[ii].is_none() {
                // Allocate a new empty table
                let table = phys_mem.alloc_phys_zeroed(
                    Layout::from_size_align(4096, 4096).unwrap())?;

                // Convert the address of the page table entry where we need
                // to insert the new table
                let ptr = phys_mem.translate_mut(entries[ii - 1].unwrap(),
                    core::mem::size_of::<u64>())?;

                if ii >= 2 {
                    // Get access to the entry with the reference count of the
                    // table we're updating
                    let ptr = phys_mem.translate_mut(entries[ii - 2].unwrap(),
                        core::mem::size_of::<u64>())?;
                    
                    // Read the entry
                    let nent = core::ptr::read(ptr as *const u64);

                    // Update the reference count
                    let in_use = (nent >> 52) & 0x3ff;
                    let nent = (nent & !0x3ff0_0000_0000_0000) |
                        ((in_use + 1) << 52);

                    // Write in the new entry
                    core::ptr::write(ptr as *mut u64, nent);
                }

                {
                    // Convert the tracking table into it's underlying type
                    let ttbl =
                        &mut *(tracking.0 as *mut [u64; 512 / 64 + 512]);

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
                    table.0 | EPT_PRESENT);

                // Update the mapping state as we have changed the tables
                entries[ii] = Some(PhysAddr(
                    table.0 + indicies[ii] * core::mem::size_of::<u64>() as u64
                ));
            }

            // Traverse the tracking table regardless of if we created a new
            // page or not.
            {
                // Convert the tracking table into it's underlying type
                let ttbl = &mut *(tracking.0 as *mut [u64; 512 / 64 + 512]);
                let nxt = ttbl[512 / 64 + indicies[ii - 1] as usize];
                tracking = VirtAddr(nxt);
            }
        }
        
        {
            // Get access to the entry with the reference count of the
            // table we're updating with the new page
            let ptr = phys_mem.translate_mut(entries[depth - 2].unwrap(),
                core::mem::size_of::<u64>())?;
            
            // Read the entry
            let nent = core::ptr::read(ptr as *const u64);

            // Update the reference count
            let in_use = (nent >> 52) & 0x3ff;
            let nent = (nent & !0x3ff0_0000_0000_0000) |
                ((in_use + 1) << 52);

            // Write in the new entry
            core::ptr::write(ptr as *mut u64, nent);
        }

        {
            // Convert the tracking table into it's underlying type
            let ttbl = &mut *(tracking.0 as *mut [u64; 512 / 64 + 512]);

            let bit = indicies[depth - 1] % 64;
            let idx = indicies[depth - 1] / 64;
            
            // Set that there is a table at this index
            ttbl[idx as usize] |= 1 << bit;
        }

        // At this point, the tables have been created, and the page doesn't
        // already exist. Thus, we can write in the mapping!
        let ptr = phys_mem.translate_mut(entries[depth - 1].unwrap(),
            core::mem::size_of::<u64>())?;
        core::ptr::write(ptr as *mut u64, raw);

        Some(())
    }
    
    /// Invoke a closure on every dirtied page
    /// Closure arguments are (guest physical, host physical)
    pub unsafe fn for_each_dirty_page<F>(&mut self, mut callback: F)
            where F: FnMut(PhysAddr, PhysAddr) {
        /// Accessed and dirty
        const AD: u64 = EPT_ACCESSED | EPT_DIRTY;

        // Get access to physical memory
        let mut phys_mem = mm::PhysicalMemory;

        // Track the level into the tracking table
        let tracking = &*(self.tracking.0 as *mut [u64; 512 / 64 + 512]);

        let mut bit = [0u64; 4];

        macro_rules! tracking {
            ($rec:expr, $pt:expr, $tracking:expr, $e:expr, $($es:expr),+) => {
                let table =
                    phys_mem.translate_mut($pt, 4096).unwrap() as *mut u64;

                for (ii, &bits) in $tracking[..512 / 64].iter().enumerate() {
                    let mut bits: u64 = bits;
                    while bits != 0 {
                        let tz = bits.trailing_zeros() as u64;
                        bits &= !(1 << tz);

                        // Compute the page index
                        let pfn = ii as u64 * 64 + tz;

                        // Get the page table entry
                        let pte = table.offset(pfn as isize);

                        // Skip non-present pages
                        if (*pte & EPT_PRESENT) == 0 {
                            continue;
                        }

                        if $rec == 3 {
                            // Skip the entry if it's not both dirty and
                            // present
                            if (*pte & EPT_DIRTY) != EPT_DIRTY { continue; }
                        } else {
                            // Skip the entry if it's not accessed
                            if (*pte & EPT_ACCESSED) != EPT_ACCESSED {
                                continue;
                            }
                        }

                        // Clear the accessed and dirty bits
                        *pte &= !AD;

                        // Compute the physical address of the table/page
                        let _next_table = PhysAddr(*pte & 0xffffffffff000);

                        bit[$rec] = pfn;
                        let _tracking =
                            &*($tracking[512 / 64 + bit[$rec] as usize] as
                               *mut [u64; 512 / 64 + 512]);
                        tracking!($rec + 1, _next_table, _tracking, $($es),*);
                    }
                }
            };
            ($rec:expr, $pt:expr, $tracking:expr, $e:expr) => {
                let gpaddr = PhysAddr(bit[0] << 39 |
                                      bit[1] << 30 |
                                      bit[2] << 21 |
                                      bit[3] << 12);
                callback(gpaddr, $pt);
            };
        }
        
        tracking!(0, self.table(), tracking, 0, 0, 0, 0, 0);
    }
}

