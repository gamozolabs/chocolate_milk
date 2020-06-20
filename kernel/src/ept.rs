//! Routines for creating and mapping extended page tables

use core::mem::size_of;
use core::alloc::Layout;

use crate::mm;

use page_table::{PhysMem, PhysAddr, Mapping, PageType};

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
        })
    }
    
    /// Get the address of the page table
    #[inline]
    pub fn table(&self) -> PhysAddr {
        self.table
    }

    /// Translate a guest physical address in the `self` page table into its
    /// components. This will include entries for every level in the table as
    /// well as the final page result if the page is mapped and present.
    pub fn translate(&self, gpaddr: PhysAddr) -> Option<Mapping> {
        unsafe {
            (*(self as *const Self as *mut Self))
                .translate_int(gpaddr, false, false)
        }
    }
    
    /// Translate a guest physical address in the `self` page table into its
    /// components. This will include entries for every level in the table as
    /// well as the final page result if the page is mapped and present.
    ///
    /// If `dirty` is set to `true`, then the accessed and dirty bits will be
    /// set during the page table walk.
    
    /// If `clear` is set to `true`, then the accessed and dirty bits will be
    /// cleared during the page table walk.
    pub fn translate_int(&mut self, gpaddr: PhysAddr, dirty: bool, clear: bool)
            -> Option<Mapping> {
        assert!(!dirty || (dirty != clear),
            "Cannot both clear and dirty EPT at the same time");

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
            let vad = unsafe {
                phys_mem.translate_mut(ptp, size_of::<u64>())?
            };
            let ent = unsafe { core::ptr::read(vad as *const u64) };

            // Check if this page is present
            if (ent & EPT_PRESENT) == 0 {
                // Page is not present, break out and stop the translation
                break;
            }

            // Update dirty bits if requested
            if dirty {
                unsafe {
                    core::ptr::write_volatile(vad as *mut u64,
                        ent | EPT_DIRTY | EPT_ACCESSED);
                }
            } else if clear {
                unsafe {
                    core::ptr::write_volatile(vad as *mut u64,
                        ent & !(EPT_DIRTY | EPT_ACCESSED));
                }
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
                ret.page = Some((PhysAddr(page_paddr), page_off, ent));

                // Translation done
                break;
            }
        }

        Some(ret)
    }

    /// Map a `gpaddr` with zeroed out pages for `len` bytes
    pub fn map(&mut self, gpaddr: PhysAddr, len: u64,
               page_type: PageType,
               read: bool, write: bool, execute: bool) -> Option<()> {
        assert!(gpaddr.0 & (page_type as u64 - 1) == 0,
            "Cannot map EPT range with unaligned base");
        assert!(len > 0 && (len & (page_type as u64 - 1)) == 0,
            "Cannot map EPT range invalid length");

        for gpaddr in (gpaddr.0..gpaddr.0.checked_add(len - 1).unwrap())
                .step_by(page_type as usize) {
            // Get access to physical memory
            let mut phys_mem = mm::PhysicalMemory;

            // Allocate the backing page
            let page = phys_mem.alloc_phys_zeroed(
                Layout::from_size_align(page_type as usize,
                                        page_type as usize).unwrap())?;

            unsafe {
                // Map it in!
                self.map_raw(PhysAddr(gpaddr), page_type,
                    if read    { EPT_READ  } else { 0 } |
                    if write   { EPT_WRITE } else { 0 } |
                    if execute { EPT_EXEC | EPT_USER_EXEC } else { 0 } |
                    if page_type != PageType::Page4K
                        { EPT_PAGE_SIZE } else { 0 } |
                    EPT_MEMTYPE_WB |
                    page.0)?;
            }
        }

        Some(())
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

                // Insert the new table at the entry in the table above us
                core::ptr::write(ptr as *mut u64, table.0 | EPT_PRESENT);

                // Update the mapping state as we have changed the tables
                entries[ii] = Some(PhysAddr(
                    table.0 + indicies[ii] * core::mem::size_of::<u64>() as u64
                ));
            }
        }
        
        // At this point, the tables have been created, and the page doesn't
        // already exist. Thus, we can write in the mapping!
        let ptr = phys_mem.translate_mut(entries[depth - 1].unwrap(),
            core::mem::size_of::<u64>())?;
        core::ptr::write(ptr as *mut u64, raw);

        Some(())
    }
    
    /*
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
    }*/
}

