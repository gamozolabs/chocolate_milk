//! A module for handling parsing of all x86 page table types

use core::ops::Range;
use core::mem::size_of;
use core::convert::TryInto;
use page_table::{VirtAddr, PhysAddr, PAGE_PRESENT, PAGE_SIZE};

/// A page table entry describing the shapes, masks, and large paging support
/// of a given level in a page table
#[derive(PartialEq, Eq)]
struct PageTableEntry {
    /// Bits from the virtual address which are used as an index into this
    /// level of the table
    bits: Range<u8>,

    /// Page table entry mask to get the physical address of the pages
    page_mask: u64,

    /// Size of a large page at this level and its physical address mask,
    /// if a large page is supported at this level
    large_page: Option<(u64, u64)>,
}

/// Creates a page table walker for a given page table shape
macro_rules! define_walker {
    ($fname:ident, $metadata:ident, $ety:ty, $cr3_mask:expr, $tbl:expr) => {
    pub fn $fname<'a, F>(cr3: u64, vaddr: VirtAddr, mut translate: F)
        -> Option<(PhysAddr, u64, u64)>
            where F: FnMut(PhysAddr) -> Option<$ety> {
        // Mask off everything but the physical address from the CR3
        let mut table = cr3 & $cr3_mask;

        for (ii, level) in $tbl.iter().enumerate() {
            // Compute the index of the page table entry at this level
            let idx = (vaddr.0 >> level.bits.start) &
                ((1 << (level.bits.end - level.bits.start)) - 1);

            // Find the byte offset into the page table
            let offset = idx * size_of::<$ety>() as u64;

            // Read the entry
            let ent = translate(PhysAddr(table + offset))? as u64;

            // If the page is not present, return page not mapped
            if (ent & PAGE_PRESENT) == 0 {
                return None;
            }

            // Check if this level supports large pages
            if let Some((lp_size, lp_mask)) = level.large_page {
                // Check if this is a large page
                if (ent & PAGE_SIZE) != 0 {
                    // Woo, we have a large page
                   
                    if lp_mask != 0 {
                        // Compute the offset into the page the virtual address
                        // is referencing
                        let offset = vaddr.0 & (lp_size - 1);
                        return Some((PhysAddr(ent & lp_mask),
                            offset, lp_size));
                    } else {
                        // Ugh, special encoding for 4 MiB pages on non-PAE
                        // 32-bit modes
                        assert!(lp_size == 4 * 1024 * 1024);

                        // Figure out the physical address from the weird
                        // encoding
                        let frame31_22 = (ent & 0xffc00000) >> 22;
                        let frame40_32 = (ent & 0x003fe000) >> 13;
                        let frame = (frame40_32 << 32) | (frame31_22 << 22);

                        // Compute the offset into the virtual address
                        let offset = vaddr.0 & (lp_size - 1);
                        return Some((PhysAddr(frame), offset, lp_size));
                    }
                }
            }

            // Check if this is the last level of the table
            if ii == $tbl.len() - 1 {
                // It's a page!

                // Compute the offset into the page the virtual address is
                // referencing
                let offset = vaddr.0 & 0xfff;
                return Some((PhysAddr(ent & level.page_mask), offset, 4096));
            } else {
                // It's a next level entry, update the table pointer
                table = ent & level.page_mask;
            }
        }

        // We cannot get here
        unreachable!();
    }

    pub fn $metadata<'a, F, C>(table: u64, depth: u8, get_page: &mut F,
                               callback: &mut C)
            where F: FnMut(PhysAddr) -> Option<&'a [u8]>,
                  C: FnMut(PhysAddr) -> bool {
        // Mask the entry to get the page table
        let table = if depth == !0 {
            table & $cr3_mask
        } else {
            table & $tbl[depth as usize].page_mask
        };

        // Invoke the callback with the metadata information
        if !callback(PhysAddr(table)) {
            return;
        }

        // Stop traversal before the final PTE, we don't actually want to
        // walk the pages in the system, only the page _tables_ so we stop
        // before the final leaf
        if depth.wrapping_add(2) as usize == $tbl.len() {
            return;
        }

        // Get the information about this page table level
        let level = &$tbl[depth.wrapping_add(1) as usize];

        // Determine the number of entries at this level
        let entries = 1 << (level.bits.end - level.bits.start);

        // Get access to the page table entries for this level
        let page = get_page(PhysAddr(table));
        if page.is_none() { return; }
        let page = page.unwrap();

        // Go through each entry at this level
        for ent in 0..entries {
            // Read the page table entry, depending on the page table type
            let ent = <$ety>::from_le_bytes(
                page[ent * size_of::<$ety>()..(ent + 1) * size_of::<$ety>()]
                .try_into().unwrap()) as u64;

            // Skip non-present pages
            if ent & PAGE_PRESENT == 0 { continue; }

            // Skip large pages as that's the end of the structure
            if level.large_page.is_some() && (ent & PAGE_SIZE) != 0 {
                // Entry was a large page, we don't have to recurse
                continue;
            }
            
            // Recurse into this table
            $metadata(ent & level.page_mask, depth.wrapping_add(1),
                get_page, callback);
        }
    }
    }
}

define_walker!(translate_32_no_pae, translate_32_no_pae_metadata, u32,
               0xfffff000, &[
    PageTableEntry { bits: 22..32, page_mask: 0xfffff000,
        large_page: Some((0, 4 * 1024 * 1024)) },

    PageTableEntry { bits: 12..22, page_mask: 0xfffff000, large_page: None },
]);

define_walker!(translate_32_pae, translate_32_pae_metadata, u64, 0xffffffe0, &[
    PageTableEntry { bits: 30..32, page_mask: 0xffffffffff000,
        large_page: None },

    PageTableEntry { bits: 21..30, page_mask: 0xffffffffff000,
        large_page: Some((2 * 1024 * 1024, 0xfffffffe00000)) },

    PageTableEntry { bits: 12..21, page_mask: 0xffffffffff000,
        large_page: None },
]);

define_walker!(translate_64_4_level, translate_64_4_level_metadata,
               u64, 0xffffffffff000, &[
    PageTableEntry { bits: 39..48, page_mask: 0xffffffffff000,
        large_page: None },

    PageTableEntry { bits: 30..39, page_mask: 0xffffffffff000,
        large_page: Some((1024 * 1024 * 1024, 0xfffffc0000000)) },

    PageTableEntry { bits: 21..30, page_mask: 0xffffffffff000,
        large_page: Some((2 * 1024 * 1024, 0xfffffffe00000)) },

    PageTableEntry { bits: 12..21, page_mask: 0xffffffffff000,
        large_page: None },
]);

