//! Memory management routines for the bootloader allocator

use core::convert::TryInto;
use core::alloc::{GlobalAlloc, Layout};

use crate::realmode::{RegisterState, invoke_realmode};

use crate::BOOT_ARGS;
use page_table::{PhysAddr, PhysMem};
use rangeset::{Range, RangeSet};

/// A wrapper on a range set to allow implementing the `PhysMem` trait
pub struct PhysicalMemory<'a>(pub &'a mut RangeSet);

impl<'a> PhysMem for PhysicalMemory<'a> {
    unsafe fn translate(&mut self, paddr: PhysAddr, size: usize)
            -> Option<*const u8> {
        self.translate_mut(paddr, size).map(|x| x as *const u8)
    }

    unsafe fn translate_mut(&mut self, paddr: PhysAddr, size: usize)
            -> Option<*mut u8> {
        assert!(size > 0, "Attempted to translate zero size memory");

        // Convert the physical address into a `usize` which is addressable in
        // the bootloader
        let paddr: usize = paddr.0.try_into().ok()?;
        let _pend: usize = paddr.checked_add(size - 1)?;

        // At this point, `paddr` for `size` bytes fits in the 32-bit address
        // space we have mapped in!
        Some(paddr as *mut u8)
    }

    unsafe fn tlb_shootdown(&mut self) {}

    fn alloc_phys(&mut self, layout: Layout) -> Option<PhysAddr> {
        Some(PhysAddr(
            self.0.allocate(layout.size() as u64, layout.align() as u64)
                .expect("Failed to allocate physical memory") as u64
        ))
    }

    fn free_phys(&mut self, addr: PhysAddr, size: u64) {
        let end = size.checked_sub(1).and_then(|x| x.checked_add(addr.0))
            .expect("Integer overflow on free");

        self.0.insert(Range { start: addr.0, end: end });
    }
}

/// The global allocator for the bootloader, this just uses physical memory as
/// a backing and does not handle any fancy things like fragmentation. Use this
/// carefully.
#[global_allocator]
static GLOBAL_ALLOCATOR: GlobalAllocator = GlobalAllocator;

/// Empty structure that we can implement `GlobalAlloc` for such that we can
/// use the `#[global_allocator]`
struct GlobalAllocator;

unsafe impl GlobalAlloc for GlobalAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Get access to physical memory
        let mut pmem = BOOT_ARGS.free_memory_ref().lock();
        pmem.as_mut().and_then(|x| {
            x.allocate(layout.size() as u64, layout.align() as u64)
        }).unwrap_or(0) as *mut u8
    }
    
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Get access to physical memory
        let mut pmem = BOOT_ARGS.free_memory_ref().lock();
        pmem.as_mut().and_then(|x| {
            let end = (ptr as u64)
                .checked_add(layout.size().checked_sub(1)? as u64)?;
            x.insert(Range { start: ptr as u64, end: end });
            Some(())
        }).expect("Cannot free memory without initialized MM");
    }
}

/// Handler for when we run out of memory, we just simply panic
#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    panic!("Out of memory");
}

/// Initialize the physical memory manager. Here we get the memory map from the
/// BIOS via E820 and put it into a `RangeSet` for tracking and allocation.
/// We also subtract off the first 1 MiB of memory to prevent BIOS data
/// structures from being overwritten.
pub fn init() {
    // Create a `RangeSet` to hold the memory that is marked free by the
    // BIOS
    let mut pmem = unsafe { BOOT_ARGS.free_memory_ref().lock() };

    // If physical memory has already been initialized, just return out!
    if pmem.is_some() {
        return;
    }

    // Create a new empty `RangeSet` for tracking free physical memory
    let mut free_memory = RangeSet::new();

    // Loop through the memory the BIOS reports twice. The first time we
    // accumulate all of the memory that is marked as free. The second pass
    // we remove all ranges that are not marked as free.
    // This sanitizes the BIOS memory map, and makes sure that any memory
    // marked both free and non-free, is not marked free at all.
    for &add_free_mem in &[true, false] {
        // Allocate a register state to use when doing the E820 call
        let mut regs = RegisterState::default();

        // Set the continuation code to 0 for the first E820 call
        regs.ebx = 0;

        loop {
            /// Raw E820 entry, to be filled in by the BIOS
            #[derive(Debug, Default)]
            #[repr(C)]
            struct E820Entry {
                base: u64,
                size: u64,
                typ:  u32,
            }

            // Create a zeroed out E820 entry
            let mut entry = E820Entry::default();

            // Set up the arguments for E820, we use the previous
            // continuation code
            regs.eax = 0xe820;
            regs.edi = &mut entry as *mut E820Entry as u32;
            regs.ecx = core::mem::size_of_val(&entry) as u32;
            regs.edx = u32::from_be_bytes(*b"SMAP");
            
            // Invoke the BIOS for the E820 memory map
            unsafe { invoke_realmode(0x15, &mut regs); }

            // Check the CF for an error
            if (regs.efl & 1) != 0 {
                panic!("Error reported by BIOS on E820");
            }

            if add_free_mem && entry.typ == 1 && entry.size > 0 {
                // If the entry is free, mark the memory as free
                free_memory.insert(Range {
                    start: entry.base,
                    end:   entry.base.checked_add(entry.size - 1).unwrap(),
                });
            } else if !add_free_mem && entry.typ != 1 && entry.size > 0 {
                // If the memory is marked as non-free, remove it from the
                // range
                free_memory.remove(Range {
                    start: entry.base,
                    end:   entry.base.checked_add(entry.size - 1).unwrap(),
                });
            }

            if regs.ebx == 0 {
                // Last entry
                break;
            }
        }
    }

    // Remove the first 1 MiB of memory for use. The BIOS does some weird stuff
    // we can't really trust the memory map in this area. Especially with
    // option ROMs potentially using some of this RAM.
    free_memory.remove(Range {
        start: 0,
        end:   1024 * 1024 - 1,
    });

    // Set up the global physical memory state with the free memory we have
    // tracked.
    *pmem = Some(free_memory);
}

