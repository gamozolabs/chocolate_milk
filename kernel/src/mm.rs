use core::convert::TryInto;
use core::alloc::{Layout, GlobalAlloc};

use rangeset::{RangeSet, Range};
use boot_args::BootArgs;
use page_table::{PhysMem, PhysAddr, VirtAddr};

/// A wrapper on a range set to allow implementing the `PhysMem` trait
pub struct PhysicalMemory<'a>(pub &'a mut RangeSet);

impl<'a> PhysMem for PhysicalMemory<'a> {
    unsafe fn translate(&mut self, paddr: PhysAddr, size: usize)
            -> Option<*mut u8> {
        // Can't translate for a 0 size access
        if size <= 0 {
            return None;
        }

        // Convert the physical address into a `usize` which is addressable in
        // the bootloader
        let paddr: usize = paddr.0.try_into().ok()?;
        let _pend: usize = paddr.checked_add(size - 1)?;

        // At this point, `paddr` for `size` bytes fits in the 32-bit address
        // space we have mapped in!
        Some(paddr as *mut u8)
    }

    fn alloc_phys(&mut self, layout: Layout) -> Option<PhysAddr> {
        self.0.allocate(layout.size() as u64, layout.align() as u64)
            .map(|x| PhysAddr(x as u64))
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
        let mut pmem = BOOT_ARGS.free_memory.lock();
        pmem.as_mut().and_then(|x| {
            x.allocate(layout.size() as u64, layout.align() as u64)
        }).unwrap_or(0) as *mut u8
    }
    
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Get access to physical memory
        let mut pmem = BOOT_ARGS.free_memory.lock();
        pmem.as_mut().and_then(|x| {
            let end = (ptr as u64)
                .checked_add(layout.size().checked_sub(1)? as u64)?;
            x.insert(Range { start: ptr as u64, end: end });
            Some(())
        }).expect("Cannot free memory without initialized MM");
    }
}

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    panic!("Out of memory");
}

pub fn init(boot_args: &'static BootArgs) {
}

