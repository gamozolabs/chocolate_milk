use core::alloc::{Layout, GlobalAlloc};
use core::sync::atomic::{AtomicU64, Ordering};

use rangeset::Range;
use boot_args::{KERNEL_PHYS_WINDOW_BASE, KERNEL_PHYS_WINDOW_SIZE};
use boot_args::KERNEL_VMEM_BASE;
use page_table::{PhysMem, PhysAddr, PageType, VirtAddr};

/// Base address for virtual allocations
static NEXT_FREE_VADDR: AtomicU64 = AtomicU64::new(KERNEL_VMEM_BASE);

/// Read a physical address containing a type `T`. This just handles the
/// windowing and performs a `core::ptr::read_volatile`.
pub unsafe fn read_phys<T>(paddr: PhysAddr) -> T {
    let end = (core::mem::size_of::<T>() as u64).checked_sub(1).and_then(|x| {
        x.checked_add(paddr.0)
    }).expect("Integer overflow on read_phys");
    assert!(end < KERNEL_PHYS_WINDOW_SIZE,
            "Physical address outside of window");

    core::ptr::read_volatile((KERNEL_PHYS_WINDOW_BASE + paddr.0) as *mut T)
}

/// Write to a physical address containing a type `T`. This just handles the
/// windowing and performs a `core::ptr::write_volatile`.
pub unsafe fn write_phys<T>(paddr: PhysAddr, val: T) {
    let end = (core::mem::size_of::<T>() as u64).checked_sub(1).and_then(|x| {
        x.checked_add(paddr.0)
    }).expect("Integer overflow on write_phys");
    assert!(end < KERNEL_PHYS_WINDOW_SIZE,
            "Physical address outside of window");

    core::ptr::write_volatile(
        (KERNEL_PHYS_WINDOW_BASE + paddr.0) as *mut T, val);
}

/// A wrapper on a range set to allow implementing the `PhysMem` trait
pub struct PhysicalMemory;

impl PhysMem for PhysicalMemory {
    unsafe fn translate(&mut self, paddr: PhysAddr, size: usize) -> *mut u8 {
        // Compute the ending physical address
        let end = (size as u64).checked_sub(1).and_then(|x| {
            x.checked_add(paddr.0)
        }).expect("Integer overflow on physical memory translation");

        // Make sure this physical address fits inside our window
        assert!(end < KERNEL_PHYS_WINDOW_SIZE,
                "Physical address outside of physical window");

        // Convert the physical address into linear mapping view address
        (paddr.0 + KERNEL_PHYS_WINDOW_BASE) as *mut u8
    }

    fn alloc_phys(&mut self, layout: Layout) -> PhysAddr {
        if layout.size() == 4096 && layout.align() == 4096 {
            // Special case, a 4-KiB page was requested

            // Get access to the free list
            let mut free_list = core!().free_pages.lock();

            // Get the head of the free list
            let mut head: PhysAddr = *free_list;

            // Check if the free list is empty
            if head == PhysAddr(0) {
                // Free list was empty
               
                /// Number of bytes to allocate if the page free list is empty
                /// This allows pre-allocating from the expensive rangeset
                /// operations.
                const BULK_SIZE: u64 = 1024 * 1024;

                assert!(BULK_SIZE % 4096 == 0 && BULK_SIZE > 0,
                    "Invalid bulk size, must be 4 KiB aligned and non-zero");

                // Get access to physical memory
                let mut phys_mem = core!().boot_args.free_memory.lock();
                let phys_mem     = phys_mem.as_mut().unwrap();
        
                // Allocate memory in bulk, populating the free list
                let bulk = phys_mem.allocate(BULK_SIZE, layout.align() as u64)
                    .map(|x| PhysAddr(x as u64));

                if bulk.is_none() {
                    // Failed to do bulk allocation, just attempt a normal
                    // allocation. We've given up on bulk operations.
                    let addr = phys_mem.allocate(layout.size() as u64,
                                                 layout.align() as u64)
                        .expect("Failed to allocate physical memory for page");
                    return PhysAddr(addr as u64);
                }
                let bulk = bulk.unwrap();

                // Go through every physical page we just allocated, except for
                // the last one, and link them to the next page
                for paddr in (bulk.0..bulk.0 + BULK_SIZE - 4096).step_by(4096){
                    let paddr = PhysAddr(paddr);
                    unsafe {
                        write_phys(paddr, PhysAddr(paddr.0 + 4096));
                    }
                }

                // Terminate the free list by writing a zero to the next
                // pointer of the final entry
                unsafe {
                    write_phys(PhysAddr(bulk.0 + BULK_SIZE - 4096),
                               PhysAddr(0));
                }

                // Re-assign the head of the free list. This is now the
                // complete free list
                head = bulk;
            }

            // Free list is not empty, allocate from it
            
            // Get the next entry in the free list
            let next_free: PhysAddr = unsafe {
                read_phys(head)
            };

            // Put the next part of the free list back up for use
            *free_list = next_free;

            // We allocated from the free list
            return head;
        }

        // Get access to physical memory
        let mut phys_mem = core!().boot_args.free_memory.lock();
        let phys_mem     = phys_mem.as_mut().unwrap();

        // Could not satisfy allocation from free list, allocate directly from
        // the physical memory pool
        let alc = phys_mem.allocate(layout.size() as u64,
                                    layout.align() as u64)
            .expect("Failed to allocate physical memory");
        PhysAddr(alc as u64)
    }

    fn free_phys(&mut self, phys: PhysAddr, size: u64) {
        if (phys.0 & 0xfff) == 0 && size == 4096 {
            // Get access to the free list
            let mut free_list = core!().free_pages.lock();

            // Link up this new page to point to the current free list head
            unsafe {
                write_phys::<PhysAddr>(phys, *free_list);
            }

            *free_list = phys;
        } else {
            // Compute the end address
            let end = size.checked_sub(1).and_then(|x| {
                x.checked_add(phys.0)
            }).expect("Integer overflow on free_phys");

            // Get access to physical memory
            let mut phys_mem = core!().boot_args.free_memory.lock();
            let phys_mem     = phys_mem.as_mut().unwrap();
            phys_mem.insert(Range { start: phys.0, end: end });
        }
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

impl GlobalAllocator {
    unsafe fn opt_alloc(&self, layout: Layout) -> Option<*mut u8> {
        // 4-KiB align up the allocation size
        let alignsize = (layout.size().checked_add(0xfff)? & !0xfff) as u64;

        // Get a unique address for this mapping
        let vaddr = NEXT_FREE_VADDR.fetch_add(alignsize, Ordering::SeqCst);
        
        // Get access to physical memory
        let mut pmem = PhysicalMemory;

        // Get access to virtual memory
        let mut page_table = core!().boot_args.page_table.lock();
        let page_table = page_table.as_mut()?;

        // Map in the memory as RW
        page_table.map(&mut pmem, VirtAddr(vaddr), PageType::Page4K,
            alignsize, true, true, false)?;

        // Allocation success, `vaddr` now is valid as read-write for
        // `alignsize` bytes!
        Some(vaddr as *mut u8)
    }
}

unsafe impl GlobalAlloc for GlobalAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.opt_alloc(layout).unwrap_or(core::ptr::null_mut())
    }
    
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Get access to physical memory
        let mut pmem = PhysicalMemory;

        // 4-KiB align up the allocation size
        let alignsize =
            (layout.size().checked_add(0xfff).unwrap() & !0xfff) as u64;

        // Get access to virtual memory
        let mut page_table = core!().boot_args.page_table.lock();
        let page_table = page_table.as_mut().unwrap();

        // Free the memory
        page_table.free(&mut pmem, VirtAddr(ptr as u64), alignsize)
            .expect("Failed to free virtual memory in dealloc");
    }
}

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    panic!("Out of memory");
}

