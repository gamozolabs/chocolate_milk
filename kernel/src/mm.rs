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
#[allow(dead_code)]
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

/// The metadata on a freed page present in the free list. We don't just
/// directly link the pages together, instead we use the entire 4 KiB of the
/// freed page to hold a list of pages. This _significantly_ reduces the
/// thrashing of TLBs during page allocations. This was about a 4x speedup
/// when allocate 16 GiB virtual allocations using 4 KiB pages compared to
/// using a linked list of free nodes.
struct FreeListNode {
    /// Physical address of the next free `FreeListNode`, could be 0 if the
    /// list terminates
    next: PhysAddr,

    /// Number of available slots in `free_pages`. The pages are always
    /// allocated from offset 509... down to 0. Thus if `free_slots` is 10 that
    /// means that `free_pages[0..9]` are invalid, and `free_pages[10..]` are
    /// valid physical addresses of free pages.
    free_slots: usize,
    
    /// Physical addresses of free pages
    free_pages: [PhysAddr; 510],
}

impl FreeListNode {
    unsafe fn from_raw<'a>(paddr: PhysAddr) -> &'a mut FreeListNode {
        &mut *((KERNEL_PHYS_WINDOW_BASE + paddr.0) as *mut FreeListNode)
    }
}

pub struct PageFreeList {
    head: PhysAddr,
}

impl PageFreeList {
    pub fn new() -> Self {
        assert!(core::mem::size_of::<FreeListNode>() == 4096);
        PageFreeList { head: PhysAddr(0) }
    }

    /// Get a page from the free list
    unsafe fn pop(&mut self) -> PhysAddr {
        // If the free list is empty
        if self.head == PhysAddr(0) {
            const FREE_LIST_BATCH: u64 = 1024 * 1024;

            // Make sure the free list batch is sane
            assert!(FREE_LIST_BATCH > 0 && FREE_LIST_BATCH % 4096 == 0);

            // Get some bulk memory
            let alc = {
                // Get access to physical memory
                let mut phys_mem = core!().boot_args.free_memory.lock();
                let phys_mem     = phys_mem.as_mut().unwrap();

                // Bulk allocate some memory to populate the empty free list
                phys_mem.allocate(FREE_LIST_BATCH, 4096)
                    .expect("Failed to allocate physical memory") as u64
            };

            // Populate the free list
            for paddr in (alc..alc + FREE_LIST_BATCH).step_by(4096) {
                self.push(PhysAddr(paddr));
            }
        }

        // At this point the free list has been populated
        let node = FreeListNode::from_raw(self.head);

        if node.free_slots < node.free_pages.len() {
            // Just grab an entry off the `free_pages`
            let free = node.free_pages[node.free_slots];

            // Note that we used this entry
            node.free_slots += 1;

            free
        } else {
            // The `free_pages` for this level is empty, thus, pop the entire
            // node and use it as the free page

            // Save off the address of this node
            let old = self.head;

            // Point the head to the next node
            self.head = node.next;

            old
        }
    }

    unsafe fn push(&mut self, page: PhysAddr) {
        // If there is no existing free list or the current one is out of slots
        // to hold pages, then we need to turn this freed page into a new
        // `FreeListNode`
        if self.head == PhysAddr(0) ||
                FreeListNode::from_raw(self.head).free_slots == 0 {
            // We need to start a new free list node
            let node = FreeListNode::from_raw(page);

            // Mark that all slots are free
            node.free_slots = node.free_pages.len();

            // Set the next pointer to the old head
            node.next = self.head;

            // Head of the free list now points to this node
            self.head = page;
        } else {
            // There is an active free list with room
            let node = FreeListNode::from_raw(self.head);

            // Decrement number of available slots
            node.free_slots -= 1;

            // Put our page into this entry
            node.free_pages[node.free_slots] = page;
        }
    }
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
            unsafe { core!().free_list.lock().pop() }
        } else {
            // Get access to physical memory
            let mut phys_mem = core!().boot_args.free_memory.lock();
            let phys_mem     = phys_mem.as_mut().unwrap();

            // Could not satisfy allocation from free list, allocate
            // directly from the physical memory pool
            let alc = phys_mem.allocate(layout.size() as u64,
                                        layout.align() as u64)
                .expect("Failed to allocate physical memory");
            PhysAddr(alc as u64)
        }
    }

    fn free_phys(&mut self, phys: PhysAddr, size: u64) {
        if (phys.0 & 0xfff) == 0 && size == 4096 {
            // Get access to the free list
            unsafe { core!().free_list.lock().push(phys); }
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

