//! The virtual and physical memory manager for the kernel

use core::marker::PhantomData;
use core::mem::{size_of, align_of};
use core::ops::{Deref, DerefMut};
use core::alloc::{Layout, GlobalAlloc};
use core::sync::atomic::{AtomicU64, AtomicU32, AtomicPtr, Ordering};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;

use crate::acpi::{self, ApicState, MAX_CORES};

use rangeset::Range;
use boot_args::{KERNEL_PHYS_WINDOW_BASE, KERNEL_PHYS_WINDOW_SIZE};
use boot_args::KERNEL_VMEM_BASE;
use page_table::{PageTable, PhysMem, PhysAddr, PageType, VirtAddr};
use page_table::{PAGE_PRESENT, PAGE_WRITE, PAGE_NX};

/// Cores should check this during an NMI to see if they are being shot down
/// If it is equal to their APIC ID, they are being shot down
static SHOULD_SHOOTDOWN: AtomicU32 = AtomicU32::new(!0);

/// Table which is indexed by an APIC identifier to map to a physical range
/// which is local to it its NUMA node
static APIC_TO_MEMORY_RANGE: AtomicPtr<[Option<Range>; MAX_CORES]> =
    AtomicPtr::new(core::ptr::null_mut());

/// Gets the current TLB shootdown state
#[inline]
pub unsafe fn shootdown_state() -> &'static AtomicU32 {
    &SHOULD_SHOOTDOWN
}

/// Get the preferred memory range for the currently running APIC. Returns
/// `None` if we have no valid APIC ID yet, or we do not have NUMA knowledge
/// of the current APIC ID
pub fn memory_range() -> Option<Range> {
    // Check to see if the `APIC_TO_MEMORY_RANGE` has been initialized
    let atmr = APIC_TO_MEMORY_RANGE.load(Ordering::SeqCst);
    if atmr.is_null() {
        return None;
    }

    // Cast the memory range structure to something we can access
    let atmr = unsafe { &*atmr };

    // Based on our current APIC ID look up the memory range
    core!().apic_id().and_then(|x| atmr[x as usize])
}

/// Establish the `APIC_TO_MEMORY_RANGE` global with the APIC IDs to their
/// corresponding NUMA-local memory regions
pub unsafe fn register_numa_nodes(apic_to_domain: BTreeMap<u32, u32>,
        domain_to_mem: BTreeMap<u32, (PhysAddr, u64)>) {
    // Create a heap-based database
    let mut apic_mappings = Box::new([None; MAX_CORES]);

    // Go through each APIC to domain mapping
    for (&apic, domain) in apic_to_domain.iter() {
        apic_mappings[apic as usize] = domain_to_mem.get(domain)
            .and_then(|&(paddr, size)| {
                Some(Range {
                    start: paddr.0,
                    end:   paddr.0.checked_add(size.checked_sub(1)?)?,
                })
            });
    }

    // Store the apic mapping database into the global!
    APIC_TO_MEMORY_RANGE.store(Box::into_raw(apic_mappings), Ordering::SeqCst);
}

/// Find a free region of virtual memory that can hold `size` bytes and return
/// the virtual address
///
/// This is only valid for virtual requests for 4 KiB mappings
pub fn alloc_virt_addr_4k(size: u64) -> VirtAddr {
    /// Base address for virtual allocations
    static NEXT_FREE_VADDR: AtomicU64 = AtomicU64::new(KERNEL_VMEM_BASE);

    /// Gap between virtual allocations
    const GUARD_PAGE_SIZE: u64 = 32 * 1024;

    assert!(size > 0 && (size & 0xfff) == 0,
        "Invalid size for virtual region allocation");

    // Compute the amount of virtual memory to reserve, including the guard
    // size.
    let reserve_size = GUARD_PAGE_SIZE.checked_add(size as u64)
        .expect("Integer overflow on virtual region size");
    
    // Get a new virtual region that is free
    let ret = VirtAddr(
        NEXT_FREE_VADDR.fetch_add(reserve_size, Ordering::SeqCst)
    );

    // If we cannot add the reserve size from the return value, then the
    // virtual memory wrapped the 64-bit boundary
    ret.0.checked_add(reserve_size)
        .expect("Integer overflow on virtual address range");

    ret
}

/// Gets access to a slice of physical memory
#[allow(dead_code)]
#[inline]
pub unsafe fn slice_phys<'a>(paddr: PhysAddr, size: u64) -> &'a [u8] {
    let end = size.checked_sub(1).and_then(|x| {
        x.checked_add(paddr.0)
    }).expect("Integer overflow on read_phys");
    assert!(end < KERNEL_PHYS_WINDOW_SIZE,
            "Physical address outside of window");

    // Return out a slice to this physical memory as mutable
    core::slice::from_raw_parts(
        (KERNEL_PHYS_WINDOW_BASE + paddr.0) as *const u8,
        size as usize)
}

/// Gets mutable access to a slice of physical memory
#[allow(dead_code)]
#[inline]
pub unsafe fn slice_phys_mut<'a>(paddr: PhysAddr, size: u64) -> &'a mut [u8] {
    let end = size.checked_sub(1).and_then(|x| {
        x.checked_add(paddr.0)
    }).expect("Integer overflow on read_phys");
    assert!(end < KERNEL_PHYS_WINDOW_SIZE,
            "Physical address outside of window");

    // Return out a slice to this physical memory as mutable
    core::slice::from_raw_parts_mut(
        (KERNEL_PHYS_WINDOW_BASE + paddr.0) as *mut u8,
        size as usize)
}

/// Read a physical address containing a type `T`. This just handles the
/// windowing and performs a `core::ptr::read_volatile`.
#[allow(dead_code)]
pub unsafe fn read_phys<T>(paddr: PhysAddr) -> T {
    let end = (size_of::<T>() as u64).checked_sub(1).and_then(|x| {
        x.checked_add(paddr.0)
    }).expect("Integer overflow on read_phys");
    assert!(end < KERNEL_PHYS_WINDOW_SIZE,
            "Physical address outside of window");

    core::ptr::read_volatile((KERNEL_PHYS_WINDOW_BASE + paddr.0) as *mut T)
}

/// Write to a physical address containing a type `T`. This just handles the
/// windowing and performs a `core::ptr::write_volatile`.
pub unsafe fn write_phys<T>(paddr: PhysAddr, val: T) {
    let end = (size_of::<T>() as u64).checked_sub(1).and_then(|x| {
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
    /// Create a mutable reference to a `FreeListNode` from a raw physical
    /// address.
    unsafe fn from_raw<'a>(paddr: PhysAddr) -> &'a mut FreeListNode {
        // Make sure the physical address is inside of our physical memory map
        let end = paddr.0.checked_add(4096 - 1).unwrap();
        assert!(end < KERNEL_PHYS_WINDOW_SIZE,
                "Physical address outside of window");

        &mut *((KERNEL_PHYS_WINDOW_BASE + paddr.0) as *mut FreeListNode)
    }
}

/// A free list structure for holding all of the freed physical 4 KiB in size,
/// 4 KiB aligned pages on the system
pub struct PageFreeList {
    /// Physical address of the first entry in the free list
    head: PhysAddr,
}

impl PageFreeList {
    /// Create a new, empty free list
    pub fn new() -> Self {
        assert!(size_of::<FreeListNode>() == 4096);
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
                let mut phys_mem = core!().boot_args.free_memory_ref().lock();
                let phys_mem     = phys_mem.as_mut().unwrap();

                // Bulk allocate some memory to populate the empty free list
                phys_mem.allocate_prefer(FREE_LIST_BATCH, 4096,
                                         memory_range())
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

    /// Put a page back onto the free list. It's up to the caller to make sure
    /// the page is 4 KiB in size and 4 KiB aligned.
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
    unsafe fn translate(&mut self, paddr: PhysAddr, size: usize)
            -> Option<*const u8> {
        self.translate_mut(paddr, size).map(|x| x as *const u8)
    }

    unsafe fn translate_mut(&mut self, paddr: PhysAddr, size: usize)
            -> Option<*mut u8> {
        // Compute the ending physical address
        let end = (size as u64).checked_sub(1).and_then(|x| {
            x.checked_add(paddr.0)
        })?;

        // Make sure this physical address fits inside our window
        if end >= KERNEL_PHYS_WINDOW_SIZE {
            return None;
        }

        // Convert the physical address into linear mapping view address
        Some((paddr.0 + KERNEL_PHYS_WINDOW_BASE) as *mut u8)
    }

    /// Perform a TLB shootdown
    /// Since this takes a mutable reference to the page table, it ensures
    /// the page table lock is currently held.
    unsafe fn tlb_shootdown(&mut self, _pt: &mut PageTable) {
        // Only do this if we have a valid APIC initialized
        if let Some(our_apic_id) = core!().apic_id() {
            // Forcibly get access to the current APIC. This is likely safe in
            // almost every situation as the APIC is not very stateful.
            let apic = &mut *core!().apic().shatter();
            let apic = apic.as_mut().unwrap();

            // Send an NMI to all cores, waiting for it to respond
            for apic_id in 0..acpi::MAX_CORES as u32 {
                // Don't NMI ourself
                if apic_id == our_apic_id { continue; }

                let state = acpi::core_state(apic_id);
                if state == ApicState::Online {
                    SHOULD_SHOOTDOWN.store(apic_id, Ordering::SeqCst);

                    let mut timeout = 0;
                    while SHOULD_SHOOTDOWN.load(Ordering::SeqCst) != !0 {
                        if cpu::rdtsc() >= timeout {
                            if timeout > 0 {
                                panic!("Failed to TLB shootdown APIC {:#x} \
                                       from APIC {:#x}\n",
                                       apic_id, our_apic_id);
                            }

                            // Send NMI
                            apic.ipi(apic_id, (1 << 14) | (4 << 8));

                            // Set a timer until we panic
                            timeout = crate::time::future(10_000);
                        }
                    }
                }
            }
        }
    }

    fn alloc_phys(&mut self, layout: Layout) -> Option<PhysAddr> {
        let ret = if layout.size() == 4096 && layout.align() >= 4096 {
            Some(unsafe { core!().free_list().lock().pop() })
        } else {
            // Get access to physical memory
            let mut phys_mem = unsafe {
                core!().boot_args.free_memory_ref().lock()
            };
            let phys_mem = phys_mem.as_mut()?;

            // Could not satisfy allocation from free list, allocate
            // directly from the physical memory pool
            let alc = phys_mem.allocate_prefer(layout.size() as u64,
                                               layout.align() as u64,
                                               memory_range())?;
            Some(PhysAddr(alc as u64))
        };
        ret
    }

    fn free_phys(&mut self, phys: PhysAddr, size: u64) {
        if (phys.0 & 0xfff) == 0 && size == 4096 {
            // Get access to the free list
            unsafe { core!().free_list().lock().push(phys); }
        } else {
            // Compute the end address
            let end = size.checked_sub(1).and_then(|x| {
                x.checked_add(phys.0)
            }).unwrap();

            // Get access to physical memory
            let mut phys_mem = unsafe {
                core!().boot_args.free_memory_ref().lock()
            };
            let phys_mem = phys_mem.as_mut().unwrap();
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
    /// Virtual memory allocation implementation
    ///
    /// Performs a virtual memory allocation using a new virtual address and
    /// constructed with new pages.
    ///
    /// Returns `None` if the allocation failed, otherwise it returns a pointer
    /// to the base of the allocation.
    unsafe fn opt_alloc(&self, layout: Layout) -> Option<*mut u8> {
        // 4-KiB align up the allocation size
        let alignsize = (layout.size().checked_add(0xfff)? & !0xfff) as u64;

        // Get a unique virtual address for this allocation
        let vaddr = alloc_virt_addr_4k(alignsize);
        
        // Get access to physical memory
        let mut pmem = PhysicalMemory;

        // Get access to virtual memory
        let mut page_table = core!().boot_args.page_table.lock();
        let page_table = page_table.as_mut()?;

        // Map in the memory as RW
        page_table.map(&mut pmem, vaddr, PageType::Page4K,
            alignsize, true, true, false, false)?;

        // Allocation success, `vaddr` now is valid as read-write for
        // `alignsize` bytes!
        Some(vaddr.0 as *mut u8)
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
        page_table.free(&mut pmem, VirtAddr(ptr as u64), alignsize);
    }
}

/// Allocation containing a physically contiguous allocation
pub struct PhysContig<T> {
    /// Virtual address of the allocation
    vaddr: VirtAddr,

    /// Physical address of the allocation
    paddr: PhysAddr,

    /// Mark that this "holds" a `T`
    _phantom: PhantomData<T>,
}

impl<T> PhysContig<T> {
    /// Allocate physically contiguous memory large enough to hold `val` and
    /// move `val` into it
    pub fn new(val: T) -> PhysContig<T> {
        assert!(size_of::<T>() > 0, "Cannot use ZST for PhysContig");

        // If the allocation is smaller than 4 KiB, then round it up to 4 KiB.
        // This allows us to take advantage of our page free lists, and
        // relieves some pressure on the physical memory allocator as the free
        // lists are per-core and do not require a global lock.
        let alc_size = core::cmp::max(4096, size_of::<T>());

        // Get access to physical memory allocations
        let mut pmem = PhysicalMemory;

        // Allocate physical memory for this allocation which is minimum
        // 4 KiB aligned
        let paddr = pmem.alloc_phys(Layout::from_size_align(
            alc_size, core::cmp::max(4096, align_of::<T>())).unwrap())
            .unwrap();
        
        // Allocate a virtual address for this mapping
        let vaddr = alloc_virt_addr_4k(alc_size as u64);
        
        // Get access to the current page table
        let mut page_table = core!().boot_args.page_table.lock();
        let page_table = page_table.as_mut().unwrap();

        // Map in each page from the allocation
        for offset in (0..alc_size as u64).step_by(4096) {
            unsafe {
                // Map the memory as RW
                page_table.map_raw(&mut pmem, VirtAddr(vaddr.0 + offset),
                                   PageType::Page4K,
                                   (paddr.0 + offset) | PAGE_NX | PAGE_WRITE | 
                                   PAGE_PRESENT)
                    .expect("Failed to map PhysContig memory");

            }
        }
        
        unsafe {
            // Initialize the memory
            core::ptr::write(vaddr.0 as *mut T, val);
        }

        // Create the `PhysContig` structure
        PhysContig {
            vaddr,
            paddr,
            _phantom: PhantomData,
        }
    }

    /// Get the physical address of the allocation
    pub fn phys_addr(&self) -> PhysAddr {
        self.paddr
    }
}

impl<T> Drop for PhysContig<T> {
    fn drop(&mut self) {
        unsafe {
            // Drop the contents of the allocation
            core::ptr::drop_in_place(self.vaddr.0 as *mut T);

            // Get access to physical memory
            let mut pmem = PhysicalMemory;
        
            // 4-KiB align up the allocation size
            let alignsize =
                (size_of::<T>().checked_add(0xfff).unwrap() & !0xfff) as u64;

            // Get access to virtual memory
            let mut page_table = core!().boot_args.page_table.lock();
            let page_table = page_table.as_mut().unwrap();

            // Free the memory and page tables used to map it
            page_table.free(&mut pmem,
                            VirtAddr(self.vaddr.0 as u64), alignsize);
        }
    }
}

impl<T> Deref for PhysContig<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe {
            &*(self.vaddr.0 as *const T)
        }
    }
}

impl<T> DerefMut for PhysContig<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            &mut *(self.vaddr.0 as *mut T)
        }
    }
}

/// Out-of-memory handler, we just panic
#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    panic!("Out of memory");
}

