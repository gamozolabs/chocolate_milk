//! The virtual and physical memory manager for the kernel

use core::marker::PhantomData;
use core::mem::{size_of, align_of};
use core::ops::{Deref, DerefMut};
use core::alloc::{Layout, GlobalAlloc};
use core::sync::atomic::{AtomicU64, AtomicPtr, Ordering};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;

use crate::acpi::MAX_CORES;

use rangeset::Range;
use boot_args::{KERNEL_PHYS_WINDOW_BASE, KERNEL_PHYS_WINDOW_SIZE};
use boot_args::KERNEL_VMEM_BASE;
use page_table::{PhysMem, PhysAddr, PageType, VirtAddr};
use page_table::{PAGE_PRESENT, PAGE_WRITE, PAGE_NX};

/// Table which is indexed by an APIC identifier to map to a physical range
/// which is local to it its NUMA node
static APIC_TO_MEMORY_RANGE: AtomicPtr<[Option<Range>; MAX_CORES]> =
    AtomicPtr::new(core::ptr::null_mut());

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

/// Metadata on a freed allocation
#[repr(C)]
struct FreeListNode {
    /// Virtual address of the next `FreeListNode`
    next: *mut FreeListNode,

    /// Number of free slots in `free_mem`
    free_slots: usize,
    
    /// Virtual addresses of free allocations
    free_addrs: [*mut u8; 0],
}

/// A free list which holds free entries of `size` bytes in a semi-linked list
/// table thingy.
pub struct FreeList {
    /// Pointer to the first entry in the free list
    head: *mut FreeListNode,
    
    /// Size of allocations (in bytes) for this free list
    size: usize,
}

impl FreeList {
    /// Create a new, empty free list containing addresses to `size` byte
    /// allocations
    pub fn new(size: usize) -> Self {
        // Ensure some properties of the free list size
        assert!(size.count_ones() == 1,
            "Free list size must be a power of two");
        assert!(size >= size_of::<usize>(),
            "Free list size must be at least pointer width");
        FreeList { head: core::ptr::null_mut(), size }
    }

    /// Get a address from the free list
    pub unsafe fn pop(&mut self) -> *mut u8 {
        // If the free list is empty
        if self.head.is_null() {
            if self.size <= 4096 {
                // Special case, if the allocation fits within a page, we can
                // directly return virtual addresses to our physical memory
                // map. This is significantly better for TLBs and caches than
                // to create new page tables for allocating a new virtual
                // address. Especially since we use large pages (if possible)
                // to map in the physical map
            
                // Get access to physical memory
                let alc = {
                    let mut phys_mem =
                        core!().boot_args.free_memory_ref().lock();
                    let phys_mem = phys_mem.as_mut().unwrap();

                    // Allocate 4096 bytes of page aligned physical memory, we
                    // do bulk allocations here to improve performance and to
                    // decrease the amount of physical memory lost due to
                    // carving off alignment bytes
                    let alc = phys_mem.allocate_prefer(4096, 4096,
                                                       memory_range())
                        .expect("Failed to allocate physical memory") as u64;

                    // Update stats
                    GLOBAL_ALLOCATOR.free_physical.store(
                        phys_mem.sum().unwrap(),
                        Ordering::Relaxed);

                    alc
                };

                // Split up this allocation and free the segments
                for offset in (0..4096).step_by(self.size) {
                    // Get the virtual address for this physical address
                    let vaddr = slice_phys_mut(
                        PhysAddr(alc + offset), self.size as u64).as_mut_ptr();

                    // Add this to the free list
                    self.push(vaddr);
                }
            } else {
                // Allocation size exceeds a page, we must allocate new virtual
                // memory to satisfy the allocation

                // Allocate a virtual address to hold this allocation
                let vaddr = alloc_virt_addr_4k(self.size as u64);
        
                // Get access to physical memory
                let mut pmem = PhysicalMemory;

                // Get access to virtual memory
                let mut page_table = core!().boot_args.page_table.lock();
                let page_table = page_table.as_mut().unwrap();

                // Map in the memory as RW
                page_table.map(&mut pmem, vaddr, PageType::Page4K,
                               self.size as u64, true, true, false, false)
                    .expect("Failed to map RW memory");

                // Return out the allocation
                return vaddr.0 as *mut u8;
            }
        }

        // We're about to pop from the free list, adjust the stats
        GLOBAL_ALLOCATOR.free_list.fetch_sub(self.size as u64,
                                             Ordering::SeqCst);

        if self.size <= core::mem::size_of::<usize>() * 2 {
            // Basic linked list for super small allocations which can't hold
            // our stack-based free list metadata

            // Save the current head (our new allocation)
            let alc = self.head;

            // Set the head to the next node
            self.head = (*alc).next;

            alc as *mut u8
        } else {
            // Get access to the free list stack
            let fl = &mut *self.head;

            // Check if there are any addresses on the stack
            if fl.free_slots <
                    ((self.size / core::mem::size_of::<usize>()) - 2) {
                // Just grab the free entry
                let alc =
                    *fl.free_addrs.as_mut_ptr().offset(fl.free_slots as isize);

                // Update number of free slots
                fl.free_slots += 1;

                // Return the allocation
                alc
            } else {
                // The free page stack is empty at this level, take the entire
                // node and use it as the allocation

                // Get the old head, will be our allocation
                let alc = self.head;

                // Update the head to point to the next entry
                self.head = fl.next;

                // Return out the allocation
                alc as *mut u8
            }
        }
    }

    /// Put an allocation back onto the free list
    pub unsafe fn push(&mut self, vaddr: *mut u8) {
        // We're about to push to the free list, adjust the stats
        GLOBAL_ALLOCATOR.free_list.fetch_add(self.size as u64,
                                             Ordering::SeqCst);

        if self.size <= core::mem::size_of::<usize>() * 2 {
            // If the free list is too small to contain our stack free list,
            // then just directly use a linked list
            
            // Write the old head into the newly freed `vaddr`
            let vaddr = vaddr as *mut FreeListNode;
            (*vaddr).next = self.head;

            // Update the head
            self.head = vaddr;
        } else {
            // Check if there is room for this allocation in the free stack,
            // or if we need to create a new stack
            if self.head.is_null() || (*self.head).free_slots == 0 {
                // No free slots, create a new stack out of the freed vaddr
                let vaddr = &mut *(vaddr as *mut FreeListNode);

                // Set the number of free slots to the maximum size, as all
                // entries are free in the stack
                // This is the size of the allocation, minus the 2 `usize`
                // header (in entries)
                vaddr.free_slots =
                    (self.size / core::mem::size_of::<usize>()) - 2;

                // Update the next to point to the old head
                vaddr.next = self.head;

                // Establish this as the new free list head
                self.head = vaddr;
            } else {
                // There's room in the current stack, just throw us in there
                let fl = &mut *self.head;

                // Decrement the number of free slots
                fl.free_slots -= 1;

                // Store our newly freed virtual address into this slot
                *fl.free_addrs.as_mut_ptr().offset(fl.free_slots as isize) =
                    vaddr;
            }
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

    fn alloc_phys(&mut self, layout: Layout) -> Option<PhysAddr> {
        if layout.size() <= 4096 && layout.align() <= layout.size() {
            // Special case, just allocate directly from our free lists. Our
            // free lists for allocations <= 4096 bytes directly map to the
            // physical memory map, and are naturally aligned
            unsafe {
                let ptr = core!().free_list(layout).lock().pop();
                Some(PhysAddr(ptr as u64 - KERNEL_PHYS_WINDOW_BASE))
            }
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

            // Update stats
            GLOBAL_ALLOCATOR.free_physical
                .store(phys_mem.sum().unwrap(), Ordering::Relaxed);
        
            Some(PhysAddr(alc as u64))
        }
    }
}

/// The global allocator for the bootloader, this just uses physical memory as
/// a backing and does not handle any fancy things like fragmentation. Use this
/// carefully.
#[global_allocator]
static GLOBAL_ALLOCATOR: GlobalAllocator = GlobalAllocator {
    num_allocs:    AtomicU64::new(0),
    num_frees:     AtomicU64::new(0),
    free_physical: AtomicU64::new(0),
    free_list:     AtomicU64::new(0),
};

/// Empty structure that we can implement `GlobalAlloc` for such that we can
/// use the `#[global_allocator]`
#[derive(Debug)]
struct GlobalAllocator {
    /// Number of allocations performed
    num_allocs: AtomicU64,

    /// Number of frees performed
    num_frees: AtomicU64,

    /// Current number of free bytes in the physical memory pool, this only
    /// ever decreases since we do not free back to physical memory
    free_physical: AtomicU64,

    /// Number of bytes sitting in free lists
    free_list: AtomicU64,
}

/// Print the allocation statistics to the screen
pub fn print_alloc_stats() {
    // Get total amount of physical memory
    let total_phys = core!().boot_args
        .total_physical_memory.load(Ordering::Relaxed);

    // Get physical memory in use
    let phys_inuse = 
        total_phys - GLOBAL_ALLOCATOR.free_physical.load(Ordering::Relaxed);

    print!("Allocs {:8} | Frees {:8} | Physical {:10.2} MiB / {:10.2} MiB | Free List {:10.2} MiB\n",
           GLOBAL_ALLOCATOR.num_allocs.load(Ordering::Relaxed),
           GLOBAL_ALLOCATOR.num_frees.load(Ordering::Relaxed),
           phys_inuse as f64 / 1024. / 1024.,
           total_phys as f64 / 1024. / 1024.,
           GLOBAL_ALLOCATOR.free_list.load(Ordering::Relaxed) as f64 / 1024. / 1024.);
}

unsafe impl GlobalAlloc for GlobalAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Allocate memory from our free lists
        let ptr = core!().free_list(layout).lock().pop();

        // Update stats
        self.num_allocs.fetch_add(1, Ordering::Relaxed);

        ptr
    }
    
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // Free the memory
        core!().free_list(layout).lock().push(ptr);

        // Update stats
        self.num_frees.fetch_add(1, Ordering::Relaxed);
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
        unimplemented!("PhysContig drop");
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

