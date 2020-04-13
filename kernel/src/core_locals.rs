//! This file is used to hold and access all of the core locals

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::mm::PageFreeList;
use lockcell::LockCell;
use page_table::PhysAddr;
use boot_args::{BootArgs, KERNEL_PHYS_WINDOW_BASE};

/// A counter of all cores online
static CORES_ONLINE: AtomicUsize = AtomicUsize::new(0);

/// A core-exclusive data structure which can be accessed via the `core!()`
/// macro.
///
/// This structure must be `Sync` since the same core locals will be used
/// during an interrupt on this core.
#[repr(C)]
pub struct CoreLocals {
    /// The address of this structure
    address: usize,

    /// A unique, sequentially allocated identifier for this core
    pub id: usize,

    /// A reference to the bootloader arguments
    pub boot_args: &'static BootArgs,

    /// A core local free list of pages
    pub free_list: LockCell<PageFreeList>,
}

/// Empty marker trait that requires `Sync`, such that we can compile-time
/// assert that `CoreLocals` is `Sync`
trait CoreGuard: Sync + Sized {}
impl CoreGuard for CoreLocals {}

/// A shortcut to get access to the core locals
#[macro_export]
macro_rules! core {
    () => {
        $crate::core_locals::get_core_locals()
    }
}

/// Get a reference to the current core locals
#[inline]
pub fn get_core_locals() -> &'static CoreLocals {
    unsafe {
        let ptr: usize;

        // Get the first `u64` from `CoreLocals`, which given we don't change
        // the structure shape, should be the address of the core locals.
        asm!("mov $0, gs:[0]" :
             "=r"(ptr) :: "memory" : "volatile", "intel");

        &*(ptr as *const CoreLocals)
    }
}

/// Initialize the locals for this core
pub fn init(boot_args: PhysAddr) {
    // Convert the physical boot args pointer into the linear mapping
    let boot_args: &'static BootArgs = unsafe {
        &*((boot_args.0 + KERNEL_PHYS_WINDOW_BASE) as *const BootArgs)
    };

    // Get access to the physical memory allocator
    let mut pmem = boot_args.free_memory.lock();
    let pmem = pmem.as_mut().unwrap();

    // Allocate the core locals
    let core_local_ptr = pmem.allocate(
        core::mem::size_of::<CoreLocals>() as u64,
        core::mem::align_of::<CoreLocals>() as u64).unwrap() +
        KERNEL_PHYS_WINDOW_BASE as usize;

    // Construct the core locals
    let core_locals = CoreLocals {
        address:   core_local_ptr,
        id:        CORES_ONLINE.fetch_add(1, Ordering::SeqCst),
        boot_args: boot_args,
        free_list: LockCell::new(PageFreeList::new()),
    };

    unsafe {
        // Move the core locals into the allocation
        core::ptr::write(core_local_ptr as *mut CoreLocals, core_locals);
        cpu::set_gs_base(core_local_ptr as u64);
    }
}

