//! This file is used to hold and access all of the core locals

use core::sync::atomic::{AtomicUsize, AtomicU32, Ordering};

use crate::apic::Apic;
use crate::mm::PageFreeList;
use crate::interrupts::Interrupts;

use lockcell::LockCell;
use page_table::PhysAddr;
use boot_args::{BootArgs, KERNEL_PHYS_WINDOW_BASE};

/// A shortcut to get access to the core locals
#[macro_export]
macro_rules! core {
    () => {
        $crate::core_locals::get_core_locals()
    }
}

/// A auto reference decrementing structure which allows scope-based reference
/// counting of an atomic usize.
pub struct AutoAtomicRef(AtomicUsize);

impl AutoAtomicRef {
    pub const fn new(init: usize) -> Self {
        AutoAtomicRef(AtomicUsize::new(init))
    }

    pub fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    pub fn increment(&self) -> AutoAtomicRefGuard {
        let count = self.0.fetch_add(1, Ordering::SeqCst);
        count.checked_add(1)
            .expect("Integer overflow on AutoAtomicRef increment");
        AutoAtomicRefGuard(self)
    }
}

pub struct AutoAtomicRefGuard<'a>(&'a AutoAtomicRef);

impl<'a> Drop for AutoAtomicRefGuard<'a> {
    fn drop(&mut self) {
        let count = (self.0).0.fetch_sub(1, Ordering::SeqCst);
        count.checked_sub(1)
            .expect("Integer overflow on AutoAtomicRef decrement");
    }
}

/// A empty structure to implement interrupt disablement for pre-emptable locks
pub struct LockInterrupts;

impl lockcell::InterruptState for LockInterrupts {
    fn in_interrupt() -> bool {
        core!().in_interrupt()
    }
    
    fn in_exception() -> bool {
        core!().in_exception()
    }

    fn core_id() -> u32 {
        core!().id
    }

    fn enter_lock() {
        core!().disable_interrupts();
    }

    fn exit_lock() {
        core!().enable_interrupts();
    }
}

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
    pub id: u32,

    /// A reference to the bootloader arguments
    pub boot_args: &'static BootArgs<LockInterrupts>,

    /// An initialized APIC implementation. Will be `None` until the APIC has
    /// been initialized for this core.
    pub apic: LockCell<Option<Apic>, LockInterrupts>,

    /// The interrupt implementation. This is used to add interrupt handlers
    /// to the interrupt table. If this is `None`, then interrupts have not
    /// yet been initialized.
    pub interrupts: LockCell<Option<Interrupts>, LockInterrupts>,

    /// A core local free list of pages
    pub free_list: LockCell<PageFreeList, LockInterrupts>,

    /// Current level of interrupt nesting. Incremented on every interrupt
    /// entry, and decremented on every interrupt return.
    pub interrupt_depth: AutoAtomicRef,
    
    /// Current level of exception nesting. Incremented on every exception
    /// entry, and decremented on every exception return.
    ///
    /// Exceptions are unique in that they may occur while a `no_preempt` lock
    /// is held. Code which may run during an exception must be sensitive to
    /// this fact and should not use blocking lock operations.
    exception_depth: AutoAtomicRef,

    /// Number of outstanding requests to have interrupts disabled. While this
    /// number is non-zero, interrupts must be disabled. When this gets
    /// decremented back to zero, we can re-enable interrupts.
    interrupt_disable_outstanding: AtomicUsize,

    /// Get the core's APIC ID
    apic_id: AtomicU32,
}

/// Empty marker trait that requires `Sync`, such that we can compile-time
/// assert that `CoreLocals` is `Sync`
trait CoreGuard: Sync + Sized {}
impl CoreGuard for CoreLocals {}

impl CoreLocals {
    /// Set the current core's APIC ID
    pub unsafe fn set_apic_id(&self, apic_id: u32) {
        self.apic_id.store(apic_id, Ordering::SeqCst);
    }
    
    /// Get the current core's APIC ID, returns `None` if the APIC has not
    /// yet been initialized
    pub fn apic_id(&self) -> Option<u32> {
        match self.apic_id.load(Ordering::SeqCst) {
            0xffff_ffff => None,
            x @ _       => Some(x),
        }
    }

    pub unsafe fn enter_exception(&self) -> AutoAtomicRefGuard {
        self.exception_depth.increment()
    }

    pub fn in_exception(&self) -> bool {
        self.exception_depth.count() > 0
    }

    pub unsafe fn enter_interrupt(&self) -> AutoAtomicRefGuard {
        self.interrupt_depth.increment()
    }

    pub fn in_interrupt(&self) -> bool {
        self.interrupt_depth.count() > 0
    }

    pub fn disable_interrupts(&self) {
        let os =
            self.interrupt_disable_outstanding.fetch_add(1, Ordering::SeqCst);
        os.checked_add(1)
            .expect("Integer overflow on disable interrupts increment");

        unsafe { cpu::disable_interrupts() }
    }

    pub fn enable_interrupts(&self) {
        let os =
            self.interrupt_disable_outstanding.fetch_sub(1, Ordering::SeqCst);
        os.checked_sub(1)
            .expect("Integer overflow on disable interrupts decrement");
       
        // If we're not already in an interrupt, and we decremented the
        // interrupt outstanding to 0, we can actually enable interrupts.
        if !core!().in_interrupt() && os == 1 {
            unsafe { cpu::enable_interrupts() }
        }
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
pub fn init(boot_args: PhysAddr, core_id: u32) {
    unsafe {
        // Temporaraly set GS base to the core ID for early locks
        cpu::set_gs_base(core_id as u64);
    }

    struct DummyLockInterrupts;
    impl lockcell::InterruptState for DummyLockInterrupts {
        fn in_interrupt() -> bool { false }
        fn in_exception() -> bool { false }
        fn core_id() -> u32 { unsafe { cpu::gs_base() as u32 } }
        fn enter_lock() {}
        fn exit_lock() {}
    }

    // Convert the physical boot args pointer into the linear mapping
    let boot_args: &'static BootArgs<DummyLockInterrupts> = unsafe {
        &*((boot_args.0 + KERNEL_PHYS_WINDOW_BASE) as
           *const BootArgs<DummyLockInterrupts>)
    };

    let core_local_ptr = {
        // Get access to the physical memory allocator
        let mut pmem = boot_args.free_memory.lock();
        let pmem = pmem.as_mut().unwrap();
        
        // Allocate the core locals
        pmem.allocate(
            core::mem::size_of::<CoreLocals>() as u64,
            core::mem::align_of::<CoreLocals>() as u64).unwrap() +
            KERNEL_PHYS_WINDOW_BASE as usize
    };

    // Construct the core locals
    let core_locals = CoreLocals {
        address:    core_local_ptr,
        id:         core_id,
        apic_id:    AtomicU32::new(!0),
        boot_args:  unsafe {
            &*(boot_args as *const _ as *const BootArgs<LockInterrupts>)
        },
        free_list:  LockCell::new(PageFreeList::new()),
        apic:       LockCell::new_no_preempt(None),
        interrupts: LockCell::new_no_preempt(None),

        interrupt_depth:               AutoAtomicRef::new(0),
        exception_depth:               AutoAtomicRef::new(0),
        interrupt_disable_outstanding: AtomicUsize::new(1),
    };

    unsafe {
        // Move the core locals into the allocation
        core::ptr::write(core_local_ptr as *mut CoreLocals, core_locals);
        cpu::set_gs_base(core_local_ptr as u64);
    }
}

