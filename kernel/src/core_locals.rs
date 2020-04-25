//! This file is used to hold and access all of the core locals

use core::mem::size_of;
use core::sync::atomic::{AtomicUsize, AtomicU32, Ordering};

use crate::apic::Apic;
use crate::mm::{PageFreeList, PhysContig};
use crate::interrupts::Interrupts;

use lockcell::LockCell;
use page_table::PhysAddr;
use boot_args::{BootArgs, PersistStore, KERNEL_PHYS_WINDOW_BASE};
use boot_args::KERNEL_PHYS_WINDOW_SIZE;

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
    /// Create a new automatically tracked atomic reference counter
    pub const fn new(init: usize) -> Self {
        AutoAtomicRef(AtomicUsize::new(init))
    }

    /// Returns the current number of references
    pub fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }

    /// Increment the reference count, and return a guard structure which will
    /// decrement the count once the guard goes out of scope.
    pub fn increment(&self) -> AutoAtomicRefGuard {
        let count = self.0.fetch_add(1, Ordering::SeqCst);
        count.checked_add(1)
            .expect("Integer overflow on AutoAtomicRef increment");
        AutoAtomicRefGuard(self)
    }
}

/// Guard structure that allows automatic reference count decrementing on
/// `AutoAtomicRef`s when the increment goes out of score
pub struct AutoAtomicRefGuard<'a>(&'a AutoAtomicRef);

impl<'a> Drop for AutoAtomicRefGuard<'a> {
    fn drop(&mut self) {
        // Decrement the reference count
        let count = (self.0).0.fetch_sub(1, Ordering::SeqCst);

        // Make sure we didn't end up going negative, this should never happen
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
        unsafe { core!().disable_interrupts(); }
    }

    fn exit_lock() {
        unsafe { core!().enable_interrupts(); }
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
    apic: LockCell<Option<Apic>, LockInterrupts>,

    /// The interrupt implementation. This is used to add interrupt handlers
    /// to the interrupt table. If this is `None`, then interrupts have not
    /// yet been initialized.
    interrupts: LockCell<Option<Interrupts>, LockInterrupts>,

    /// A core local free list of pages
    free_list: LockCell<PageFreeList, LockInterrupts>,

    /// Current level of interrupt nesting. Incremented on every interrupt
    /// entry, and decremented on every interrupt return.
    interrupt_depth: AutoAtomicRef,
    
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

    /// VMXON region for this core. If VMXON has not yet executed, or VMXOFF
    /// was executed, then this will be `None`
    vmxon_region: LockCell<Option<PhysContig<[u8; 4096]>>, LockInterrupts>,
}

/// Empty marker trait that requires `Sync`, such that we can compile-time
/// assert that `CoreLocals` is `Sync`
trait CoreGuard: Sync + Sized {}
impl CoreGuard for CoreLocals {}

/// Type of the `PersistStore`
type Persist = PersistStore<LockInterrupts>;

impl CoreLocals {
    /// Get access to the VMXON region
    pub unsafe fn vmxon_region(&self) ->
            &LockCell<Option<PhysContig<[u8; 4096]>>, LockInterrupts> {
        &self.vmxon_region
    }
    
    /// Get access to the interrupts
    pub unsafe fn interrupts(&self) ->
            &LockCell<Option<Interrupts>, LockInterrupts> {
        &self.interrupts
    }
    
    /// Get access to the APIC
    pub unsafe fn apic(&self) -> &LockCell<Option<Apic>, LockInterrupts> {
        &self.apic
    }
    
    /// Get access to the free list 
    pub unsafe fn free_list(&self) -> &LockCell<PageFreeList, LockInterrupts> {
        &self.free_list
    }

    /// Get access to the persistent storage
    pub unsafe fn persist_store(&self) -> &'static Persist {
        // Get the physical address of the persist store
        let addr = self.boot_args.persist_store();
        assert!(addr.0 != 0, "Invalid persist store address");

        // Make sure the persist store is within the physical window
        let persist_store_end = addr.0.checked_add(size_of::<Persist>() as u64)
            .unwrap();
        assert!(persist_store_end <= KERNEL_PHYS_WINDOW_SIZE,
            "Persist store out of bounds of physical window");

        // Return a reference to the persist store
        &*((KERNEL_PHYS_WINDOW_BASE + addr.0) as *const Persist)
    }

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

    /// Set that we have entered an exception handler
    /// (increment exception count)
    pub unsafe fn enter_exception(&self) -> AutoAtomicRefGuard {
        self.exception_depth.increment()
    }

    /// Get whether or not we're currently in an exception handler
    pub fn in_exception(&self) -> bool {
        self.exception_depth.count() > 0
    }

    /// Set that we're currently in an interrupt (increments interrupt count)
    pub unsafe fn enter_interrupt(&self) -> AutoAtomicRefGuard {
        self.interrupt_depth.increment()
    }

    /// Get whether or not we're currently in an interrupt handler
    pub fn in_interrupt(&self) -> bool {
        self.interrupt_depth.count() > 0
    }

    /// Disable interrupts and increase the interrupt disable reference count
    ///
    /// Interrupts will always be disabled when this code executes. This will
    /// increment the number of disable requests, and thus interrupts will not
    /// be re-enabled until an identical number of `enable_interrupts` are
    /// called.
    pub unsafe fn disable_interrupts(&self) {
        let os =
            self.interrupt_disable_outstanding.fetch_add(1, Ordering::SeqCst);
        os.checked_add(1)
            .expect("Integer overflow on disable interrupts increment");

        cpu::disable_interrupts()
    }

    /// Attempt to enable interrupts
    ///
    /// If the reference count for requested interrupt disables drops to zero
    /// then we actually enable interrupts. Otherwise we just decrement the
    /// interrupt request number.
    pub unsafe fn enable_interrupts(&self) {
        let os =
            self.interrupt_disable_outstanding.fetch_sub(1, Ordering::SeqCst);
        os.checked_sub(1)
            .expect("Integer overflow on disable interrupts decrement");
       
        // If we're not already in an interrupt, and we decremented the
        // interrupt outstanding to 0, we can actually enable interrupts.
        //
        // Since it's possible interrupts can be enabled when we enter an
        // interrupt, if we acquire a lock in an interrupt and release it it
        // may attempt to re-enable interrupts. Thus, we never allow enabling
        // interrupts from an interrupt handler. This means interrupts will
        // correctly get re-enabled in this case when the IRET loads the old
        // interrupt flag.
        if !core!().in_interrupt() && os == 1 {
            cpu::enable_interrupts();
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
        llvm_asm!("mov $0, gs:[0]" :
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

    /// Dummy structure to allow early `LockCell` access prior to having
    /// the `core!()` macro set up
    struct DummyLockInterrupts;

    // This dummy interrupt state implementation always reports no interrupts
    // or exceptions, as this code is run during early boot prior to interrupts
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
    
    // Make sure the structure size is the same betewen the bootloader and
    // kernel
    assert!(boot_args.struct_size == core::mem::size_of_val(boot_args) as u64,
        "Bootloader struct size mismatch");

    let core_local_ptr = {
        // Get access to the physical memory allocator
        let mut pmem = unsafe { boot_args.free_memory_ref().lock() };
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
        free_list:  LockCell::new_no_preempt(PageFreeList::new()),
        apic:       LockCell::new_no_preempt(None),
        interrupts: LockCell::new_no_preempt(None),

        interrupt_depth:               AutoAtomicRef::new(0),
        exception_depth:               AutoAtomicRef::new(0),
        interrupt_disable_outstanding: AtomicUsize::new(1),

        vmxon_region: LockCell::new_no_preempt(None),
    };

    unsafe {
        // Move the core locals into the allocation
        core::ptr::write(core_local_ptr as *mut CoreLocals, core_locals);

        // Set the GS base such that we can get access to core locals in any
        // context via the `core!()` macro
        cpu::set_gs_base(core_local_ptr as u64);
    }
}

