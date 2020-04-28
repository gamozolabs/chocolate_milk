//! Inner-mutability on shared variables through spinlocks

#![no_std]
#![feature(const_fn, track_caller, llvm_asm)]

use core::ops::{Deref, DerefMut};
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU32, Ordering, spin_loop_hint};

/// Read the time stamp counter
#[inline]
pub fn rdtsc() -> u64 {
    let unused = 0_u64;
    let val_lo: u32;
    let val_hi: u32;

    unsafe {
        llvm_asm!("rdtsc" : "={edx}"(val_hi), "={eax}"(val_lo) ::
             "memory" : "volatile", "intel");
    }

    ((val_hi as u64) << 32) | val_lo as u64
}

/// Trait that allows access to OS-level constructs defining interrupt state,
/// exception state, unique core IDs, and enter/exit lock (for interrupt
/// disabling and enabling) primitives.
pub trait InterruptState {
    /// Returns `true` if we're currently in an interrupt
    fn in_interrupt() -> bool;
    
    /// Returns `true` if we're currently in an exception. Which indicates that
    /// a lock cannot be held as we may have pre-empted a non-preemptable lock
    fn in_exception() -> bool;

    /// Gets the ID of the running core. It's required that this core ID is
    /// unique to the core, and cannot be `!0`
    fn core_id() -> u32;

    /// A lock which does not allow interrupting was taken, and thus interrupts
    /// must be disabled. It's up to the callee to handle the nesting of the
    /// interrupt status. Eg. using a refcount of number of interrupt disable
    /// requests
    fn enter_lock();

    /// A lock which does not allow interrupting was released, and thus
    /// interrupts can be enabled. It's up to the callee to handle the nesting
    /// of the interrupt status. Eg. using a refcount of number of interrupt
    /// disable requests
    fn exit_lock();
}

/// A spinlock-guarded variable
#[repr(C)]
pub struct LockCell<T: ?Sized, I: InterruptState> {
    /// A ticket for the lock. You grab this ticket and then wait until
    /// `release` is set to your ticket
    ticket: AtomicU32,

    /// Tracks which ticket currently owns the lock
    release: AtomicU32,

    /// Tracks the core that currently holds the lock
    owner: AtomicU32,

    /// A holder of the `InterruptState` trait for this implementation
    _interrupt_state: PhantomData<I>,

    /// If set to `true`, it is required that interrupts are disabled prior to
    /// this lock being taken.
    disables_interrupts: bool,
    
    /// Value which is guarded by locks
    val: UnsafeCell<T>,
}
unsafe impl<T: ?Sized, I: InterruptState> Sync for LockCell<T, I> {}

impl<T, I: InterruptState> LockCell<T, I> {
    /// Move a `val` into a `LockCell`, a type which allows inner mutability
    /// around ticket spinlocks.
    pub const fn new(val: T) -> Self {
        LockCell {
            ticket:              AtomicU32::new(0),
            release:             AtomicU32::new(0),
            owner:               AtomicU32::new(0),
            val:                 UnsafeCell::new(val),
            disables_interrupts: false,
            _interrupt_state:    PhantomData,
        }
    }

    /// Create a new `LockCell` which will disable interrupts for the entire
    /// time the lock is held.
    pub const fn new_no_preempt(val: T) -> Self {
        LockCell {
            ticket:              AtomicU32::new(0),
            release:             AtomicU32::new(0),
            owner:               AtomicU32::new(0),
            val:                 UnsafeCell::new(val),
            disables_interrupts: true,
            _interrupt_state:    PhantomData,
        }
    }
}

impl<T: ?Sized, I: InterruptState> LockCell<T, I> {
    /// Get exclusive access to the value guarded by the lock
    #[track_caller]
    pub fn lock(&self) -> LockCellGuard<T, I> {
        // If this lock does not disable interrupts, and we're currently in
        // an interrupt. Then, we just used a non-preemptable lock during an
        // interrupt. This means the lock creation for this lock should be
        // changed to a `new_no_preempt`
        assert!(self.disables_interrupts || !I::in_interrupt(),
            "Attempted to take a non-preemptable lock in an interrupt");
        
        // Get the core ID of the running core
        let core_id = I::core_id();

        // Disable interrupts if needed
        if self.disables_interrupts {
            I::enter_lock();
        }

        // Take a ticket
        let ticket = self.ticket.fetch_add(1, Ordering::SeqCst);

        // Number of attempts of taking the lock until we use a TSC based
        // countdown until a timeout panic. We only use this timeout during
        // exceptions, as all other conditions should either never deadlock
        // due to interrupts getting disabled ala. locks that get taken during
        // and interrupt. Deadlocks on a single core are easily detected and
        // thus we can panic on those.
        //
        // This leave one condition. Exceptions. During an exception it is
        // possible that we need access to a lock. If we cannot get access to
        // a lock in a given amount of time, the exception handler cannot
        // do the correct thing anyways, and thus we need to bring the system
        // down with a panic.
        let mut time_threshold: u32 = if I::in_exception() {
            10_000
        } else {
            !0
        };

        // Timeout based off of the TSC to determine when to give up on the
        // lock and just panic.
        let mut timeout = 0;

        while self.release.load(Ordering::SeqCst) != ticket {
            // If the current core is the owner of the load
            if self.owner.load(Ordering::SeqCst) == core_id {
                panic!("Deadlock detected");
            }

            if time_threshold > 0 {
                // Decrement number of attempts
                time_threshold -= 1;
            } else {
                // We've tried getting access to the lock for a decent enough
                // amount of time that we can affordibly use RDTSC now to
                // enforce a seconds-based timeout
                if timeout == 0 {
                    // 1 second on a 3 GHz processor
                    timeout = rdtsc() + 3_000_000_000;
                } else {
                    if rdtsc() >= timeout {
                        panic!("Timed out when attempting to take lock");
                    }
                }
            }

            spin_loop_hint();
        }

        // Note that this core owns the lock
        self.owner.store(core_id, Ordering::SeqCst);

        // At this point we have exclusive access
        LockCellGuard {
            cell: self,
        }
    }
    
    /// Return a raw pointer to the internal locked value, regardless of the
    /// lock state. This bypasses the lock.
    pub unsafe fn shatter(&self) -> *mut T {
        self.val.get()
    }
}

/// A guard structure which can implement `Drop` such that locks can be
/// automatically released based on scope.
pub struct LockCellGuard<'a, T: ?Sized, I: InterruptState> {
    /// A reference to the value we currently have exclusive access to
    cell: &'a LockCell<T, I>,
}

impl<'a, T: ?Sized, I: InterruptState> Drop for LockCellGuard<'a, T, I> {
    fn drop(&mut self) {
        // Set that there is no owner of the lock
        self.cell.owner.store(!0, Ordering::SeqCst);

        // Release the lock
        self.cell.release.fetch_add(1, Ordering::SeqCst);
        
        // Enable interrupts if needed
        if self.cell.disables_interrupts {
            I::exit_lock();
        }
    }
}

impl<'a, T: ?Sized, I: InterruptState> Deref for LockCellGuard<'a, T, I> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe {
            &*self.cell.val.get()
        }
    }
}

impl<'a, T: ?Sized, I: InterruptState> DerefMut for LockCellGuard<'a, T, I> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            &mut *self.cell.val.get()
        }
    }
}

