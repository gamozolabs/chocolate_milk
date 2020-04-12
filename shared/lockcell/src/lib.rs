//! Inner-mutability on shared variables through spinlocks

#![no_std]

use core::ops::{Deref, DerefMut};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering, spin_loop_hint};

/// A spinlock-guarded variable
#[repr(C)]
pub struct LockCell<T: ?Sized> {
    /// Ticket counter to get new tickets to access the `val`
    ticket: AtomicU32,

    /// Current ticket value which can be released
    release: AtomicU32,
    
    /// Value which is guarded by locks
    val: UnsafeCell<T>,
}
unsafe impl<T: ?Sized> Sync for LockCell<T> {}

impl<T> LockCell<T> {
    /// Move a `val` into a `LockCell`, a type which allows inner mutability
    /// around ticket spinlocks.
    pub const fn new(val: T) -> Self {
        LockCell {
            val:     UnsafeCell::new(val),
            ticket:  AtomicU32::new(0),
            release: AtomicU32::new(0),
        }
    }
}

impl<T: ?Sized> LockCell<T> {
    /// Acquire exclusive access to `self`
    pub fn lock(&self) -> LockCellGuard<T> {
        // Get a ticket
        let ticket = self.ticket.fetch_add(1, Ordering::SeqCst);

        // Spin while our ticket doesn't match the release
        while self.release.load(Ordering::SeqCst) != ticket {
            spin_loop_hint();
        }

        // At this point we have exclusive access
        LockCellGuard {
            cell: self,
        }
    }
}

/// A guard structure which can implement `Drop` such that locks can be
/// automatically released based on scope.
pub struct LockCellGuard<'a, T: ?Sized> {
    /// A reference to the value we currently have exclusive access to
    cell: &'a LockCell<T>,
}

impl<'a, T: ?Sized> Drop for LockCellGuard<'a, T> {
    fn drop(&mut self) {
        // Release the lock
        self.cell.release.fetch_add(1, Ordering::SeqCst);
    }
}

impl<'a, T: ?Sized> Deref for LockCellGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe {
            &*self.cell.val.get()
        }
    }
}

impl<'a, T: ?Sized> DerefMut for LockCellGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe {
            &mut *self.cell.val.get()
        }
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use crate::LockCell;

    #[test]
    fn test_lock() {
        static VAR: LockCell<usize> = LockCell::new(5);

        {
            let mut access = VAR.lock();
            assert!(*access == 5);
            *access = 10;
        }

        {
            let access = VAR.lock();
            assert!(*access == 10);
        }
    }

    #[test]
    #[should_panic]
    fn test_dest() {
        struct Foo;
        impl Drop for Foo {
            fn drop(&mut self) { panic!("Got drop"); }
        }

        let _var = LockCell::new(Foo);
        let _lk  = _var.lock();
    }
}


