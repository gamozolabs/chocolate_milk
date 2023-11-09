//! An atomic vector with a fixed size capacity and insert-only semantics

#![no_std]
#![allow(incomplete_features)]

extern crate alloc;

use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use core::alloc::Layout;
use alloc::boxed::Box;
use alloc::alloc::alloc_zeroed;

/// A fixed-capacity insert-only vector which allows multi-threaded insertion
/// via atomics.
pub struct AtomicVec<T, const N: usize> {
    /// The backing for the atomic vector
    ///
    /// The entries are null pointers when invalid, and when they become valid
    /// they turn into non-null pointers.
    backing: Box<[AtomicPtr<T>; N]>,

    /// Number of entries in use in the vector
    in_use: AtomicUsize,
}

impl<T, const N: usize> AtomicVec<T, N> {
    /// Create a new `AtomicVec` which contains a vector of pointers to type
    /// `T`s, with a capacity of `N`
    #[track_caller]
    pub fn new() -> Self {
        // Determine the layout for an allocation to satisfy an array of `N`
        // `AtomicPtr<T>`'s
        let layout = Layout::array::<AtomicPtr<T>>(N)
            .expect("Invalid shape for AtomicVec");

        // Create a zeroed allocation, which will be all null atomic pointers
        let allocation = unsafe { alloc_zeroed(layout) };
        let allocation = allocation as *mut [AtomicPtr<T>; N];
        assert!(!allocation.is_null(), "Allocation failure for AtomicVec");

        // Return out the empty `AtomicVec`
        AtomicVec { 
            backing: unsafe { Box::from_raw(allocation) },
            in_use:  AtomicUsize::new(0),
        }
    }

    /// Get the length of this vector, in elements
    pub fn len(&self) -> usize { self.in_use.load(Ordering::SeqCst) }

    /// Get the capacity of this vector, in elements
    pub const fn capacity(&self) -> usize { N }

    /// Push an element to the vector
    #[track_caller]
    pub fn push(&self, element: Box<T>) {
        // Get a unique index for insertion. We don't do a fetch add here such
        // that we can make sure we do not overflow capacity
        let idx = loop {
            // Get the current in use
            let cur = self.in_use.load(Ordering::SeqCst);
            assert!(cur < N, "AtomicVec out of capacity");

            // Attempt to reserve this index
            if self.in_use.compare_exchange(cur, cur + 1,
                                            Ordering::SeqCst, Ordering::SeqCst)
                          .unwrap_or_else(|x| x) == cur {
                break cur;
            }
        };

        // Store the element into the array!
        let ptr = Box::into_raw(element);
        assert!(!ptr.is_null(), "Whoa, can't use a null pointer in AtomicVec");
        self.backing[idx].store(ptr, Ordering::SeqCst);
    }

    /// Get a reference to the element at `idx` in the `AtomicVec`
    #[track_caller]
    pub fn get(&self, idx: usize) -> Option<&T> {
        // Get the element pointer
        let ptr = self.backing.get(idx)?.load(Ordering::SeqCst);

        // If the pointer is null, this entry is not filled in yet, thus return
        // `None`
        if ptr.is_null() { return None; }

        // Return out a Rust reference to the contents
        Some(unsafe { &*ptr })
    }
}

impl<T, const N: usize> Drop for AtomicVec<T, N> {
    fn drop(&mut self) {
        // Go through each entry in the vector
        for ii in 0..self.len() {
            // Get the old pointer so we can drop it
            let ptr = self.backing[ii].load(Ordering::SeqCst);

            // If the pointer was non-null, convert it back into a `Box` and
            // let it drop
            if !ptr.is_null() {
                unsafe { let _ = Box::from_raw(ptr); }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn it_works() {
        loop {
            let _foo: AtomicVec<u32, 4096> = AtomicVec::new();
            for _ in 0..4096 {
                _foo.push(Box::new(5));
            }
        }
    }
}

