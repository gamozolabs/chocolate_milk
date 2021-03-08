//! Atomic hash table. Allows thread-safe atomic hash table insertions without
//! needing locks

#![feature(const_generics)]
#![allow(incomplete_features)]
#![no_std]

extern crate alloc;

use core::mem::MaybeUninit;
use core::borrow::Borrow;
use core::alloc::Layout;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use alloc::boxed::Box;
use alloc::alloc::alloc_zeroed;
use alloc::borrow::ToOwned;

/// Type for an internal hash table entry. Tuple is
/// (pointer to boxed value, key)
type HashTableEntry<K, V> = (AtomicPtr<V>, MaybeUninit<K>);

/// Type used for a hash table internal table
type HashTable<K, V, const N: usize> = [HashTableEntry<K, V>; N];

/// An enum which contains information of whether an entry was inserted or
/// already existed for returning from `entry_or_insert`
pub enum Entry<'a, V> {
    /// `V` is a reference to a value that was just inserted into the table
    Inserted(&'a V),

    /// `V` is a reference to an old entry in the table
    Exists(&'a V),
}

impl<'a, V> Entry<'a, V> {
    /// Gets a `bool` indicating if the entry was inserted
    pub fn inserted(&self) -> bool { matches!(self, Entry::Inserted(..)) }

    /// Gets a `bool` indicating if the entry already exists
    pub fn exists(&self) -> bool { matches!(self, Entry::Exists(..)) }

    /// Gets the reference to the entry
    pub fn entry(&self) -> &'a V {
        match self {
            Entry::Inserted(x) => x,
            Entry::Exists(x)   => x,
        }
    }
}

/// An atomic hash table that allows insertions and lookups in parallel.
/// However resizing of the hash table or removing of entries is not supported.
pub struct Aht<K, V, const N: usize> {
    /// Raw hash table
    hash_table: Box<HashTable<K, V, N>>,

    /// Number of entries currently present in the hash table
    entries: AtomicUsize,
}

impl<K, V, const N: usize> Aht<K, V, N> {
    /// Create a new atomic hash table
    pub fn new() -> Self {
        // Determine the layout for an allocation to satisfy an array of `N`
        // `HashTableEntry`'s
        let layout = Layout::array::<HashTableEntry<K, V>>(N)
            .expect("Invalid shape for Aht");

        // Create a new, initialized-as-zero allocation
        // This will create uninitialized keys, which are held in `MaybeUninit`
        // and zeroed out `AtomicPtr`s, which are "empty" entries in the table
        let allocation = unsafe { alloc_zeroed(layout) };
        let allocation = allocation as *mut HashTable<K, V, N>;
        assert!(!allocation.is_null(), "Allocation failure for Aht");

        // Convert the new allocation into a `Box`
        let boxed = unsafe { Box::from_raw(allocation) };

        Aht {
            hash_table: boxed,
            entries:    AtomicUsize::new(0),
        }
    }

    /// Get the number of entries in this hash table
    pub fn len(&self) -> usize { self.entries.load(Ordering::SeqCst) }
    
    /// Insert a `key` into the hash table using `hash` as the first index
    /// into the table.
    ///
    /// If `key` is not present in the hash table, `insert` will be invoked to
    /// produce a value which will be inserted.
    ///
    /// Returns a reference to the inserted or old entry in the table
    /// If the key was already in the table, returns `Err(ref old entry)`
    /// otherwise it returns `Ok(ref new entry)`
    pub fn entry_or_insert<F, Q>(&self, key: &Q, mut hash: usize,
                                 insert: F) -> Entry<V>
            where F: FnOnce() -> Box<V>,
                  K: Borrow<Q>,
                  Q: Eq + ToOwned + ?Sized,
                  Q::Owned: Into<K> {
        let empty:   *mut V =  0 as *mut V;
        let filling: *mut V = !0 as *mut V;

        for attempts in 0usize.. {
            // Check if there are no free entries left in the hash table
            assert!(attempts < N, "Out of entries in the atomic hash table");

            // Get the index into the hash table for this entry
            let hti = hash % N;

            // Try to get exclusive access to this hash table entry
            if self.hash_table[hti].0.load(Ordering::SeqCst) == empty &&
                    self.hash_table[hti].0
                        .compare_exchange(empty, filling,
                                          Ordering::SeqCst, Ordering::SeqCst)
                        .unwrap_or_else(|x| x) == empty {
                // Request the caller to create the entry
                let ent = Box::into_raw(insert());

                // Make sure the pointer doesn't end up turning into one of
                // the reserved values we use for our hash table internals.
                assert!(ent != empty && ent != filling,
                    "Invalid pointer value for Aht");
                
                // Save the key into the table. It is safe to fill this entry
                // in with an immutable reference as we have exclusive access
                // to it
                unsafe {
                    let ht = self.hash_table[hti].1.as_ptr() as *mut K;
                    core::ptr::write(ht, key.to_owned().into());
                }

                // Fill in the entry
                self.hash_table[hti].0.store(ent, Ordering::SeqCst);

                // Update number of entries in our table
                self.entries.fetch_add(1, Ordering::SeqCst);

                // Return a reference to the newly created data
                return Entry::Inserted(unsafe { &*ent });
            } else {
                // Either we lost the race, or the entry was valid. Lets wait
                // for it to become valid first.

                // Loop forever until this entry in the hash table is valid
                while self.hash_table[hti]
                    .0.load(Ordering::SeqCst) == filling {}

                // Now that we know the entry is valid, check if the keys match
                if key == unsafe {
                        (*self.hash_table[hti].1.as_ptr()).borrow() } {
                    // Entry is already in the map, just return the existing
                    // entry!
                    let reference = self.hash_table[hti].0
                        .load(Ordering::SeqCst) as *const V;
                    return Entry::Exists(unsafe { &*reference });
                } else {
                    // There was a collision in the hash table for this entry.
                    // We were stored at the same index, however we were not
                    // a matching entry. Move to the next entry in the hash
                    // table by falling through and going to the next iteration
                    // of this loop.
                }
            }

            // Advance to the next index in the hash table
            hash = hash.wrapping_add(1);
        }

        unreachable!("Unreachable");
    }
}

impl<K, V, const N: usize> Drop for Aht<K, V, N> {
    fn drop(&mut self) {
        for ii in 0..N {
            // Get the entry
            let ptr = self.hash_table[ii].0.load(Ordering::SeqCst);

            // It should be impossible to `Drop` while an entry is being filled
            // in
            assert!(ptr != !0usize as *mut V);

            if !ptr.is_null() {
                // Drop the value
                unsafe { Box::from_raw(ptr); }

                // Drop the key as well, as it's not automatically dropped due
                // to `MaybeUninit`
                unsafe {
                    core::ptr::drop_in_place(
                        self.hash_table[ii].1.as_mut_ptr())
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::*;

    extern crate std;
    use alloc::string::String;

    #[test]
    fn test() {
        let mut table: Aht<u32, u64, 64> = Aht::new();
        let foo1 = table.entry_or_insert(&11, 50, || Box::new(57));
        assert!(*foo1 == 57);
        let foo2 = table.entry_or_insert(&15, 50, || Box::new(52));
        assert!(*foo2 == 52);
        let foo3 = table.entry_or_insert(&11, 50, || Box::new(1111));
        assert!(*foo3 == 57);
    }
}

