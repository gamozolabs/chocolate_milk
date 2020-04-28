//! Atomic hash table. Allows thread-safe atomic hash table insertions without
//! needing locks

#![no_std]

extern crate alloc;

use core::sync::atomic::{AtomicUsize, Ordering};
use core::marker::PhantomData;
use alloc::vec::Vec;
use alloc::boxed::Box;

/// An atomic hash table that allows insertions and lookups in parallel.
/// However resizing of the hash table or removing of entries is not supported.
pub struct Aht<K: Copy + Eq + Default + Sync, V: Sync> {
    /// Raw hash table
    /// Tuple is (pointer to entry, key)
    hash_table: Vec<(AtomicUsize, K)>,

    /// List of all pointers to entries in the hash table. This allows the
    /// hash table to be iterated cheaply.
    contig_table: Vec<AtomicUsize>,

    /// Number of entries present in the hash table
    entries: AtomicUsize,

    /// Marker for the `T` used for the hash table
    _phantom: PhantomData<V>,
}

/// Guard structure to give access to a hash table entry that we have exclusive
/// access to
pub struct HashEntry<'a, K: Copy + Eq + Default + Sync, V: Sync> {
    /// Reference to the hash table this entry belongs to
    aht: &'a Aht<K, V>,

    /// Index into the hash table which this entry corresponds to
    index: usize,
}

impl<'a, K: Copy + Eq + Default + Sync, V: Sync> HashEntry<'a, K, V> {
    /// Fill in a missing hash table entry returned by `fetch_or_insert`
    pub fn insert(self, entry: Box<V>) {
        let entry = Box::into_raw(entry) as usize;

        // Update the corresponding hash table entry with the provided `entry`
        self.aht.hash_table[self.index].0
            .store(entry, Ordering::SeqCst);
        let cidx = self.aht.entries.fetch_add(1, Ordering::SeqCst);
        self.aht.contig_table[cidx].store(entry, Ordering::SeqCst);
    }
}

impl<K: Copy + Eq + Default + Sync, V: Sync> Aht<K, V> {
    /// Create a new atomic hash table capable of holding `entries` entries
    pub fn new(entries: usize) -> Aht<K, V> {
        assert!(entries.count_ones() == 1, "entries is not a power of two");

        // Create the backing for the hash table
        let mut data = Vec::with_capacity(entries);
        for _ in 0..entries {
            data.push((AtomicUsize::new(0), K::default()));
        }
        
        // Create the backing for the contiguous region
        let mut contig = Vec::with_capacity(entries);
        for _ in 0..entries {
            contig.push(AtomicUsize::new(0));
        }

        Aht {
            hash_table:   data,
            entries:      AtomicUsize::new(0),
            contig_table: contig,
            _phantom:     PhantomData,
        }
    }

    /// Creates an atomic hash table from an existing hash table.
    /// Since we have no way to correctly de-allocate the backing, this will
    /// never be able to be freed.
    /// 
    /// For correct behavior, `backing` must be entirely zeroed out.
    pub unsafe fn from_existing(entries: usize,
            backing: *mut (AtomicUsize, K), contig: *mut AtomicUsize)
            -> Aht<K, V> {
        assert!(entries.count_ones() == 1, "entries is not a power of two");

        Aht {
            hash_table:   Vec::from_raw_parts(backing, entries, entries),
            entries:      AtomicUsize::new(0),
            _phantom:     PhantomData,
            contig_table: Vec::from_raw_parts(contig, entries, entries),
        }
    }

    /// Get the number of entires present in the hash table
    pub fn len(&self) -> usize {
        self.entries.load(Ordering::SeqCst)
    }

    /// Get an entry from the hash table based on the index
    pub fn get(&self, idx: usize) -> Option<&V> {
        let dbsize = self.len();

        // Make sure the index is in bounds
        if idx >= dbsize {
            return None;
        }

        // Make sure this entry has been filled in
        if self.contig_table[idx].load(Ordering::SeqCst) == 0 {
            return None;
        }
        
        // Return the entry!
        let reference = self.contig_table[idx]
            .load(Ordering::SeqCst) as *const V;

        Some(unsafe { &*reference })
    }

    /// Attempt to insert `hash` into `self`. Returns `Ok` and a reference to
    /// the existing entry if one already exists with the same hash, otherwise
    /// it returns a `Err(HashEntry)` which must be used to insert a valid
    /// entry into the hash table.
    pub fn fetch_or_insert(&self, key: K, hash: u128)
            -> Result<&V, HashEntry<K, V>> {
        // Get the low part of the hash
        let mut fh_low = hash as usize;

        // Compute the mask used to index the hash table
        let mask = self.hash_table.len() - 1;

        for attempts in 0usize.. {
            // Check if there are no free entries left in the hash table
            assert!(attempts < self.hash_table.len(),
                "Out of entries in the atomic hash map");

            // Get the index into the hash table for this entry
            let hash_table_idx = fh_low & mask;

            // Try to get exclusive access to this hash table entry
            if self.hash_table[hash_table_idx].0.load(Ordering::SeqCst) == 0 &&
                    self.hash_table[hash_table_idx].0
                    .compare_and_swap(0, 1, Ordering::SeqCst) == 0 {
                // Save the key into the table. It is safe to fill this entry
                // in with an immutable reference as we have exclusive access
                // to it
                unsafe {
                    (*(&self.hash_table as *const Vec<(AtomicUsize, K)> as 
                        *mut Vec<(AtomicUsize, K)>))
                        [hash_table_idx].1 = key;
                }

                // Return out the the user to fill in this entry
                return Err(HashEntry {
                    aht:   self,
                    index: hash_table_idx,
                });
            } else {
                // Either we lost the race, or the entry was valid. Lets wait
                // for it to become valid first.

                // Loop forever until this entry in the hash table is valid
                while self.hash_table[hash_table_idx]
                    .0.load(Ordering::SeqCst) == 1 {}

                if key == self.hash_table[hash_table_idx].1 {
                    // Entry is already in the map, just return the existing
                    // entry!
                    let reference = self.hash_table[hash_table_idx].0
                        .load(Ordering::SeqCst) as *const V;
                    return Ok(unsafe { &*reference });
                } else {
                    // There was a collision in the hash table for this entry.
                    // We were stored at the same index, however we were not
                    // a matching entry. Move to the next entry in the hash
                    // table by falling through and going to the next iteration
                    // of this loop.
                }
            }

            // Advance to the next index in the hash table
            fh_low = fh_low.wrapping_add(1);
        }

        unreachable!("Unreachable");
    }
}
