//! Library which provides a `RangeSet` which contains non-overlapping sets of
//! `u64` inclusive ranges. The `RangeSet` can be used to insert or remove
//! ranges of `u64`s and thus is very useful for physical memory management.

#![no_std]

use core::cmp;

/// An inclusive range. We do not use `RangeInclusive` as it does not implement
/// `Copy`
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Range {
    pub start: u64,
    pub end:   u64,
}

/// A set of non-overlapping inclusive `u64` ranges
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RangeSet {
    /// Fixed array of ranges in the set
    ranges: [Range; 256],

    /// Number of in use entries in `ranges`
    ///
    /// This is not a usize to make the structure fixed size so we can pass it
    /// directly from protected mode to long mode. Since `ranges` is fixed u32
    /// is plenty large for this use.
    in_use: u32,
}

impl RangeSet {
    /// Create a new empty RangeSet
    pub const fn new() -> RangeSet {
        RangeSet {
            ranges: [Range { start: 0, end: 0 }; 256],
            in_use: 0,
        }
    }

    /// Get all the entries in the RangeSet as a slice
    pub fn entries(&self) -> &[Range] {
        &self.ranges[..self.in_use as usize]
    }

    /// Delete the Range contained in the RangeSet at `idx`
    fn delete(&mut self, idx: usize) {
        assert!(idx < self.in_use as usize, "Index out of bounds");

        // Copy the deleted range to the end of the list
        for ii in idx..self.in_use as usize - 1 {
            self.ranges.swap(ii, ii+1);
        }

        // Decrement the number of valid ranges
        self.in_use -= 1;
    }

    /// Insert a new range into this RangeSet.
    ///
    /// If the range overlaps with an existing range, then the ranges will
    /// be merged. If the range has no overlap with an existing range then
    /// it will simply be added to the set.
    pub fn insert(&mut self, mut range: Range) {
        assert!(range.start <= range.end, "Invalid range shape");

        // Outside loop forever until we run out of merges with existing
        // ranges.
        'try_merges: loop {
            for ii in 0..self.in_use as usize {
                let ent = self.ranges[ii];

                // Check for overlap with an existing range.
                // Note that we do a saturated add of one to each range.
                // This is done so that two ranges that are 'touching' but
                // not overlapping will be combined.
                if overlaps(
                        Range {
                            start: range.start,
                            end:   range.end.saturating_add(1),
                        },
                        Range {
                            start: ent.start,
                            end:   ent.end.saturating_add(1)
                        }).is_none() {
                    continue;
                }

                // There was overlap with an existing range. Make this range
                // a combination of the existing ranges.
                range.start = cmp::min(range.start, ent.start);
                range.end   = cmp::max(range.end,   ent.end);

                // Delete the old range, as the new one is now all inclusive
                self.delete(ii);

                // Start over looking for merges
                continue 'try_merges;
            }

            break;
        }

        assert!((self.in_use as usize) < self.ranges.len(),
            "Too many entries in RangeSet on insert");

        // Add the new range to the end
        self.ranges[self.in_use as usize] = range;
        self.in_use += 1;
    }

    /// Remove `range` from the RangeSet
    ///
    /// Any range in the RangeSet which overlaps with `range` will be trimmed
    /// such that there is no more overlap. If this results in a range in
    /// the set becoming empty, the range will be removed entirely from the
    /// set.
    pub fn remove(&mut self, range: Range) {
        assert!(range.start <= range.end, "Invalid range shape");
        
        'try_subtractions: loop {
            for ii in 0..self.in_use as usize {
                let ent = self.ranges[ii];

                // If there is no overlap, there is nothing to do with this
                // range.
                if overlaps(range, ent).is_none() {
                    continue;
                }

                // If this entry is entirely contained by the range to remove,
                // then we can just delete it.
                if contains(ent, range) {
                    self.delete(ii);
                    continue 'try_subtractions;
                }

                // At this point we know there is overlap, but only partial.
                // This means we need to adjust the size of the current range
                // and potentially insert a new entry if the entry is split
                // in two.

                if range.start <= ent.start {
                    // If the overlap is on the low end of the range, adjust
                    // the start of the range to the end of the range we want
                    // to remove.
                    self.ranges[ii].start = range.end.saturating_add(1);
                } else if range.end >= ent.end {
                    // If the overlap is on the high end of the range, adjust
                    // the end of the range to the start of the range we want
                    // to remove.
                    self.ranges[ii].end = range.start.saturating_sub(1);
                } else {
                    // If the range to remove fits inside of the range then
                    // we need to split it into two ranges.
                    self.ranges[ii].start = range.end.saturating_add(1);

                    assert!((self.in_use as usize) < self.ranges.len(),
                        "Too many entries in RangeSet on split");

                    self.ranges[self.in_use as usize] = Range {
                        start: ent.start,
                        end:   range.start.saturating_sub(1),
                    };
                    self.in_use += 1;
                    continue 'try_subtractions;
                }
            }

            break;
        }
    }

    /// Subtracts a `RangeSet` from `self`
    pub fn subtract(&mut self, rs: &RangeSet) {
        for &ent in rs.entries() {
            self.remove(ent);
        }
    }

    /// Compute the size of the range covered by this rangeset
    pub fn sum(&self) -> Option<u64> {
        self.entries().iter().try_fold(0u64, |acc, x| {
            Some(acc + (x.end - x.start).checked_add(1)?)
        })
    }

    /// Allocate `size` bytes of memory with `align` requirement for alignment
    pub fn allocate(&mut self, size: u64, align: u64) -> Option<usize> {
        // Allocate anywhere from the `RangeSet`
        self.allocate_prefer(size, align, None)
    }

    /// Allocate `size` bytes of memory with `align` requirement for alignment
    /// Preferring to allocate from the `region`. If an allocation cannot be
    /// satisfied from `regions` the allocation will come from whatever is next
    /// best. If `regions` is `None`, then the allocation will be satisfied
    /// from anywhere.
    pub fn allocate_prefer(&mut self, size: u64, align: u64,
                           regions: Option<&RangeSet>) -> Option<usize> {
        // Don't allow allocations of zero size
        if size == 0 {
            return None;
        }

        // Validate alignment is non-zero and a power of 2
        if align.count_ones() != 1 {
            return None;
        }

        // Generate a mask for the specified alignment
        let alignmask = align - 1;

        // Go through each memory range in the `RangeSet`
        let mut allocation = None;
        'allocation_search: for ent in self.entries() {
            // Determine number of bytes required for front padding to satisfy
            // alignment requirements.
            let align_fix = (align - (ent.start & alignmask)) & alignmask;
            
            // Compute base and end of allocation as an inclusive range
            // [base, end]
            let base = ent.start;
            let end  = base.checked_add(size - 1)?.checked_add(align_fix)?;

            // Validate that this allocation is addressable in the current
            // processor state.
            if base > core::usize::MAX as u64 ||
                    end > core::usize::MAX as u64 {
                continue;
            }

            // Check that this entry has enough room to satisfy allocation
            if end > ent.end {
                continue;
            }

            // If there was a specific region the caller wanted to use
            if let Some(regions) = regions {
                // Check if there is overlap with this region
                for &region in regions.entries() {
                    if let Some(overlap) = overlaps(*ent, region) {
                        // Compute the rounded-up alignment from the
                        // overlapping region
                        let align_overlap =
                            (overlap.start.wrapping_add(alignmask)) &
                            !alignmask;

                        if align_overlap >= overlap.start &&
                                align_overlap <= overlap.end &&
                                (overlap.end - align_overlap) >= (size - 1) {
                            // Alignment did not cause an overflow AND
                            // Alignment did not cause exceeding the end AND
                            // Amount of aligned overlap can satisfy the
                            // allocation

                            // Compute the inclusive end of this proposed
                            // allocation
                            let overlap_alc_end = align_overlap + (size - 1);
                            
                            // Make sure the allocation fits in the current
                            // addressable address space
                            if align_overlap > core::usize::MAX as u64 ||
                                    overlap_alc_end > core::usize::MAX as u64 {
                                continue 'allocation_search;
                            }

                            // We know the allocation can be satisfied starting
                            // at `align_overlap`
                            allocation = Some((align_overlap,
                                               overlap_alc_end,
                                               align_overlap as usize));
                            break 'allocation_search;
                        }
                    }
                }
            }

            // Compute the "best" allocation size to date
            let prev_size = allocation.map(|(base, end, _)| end - base);

            if allocation.is_none() || prev_size.unwrap() > end - base {
                // Update the allocation to the new best size
                allocation = Some((base, end, (base + align_fix) as usize));
            }
        }

        allocation.map(|(base, end, ptr)| {
            // Remove this range from the available set
            self.remove(Range { start: base, end: end });
            
            // Return out the pointer!
            ptr
        })
    }
}

/// Determines overlap of `a` and `b`. If there is overlap, returns the range
/// of the overlap
///
/// In this overlap, returns:
///
/// [a.start -------------- a.end]
///            [b.start -------------- b.end]
///            |                 |
///            ^-----------------^
///            [ Return value    ]
///
fn overlaps(mut a: Range, mut b: Range) -> Option<Range> {
    // Make sure range `a` is always lowest to biggest
    if a.start > a.end {
        core::mem::swap(&mut a.end, &mut a.start);
    }

    // Make sure range `b` is always lowest to biggest
    if b.start > b.end {
        core::mem::swap(&mut b.end, &mut b.start);
    }

    // Check if there is overlap
    if a.start <= b.end && b.start <= a.end {
        Some(Range {
            start: core::cmp::max(a.start, b.start),
            end:   core::cmp::min(a.end,   b.end)
        })
    } else {
        None
    }
}

/// Returns true if the entirity of `a` is contained inside `b`, else
/// returns false.
fn contains(mut a: Range, mut b: Range) -> bool {
    // Make sure range `a` is always lowest to biggest
    if a.start > a.end {
        core::mem::swap(&mut a.end, &mut a.start);
    }

    // Make sure range `b` is always lowest to biggest
    if b.start > b.end {
        core::mem::swap(&mut b.end, &mut b.start);
    }

    a.start >= b.start && a.end <= b.end
}

