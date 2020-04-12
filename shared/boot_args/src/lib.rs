//! This library only exists to have a common structure definition that can be
//! passed from the bootloader to the kernel. This contains any information
//! that the bootloader wants to enlighten the kernel with.
//!
//! This structure also support backwards passing, for the kernel to pass
//! information back to the bootloader. This just means that this structure
//! lives forever and is not deleted or moved by either the bootloader or
//! kernel.

#![no_std]

use core::sync::atomic::AtomicU64;

use serial::SerialPort;
use rangeset::RangeSet;
use lockcell::LockCell;
use page_table::PageTable;

/// Structures to pass between both the 32-bit and 64-bit modes. This structure
/// MUST be identical in both modes. Thus, no using pointers, references, or
/// usizes. Also, make sure everything is marked `#[repr(C)]` otherwise the
/// 32 and 64-bit variants may slightly be reordered as Rust by default allows
/// re-ordering of non-repr-C structures to fit alignment demands without
/// padding.
#[repr(C)]
pub struct BootArgs {
    /// All memory which is available for use by the kernel and bootloader.
    /// This structure is potentially used at the same time by both the
    /// bootloader and the kernel.
    pub free_memory: LockCell<Option<RangeSet>>,

    /// The serial driver
    pub serial: LockCell<Option<SerialPort>>,

    /// The page table used for the kernel
    pub page_table: LockCell<Option<PageTable>>,

    /// Address of the kernel entry point
    pub kernel_entry: LockCell<Option<u64>>,

    /// The virtual address of the "next available stack". This is just used to
    /// give unique stack addresses to each core as they come online. This
    /// doesn't need to be honored if you have another method of creating
    /// unique non-overlapping stacks for cores.
    pub stack_vaddr: AtomicU64,

    /// A lock to be used to make `print!()` macros fully atomic
    pub print_lock: LockCell<()>,
}

