//! This library only exists to have a common structure definition that can be
//! passed from the bootloader to the kernel. This contains any information
//! that the bootloader wants to enlighten the kernel with.
//!
//! This structure also support backwards passing, for the kernel to pass
//! information back to the bootloader. This just means that this structure
//! lives forever and is not deleted or moved by either the bootloader or
//! kernel.

#![feature(const_fn)]
#![no_std]

use core::sync::atomic::{AtomicU64, Ordering};

use serial::SerialPort;
use rangeset::RangeSet;
use lockcell::{LockCell, InterruptState};
use page_table::{PhysAddr, PageTable};

/// Base vaddr to use for kernel stacks
pub const KERNEL_STACKS_BASE: u64 = 0x0000_7473_0000_0000;

/// The virtual base in the kernel page tables where physical memory is
/// linearally mapped. Such that a dereference of `KERNEL_PHYS_WINDOW_BASE`
/// in the kernel address space, will be accessing `0` in physical memory.
pub const KERNEL_PHYS_WINDOW_BASE: u64 = 0xffff_cafe_0000_0000;

/// The base virtual address to use for dynamic virtual allocations
pub const KERNEL_VMEM_BASE: u64 = 0xffff_8000_0000_0000;

/// Size to allocate for kernel stacks
pub const KERNEL_STACK_SIZE: u64 = 512 * 1024;

/// Padding deadspace to add between kernel stacks
pub const KERNEL_STACK_PAD: u64 = 32 * 1024;

/// Size of the kernel physical window (in bytes)
pub const KERNEL_PHYS_WINDOW_SIZE: u64 = 1024 * 1024 * 1024 * 1024;

/// Memory that can persist a soft reboot. Similar to `BootArgs` this structure
/// must not change shape between 32-bit and 64-bit versions. No using
/// references, pointers, `usize`s, etc.
#[repr(C)]
pub struct PersistStore<I: InterruptState> {
    /// Bitmap of where to find PCI devices on the system. The bitmap is
    /// indexed by B:D:A
    pub pci_devices: LockCell<Option<[u64; 256 * 32 * 8 / 64]>, I>,

    /// Tick rate of the RDTSC in MHz
    pub rdtsc_freq: LockCell<Option<u64>, I>,
}

impl<I: InterruptState> PersistStore<I> {
    /// Create a new persist store
    pub const fn new() -> Self {
        PersistStore {
            pci_devices: LockCell::new(None),
            rdtsc_freq:  LockCell::new(None),
        }
    }
}

/// Structures to pass between both the 32-bit and 64-bit modes. This structure
/// MUST be identical in both modes. Thus, no using pointers, references, or
/// usizes. Also, make sure everything is marked `#[repr(C)]` otherwise the
/// 32 and 64-bit variants may slightly be reordered as Rust by default allows
/// re-ordering of non-repr-C structures to fit alignment demands without
/// padding.
#[repr(C)]
pub struct BootArgs<I: InterruptState> {
    /// Size of the `BootArgs` structure (init by the bootloader)
    pub struct_size: u64,

    /// Physical address of the `PersistStore` structure
    persist: AtomicU64,

    /// All memory which is available for use by the kernel and bootloader.
    /// This structure is potentially used at the same time by both the
    /// bootloader and the kernel.
    free_memory: LockCell<Option<RangeSet>, I>,

    /// The page table used for the kernel
    pub page_table: LockCell<Option<PageTable>, I>,

    /// Total amount of physical memory we compute as free from the E820
    /// during early boot. Not used for anything but statistics and
    /// informational messages
    pub total_physical_memory: AtomicU64,
    
    /// The trampoline page table to be used during the paging transition from
    /// the bootloader to the kernel. This will have [0..bootloader_end] mapped
    /// in identity mapped, as well as [0..bootloader_end] mapped in at the
    /// address that the linear physical map will be present in the kernel page
    /// tables. This allows us to temporarily have both the kernel's physical
    /// memory view, and an identity mapped memory view such that the
    /// page table can be switched while executing in the low-memory physical
    /// addresses of the bootloader, and then we can jump to the kernel
    /// physical mapping.
    ///
    /// This holds the physical address of the base of the trampoline page
    /// table.
    trampoline_page_table: AtomicU64,

    /// Address of the kernel entry point
    kernel_entry: LockCell<Option<u64>, I>,

    /// The virtual address of the "next available stack". This is just used to
    /// give unique stack addresses to each core as they come online. This
    /// doesn't need to be honored if you have another method of creating
    /// unique non-overlapping stacks for cores.
    stack_vaddr: AtomicU64,

    /// Address of the soft reboot entry point (0 means uninitialized)
    soft_reboot_addr: AtomicU64,
    
    /// The serial driver
    pub serial: LockCell<Option<SerialPort>, I>,
    
    /// A lock to be used to make `print!()` macros fully atomic
    pub print_lock: LockCell<(), I>,
}

impl<I: InterruptState> BootArgs<I> {
    /// Create a new `BootArgs`
    pub const fn new() -> Self {
        BootArgs {
            struct_size:           core::mem::size_of::<Self>() as u64,
            persist:               AtomicU64::new(0),
            free_memory:           LockCell::new_no_preempt(None),
            serial:                LockCell::new_no_preempt(None),
            page_table:            LockCell::new_no_preempt(None),
            trampoline_page_table: AtomicU64::new(0),
            kernel_entry:          LockCell::new(None),
            stack_vaddr:           AtomicU64::new(KERNEL_STACKS_BASE),
            print_lock:            LockCell::new_no_preempt(()),
            soft_reboot_addr:      AtomicU64::new(0),
            total_physical_memory: AtomicU64::new(0),
        }
    }

    /// Get a reference to the soft reboot address
    pub unsafe fn soft_reboot_addr_ref(&self) -> &AtomicU64 {
        &self.soft_reboot_addr
    }

    /// Get a reference to the kernel entry point
    pub unsafe fn kernel_entry_ref(&self) -> &LockCell<Option<u64>, I> {
        &self.kernel_entry
    }
    
    /// Get a reference to the trampoline page table
    pub unsafe fn trampoline_page_table_ref(&self) -> &AtomicU64 {
        &self.trampoline_page_table
    }
    
    /// Get a reference to the free memory
    pub unsafe fn free_memory_ref(&self) -> &LockCell<Option<RangeSet>, I> {
        &self.free_memory
    }
    
    /// Get a reference to the stack virtual address
    pub unsafe fn stack_vaddr_ref(&self) -> &AtomicU64 {
        &self.stack_vaddr
    }
    
    /// Get the physical address of the persist store
    pub fn persist_store(&self) -> PhysAddr {
        PhysAddr(self.persist.load(Ordering::SeqCst)) 
    }
    
    /// Set the physical address of the persist store
    pub unsafe fn set_persist_store(&self, addr: PhysAddr) {
        self.persist.store(addr.0, Ordering::SeqCst);
    }
}

