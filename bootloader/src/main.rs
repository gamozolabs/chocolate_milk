//! Bootloader for BIOS-based x86 implementations using PXE to download a
//! second stage x86_64 PE file which will be loaded and executed in long mode

#![feature(panic_info_message, rustc_private, alloc_error_handler)]
#![no_std]
#![no_main]

extern crate compiler_builtins;
extern crate core_reqs;

#[allow(unused_imports)]
#[macro_use] extern crate alloc;

mod realmode;
mod mm;
mod panic;
mod pxe;
mod intrins;

use core::mem::{size_of, align_of};
use core::sync::atomic::{AtomicU32, Ordering};
use serial::SerialPort;
use boot_args::{BootArgs, PersistStore, KERNEL_PHYS_WINDOW_SIZE};
use boot_args::{KERNEL_PHYS_WINDOW_BASE, KERNEL_STACK_SIZE, KERNEL_STACK_PAD};
use pe_parser::PeParser;
use page_table::{VirtAddr, PageType, PageTable, PAGE_PRESENT, PAGE_WRITE};
use page_table::{PhysAddr, PAGE_SIZE};

/// Empty structure to implement locking semantics for pre-emptable locks
pub struct LockInterrupts;

/// The type of the `PersistStore`
type Persist = PersistStore<LockInterrupts>;

/// Current running core ID. The entire bootloader is protected with a lock
/// preventing 2 cores from every running in the bootloader at the same time.
/// This is due to the fact that during the bootloader process, cores use a
/// fixed address for the stack. Thus the `stage0.asm` has a state variable
/// called `stack_avail` which makes the stack, and thus the entire Rust
/// bootloader exclusive.
static CORE_ID: AtomicU32 = AtomicU32::new(0);

impl lockcell::InterruptState for LockInterrupts {
    fn in_interrupt() -> bool { false }
    fn in_exception() -> bool { false }
    fn core_id() -> u32 { CORE_ID.load(Ordering::SeqCst) }
    fn enter_lock() {}
    fn exit_lock() {}
}

/// Global arguments shared between the kernel and bootloader. It is critical
/// that every structure in here is identical in shape between both 64-bit
/// and 32-bit representations.
pub static BOOT_ARGS: BootArgs<LockInterrupts> = BootArgs::new();

/// Rust entry point for the bootloader
///
/// * `bootloader_end`    - One byte past the end of the bootloader
/// * `soft_reboot_entry` - Long mode soft reboot entry point
/// * `num_boots`         - Number of boots that has occurred, starts at 1
#[no_mangle]
extern fn entry(bootloader_end: usize, soft_reboot_entry: usize,
                num_boots: u64) -> ! {

    // Initialize the serial driver
    {
        // Get access to the serial driver
        let mut serial = BOOT_ARGS.serial.lock();

        if serial.is_none() {
            // Create a new serial driver
            let mut driver = unsafe { SerialPort::new(0x400 as *const u16) };

            // "Clear" the screen
            for _ in 0..100 {
                driver.write(b"\n");
            }

            // Print the bootloader banner
            driver.write(b"Chocolate Milk bootloader starting...\n");

            // Store the driver in the `BOOT_ARGS`
            *serial = Some(driver);
        }
    }

    unsafe {
        // Store information about the soft reboot address
        BOOT_ARGS.soft_reboot_addr_ref().store(
            soft_reboot_entry as u64, Ordering::SeqCst);
    
        // Establish the address of the persist store and make sure it's
        // aligned
        let addr = bootloader_end
            .checked_add(align_of::<Persist>() - 1).unwrap() &
            !(align_of::<Persist>() - 1);
        let persist_store_end = addr.checked_add(size_of::<Persist>())
            .unwrap();

        // Make sure persist store doesn't overflow into the EBDA
        assert!(persist_store_end <= 0x00080000,
                "Persist store doesn't fit before EBDA");

        // Initialize the persist store on only the first boot
        if CORE_ID.load(Ordering::SeqCst) == 0 && num_boots == 1 {
            core::ptr::write_volatile(
                addr as *mut Persist, Persist::new());

            BOOT_ARGS.serial.lock().as_mut().unwrap()
                .write(b"Initialized persist store\n");
        }

        // Establish the address of the persist store
        BOOT_ARGS.set_persist_store(PhysAddr(addr as u64));
    }

    // Initialize the MMU
    mm::init();

    // Download the kernel and create the kernel page table
    let (entry_point, stack, cr3, tramp_cr3) = {
        let mut kernel_entry = unsafe { BOOT_ARGS.kernel_entry_ref().lock() };
        let mut page_table   = BOOT_ARGS.page_table.lock();

        // If no kernel entry is set yet, download the kernel and load it
        if kernel_entry.is_none() {
            // Make sure the trampoline table hasn't been set yet
            let tramp_table = unsafe {
                BOOT_ARGS.trampoline_page_table_ref().load(Ordering::SeqCst)
            };
            assert!(page_table.is_none() && tramp_table == 0,
                "Page tables set up before kernel!?");

            // Print that we're about to start downloading the kernel. This
            // is a common point for things to "freeze" if the PXE boot code
            // breaks or the PXE server is unreachable
            BOOT_ARGS.serial.lock().as_mut().unwrap()
                .write(b"Downloading kernel...\n");

            let kernel = loop {
                // Download the kernel
                if let Some(kern) = pxe::download("chocolate_milk.kern") {
                    // Downloaded the kernel, return it out of the loop
                    break kern;
                }
    
                // Print that we failed
                BOOT_ARGS.serial.lock().as_mut().unwrap()
                    .write(b"Kernel download failed, retrying\n");
            };
            
            BOOT_ARGS.serial.lock().as_mut().unwrap()
                .write(b"Kernel download complete!\n");

            // Parse the PE from the kernel
            let pe = PeParser::parse(&kernel).expect("Failed to parse PE");

            // Get exclusive access to physical memory
            let mut pmem = unsafe { BOOT_ARGS.free_memory_ref().lock() };
            let pmem = pmem.as_mut()
                .expect("Whoa, physical memory not initialized yet");
            let mut pmem = mm::PhysicalMemory(pmem);
            
            // Create the trampoline page table
            let mut trampoline_table = PageTable::new(&mut pmem)
                .expect("Failed to create trampoline table");

            // Create the 2 different physical map windows for the trampoline
            // page table
            for paddr in (0..bootloader_end as u64).step_by(4096) {
                unsafe {
                    // Create a mapping where vaddr == paddr
                    trampoline_table.map_raw(
                        &mut pmem, VirtAddr(paddr), PageType::Page4K,
                        paddr | PAGE_WRITE | PAGE_PRESENT).unwrap();

                    // Create a mapping where
                    // vaddr == (paddr + KERNEL_PHYS_WINDOW_BASE)
                    trampoline_table.map_raw(
                        &mut pmem, VirtAddr(KERNEL_PHYS_WINDOW_BASE + paddr),
                        PageType::Page4K,
                        paddr | PAGE_WRITE | PAGE_PRESENT).unwrap();
                }
            }

            // Create a new page table
            let mut table = PageTable::new(&mut pmem)
                .expect("Failed to create page table");

            // Get the support CPU features
            let features = cpu::get_cpu_features();

            // Create the linear map of physical memory, using the largest page
            // size available on this processor
            if features.gbyte_pages {
                // Use 1 GiB pages if supported
                
                const MAX_PAGE_SIZE: u64 = 1024 * 1024 * 1024;
                assert!((KERNEL_PHYS_WINDOW_SIZE % MAX_PAGE_SIZE) == 0,
                    "KERNEL_PHYS_WINDOW_SIZE not mod page size");
                
                // Create a linear map of physical memory
                for paddr in (0..KERNEL_PHYS_WINDOW_SIZE)
                        .step_by(MAX_PAGE_SIZE as usize) {
                    unsafe {
                        table.map_raw(&mut pmem,
                            VirtAddr(KERNEL_PHYS_WINDOW_BASE + paddr),
                            PageType::Page1G,
                            paddr | PAGE_SIZE | PAGE_WRITE | PAGE_PRESENT)
                            .unwrap();
                    }
                }
            } else if features.pse {
                // Use 2 MiB pages if supported
                
                const MAX_PAGE_SIZE: u64 = 2 * 1024 * 1024;
                assert!((KERNEL_PHYS_WINDOW_SIZE % MAX_PAGE_SIZE) == 0,
                    "KERNEL_PHYS_WINDOW_SIZE not mod page size");
                
                // Create a linear map of physical memory
                for paddr in (0..KERNEL_PHYS_WINDOW_SIZE)
                        .step_by(MAX_PAGE_SIZE as usize) {
                    unsafe {
                        table.map_raw(&mut pmem,
                            VirtAddr(KERNEL_PHYS_WINDOW_BASE + paddr),
                            PageType::Page2M,
                            paddr | PAGE_SIZE | PAGE_WRITE | PAGE_PRESENT)
                            .unwrap();
                    }
                }
            } else {
                // Fall back to good ol' 4 KiB pages
                
                const MAX_PAGE_SIZE: u64 = 4 * 1024;
                assert!((KERNEL_PHYS_WINDOW_SIZE % MAX_PAGE_SIZE) == 0,
                    "KERNEL_PHYS_WINDOW_SIZE not mod page size");
                
                // Create a linear map of physical memory
                for paddr in (0..KERNEL_PHYS_WINDOW_SIZE)
                        .step_by(MAX_PAGE_SIZE as usize) {
                    unsafe {
                        table.map_raw(&mut pmem,
                            VirtAddr(KERNEL_PHYS_WINDOW_BASE + paddr),
                            PageType::Page4K,
                            paddr | PAGE_WRITE | PAGE_PRESENT)
                            .unwrap();
                    }
                }
            }

            // Load all the sections from the PE into the new page table
            pe.sections(|vaddr, vsize, raw, read, write, execute| {
                // Create a new virtual mapping for the PE range and initialize
                // it to the raw bytes from the PE file, otherwise to zero for
                // all bytes that were not initialized in the file.
                table.map_init(&mut pmem, VirtAddr(vaddr),
                    PageType::Page4K,
                    vsize as u64, read, write, execute, false,
                    Some(|off| {
                        raw.get(off as usize).copied().unwrap_or(0)
                    }));

                Some(())
            }).unwrap();

            // Set up the entry point and page table
            *kernel_entry = Some(pe.entry_point);
            *page_table   = Some(table);
           
            unsafe {
                // Save the trampoline table address
                BOOT_ARGS.trampoline_page_table_ref()
                    .store(trampoline_table.table().0, Ordering::SeqCst);
            }
        }

        // Get exclusive access to physical memory
        let mut pmem = unsafe { BOOT_ARGS.free_memory_ref().lock() };
        let pmem = pmem.as_mut()
            .expect("Whoa, physical memory not initialized yet");
        let mut pmem = mm::PhysicalMemory(pmem);

        // At this point the page table is always set up
        let page_table = page_table.as_mut().unwrap();

        // Get a unique stack address for this core
        let stack_addr = unsafe {
            BOOT_ARGS.stack_vaddr_ref().fetch_add(
                KERNEL_STACK_SIZE + KERNEL_STACK_PAD, Ordering::SeqCst)
        };
        
        // Map in the stack
        page_table.map(&mut pmem,
                       VirtAddr(stack_addr), PageType::Page4K,
                       KERNEL_STACK_SIZE, true, true, false, false).unwrap();
        
        // Get the address of the trampoline table
        let tramp_table = unsafe {
            BOOT_ARGS.trampoline_page_table_ref().load(Ordering::SeqCst)
        };

        (
            *kernel_entry.as_ref().unwrap(),
            stack_addr + KERNEL_STACK_SIZE,
            page_table.table().0 as u32,
            tramp_table as u32,
        )
    };


    // Update the core ID count and get a unique 0-indexed core ID
    let core_id = CORE_ID.fetch_add(1, Ordering::SeqCst);

    unsafe {
        extern {
            /// Entry point for the kernel transition
            fn enter64(entry_point: u64, stack: u64, param: u64, cr3: u32,
                       tramp_cr3: u32, phys_window_base: u64,
                       core_id: u32) -> !;
        }

        // Jump into the 64-bit kernel!
        enter64(entry_point, stack, &BOOT_ARGS as *const _ as u64,
                cr3, tramp_cr3, KERNEL_PHYS_WINDOW_BASE, core_id);
    }
}

