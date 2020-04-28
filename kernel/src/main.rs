//! A kernel written all in Rust

#![feature(panic_info_message, alloc_error_handler, llvm_asm, global_asm)]
#![feature(const_in_array_repeat_expressions)]

#![no_std]
#![no_main]

extern crate core_reqs;

#[allow(unused_imports)]
#[macro_use] extern crate alloc;

#[allow(unused_imports)]
#[macro_use] extern crate noodle;

#[macro_use] pub mod core_locals;
#[macro_use] pub mod print;
pub mod panic;
pub mod mm;
pub mod interrupts;
pub mod apic;
pub mod acpi;
pub mod intrinsics;
pub mod pci;
pub mod net;
pub mod time;
pub mod vtx;
pub mod snapshotted_app;

use lockcell::LockCell;
use page_table::PhysAddr;
use core_locals::LockInterrupts;
use snapshotted_app::SnapshottedApp;

/// Release the early boot stack such that other cores can use it by marking
/// it as available
fn release_early_stack() {
    unsafe { mm::write_phys(PhysAddr(0x7e00), 1u8); }
}

/// Entry point of the kernel!
#[no_mangle]
pub extern fn entry(boot_args: PhysAddr, core_id: u32) -> ! {
    // Release the early boot stack, now that we have our own stack
    release_early_stack();

    // Initialize the core locals, this must happen first.
    core_locals::init(boot_args, core_id);
     
    // Calibrate the TSC so we can use `time` routines
    if core_id == 0 { unsafe { time::calibrate(); } }
    
    // Initialize interrupts
    interrupts::init();

    // Initialize the APIC
    unsafe { apic::init(); }
    
    if core!().id == 0 {
        // One-time initialization for the whole kernel

        // Initialize PCI devices
        unsafe { pci::init() }

        // Bring up all APICs on the system and also initialize NUMA
        // information with the memory manager through the use of the ACPI
        // information.
        unsafe { acpi::init() }
    }

    // Enable the APIC timer
    unsafe { core!().apic().lock().as_mut().unwrap().enable_timer(); }

    // Now we're ready for interrupts!
    unsafe { core!().enable_interrupts(); }

    // Let ACPI know that we've booted, it'll be happy to know we're here!
    // This will also serialize until all cores have come up. Once all cores
    // are online this will release all of the cores. This ensures that no
    // kernel task ends up hogging locks which are needed during bootloader
    // stack creation on other cores. This makes sure that by the time cores
    // get free reign of execution, we've intialized all cores to a state where
    // NMIs and soft reboots work.
    acpi::core_checkin();

    {
        use core::sync::atomic::Ordering;
        use alloc::sync::Arc;
        use page_table::VirtAddr;

        static SNAPSHOT:
            LockCell<Option<Arc<SnapshottedApp>>, LockInterrupts> =
            LockCell::new(None);

        // Create the master snapshot, and fork from it for all cores
        let snapshot = {
            let mut snap = SNAPSHOT.lock();
            if snap.is_none() {
                *snap = Some(
                    Arc::new(
                        SnapshottedApp::new("192.168.101.1:1911", "falkdump")
                    )
                );
            }
            snap.as_ref().unwrap().clone()
        };

        //if core!().id != 0 { cpu::halt(); }

        // Create a new worker for the snapshot
        let mut worker = snapshot.worker();

        // Save the current time and compute a time in the future to print
        // status messages
        let it = cpu::rdtsc();
        let mut next_print = time::future(1_000_000);

        /// Buffer for the file contents in WinRAR
        const BUFFER_ADDR: VirtAddr = VirtAddr(0x02bcbb1b7040);
        const BUFFER_SIZE: usize    = 0x2123;

        loop {
            if core!().id == 0 && cpu::rdtsc() >= next_print {
                let fuzz_cases = snapshot.fuzz_cases.load(Ordering::SeqCst);
                let coverage   = snapshot.coverage.lock().len();

                print!("{:12} cases | {:12.3} fcps | {:6} coverage\n",
                       fuzz_cases, fuzz_cases as f64 / time::elapsed(it),
                       coverage);
                next_print = time::future(1_000_000);
            }

            // Corrupt the input
            {
                for _ in 0..worker.rng.rand() % 64 {
                    let offset = worker.rng.rand() % BUFFER_SIZE;
                    worker.write(VirtAddr(BUFFER_ADDR.0 + offset as u64),
                        &[worker.rng.rand() as u8]).unwrap();
                }
            }

            worker.run_fuzz_case();
        }
    }
}

