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

use page_table::PhysAddr;

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

    /*
    if core!().id == acpi::num_cores() - 1 {
        print!("[{:16.8}] We made it! All cores online! {}\n",
               time::uptime(), core!().id + 1);
    }*/

    //if core!().id == 0 {
        test_vm();
    //}

    cpu::halt();
}

fn test_vm() {
    use core::alloc::Layout;
    use core::sync::atomic::{AtomicU64, Ordering};
    use alloc::sync::Arc;
    use vtx::{Vm, VmExit, Exception};
    use page_table::{VirtAddr, PhysMem, PageType};
    use page_table::{PAGE_PRESENT, PAGE_WRITE, PAGE_USER};
    use lockcell::LockCell;
    use net::netmapping::NetMapping;
    use core_locals::LockInterrupts;

    /// Network mapped file to execute from
    static MAPPING: LockCell<Option<Arc<NetMapping>>, LockInterrupts> =
        LockCell::new(None);

    /// Base for this test VM
    const VM_BASE: VirtAddr = VirtAddr(0x13370000);

    /// Number of fuzz cases
    static FUZZ_CASES: AtomicU64 = AtomicU64::new(0);
    
    let mapping = {
        let mut ms = MAPPING.lock();
        if let Some(mapping) = &*ms {
            mapping.clone()
        } else {
            // Network map the memory contents as read-only
            let mapping = Arc::new(NetMapping::new(
                "192.168.101.1:1911", "test.bin", true)
                .expect("Failed to netmap file"));
            let ret = mapping.clone();
            *ms = Some(mapping);
            ret
        }
    };
    
    // Compute the end of the mapped space
    let mapping_end = VirtAddr(VM_BASE.0 + (mapping.len() as u64 - 1));

    let it = cpu::rdtsc();
    
    // Create a new virtual machine
    let mut vm = Vm::new_user();
    vm.guest_regs.rip = VM_BASE.0;

    // Save off the original register state
    let orig_regs = vm.guest_regs.clone();

    // Time to print the next status message
    let mut next_print = time::future(1_000_000);

    loop {
        // Print status messages on an interval
        if core!().id == 0 && cpu::rdtsc() >= next_print {
            let fuzz_case = FUZZ_CASES.load(Ordering::Relaxed);

            print!("Fuzz case {:12} | {:12.1} fcps\n", fuzz_case,
                   fuzz_case as f64 / time::elapsed(it));
            next_print = time::future(1_000_000);
        }

        // Reset the register state
        vm.guest_regs = orig_regs;

        unsafe {
            // Reset memory
            vm.page_table.for_each_dirty_page(&mut mm::PhysicalMemory,
                                              VM_BASE, mapping_end,
                                              |addr, page| {
                // Compute the offset into the mapped file
                let offset = ((addr.0 & !0xfff) - VM_BASE.0) as usize;

                // Get mutable access to the underlying page
                let psl = mm::slice_phys_mut(page, 4096);

                // Compute the number of bytes to copy
                let to_copy =
                    core::cmp::min(4096, mapping.len() - offset);

                // Copy in the bytes to initialize the page
                psl[..to_copy].copy_from_slice(
                    &mapping[offset..offset + to_copy]);
            });
        }

        'vm_loop: loop {
            let vmexit = vm.run();
            if matches!(vmexit, VmExit::ExternalInterrupt) {
                continue 'vm_loop;
            }
            
            //print!("[{:16.8}] {:x?}\n", time::uptime(), vmexit);

            if let VmExit::Exception(Exception::PageFault { addr, .. }) =
                    vmexit {

                // If the page fault was inbounds of our mapping
                if addr.0 >= VM_BASE.0 && addr.0 <= mapping_end.0 {
                    // Map in the page
                    let mut pmem = mm::PhysicalMemory;

                    // Allocate a new page and zero it out
                    let page = pmem.alloc_phys_zeroed(
                        Layout::from_size_align(4096, 4096).unwrap());

                    unsafe {
                        // Compute the offset into the mapped file
                        let offset = ((addr.0 & !0xfff) - VM_BASE.0) as usize;

                        // Get mutable access to the underlying page
                        let psl = mm::slice_phys_mut(page, 4096);

                        // Compute the number of bytes to copy
                        let to_copy =
                            core::cmp::min(4096, mapping.len() - offset);

                        // Copy in the bytes to initialize the page
                        psl[..to_copy].copy_from_slice(
                            &mapping[offset..offset + to_copy]);

                        // Map in the page
                        vm.page_table.map_raw(&mut pmem,
                            VirtAddr(addr.0 & !0xfff),
                            PageType::Page4K,
                            page.0 |
                            PAGE_USER | PAGE_WRITE | PAGE_PRESENT).unwrap();
                    }
                } else {
                    break 'vm_loop;
                }
            } else {
                break 'vm_loop;
            }
        }

        FUZZ_CASES.fetch_add(1, Ordering::Relaxed);
    }
}

