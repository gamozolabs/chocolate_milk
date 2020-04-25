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
        //unsafe { pci::init() }

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

    if core!().id == 0 {
        use page_table::{VirtAddr, PageType};
        
        // Create a new virtual machine
        let mut vm = vtx::Vm::new_user();

        // Map in 1 page as RWXU 0x13370000
        let mut pmem = mm::PhysicalMemory;
        vm.page_table.map(&mut pmem, VirtAddr(0x13370000), PageType::Page4K,
            4096, true, true, true, true);

        // Get the physical address of the page and write in some assembly
        let page = vm.page_table.translate(&mut pmem, VirtAddr(0x13370000))
            .unwrap().page.unwrap().0;
        unsafe {
            crate::mm::write_phys(page,
            *b"\xb8\x13\x37\x13\x37\x66\x48\x0f\x6e\xc0\x50\xcc");
        }

        vm.guest_regs.rip = 0x13370000;
        vm.guest_regs.rsp = 0x13370fe8;

        let vmexit = vm.run();
        print!("[{:16.8}] {:x?}\n", time::uptime(), vmexit);

        unsafe {
        print!("{:x?}\n", crate::mm::read_phys::<u64>(PhysAddr(page.0 + 0xfe0)));
        }

        /*
        use net::netmapping::NetMapping;
        let mapping = NetMapping::new("192.168.101.1:1911", "foobar.bin")
            .expect("Failed to netmap file");

        for off in (0..mapping.len()).step_by(4096) {
            unsafe { core::ptr::read_volatile(&mapping[off]); }
        }

        print!("Got whole buffer\n");*/
    }

    cpu::halt();
}

