//! The main kernel entry point!

#![feature(panic_info_message, alloc_error_handler, asm, global_asm)]
#![feature(const_in_array_repeat_expressions)]

#![no_std]
#![no_main]

extern crate core_reqs;

#[allow(unused_imports)]
#[macro_use] extern crate alloc;

#[macro_use] mod core_locals;
#[macro_use] mod print;
mod panic;
mod mm;
mod interrupts;
mod apic;
mod acpi;
mod intrinsics;

use page_table::PhysAddr;

/// Release the early boot stack such that other cores can use it by marking
/// it as available
fn release_early_stack() {
    unsafe { mm::write_phys(PhysAddr(0x7e00), 1u8); }
}

#[no_mangle]
pub extern fn entry(boot_args: PhysAddr, core_id: u32) -> ! {
    // Release the early boot stack, now that we have our own stack
    release_early_stack();

    // Initialize the core locals, this must happen first.
    core_locals::init(boot_args, core_id);
    
    // Initialize interrupts
    interrupts::init();

    // Initialize the APIC
    apic::init();
    
    if core!().id == 0 {
        // One-time initialization for the whole kernel

        // Bring up all APICs on the system and also initialize NUMA
        // information with the memory manager through the use of the ACPI
        // information.
        unsafe { acpi::init() }
    }

    // Let ACPI know that we've booted, it'll be happy to know we're here!
    acpi::core_checkin();

    if core!().id == 0 {
        // Enable the APIC timer
        unsafe { core!().apic.lock().as_mut().unwrap().enable_timer(); }
        //core!().enable_interrupts();
    }

    //print!("Core online {}\n", core!().id);

    if core!().id == acpi::num_cores() - 1 {
        print!("We made it! All cores online! {}\n", core!().id + 1);
    }

    if core!().id == 0 {
        panic!("OH NO I MYSELF DIED");
    }

    //loop {
        //let mut freemem = core!().boot_args.free_memory.lock();
        //let freemem = freemem.as_mut().unwrap();


        //let alc = freemem.allocate_prefer(4096, 4096, mm::memory_range());
        //core::mem::drop(freemem);
    //}

    cpu::halt();
}

