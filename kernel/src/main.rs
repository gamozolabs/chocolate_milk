//! The main kernel entry point!

#![feature(panic_info_message, alloc_error_handler, asm)]

#![no_std]
#![no_main]

extern crate core_reqs;

#[allow(unused_imports)]
#[macro_use] extern crate alloc;

#[macro_use] mod core_locals;
#[macro_use] mod print;
mod panic;
mod mm;

use page_table::PhysAddr;

/// Release the early boot stack such that other cores can use it by marking
/// it as available
fn release_early_stack() {
    unsafe { mm::write_phys(PhysAddr(0x7e00), 1u8); }
}

/// INIT all processors, shutdown the kernel, download a new kernel, and boot
/// into it without resetting the actual CPU.
pub unsafe fn soft_reboot() {
    // INIT the other processors
    mm::write_phys(PhysAddr(0xfee0_0300), 0xc4500u32);
    mm::write_phys(PhysAddr(0xfee0_0300), 0xc4500u32);

    // Get access to the soft reboot address as well as the trampoline page
    // table.
    let soft_reboot = core!().boot_args.soft_reboot_addr.lock().unwrap();
    let trampoline_cr3 = core!().boot_args.trampoline_page_table.lock()
        .as_ref().unwrap().table();

    // Compute the virtual address of the soft reboot entry point based
    // on the physical address
    let vaddr = boot_args::KERNEL_PHYS_WINDOW_BASE + soft_reboot.0;

    // Convert the soft reboot virtual address into a function pointer that
    // takes one `PhysAddr` argument, which is the trampoline cr3
    let soft_reboot = *(&vaddr as *const u64 as *const extern fn(PhysAddr));

    // Perform the soft reboot!
    soft_reboot(trampoline_cr3);
}

#[no_mangle]
pub extern fn entry(boot_args: PhysAddr) -> ! {
    // Release the early boot stack, now that we have our own stack
    release_early_stack();

    // Initialize the core locals
    core_locals::init(boot_args);
    
    if cpu::is_bsp() {
        // One-time initialization for the whole kernel

        /*
        // Bring up all other cores
        unsafe {
            cpu::wrmsr(0x1b, 0xfee0_0000 | (1 << 11) |
                       ((cpu::is_bsp() as u64) << 8));

            mm::write_phys(PhysAddr(0xfee0_0300), 0xc4500u32);
            mm::write_phys(PhysAddr(0xfee0_0300), 0xc4608u32);
            mm::write_phys(PhysAddr(0xfee0_0300), 0xc4608u32);
        }*/
    }

    print!("Core ID {} online! {}\n", core!().id, cpu::rdtsc());

    if core!().id == 0 {
        unsafe {

            mm::write_phys(PhysAddr(0xfee0_0300), 0xc4500u32);
            mm::write_phys(PhysAddr(0xfee0_0300), 0xc4500u32);

        }
    }

    cpu::halt();
}

