//! The main kernel entry point!

#![feature(panic_info_message, alloc_error_handler, asm)]

#![no_std]
#![no_main]

extern crate core_reqs;

#[macro_use] mod core_locals;
#[macro_use] mod print;
mod panic;

use boot_args::BootArgs;

/// Release the early boot stack such that other cores can use it by marking
/// it as available
fn release_early_stack() {
    use core::sync::atomic::{AtomicU8, Ordering};

    unsafe {
        (*(0x7e00 as *const AtomicU8)).store(1, Ordering::SeqCst);
    }
}

#[no_mangle]
pub extern fn entry(boot_args: &'static BootArgs) -> ! {
    // Release the early boot stack, now that we have our own stack
    release_early_stack();

    // Initialize the core locals
    core_locals::init(boot_args);

    if cpu::is_bsp() {
        // One-time initialization for the whole kernel

        // Bring up all other cores

        unsafe {
            cpu::wrmsr(0x1b, 0xfee0_0000 | (1 << 11) |
                       ((cpu::is_bsp() as u64) << 8));

            core::ptr::write_volatile(0xfee0_0300 as *mut u32, 0xc4500);
            core::ptr::write_volatile(0xfee0_0300 as *mut u32, 0xc4608);
            core::ptr::write_volatile(0xfee0_0300 as *mut u32, 0xc4608);
        }
    }

    print!("Core ID {} online!\n", core!().id);

    cpu::halt();
}

