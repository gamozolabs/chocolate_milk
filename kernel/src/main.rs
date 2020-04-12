//! The main kernel entry point!

#![feature(panic_info_message, alloc_error_handler, asm)]

#![no_std]
#![no_main]

extern crate core_reqs;

#[macro_use] mod core_locals;
#[macro_use] mod print;
mod panic;

use boot_args::BootArgs;

#[no_mangle]
pub extern fn entry(boot_args: &'static BootArgs) -> ! {
    // Initialize the core locals. This must be the first thing that happens
    core_locals::init(boot_args);

    if core!().id == 0 {
        // One-time initialization for the whole kernel
    }

    cpu::halt();
}

