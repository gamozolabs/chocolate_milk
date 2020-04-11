//! Main Rust entry point for the chocolate milk bootloader

#![feature(rustc_private, panic_info_message, alloc_error_handler)]
#![no_std]
#![no_main]

extern crate alloc;

mod core_reqs;
mod realmode;
mod mm;
mod panic;

use serial::print;

#[no_mangle]
extern fn entry() -> ! {
    serial::init();
    mm::init();

    let mut data = alloc::vec![50];
    data.push(5);

    print!("Welcome to the chocolate milk! {:?}\n", data);

    cpu::halt();
}

