#![feature(panic_info_message)]

#![no_std]
#![no_main]

extern crate core_reqs;

mod panic;

#[no_mangle]
pub extern fn entry() -> ! {
    cpu::halt();
}

