//! Main Rust entry point for the chocolate milk bootloader

#![feature(panic_info_message, alloc_error_handler)]
#![no_std]
#![no_main]

extern crate core_reqs;
extern crate alloc;

mod realmode;
mod mm;
mod panic;
mod pxe;

use pe_parser::PeParser;

#[no_mangle]
extern fn entry() -> ! {
    serial::init();
    mm::init();

    // Download the kernel
    let kernel = pxe::download("chocolate_milk.kern").unwrap();

    // Parse the PE from the kernel
    let pe = PeParser::parse(&kernel).expect("Failed to parse PE");
    pe.sections(|vaddr, vsize, _raw| {
        serial::print!("{:#018x} {:#018x}\n", vaddr, vsize);
        Some(())
    }).unwrap();

    cpu::halt();
}

