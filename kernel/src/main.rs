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
mod vmx;

use page_table::PhysAddr;

/// Release the early boot stack such that other cores can use it by marking
/// it as available
fn release_early_stack() {
    unsafe { mm::write_phys(PhysAddr(0x7e00), 1u8); }
}

#[no_mangle]
pub extern fn entry(boot_args: PhysAddr) -> ! {
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

            mm::write_phys(PhysAddr(0xfee0_0300), 0xc4500u32);
            mm::write_phys(PhysAddr(0xfee0_0300), 0xc4608u32);
            mm::write_phys(PhysAddr(0xfee0_0300), 0xc4608u32);
        }
    }

    print!("Core ID {} online!\n", core!().id);

    vmx::vmx_test();

    cpu::halt();
}

