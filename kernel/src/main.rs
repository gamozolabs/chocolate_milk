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
    use core::sync::atomic::{AtomicU8, Ordering};

    unsafe {
        (*((0x7e00 + boot_args::KERNEL_PHYS_WINDOW_BASE) as
           *const AtomicU8)).store(1, Ordering::SeqCst);
    }
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
    if core!().id != 0 {
        cpu::halt();
    }

    // FREE PAGE 4096
    // 
    // [ free idx: 509 ] [ next: PhysAddr(0) ] [ [free pages: u64; 510] ]
    // [ free idx: 508 ] [ next: PhysAddr(0) ] [ [free pages: u64; 510] ]
    // ...
    // [ free idx:   0 ] [ next: PhysAddr(0) ] [ [free pages: u64; 510] ]
    // [ free idx:  !0 ] [ next: PhysAddr(0) ] [ [free pages: u64; 510] ]
    // FREE 
    // [ free idx:  !0 ] [ next: PhysAddr(OLD) ] [ [free pages: u64; 510] ]

    for _ in 0u64.. {
        use alloc::vec::Vec;
        
        let it = cpu::rdtsc();
        let foo: Vec<u8> = Vec::with_capacity(16 * 1024 * 1024 * 1024);
        //let foo = vec![5u128; 1024 * 1024 * 1024];
        let elapsed = cpu::rdtsc() - it;

        print!("Elapsed {:12.4} Mcyc {:p}\n", elapsed as f64 / 1_000_000.,
               foo.as_ptr());
    }

    cpu::halt();
}

