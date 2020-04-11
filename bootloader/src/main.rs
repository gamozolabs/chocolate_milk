#![feature(rustc_private, asm)]
#![no_std]
#![no_main]

mod core_reqs;

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop { }
}

#[no_mangle]
fn entry() {
    unsafe {
        core::ptr::write(0xb8000 as *mut u16, 0x0f45);

        asm!(r#"
            cli
            hlt
        "# :::: "volatile", "intel");
    }
}

