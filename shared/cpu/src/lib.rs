//! x86 CPU routines

#![feature(asm)]
#![no_std]

/// Output `val` to I/O port `addr`
#[inline]
pub unsafe fn out8(addr: u16, val: u8) {
    asm!("out dx, al" :: "{dx}"(addr), "{al}"(val) :: "volatile", "intel");
}

/// Read an 8-bit value from I/O port `addr`
#[inline]
pub unsafe fn in8(addr: u16) -> u8 {
    let val: u8;
    asm!("in al, dx" : "={al}"(val) : "{dx}"(addr) :: "volatile", "intel");
    val
}

/// Disable interrupts and halt forever
#[inline]
pub fn halt() -> ! {
    unsafe {
        loop {
            asm!(r#"
                cli
                hlt
            "# :::: "volatile", "intel");
        }
    }
}

