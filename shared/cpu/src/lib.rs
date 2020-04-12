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

/// Invalidate a page table entry
#[inline]
pub unsafe fn invlpg(vaddr: usize) {
    asm!("invlpg [$0]" :: "r"(vaddr) : "memory" : "volatile", "intel");
}

/// Write an MSR
#[inline]
pub unsafe fn wrmsr(msr: u32, val: u64) {
    asm!("wrmsr" ::
         "{ecx}"(msr),
         "{edx}"((val >> 32) as u32),
         "{eax}"((val >>  0) as u32) :
         "memory" : "volatile", "intel");
}

/// Set the GS
#[inline]
pub unsafe fn set_gs_base(base: u64) {
    wrmsr(0xc000_0101, base);
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

