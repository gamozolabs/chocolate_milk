//! x86 CPU routines

#![feature(asm)]
#![no_std]

/// MSR for APIC base
const IA32_APIC_BASE: u32 = 0x1b;

/// MSR for active GS base
const IA32_GS_BASE: u32 = 0xc0000101;

/// Returns true if the current CPU is the BSP, otherwise returns false.
#[inline]
pub fn is_bsp() -> bool {
    (unsafe { rdmsr(IA32_APIC_BASE) } & (1 << 8)) != 0
}

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

/// Read an MSR
#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let val_lo: u32;
    let val_hi: u32;
    asm!("rdmsr" : "={edx}"(val_hi), "={eax}"(val_lo) : "{ecx}"(msr) :
         "memory" : "volatile", "intel");
    ((val_hi as u64) << 32) | val_lo as u64
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

/// Read the time stamp counter
#[inline]
pub fn rdtsc() -> u64 {
    let val_lo: u32;
    let val_hi: u32;

    unsafe {
        asm!("rdtsc" : "={edx}"(val_hi), "={eax}"(val_lo) ::
             "memory" : "volatile", "intel");
    }

    ((val_hi as u64) << 32) | val_lo as u64
}

/// Set the GS
#[inline]
pub unsafe fn set_gs_base(base: u64) {
    wrmsr(IA32_GS_BASE, base);
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

/// Canonicalize an address
#[inline]
pub fn canonicalize_address(addr: u64) -> u64 {
    (((addr as i64) << 16) >> 16) as u64
}

