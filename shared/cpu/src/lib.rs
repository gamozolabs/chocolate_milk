//! x86 CPU routines

#![no_std]

use core::arch::asm;

/// MSR for active FS base
const IA32_FS_BASE: u32 = 0xc0000100;

/// MSR for active GS base
const IA32_GS_BASE: u32 = 0xc0000101;

/// Output an 8-bit `val` to I/O port `addr`
#[inline]
pub unsafe fn out8(addr: u16, val: u8) {
    asm!(
        "out dx, al",
        in("dx") addr,
        in("al") val,
    );
}

/// Read an 8-bit value from I/O port `addr`
#[inline]
pub unsafe fn in8(addr: u16) -> u8 {
    let val: u8;
    asm!(
        "in al, dx",
        in("dx") addr,
        out("al") val,
    );
    val
}

/// Output a 32-bit `val` to I/O port `addr`
#[inline]
pub unsafe fn out32(addr: u16, val: u32) {
    asm!(
        "out dx, eax",
        in("dx") addr,
        in("eax") val,
    );
}

/// Read an 32-bit value from I/O port `addr`
#[inline]
pub unsafe fn in32(addr: u16) -> u32 {
    let val: u32;
    asm!(
        "in eax, dx",
        out("eax") val,
        in("dx") addr,
    );
    val
}

/// Invalidate a page table entry
#[inline]
pub unsafe fn invlpg(vaddr: usize) {
    asm!("invlpg [{0}]", in(reg) vaddr);
}
/// Flush a cache line containg `vaddr`
#[inline]
pub unsafe fn clflush(vaddr: usize) {
    asm!("clflush [{0}]", in(reg) vaddr);
}

/// Enable interrupts
#[inline]
pub unsafe fn enable_interrupts() {
    asm!("sti");
}

/// Disable interrupts
#[inline]
pub unsafe fn disable_interrupts() {
    asm!("cli");
}

/// Read an MSR
#[inline]
pub unsafe fn rdmsr(msr: u32) -> u64 {
    let val_lo: u32;
    let val_hi: u32;
    asm!(
        "rdmsr",
        out("edx") val_hi,
        out("eax") val_lo,
        in("ecx") msr,
    );
    ((val_hi as u64) << 32) | val_lo as u64
}

/// Write an MSR
#[inline]
pub unsafe fn wrmsr(msr: u32, val: u64) {
    asm!(
        "wrmsr",
        in("ecx") msr,
        in("edx") (val >> 32) as u32,
        in("eax") (val >>  0) as u32,
    );
}

/// Read the time stamp counter
#[inline]
pub fn rdtsc() -> u64 {
    let val_lo: u32;
    let val_hi: u32;

    unsafe {
        asm!(
            "rdtsc",
            out("edx") val_hi,
            out("eax") val_lo,
        );
    }

    ((val_hi as u64) << 32) | val_lo as u64
}

/// Get the GS base
#[inline]
pub unsafe fn gs_base() -> u64 {
    rdmsr(IA32_GS_BASE)
}

/// Set the GS base
#[inline]
pub unsafe fn set_gs_base(base: u64) {
    wrmsr(IA32_GS_BASE, base);
}

/// Get the FS base
#[inline]
pub unsafe fn fs_base() -> u64 {
    rdmsr(IA32_FS_BASE)
}

/// Set the FS base
#[inline]
pub unsafe fn set_fs_base(base: u64) {
    wrmsr(IA32_FS_BASE, base);
}

/// Halt once
#[inline]
pub fn single_halt() {
    unsafe {
        asm!("hlt");
    }
}

/// Halt forever
#[inline]
pub fn halt() -> ! {
    unsafe {
        loop {
            asm!("hlt");
        }
    }
}

/// Canonicalize an address
#[inline]
pub fn canonicalize_address(addr: u64) -> u64 {
    (((addr as i64) << 16) >> 16) as u64
}

/// Performs cpuid passing in eax and ecx as parameters. Returns a tuple
/// containing the resulting (eax, ebx, ecx, edx)
#[inline]
pub unsafe fn cpuid(eax: u32, ecx: u32) -> (u32, u32, u32, u32) {
    let (oeax, oebx, oecx, oedx);

    asm!(
        "cpuid",
        "mov {:e}, ebx",
        // ebx cannot be used directly by asm
        out(reg) oebx,
        inout("eax") eax => oeax,
        inout("ecx") ecx => oecx,
        out("edx") oedx,
    );

    (oeax, oebx, oecx, oedx)
}

#[cfg(target_arch="x86_64")]
mod x86_64 {
    use core::arch::asm;

    /// Read `cr0`
    #[inline]
    pub fn read_cr0() -> u64 {
        let val: u64;
        unsafe {
            asm!("mov {0}, cr0", out(reg) val);
        }
        val
    }

    /// Write to `cr0`
    #[inline]
    pub unsafe fn write_cr0(val: u64) {
        asm!("mov cr0, {0}", in(reg) val);
    }

    /// Read `cr2`
    #[inline]
    pub fn read_cr2() -> u64 {
        let val: u64;
        unsafe {
            asm!("mov {0}, cr2", out(reg) val);
        }
        val
    }

    /// Write to `cr2`
    #[inline]
    pub unsafe fn write_cr2(val: u64) {
        asm!("mov cr2, {0}", in(reg) val);
    }

    /// Read `cr3`
    #[inline]
    pub fn read_cr3() -> u64 {
        let val: u64;
        unsafe {
            asm!("mov {0}, cr3", out(reg) val);
        }
        val
    }

    /// Write to `cr3`
    #[inline]
    pub unsafe fn write_cr3(val: u64) {
        asm!("mov cr3, {0}", in(reg) val);
    }

    /// Read `cr4`
    #[inline]
    pub fn read_cr4() -> u64 {
        let val: u64;
        unsafe {
            asm!("mov {0}, cr4", out(reg) val);
        }
        val
    }

    /// Write to `cr4`
    #[inline]
    pub unsafe fn write_cr4(val: u64) {
        asm!("mov cr4, {0}", in(reg) val);
    }

    /// Read `cr8`
    #[inline]
    pub fn read_cr8() -> u64 {
        let val: u64;
        unsafe {
            asm!("mov {0}, cr8", out(reg) val);
        }
        val
    }

    /// Write to `cr8`
    #[inline]
    pub unsafe fn write_cr8(val: u64) {
        asm!("mov cr8, {0}", in(reg) val);
    }


    /// Read `dr6`
    #[inline]
    pub fn read_dr6() -> u64 {
        let val: u64;
        unsafe {
            asm!("mov {0}, dr6", out(reg) val);
        }
        val
    }

    /// Write to `dr6`
    #[inline]
    pub unsafe fn write_dr6(val: u64) {
        asm!("mov dr6, {0}", in(reg) val);
    }
}

#[cfg(target_arch="x86_64")]
pub use x86_64::*;

/// Gets the ES selector value
#[inline]
pub unsafe fn read_es() -> u16 {
    let ret;
    asm!("mov {0:x}, es", out(reg) ret);
    ret
}

/// Gets the CS selector value
#[inline]
pub unsafe fn read_cs() -> u16 {
    let ret;
    asm!("mov {0:x}, cs", out(reg) ret);
    ret
}

/// Gets the SS selector value
#[inline]
pub unsafe fn read_ss() -> u16 {
    let ret;
    asm!("mov {0:x}, ss", out(reg) ret);
    ret
}

/// Gets the DS selector value
#[inline]
pub unsafe fn read_ds() -> u16 {
    let ret;
    asm!("mov {0:x}, ds", out(reg) ret);
    ret
}

/// Gets the FS selector value
#[inline]
pub unsafe fn read_fs() -> u16 {
    let ret;
    asm!("mov {0:x}, fs", out(reg) ret);
    ret
}

/// Gets the GS selector value
#[inline]
pub unsafe fn read_gs() -> u16 {
    let ret;
    asm!("mov {0:x}, gs", out(reg) ret);
    ret
}

/// Gets the TR selector value
#[inline]
pub unsafe fn read_tr() -> u16 {
    let mut ret: u16 = 0;
    asm!(
        "str [{0}]",
        in(reg) &mut ret as *mut u16,
    );
    ret
}

/// Get the current flags
#[inline]
#[cfg(target_arch = "x86_64")]
pub unsafe fn flags() -> u64 {
    let val: u64;
    asm!(
        "pushfq",
        "pop {0}",
        out(reg) val,
    );
    val
}

/// Busy delay loop
#[inline]
#[cfg(target_arch = "x86_64")]
pub fn delay(cycles: u64) {
    if cycles <= 0 { return; }

    unsafe {
        asm!(r#"
        2:
            dec rax
            jnz 2b
        "#,
            inout("rax") cycles => _,
        );
    }
}

/// Structure representing the various CPU features which are supported on this
/// system. These can be detected with the `get_cpu_features` function
#[derive(Default, Debug)]
pub struct CPUFeatures {
    pub max_cpuid: u32,
    pub max_extended_cpuid: u32,

    pub fpu: bool,
    pub vme: bool,
    pub de:  bool,
    pub pse: bool,
    pub tsc: bool,
    pub mmx: bool,
    pub fxsr: bool,
    pub sse: bool,
    pub sse2: bool,
    pub htt: bool,
    pub sse3: bool,
    pub ssse3: bool,
    pub sse4_1: bool,
    pub sse4_2: bool,
    pub x2apic: bool,
    pub aesni: bool,
    pub xsave: bool,
    pub avx: bool,
    pub apic: bool,

    pub vmx: bool,

    pub lahf: bool,
    pub lzcnt: bool,
    pub prefetchw: bool,

    pub syscall: bool,
    pub xd: bool,
    pub gbyte_pages: bool,
    pub rdtscp: bool,
    pub bits64: bool,

    pub avx512f: bool,
}

/// Get set of CPU features
pub fn get_cpu_features() -> CPUFeatures {
    let mut features: CPUFeatures = Default::default();

    unsafe {
        features.max_cpuid          = cpuid(0, 0).0;
        features.max_extended_cpuid = cpuid(0x80000000, 0).0;

        if features.max_cpuid >= 1 {
            let cpuid_1   = cpuid(1, 0);
            features.fpu  = ((cpuid_1.3 >>  0) & 1) == 1;
            features.vme  = ((cpuid_1.3 >>  1) & 1) == 1;
            features.de   = ((cpuid_1.3 >>  2) & 1) == 1;
            features.pse  = ((cpuid_1.3 >>  3) & 1) == 1;
            features.tsc  = ((cpuid_1.3 >>  4) & 1) == 1;
            features.apic = ((cpuid_1.3 >>  9) & 1) == 1;
            features.mmx  = ((cpuid_1.3 >> 23) & 1) == 1;
            features.fxsr = ((cpuid_1.3 >> 24) & 1) == 1;
            features.sse  = ((cpuid_1.3 >> 25) & 1) == 1;
            features.sse2 = ((cpuid_1.3 >> 26) & 1) == 1;
            features.htt  = ((cpuid_1.3 >> 28) & 1) == 1;

            features.sse3    = ((cpuid_1.2 >>  0) & 1) == 1;
            features.vmx     = ((cpuid_1.2 >>  5) & 1) == 1;
            features.ssse3   = ((cpuid_1.2 >>  9) & 1) == 1;
            features.sse4_1  = ((cpuid_1.2 >> 19) & 1) == 1;
            features.sse4_2  = ((cpuid_1.2 >> 20) & 1) == 1;
            features.x2apic  = ((cpuid_1.2 >> 21) & 1) == 1;
            features.aesni   = ((cpuid_1.2 >> 25) & 1) == 1;
            features.xsave   = ((cpuid_1.2 >> 26) & 1) == 1;
            features.avx     = ((cpuid_1.2 >> 28) & 1) == 1;
        }

        // Detect AVX-512 support
        if features.max_cpuid >= 7 {
            let cpuid_7 = cpuid(7, 0);
            features.avx512f = ((cpuid_7.1 >> 16) & 1) == 1;
        }

        if features.max_extended_cpuid >= 0x80000001 {
            let cpuid_e1 = cpuid(0x80000001, 0);

            features.lahf      = ((cpuid_e1.2 >> 0) & 1) == 1;
            features.lzcnt     = ((cpuid_e1.2 >> 5) & 1) == 1;
            features.prefetchw = ((cpuid_e1.2 >> 8) & 1) == 1;

            features.syscall     = ((cpuid_e1.3 >> 11) & 1) == 1;
            features.xd          = ((cpuid_e1.3 >> 20) & 1) == 1;
            features.gbyte_pages = ((cpuid_e1.3 >> 26) & 1) == 1;
            features.rdtscp      = ((cpuid_e1.3 >> 27) & 1) == 1;
            features.bits64      = ((cpuid_e1.3 >> 29) & 1) == 1;
        }
    }

    features
}
