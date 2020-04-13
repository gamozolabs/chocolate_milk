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

/// Sets the contents of the current VMCS field based on `encoding` and `val`
#[inline]
pub unsafe fn vmwrite(encoding: u64, val: u64) {
    asm!("vmwrite $0, $1" :: "r"(encoding), "r"(val) : "memory" :
         "intel", "volatile");
}

/// Reads the contents of the current VMCS field based on `encoding`
#[inline]
pub unsafe fn vmread(encoding: u64) -> u64 {
    let ret;
    asm!("vmread $0, $1" : "=r"(ret) : "r"(encoding) : "memory" :
         "intel", "volatile");
    ret
}

/// Reads the contents of cr0
#[inline]
pub unsafe fn read_cr0() -> u64 {
    let cr0;
    asm!("mov $0, cr0" : "=r"(cr0) :: "memory" : "intel", "volatile");
    cr0
}

/// Writes to cr0
#[inline]
pub unsafe fn write_cr0(val: u64) {
    asm!("mov cr0, $0" :: "r"(val) : "memory" : "intel", "volatile");
}

/// Reads the contents of cr2
#[inline]
pub unsafe fn read_cr2() -> u64 {
    let cr2;
    asm!("mov $0, cr2" : "=r"(cr2) :: "memory" : "intel", "volatile");
    cr2
}

/// Writes to cr2
#[inline]
pub unsafe fn write_cr2(val: u64) {
    asm!("mov cr2, $0" :: "r"(val) : "memory" : "intel", "volatile");
}

/// Reads the contents of cr3
#[inline]
pub unsafe fn read_cr3() -> u64 {
    let cr3;
    asm!("mov $0, cr3" : "=r"(cr3) :: "memory" : "intel", "volatile");
    cr3
}

/// Writes to cr3
#[inline]
pub unsafe fn write_cr3(val: u64) {
    asm!("mov cr3, $0" :: "r"(val) : "memory" : "intel", "volatile");
}

/// Reads the contents of cr4
#[inline]
pub unsafe fn read_cr4() -> u64 {
    let cr4;
    asm!("mov $0, cr4" : "=r"(cr4) :: "memory" : "intel", "volatile");
    cr4
}

/// Writes to cr4
#[inline]
pub unsafe fn write_cr4(val: u64) {
    asm!("mov cr4, $0" :: "r"(val) : "memory" : "intel", "volatile");
}

/// Performs cpuid passing in eax and ecx as parameters. Returns a tuple
/// containing the resulting (eax, ebx, ecx, edx)
#[inline]
pub unsafe fn cpuid(eax: u32, ecx: u32) -> (u32, u32, u32, u32) {
    let (oeax, oebx, oecx, oedx);

    asm!("cpuid" :
         "={eax}"(oeax), "={ebx}"(oebx), "={ecx}"(oecx), "={edx}"(oedx) :
         "{eax}"(eax), "{ecx}"(ecx) :: "volatile", "intel");

    (oeax, oebx, oecx, oedx)
}

/// Gets the ES selector value
#[inline]
pub unsafe fn read_es() -> u16 {
    let ret;
    asm!("mov $0, es" : "=r"(ret) ::: "intel", "volatile");
    ret
}

/// Gets the CS selector value
#[inline]
pub unsafe fn read_cs() -> u16 {
    let ret;
    asm!("mov $0, cs" : "=r"(ret) ::: "intel", "volatile");
    ret
}

/// Gets the SS selector value
#[inline]
pub unsafe fn read_ss() -> u16 {
    let ret;
    asm!("mov $0, ss" : "=r"(ret) ::: "intel", "volatile");
    ret
}

/// Gets the DS selector value
#[inline]
pub unsafe fn read_ds() -> u16 {
    let ret;
    asm!("mov $0, ds" : "=r"(ret) ::: "intel", "volatile");
    ret
}

/// Gets the FS selector value
#[inline]
pub unsafe fn read_fs() -> u16 {
    let ret;
    asm!("mov $0, fs" : "=r"(ret) ::: "intel", "volatile");
    ret
}

/// Gets the GS selector value
#[inline]
pub unsafe fn read_gs() -> u16 {
    let ret;
    asm!("mov $0, gs" : "=r"(ret) ::: "intel", "volatile");
    ret
}

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
            let cpuid_1 = cpuid(1, 0);
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
            features.xsave   = ((cpuid_1.2 >> 26) & 1) == 1;
            features.avx     = ((cpuid_1.2 >> 28) & 1) == 1;
        }

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

