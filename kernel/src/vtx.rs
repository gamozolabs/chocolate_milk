//! Intel VT-x extensions support
//!
//! To enable nested VT-x in KVM do the following:
//!
//! modprobe -r kvm_intel
//! modprobe kvm_intel nested=1

use core::cell::Cell;
use core::mem::size_of;
use core::sync::atomic::Ordering;
use page_table::{PhysAddr, VirtAddr};
use crate::mm::PhysContig;
use crate::ept::Ept;
use crate::interrupts::Tss;

/// Selectors for use during a syscall
pub const IA32_STAR: u32 = 0xc0000081;

/// Syscall 64-bit entry point
pub const IA32_LSTAR: u32 = 0xc0000082;

/// Syscall 32-bit entry point
pub const IA32_CSTAR: u32 = 0xc0000083;

/// Syscall rflags mask
pub const IA32_FMASK: u32 = 0xc0000084;

/// FS base MSR
pub const IA32_FS_BASE: u32 = 0xc000_0100;

/// GS base MSR
pub const IA32_GS_BASE: u32 = 0xc000_0101;

/// Kernel GS base MSR
pub const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;

/// EPT capabilities MSR
pub const IA32_VMX_EPT_VPID_CAP: u32 = 0x48c;

/// VMX enable bit in CR4
const CR4_VMXE: u64 = 1 << 13;

/// VMX basic 
const IA32_VMX_BASIC: u32 = 0x480;

/// Feature control MSR which VM-x lock and enablement bits
const IA32_FEATURE_CONTROL: u32 = 0x3a;

/// When set, writes to the feature control MSR will #GP, often set by the BIOS
const IA32_FEATURE_CONTROL_LOCK: u64 = 1 << 0;

/// When set, VMXON inside of SMX is allowed
const IA32_FEATURE_CONTROL_VMX_IN_SMX: u64 = 1 << 1;

/// When set, VMXON outside of SMX is allowed
const IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX: u64 = 1 << 2;

/// Bits set in this _must_ be set in cr0 when doing vmxon
const IA32_VMX_CR0_FIXED0: u32 = 0x486;

/// Bits clear in this _must_ be set to 0 in cr0 when doing vmxon
const IA32_VMX_CR0_FIXED1: u32 = 0x487;

/// Bits set in this _must_ be set in cr4 when doing vmxon
const IA32_VMX_CR4_FIXED0: u32 = 0x488;

/// Bits clear in this _must_ be set to 0 in cr4 when doing vmxon
const IA32_VMX_CR4_FIXED1: u32 = 0x489;

/// VMX pin based controls
const IA32_VMX_PINBASED_CTLS:  u32 = 0x481;

/// VMX processor based controls
const IA32_VMX_PROCBASED_CTLS: u32 = 0x482;

/// VMX processor based controls (part 2)
const IA32_VMX_PROCBASED_CTLS2: u32 = 0x48b;

/// VMX exit controls
const IA32_VMX_EXIT_CTLS: u32 = 0x483;

/// VMX entry controls
const IA32_VMX_ENTRY_CTLS: u32 = 0x484;

#[inline]
unsafe fn invalidate_ept(eptp: u128) {
    llvm_asm!("invept $0, [$1]" :: "r"(1u64), "r"(&eptp) : "memory" :
              "intel", "volatile");
}

/// Reads the contents of the current VMCS field based on `encoding`
#[inline]
unsafe fn vmread(encoding: Vmcs) -> u64 {
    let ret;
    llvm_asm!("vmread $0, $1" : "=r"(ret) : "r"(encoding as u64) : "memory" :
         "intel", "volatile");
    ret
}

/// Sets the contents of the current VMCS field based on `encoding` and `val`
#[inline]
unsafe fn vmwrite(encoding: Vmcs, val: u64) {
    llvm_asm!("vmwrite $0, $1" :: "r"(encoding as u64), "r"(val) : "memory" :
              "intel", "volatile");
}

/// VMCS region encodings (the values to be used with `vmread` and `vmwrite`
/// instructions)
#[derive(Clone, Copy)]
#[allow(unused)]
#[repr(u64)]
enum Vmcs {
    /// Virtual processor identifier
    Vpid = 0,

    /// VM instruction error information
    VmInstructionError = 0x00004400,

    /// VM exit reason
    ExitReason = 0x00004402,
    
    /// VM exit interruption information
    InterruptionInformation = 0x4404,
    
    /// VM exit interruption error code
    InterruptionErrorCode = 0x4406,

    /// VM exit qualification
    ExitQualification = 0x6400,

    /// Pin based controls
    PinBasedControls = 0x00004000,

    /// Processsor based controls
    ProcBasedControls = 0x00004002,

    /// Exception vmexit bitmap
    ExceptionBitmap = 0x00004004,
    
    /// Processsor based controls (part 2)
    ProcBasedControls2 = 0x0000401e,

    /// VM exit controls
    ExitControls = 0x0000400c,

    /// VM entry controls
    EntryControls = 0x00004012,
    
    /// Host ES selector
    HostESSel = 0xc00,
    
    /// Host CS selector
    HostCSSel = 0xc02,

    /// Host SS selector
    HostSSSel = 0xc04,

    /// Host DS selector
    HostDSSel = 0xc06,

    /// Host FS selector
    HostFSSel = 0xc08,

    /// Host GS selector
    HostGSSel = 0xc0a,

    /// Host TR selector
    HostTRSel = 0xc0c,

    /// Host sysenter CS selector
    HostSysenterCs = 0x4c00,

    /// Host CR0 register
    HostCr0 = 0x6c00,
    
    /// Host CR3 register
    HostCr3 = 0x6c02,
    
    /// Host CR4 register
    HostCr4 = 0x6c04,
    
    /// Host FS base
    HostFSBase = 0x6c06,
    
    /// Host GS base
    HostGSBase = 0x6c08,
    
    /// Host TR base
    HostTRBase = 0x6c0a,
    
    /// Host GDTR base
    HostGDTRBase = 0x6c0c,
    
    /// Host IDTR base
    HostIDTRBase = 0x6c0e,
    
    /// Host IA32_SYSENTER_ESP
    HostSysenterEspBase = 0x6c10,
    
    /// Host IA32_SYSENTER_EIP
    HostSysenterEipBase = 0x6c12,
    
    /// Host RSP
    HostRsp = 0x6c14,
    
    /// Host RIP
    HostRip = 0x6c16,
    
    /// Host IA32_EFER register
    HostIa32Efer = 0x2c02,

    /// Guest ES selector value
    GuestESSel = 0x800,

    /// Guest CS selector value
    GuestCSSel = 0x802,

    /// Guest SS selector value
    GuestSSSel = 0x804,

    /// Guest DS selector value
    GuestDSSel = 0x806,

    /// Guest FS selector value
    GuestFSSel = 0x808,

    /// Guest GS selector value
    GuestGSSel = 0x80a,

    /// Guest local task register selector value
    GuestLDTRSel = 0x80c,
    
    /// Guest task register selector value
    GuestTRSel = 0x80e,

    /// Guest VMCS link pointer
    GuestVmcsLinkPtr = 0x2800,

    /// Guest IA32_DEBUGCTL register
    GuestIa32DebugControl = 0x2802,

    /// Guest IA32_EFER register
    GuestIa32Efer = 0x2806,

    /// Guest ES segment limit
    GuestESLimit = 0x4800,
    
    /// Guest CS segment limit
    GuestCSLimit = 0x4802,

    /// Guest SS segment limit
    GuestSSLimit = 0x4804,

    /// Guest DS segment limit
    GuestDSLimit = 0x4806,

    /// Guest FS segment limit
    GuestFSLimit = 0x4808,

    /// Guest GS segment limit
    GuestGSLimit = 0x480a,

    /// Guest LDTR segment limit
    GuestLDTRLimit = 0x480c,

    /// Guest TR segment limit
    GuestTRLimit = 0x480e,

    /// Guest GDTR segment limit
    GuestGDTRLimit = 0x4810,

    /// Guest IDTR segment limit
    GuestIDTRLimit = 0x4812,
    
    /// Guest ES access rights
    GuestESAccessRights = 0x4814,
    
    /// Guest CS access rights
    GuestCSAccessRights = 0x4816,

    /// Guest SS access rights
    GuestSSAccessRights = 0x4818,

    /// Guest DS access rights
    GuestDSAccessRights = 0x481a,

    /// Guest FS access rights
    GuestFSAccessRights = 0x481c,

    /// Guest GS access rights
    GuestGSAccessRights = 0x481e,

    /// Guest LDTR access rights
    GuestLDTRAccessRights = 0x4820,

    /// Guest TR access rights
    GuestTRAccessRights = 0x4822,

    /// Guest interruptability state
    GuestInterruptabilityState = 0x4824,
    
    /// Guest activity state
    GuestActivityState = 0x4826,

    /// Guest SM base
    GuestSMBase = 0x4828,
    
    /// Guest IA32_SYSENTER_CS MSR
    GuestIa32SysenterCs = 0x482a,

    /// Guest CR0
    GuestCr0 = 0x6800,
    
    /// Guest CR3
    GuestCr3 = 0x6802,
    
    /// Guest CR4
    GuestCr4 = 0x6804,
    
    /// Guest ES segment base
    GuestESBase = 0x6806,
    
    /// Guest CS segment base
    GuestCSBase = 0x6808,

    /// Guest SS segment base
    GuestSSBase = 0x680a,

    /// Guest DS segment base
    GuestDSBase = 0x680c,

    /// Guest FS segment base
    GuestFSBase = 0x680e,

    /// Guest GS segment base
    GuestGSBase = 0x6810,

    /// Guest LDTR segment base
    GuestLDTRBase = 0x6812,

    /// Guest TR segment base
    GuestTRBase = 0x6814,

    /// Guest GDTR segment base
    GuestGDTRBase = 0x6816,

    /// Guest IDTR segment base
    GuestIDTRBase = 0x6818,

    /// Guest DR7
    GuestDr7 = 0x681a,

    /// Guest RSP
    GuestRsp = 0x681c,
    
    /// Guest RIP
    GuestRip = 0x681e,
    
    /// Guest RFLAGS
    GuestRflags = 0x6820,
    
    /// Guest pending debug exceptions
    GuestPendingDebugExceptions = 0x6822,
    
    /// Guest IA32_SYSENTER_ESP
    GuestIa32SysenterEsp = 0x6824,
    
    /// Guest IA32_SYSENTER_EIP
    GuestIa32SysenterEip = 0x6826,

    /// Pre-emption timer
    PreemptionTimer = 0x482e,

    /// Extended page table pointer
    EptPointer = 0x201a,

    /// Guest physical address (used in EPT violations)
    GuestPhysicalAddress = 0x2400,

    /// Length of the instruction which caused the VM exit
    VmExitInstructionLength = 0x440c,

    /// Page modification logging physical address (4 KiB page)
    PmlAddress = 0x200e,

    /// PML index, points to the index of the next free entry in the PML
    PmlIndex = 0x812,
}

/// Floating point state from an `fxsave` instruction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C, align(512))]
pub struct FxSave {
    // Floating point state information like the FXCS, MXCSR, etc
    fcw:        u16,
    fsw:        u16,
    ftw:        u8,
    _rsvd0:     u8,
    fop:        u16,
    fip:        u32,
    fcs:        u16,
    _rsvd1:     u16,
    fdp:        u32,
    fds:        u16,
    _rsvd2:     u16,
    mxcsr:      u32,
    mxcsr_mask: u32,

    /// MM registers 0-7
    pub mm: [u128; 8],

    /// XMM registers 0-15
    pub xmm: [u128; 16],

    /// Reserved fields
    reserved: [u128; 6],
}

impl Default for FxSave {
    fn default() -> Self {
        FxSave {
            fcw:        0x40,
            fsw:        0,
            ftw:        0,
            _rsvd0:     0,
            fop:        0,
            fip:        0,
            fcs:        0,
            _rsvd1:     0,
            fdp:        0,
            fds:        0,
            _rsvd2:     0,
            mxcsr:      0x0000_1f80,
            mxcsr_mask: 0xffff_0000,

            mm:       [0; 8],
            xmm:      [0; 16],
            reserved: [0; 6],
        }
    }
}

/// All registers in our VM state
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(usize)]
pub enum Register {
    Rax = 0,
    Rbx,
    Rcx,
    Rdx,
    Rsp,
    Rbp,
    Rsi,
    Rdi,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
    Rflags,

    Cr0,
    Cr2,
    Cr3,
    Cr4,
    Cr8,

    Efer,

    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
    Ldtr,
    Tr,

    EsBase,
    CsBase,
    SsBase,
    DsBase,
    FsBase,
    GsBase,
    LdtrBase,
    TrBase,
    GdtrBase,
    IdtrBase,

    EsLimit,
    CsLimit,
    SsLimit,
    DsLimit,
    FsLimit,
    GsLimit,
    LdtrLimit,
    TrLimit,
    GdtrLimit,
    IdtrLimit,

    EsAccessRights,
    CsAccessRights,
    SsAccessRights,
    DsAccessRights,
    FsAccessRights,
    GsAccessRights,
    LdtrAccessRights,
    TrAccessRights,

    Dr7,
    DebugCtl,

    SysenterCs,
    SysenterEsp,
    SysenterEip,

    KernelGsBase,

    CStar,
    LStar,
    FMask,
    Star,

    InterruptabilityState,
    ActivityState,
    PendingDebug,
    
    PmlAddress,
    PmlIndex,

    NumRegisters,
}

/// Where different registers are stored
#[derive(Clone, Copy)]
enum RegType {
    /// GPRs are automatically saved and restored unconditionally
    Gpr,

    /// Register is stored in the VMCS, at `Vmcs`
    Vmcs(Vmcs),

    /// Register is stored in the host `cr2`
    Cr2,
    
    /// Register is stored in the host `cr8`
    Cr8,

    /// Register is stored in the host MSR state at a given MSR
    Msr(u32),
}

/// Register IDs to register mappings
///
/// This also contains the register itself so we can panic if `Register` and
/// `REG_TYPES` desyncs :)
const REG_TYPES: &[(Register, RegType)] = &[
    (Register::Rax, RegType::Gpr),
    (Register::Rbx, RegType::Gpr),
    (Register::Rcx, RegType::Gpr),
    (Register::Rdx, RegType::Gpr),
    (Register::Rsp, RegType::Vmcs(Vmcs::GuestRsp)),
    (Register::Rbp, RegType::Gpr),
    (Register::Rsi, RegType::Gpr),
    (Register::Rdi, RegType::Gpr),
    (Register::R8, RegType::Gpr),
    (Register::R9, RegType::Gpr),
    (Register::R10, RegType::Gpr),
    (Register::R11, RegType::Gpr),
    (Register::R12, RegType::Gpr),
    (Register::R13, RegType::Gpr),
    (Register::R14, RegType::Gpr),
    (Register::R15, RegType::Gpr),
    (Register::Rip, RegType::Vmcs(Vmcs::GuestRip)),
    (Register::Rflags, RegType::Vmcs(Vmcs::GuestRflags)),
    (Register::Cr0, RegType::Vmcs(Vmcs::GuestCr0)),
    (Register::Cr2, RegType::Cr2),
    (Register::Cr3, RegType::Vmcs(Vmcs::GuestCr3)),
    (Register::Cr4, RegType::Vmcs(Vmcs::GuestCr4)),
    (Register::Cr8, RegType::Cr8),
    (Register::Efer, RegType::Vmcs(Vmcs::GuestIa32Efer)),
    (Register::Es, RegType::Vmcs(Vmcs::GuestESSel)),
    (Register::Cs, RegType::Vmcs(Vmcs::GuestCSSel)),
    (Register::Ss, RegType::Vmcs(Vmcs::GuestSSSel)),
    (Register::Ds, RegType::Vmcs(Vmcs::GuestDSSel)),
    (Register::Fs, RegType::Vmcs(Vmcs::GuestFSSel)),
    (Register::Gs, RegType::Vmcs(Vmcs::GuestGSSel)),
    (Register::Ldtr, RegType::Vmcs(Vmcs::GuestLDTRSel)),
    (Register::Tr, RegType::Vmcs(Vmcs::GuestTRSel)),
    (Register::EsBase, RegType::Vmcs(Vmcs::GuestESBase)),
    (Register::CsBase, RegType::Vmcs(Vmcs::GuestCSBase)),
    (Register::SsBase, RegType::Vmcs(Vmcs::GuestSSBase)),
    (Register::DsBase, RegType::Vmcs(Vmcs::GuestDSBase)),
    (Register::FsBase, RegType::Vmcs(Vmcs::GuestFSBase)),
    (Register::GsBase, RegType::Vmcs(Vmcs::GuestGSBase)),
    (Register::LdtrBase, RegType::Vmcs(Vmcs::GuestLDTRBase)),
    (Register::TrBase, RegType::Vmcs(Vmcs::GuestTRBase)),
    (Register::GdtrBase, RegType::Vmcs(Vmcs::GuestGDTRBase)),
    (Register::IdtrBase, RegType::Vmcs(Vmcs::GuestIDTRBase)),
    (Register::EsLimit, RegType::Vmcs(Vmcs::GuestESLimit)),
    (Register::CsLimit, RegType::Vmcs(Vmcs::GuestCSLimit)),
    (Register::SsLimit, RegType::Vmcs(Vmcs::GuestSSLimit)),
    (Register::DsLimit, RegType::Vmcs(Vmcs::GuestDSLimit)),
    (Register::FsLimit, RegType::Vmcs(Vmcs::GuestFSLimit)),
    (Register::GsLimit, RegType::Vmcs(Vmcs::GuestGSLimit)),
    (Register::LdtrLimit, RegType::Vmcs(Vmcs::GuestLDTRLimit)),
    (Register::TrLimit, RegType::Vmcs(Vmcs::GuestTRLimit)),
    (Register::GdtrLimit, RegType::Vmcs(Vmcs::GuestGDTRLimit)),
    (Register::IdtrLimit, RegType::Vmcs(Vmcs::GuestIDTRLimit)),
    (Register::EsAccessRights, RegType::Vmcs(Vmcs::GuestESAccessRights)),
    (Register::CsAccessRights, RegType::Vmcs(Vmcs::GuestCSAccessRights)),
    (Register::SsAccessRights, RegType::Vmcs(Vmcs::GuestSSAccessRights)),
    (Register::DsAccessRights, RegType::Vmcs(Vmcs::GuestDSAccessRights)),
    (Register::FsAccessRights, RegType::Vmcs(Vmcs::GuestFSAccessRights)),
    (Register::GsAccessRights, RegType::Vmcs(Vmcs::GuestGSAccessRights)),
    (Register::LdtrAccessRights, RegType::Vmcs(Vmcs::GuestLDTRAccessRights)),
    (Register::TrAccessRights, RegType::Vmcs(Vmcs::GuestTRAccessRights)),
    (Register::Dr7, RegType::Vmcs(Vmcs::GuestDr7)),
    (Register::DebugCtl, RegType::Vmcs(Vmcs::GuestIa32DebugControl)),
    (Register::SysenterCs, RegType::Vmcs(Vmcs::GuestIa32SysenterCs)),
    (Register::SysenterEsp, RegType::Vmcs(Vmcs::GuestIa32SysenterEsp)),
    (Register::SysenterEip, RegType::Vmcs(Vmcs::GuestIa32SysenterEip)),
    (Register::KernelGsBase, RegType::Msr(IA32_KERNEL_GS_BASE)),
    (Register::CStar, RegType::Msr(IA32_CSTAR)),
    (Register::LStar, RegType::Msr(IA32_LSTAR)),
    (Register::FMask, RegType::Msr(IA32_FMASK)),
    (Register::Star, RegType::Msr(IA32_STAR)),
    (Register::InterruptabilityState,
        RegType::Vmcs(Vmcs::GuestInterruptabilityState)),
    (Register::ActivityState, RegType::Vmcs(Vmcs::GuestActivityState)),
    (Register::PendingDebug, RegType::Vmcs(Vmcs::GuestPendingDebugExceptions)),
    (Register::PmlAddress, RegType::Vmcs(Vmcs::PmlAddress)),
    (Register::PmlIndex, RegType::Vmcs(Vmcs::PmlIndex)),
];

/// General purpose register state
#[derive(Clone)]
#[repr(C)]
pub struct RegisterState {
    registers: [Cell<u64>; Register::NumRegisters as usize],
    fxsave:    FxSave,

    /// Bitmap tracking if registers are cached, if they are cached, they can
    /// be pulled directly from `registers`, otherwise they must be fetched
    /// directly from the source
    cached: [Cell<u8>; (Register::NumRegisters as usize + 7) / 8],

    /// Bitmap tracking if registers are dirtied, this indicates that the
    /// value in a `registers` field is different from what is commit to the
    /// VM state and must be flushed before the next VM entry
    dirtied: [Cell<u8>; (Register::NumRegisters as usize + 7) / 8],
}

impl RegisterState {
    /// Copy a register state from another one
    pub fn copy_from(&mut self, other: &RegisterState) {
        for &(reg, _) in REG_TYPES.iter() {
            let idx = reg as usize / 8;
            let bit = reg as usize % 8;

            // Only restore registers which were cached in `other`, we cannot
            // pull in from their context if they're not cached
            if (other.cached[idx].get() & (1 << bit)) != 0 {
                // Only update if the register changed
                if self.reg(reg) != other.reg(reg) {
                    // Update the register
                    self.set_reg(reg, other.reg(reg));
                }
            } else {
                // Register is not cached in `other`, zero it out
                if self.reg(reg) != 0 {
                    self.set_reg(reg, 0);
                }
            }
        }

        // Copy the fxsave unconditionally
        self.fxsave = other.fxsave;
    }

    /// Get a register
    #[inline]
    pub fn reg(&self, reg: Register) -> u64 {
        let idx = reg as usize / 8;
        let bit = reg as usize % 8;

        if (self.cached[idx].get() & (1 << bit)) == 0 {
            // Register is not cached, we must get it from the guest state
            let (_, rt) = REG_TYPES[reg as usize];
            match rt {
                RegType::Gpr => {
                    // These are always unconditionally cached
                }
                RegType::Vmcs(vmcs) => {
                    // Get the register from the VMCS
                    self.registers[reg as usize].set(unsafe {
                        vmread(vmcs)
                    });
                    self.cached[idx].set(
                        self.cached[idx].get() | (1 << bit));
                }
                RegType::Cr2 => {
                    // Due to the nature of CR2 being overwritten on the host,
                    // this register is always cached
                }
                RegType::Cr8 => {
                    // Get the CR8 from the host CR8
                    self.registers[reg as usize].set(
                        cpu::read_cr8());
                    self.cached[idx].set(
                        self.cached[idx].get() | (1 << bit));
                }
                RegType::Msr(msr) => {
                    // Get the MSR from the real MSR state
                    self.registers[reg as usize].set(unsafe {
                        cpu::rdmsr(msr)
                    });
                    self.cached[idx].set(
                        self.cached[idx].get() | (1 << bit));
                }
            }
        }

        // Register is actively cached in the current register state
        self.registers[reg as usize].get()
    }

    /// Set a register to the internal cache
    #[inline]
    pub fn set_reg(&self, reg: Register, val: u64) {
        let idx = reg as usize / 8;
        let bit = reg as usize % 8;
        self.registers[reg as usize].set(val);
        self.cached[idx].set(
            self.cached[idx].get() | (1 << bit));
        self.dirtied[idx].set(
            self.dirtied[idx].get() | (1 << bit));
    }

    /// Set the fxsave state for the VM
    #[inline]
    pub fn set_fxsave(&mut self, fxsave: FxSave) {
        self.fxsave = fxsave;
    }

    /// Flush a register from the internal cache to the correct location
    #[inline]
    fn flush_reg(&self, reg: usize) {
        let idx = reg as usize / 8;
        let bit = reg as usize % 8;

        if (self.dirtied[idx].get() & (1 << bit)) != 0 {
            // Clear the dirtied bit
            self.dirtied[idx].set(
                self.dirtied[idx].get() & !(1 << bit));

            // Register is not dirtied, we must get it from the guest state
            let (_, rt) = REG_TYPES[reg as usize];
            match rt {
                RegType::Gpr => {
                    // Automatically synced during vmentry, nothing to do
                }
                RegType::Vmcs(vmcs) => {
                    // Set the register in the VMCS
                    unsafe {
                        vmwrite(vmcs,
                                self.registers[reg as usize].get());
                    }
                }
                RegType::Cr2 => {
                    // Sync only if different
                    let val = self.registers[reg as usize].get();
                    if cpu::read_cr2() != val {
                        unsafe { cpu::write_cr2(val); }
                    }
                }
                RegType::Cr8 => {
                    // Sync only if different
                    let val = self.registers[reg as usize].get();
                    if cpu::read_cr8() != val {
                        unsafe { cpu::write_cr8(val); }
                    }
                }
                RegType::Msr(msr) => {
                    // Sync only if different
                    let val = self.registers[reg as usize].get();
                    unsafe {
                        if cpu::rdmsr(msr) != val {
                            cpu::wrmsr(msr, val);
                        }
                    }
                }
            }
        }
    }
}

impl Default for RegisterState {
    fn default() -> Self {
        RegisterState {
            registers: unsafe { core::mem::zeroed() },
            fxsave:    FxSave::default(),
            cached:    unsafe { core::mem::zeroed() },
            dirtied:   unsafe { core::mem::zeroed() },
        }
    }
}

/// An x86 exception
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Exception {
    DivideError,
    DebugException,
    NMI,
    Breakpoint,
    Overflow,
    BoundRangeExceeded,
    InvalidOpcode,
    DeviceNotAvailable,
    DoubleFault,
    CoprocessorSegmentOverrun,
    InvalidTSS,
    SegmentNotPresent,
    StackSegmentFault,
    GeneralProtectionFault(u64),
    PageFault {
        /// Faulting address
        addr: VirtAddr,

        /// Page is present
        present: bool,

        /// Access was a write
        write: bool,

        /// Access was a user-mode access
        user: bool,

        /// Access was an instruction fetch
        exec: bool,
    },
    FloatingPointError,
    AlignmentCheck,
    MachineCheck,
    SimdFloatingPointException,
    VirtualizationException,
    ControlProtectionException,
}

impl From<u8> for Exception {
    fn from(val: u8) -> Self {
        match val {
             0 => Exception::DivideError,
             1 => Exception::DebugException,
             2 => Exception::NMI,
             3 => Exception::Breakpoint,
             4 => Exception::Overflow,
             5 => Exception::BoundRangeExceeded,
             6 => Exception::InvalidOpcode,
             7 => Exception::DeviceNotAvailable,
             8 => Exception::DoubleFault,
             9 => Exception::CoprocessorSegmentOverrun,
            10 => Exception::InvalidTSS,
            11 => Exception::SegmentNotPresent,
            12 => Exception::StackSegmentFault,
            13 => Exception::GeneralProtectionFault(0),
            14 => Exception::PageFault {
                addr:    VirtAddr(0),
                present: false,
                write:   false,
                user:    false,
                exec:    false,
            },
            16 => Exception::FloatingPointError,
            17 => Exception::AlignmentCheck,
            18 => Exception::MachineCheck,
            19 => Exception::SimdFloatingPointException,
            20 => Exception::VirtualizationException,
            21 => Exception::ControlProtectionException,
            _  => unreachable!(),
        }
    }
}

/// Virtual machine exit reason
#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub enum VmExit {
    EptViolation {
        addr:  PhysAddr,
        read:  bool,
        write: bool,
        exec:  bool,
    },
    Exception(Exception),
    ExternalInterrupt,
    PreemptionTimer,
    Rdtsc { inst_len: u64 },
    Timeout,
    ReadMsr { inst_len: u64 },
    WriteMsr { inst_len: u64 },
    WriteCr {
        /// Control register index
        cr:  u8,

        /// GPR index
        gpr: u8,
        
        /// Length of the instruction
        inst_len: u64,
    },
    ReadCr {
        /// Control register index
        cr:  u8,

        /// GPR index
        gpr: u8,

        /// Length of the instruction
        inst_len: u64,
    },
    PmlFull,
}

/// A virtual machine using Intel VT-x extensions
pub struct Vm {
    /// The VMCS for this VM
    vmcs: PhysContig<[u8; 4096]>,
    
    /// Page modification log
    pml: PhysContig<[u64; 512]>,

    /// Tracks if the VM controls and unchanging host and guest state has been
    /// initialized
    init: bool,

    /// Host registers
    host_regs: RegisterState,
       
    /// Guest physical to host physical translations
    ept: Ept,

    /// Tracks if the EPT has been borrowed as mutable at some point, this
    /// lets us know that we should invalidate EPT entries
    pub ept_dirty: bool,

    /// Guest registers
    pub guest_regs: RegisterState,

    /// Tracks if this VM is currently launched (thus, `vmresume` should be
    /// used)
    launched: bool,

    /// Pre-emption timer value to use
    pub preemption_timer: Option<u32>,

    /// Current setting for the pin-based controls
    pinbased_controls: u64,
}

impl Vm {
    /// Create a new virtual machine
    pub fn new() -> Vm {
        // Make sure `REG_TYPES` is well formed
        for reg in 0..Register::NumRegisters as usize {
            assert!(reg == REG_TYPES[reg].0 as usize,
                    "REG_TYPES not in sync with Registers");
        }

        // First, detect if VM-x is supported on the machine
        // See section 23.6 in the Intel Manual "DISCOVERING SUPPORT FOR VMX"
        let cpu_features = cpu::get_cpu_features();
        assert!(cpu_features.vmx, "VT-x is not supported, cannot create VM");

        unsafe {
            // Enable VMX extensions if not already enabled
            if (cpu::read_cr4() & CR4_VMXE) == 0 {
                cpu::write_cr4(cpu::read_cr4() | CR4_VMXE);
            }
        }

        unsafe {
            // Check if the lock bit is not set, if it is not set, enable
            // VTX in all modes and set the lock bit
            if (cpu::rdmsr(IA32_FEATURE_CONTROL) &
                    IA32_FEATURE_CONTROL_LOCK) == 0 {
                // Lock bit is not set yet (typically the BIOS sets this), so
                // we can set it ourselves with the features we want
                cpu::wrmsr(IA32_FEATURE_CONTROL,
                           IA32_FEATURE_CONTROL_VMX_OUTSIDE_SMX |
                           IA32_FEATURE_CONTROL_VMX_IN_SMX      |
                           IA32_FEATURE_CONTROL_LOCK);
            }
        }

        unsafe {
            // Get the EPT feature set
            let ept_features = cpu::rdmsr(IA32_VMX_EPT_VPID_CAP);

            /// Expected EPT values
            /// - Execute-only memory supported
            /// - 4-level paging
            /// - Write-back EPT memory
            const EPT_EXPECTED: u64 = (1 << 0) | (1 << 6) | (1 << 14);

            assert!(ept_features & EPT_EXPECTED == EPT_EXPECTED,
                "EPT does not support all requested features");
        }

        unsafe {
            // Get access to the VMXON region
            let mut vmxon_lock = core!().vmxon_region().lock();

            // Set the mandatory bits in CR0 and clear bits that are mandatory
            // zero
            cpu::write_cr0((cpu::read_cr0() | cpu::rdmsr(IA32_VMX_CR0_FIXED0))
                & cpu::rdmsr(IA32_VMX_CR0_FIXED1));

            // Set the mandatory bits in CR4 and clear bits that are mandatory
            // zero
            cpu::write_cr4((cpu::read_cr4() | cpu::rdmsr(IA32_VMX_CR4_FIXED0))
                & cpu::rdmsr(IA32_VMX_CR4_FIXED1));

            // Check if we need to create a VMXON region for this core
            if vmxon_lock.is_none() {
                // Get the VMCS revision number
                let vmcs_revision_number: u32 =
                    (cpu::rdmsr(IA32_VMX_BASIC) as u32) & 0x7fff_ffff;

                // Allocate a page in physical memory that is also virtually 
                // mapped
                let mut vmxon_region = PhysContig::new([0u8; 4096]);

                // Write the revision number to the first 32-bits of the VMXON
                // region
                vmxon_region[..size_of::<u32>()].copy_from_slice(
                    &vmcs_revision_number.to_le_bytes());

                // Enable VMX by switching VMX to on
                llvm_asm!("vmxon ($0)" :: "r"(&vmxon_region.phys_addr()) :
                          "memory" : "volatile");

                // Save the VMXON region as the current VMXON region
                *vmxon_lock = Some(vmxon_region);
            }
        }

        // Allocate a VMCS region
        let mut vmcs = PhysContig::new([0u8; 4096]);
        
        // Get the revision number and write it into the VMCS
        let vmcs_revision_number: u32 = unsafe {
            (cpu::rdmsr(IA32_VMX_BASIC) as u32) & 0x7fff_ffff
        };
        vmcs[..size_of::<u32>()].copy_from_slice(
            &vmcs_revision_number.to_le_bytes());

        Vm {
            vmcs: vmcs,
            init: false,
            ept:  Ept::new().expect("Failed to create EPT table"),
            ept_dirty: false,
            pml:  PhysContig::new([0; 512]),
            host_regs:  RegisterState::default(),
            guest_regs: RegisterState::default(),
            launched:   false,
            preemption_timer: None,
            pinbased_controls: 0,
        }
    }
    
    /// Get access to the EPT
    pub fn ept(&self) -> &Ept {
        &self.ept
    }
    
    /// Get mutable access to the EPT
    pub fn ept_mut(&mut self) -> &mut Ept {
        &mut self.ept
    }
    
    /// Get a register
    #[inline]
    pub fn reg(&self, reg: Register) -> u64 {
        self.guest_regs.reg(reg)
    }

    /// Set a register to the internal cache
    #[inline]
    pub fn set_reg(&self, reg: Register, val: u64) {
        self.guest_regs.set_reg(reg, val);
    }

    /// Set the fxsave state for the VM
    #[inline]
    pub fn set_fxsave(&mut self, fxsave: FxSave) {
        self.guest_regs.set_fxsave(fxsave);
    }

    /// Get access to the page modification log
    #[inline]
    pub fn pml(&mut self) -> &mut [u64; 512] {
        &mut *self.pml
    }

    /// Reset the VMCS to the original VMCS state
    pub fn reset(&mut self) {
        unsafe {
            // Initialize the PML base address
            self.set_reg(Register::PmlAddress, self.pml.phys_addr().0);
            
            // Reset the PML index
            self.set_reg(Register::PmlIndex, 511);

            if self.ept_dirty {
                // Invalidate the EPT
                invalidate_ept(
                    (self.ept.table().0 | (3 << 3) | (1 << 6) | 6) as u128);
                self.ept_dirty = false;
            }
        }
    }

    /// Run the VM
    pub fn run(&mut self) -> (VmExit, u64) {
        unsafe {
            // Check if we need to switch to a different active VM 
            if core!().current_vm_ptr().load(Ordering::SeqCst) !=
                    self.vmcs.phys_addr().0 {
                // Set the current VM as the active VM
                llvm_asm!("vmptrld ($0)" :: "r"(&self.vmcs.phys_addr()) :
                          "memory" : "volatile");
                core!().current_vm_ptr().store(self.vmcs.phys_addr().0,
                                               Ordering::SeqCst);
            }
        }

        // Do one-time initialization
        if !self.init {
            unsafe {
                // Bits that are set in `ctrl0` MUST be SET in the respective
                // VMCS control
                //
                // Bits that are clear in `ctrl1` MUST be CLEAR in the
                // respective VMCS control
                let pinbased_ctrl0 =
                    (cpu::rdmsr(IA32_VMX_PINBASED_CTLS) >> 0) & 0xffff_ffff;
                let pinbased_ctrl1 =
                    (cpu::rdmsr(IA32_VMX_PINBASED_CTLS) >> 32) & 0xffff_ffff;
                let procbased_ctrl0 =
                    (cpu::rdmsr(IA32_VMX_PROCBASED_CTLS) >> 0) & 0xffff_ffff;
                let procbased_ctrl1 =
                    (cpu::rdmsr(IA32_VMX_PROCBASED_CTLS) >> 32) & 0xffff_ffff;
                let proc2based_ctrl0 =
                    (cpu::rdmsr(IA32_VMX_PROCBASED_CTLS2) >> 0) & 0xffff_ffff;
                let proc2based_ctrl1 =
                    (cpu::rdmsr(IA32_VMX_PROCBASED_CTLS2) >> 32) & 0xffff_ffff;
                let exit_ctrl0 =
                    (cpu::rdmsr(IA32_VMX_EXIT_CTLS) >> 0) & 0xffff_ffff;
                let exit_ctrl1 =
                    (cpu::rdmsr(IA32_VMX_EXIT_CTLS) >> 32) & 0xffff_ffff;
                let entry_ctrl0 =
                    (cpu::rdmsr(IA32_VMX_ENTRY_CTLS) >> 0) & 0xffff_ffff;
                let entry_ctrl1 =
                    (cpu::rdmsr(IA32_VMX_ENTRY_CTLS) >> 32) & 0xffff_ffff;
                
                let pinbased_minimum   = pinbased_ctrl0   & pinbased_ctrl1;
                let procbased_minimum  = procbased_ctrl0  & procbased_ctrl1;
                let proc2based_minimum = proc2based_ctrl0 & proc2based_ctrl1;
                let exit_minimum       = exit_ctrl0       & exit_ctrl1;
                let entry_minimum      = entry_ctrl0      & entry_ctrl1;
                
                // Set the controls you do and don't want here

                // We want pin entries:
                // External interrupt exiting
                // NMI existing
                // Virtual NMIs
                let pin_on  = (1 << 0) | (1 << 3) | (1 << 5);
                let pin_off = 0;

                // On entry we want:
                // Load debug controls (required on Skylake)
                // 64-bit guest
                // Load IA32_EFER
                let entry_on = (1 << 2) | (1 << 9) | (1 << 15);

                // On entry we don't want:
                // Load IA32_PERF_GLOBAL_CTRL
                // Load IA32_PAT
                // Load IA32_BNDCFGS
                // Load IA32_RTIT_CTL
                // Load CET state
                let entry_off = (1 << 13) | (1 << 14) |
                    (1 << 16) | (1 << 18) | (1 << 20);

                // On exit we want:
                // Host is 64-bit
                // Save debug controls
                // Save IA32_EFER
                // Load IA32_EFER
                let exit_on = (1 << 2) | (1 << 9) | (1 << 20) | (1 << 21);
                
                // On exit we don't want:
                // Load IA32_PERF_GLOBAL_CTRL
                // Save IA32_PAT
                // Load IA32_PAT
                // Clear IA32_BNDCFGS
                // Clear IA32_RTIT_CTL
                // Load CET state
                let exit_off = (1 << 12) | (1 << 18) | (1 << 19) |
                    (1 << 23) | (1 << 25) | (1 << 28);

                // Processor controls:
                // On:
                //   Activate secondary controls
                //   HLT exiting
                //   RDPMC exiting
                //   CR3 load exiting
                //   CR3 store exiting
                //   MOV DR exiting
                //   Unconditional I/O exiting
                //   RDPMC exiting
                //   RDTSC exiting
                // Off:
                //   Use MSR bitmaps
                //   Use I/O bitmaps
                //   TPR shadow
                let proc_on  = (1 << 31) | (1 << 7) | (1 << 11) | (1 << 15) |
                    (1 << 16) | (1 << 23) | (1 << 24) | (1 << 11) | (1 << 12);
                let proc_off = (1 << 28) | (1 << 25) | (1 << 21);
                
                // Processor controls 2:
                // On:
                //     Enable EPT
                //     Enable VPID
                //     Enable PML
                //     RDRAND exiting
                //     RDSEED exiting
                // Off:
                //     Disable RDTSCP
                //     Disable XSAVES/XRSTORS
                let proc2_on  = (1 << 1) | (1 << 5) | (1 << 17) | (1 << 11) |
                    (1 << 16);
                let proc2_off = (1 << 3) | (1 << 20);

                // Validate that desired bits can be what was desired
                {
                    let checks = &[
                        (entry_ctrl0, entry_ctrl1, entry_on, entry_off),
                        (exit_ctrl0, exit_ctrl1, exit_on, exit_off),
                        (pinbased_ctrl0, pinbased_ctrl1, pin_on, pin_off),
                        (procbased_ctrl0, procbased_ctrl1, proc_on, proc_off),
                        (proc2based_ctrl0, proc2based_ctrl1,
                            proc2_on, proc2_off),
                    ];

                    // mb1 = must be 1
                    // cb1 = can be 1
                    for &(mb1, cb1, on, off) in checks {
                        // Compute what can be zero
                        let cb0 = !mb1;

                        assert!((on  & cb1) == on);
                        assert!((off & cb0) == off);
                    }
                }

                // Establish the VM controls
                vmwrite(Vmcs::PinBasedControls,
                             pinbased_minimum | pin_on);
                self.pinbased_controls = pinbased_minimum | pin_on;
                vmwrite(Vmcs::ProcBasedControls,
                             procbased_minimum | proc_on);
                vmwrite(Vmcs::ProcBasedControls2,
                             proc2based_minimum | proc2_on);
                vmwrite(Vmcs::ExitControls, 
                            exit_minimum | exit_on);
                vmwrite(Vmcs::EntryControls, 
                            entry_minimum | entry_on);

                // Set the EPT table as a 4 level EPT with accessed and dirty
                // bit tracking
                vmwrite(Vmcs::EptPointer,
                        self.ept.table().0 | (3 << 3) | (1 << 6) | 6);

                // Exit on all exceptions
                vmwrite(Vmcs::ExceptionBitmap, !0 & !(1 << 14));

                // Write in the host state which will not change per run

                // Set host selectors
                vmwrite(Vmcs::HostESSel, cpu::read_es() as u64);
                vmwrite(Vmcs::HostCSSel, cpu::read_cs() as u64);
                vmwrite(Vmcs::HostSSSel, cpu::read_ss() as u64);
                vmwrite(Vmcs::HostDSSel, cpu::read_ds() as u64);
                vmwrite(Vmcs::HostFSSel, cpu::read_fs() as u64);
                vmwrite(Vmcs::HostGSSel, cpu::read_gs() as u64);
                vmwrite(Vmcs::HostTRSel, cpu::read_tr() as u64);
                vmwrite(Vmcs::HostSysenterCs, 0);

                // Set the host control registers
                vmwrite(Vmcs::HostCr0, cpu::read_cr0());
                vmwrite(Vmcs::HostCr3, cpu::read_cr3());
                vmwrite(Vmcs::HostCr4, cpu::read_cr4());
               
                // Set the host segment bases
                vmwrite(Vmcs::HostFSBase, cpu::fs_base());
                vmwrite(Vmcs::HostGSBase, cpu::gs_base());

                // Get access to interrupt state, which will let us get access
                // to our GDT, IDT, and TR bases
                let interrupts = core!().interrupts().lock();
                let interrupts = interrupts.as_ref().unwrap();

                // Host table bases
                vmwrite(Vmcs::HostTRBase,
                    &*interrupts.tss as *const Tss as u64);
                vmwrite(Vmcs::HostGDTRBase,
                    interrupts.gdt.as_ptr() as u64);
                vmwrite(Vmcs::HostIDTRBase,
                    interrupts.idt.as_ptr() as u64);

                // Host sysenter information
                vmwrite(Vmcs::HostSysenterEspBase, 0);
                vmwrite(Vmcs::HostSysenterEipBase, 0);
            
                // NX enable
                // Long mode active, enable
                vmwrite(Vmcs::HostIa32Efer, (1 << 11) | (1 << 10) | (1 << 8));

                // Set the VPID for the guest
                vmwrite(Vmcs::Vpid, core!().id as u64 + 1);
            
                // Set up guest state
                vmwrite(Vmcs::GuestVmcsLinkPtr, !0);
                vmwrite(Vmcs::GuestSMBase, 0);
            }

            self.reset();
 
            // We have initialized the VM
            self.init = true;
        }

        // Make sure the fxsave starts at `0x400` from the `guest_regs`
        assert!((&self.guest_regs.fxsave as *const _ as usize -
                 &self.guest_regs as *const _ as usize) == 0x400);
         
        // Time spent inside the VM
        let vm_cycles;

        unsafe {
            core!().disable_interrupts();
           
            if let Some(timer) = self.preemption_timer {
                if (self.pinbased_controls & (1 << 6)) == 0 {
                    // Enable the pre-emption timer
                    self.pinbased_controls |= 1 << 6;
                    vmwrite(Vmcs::PinBasedControls, self.pinbased_controls);
                }
                vmwrite(Vmcs::PreemptionTimer, timer as u64);
            } else {
                if (self.pinbased_controls & (1 << 6)) != 0 {
                    // Disable the pre-emption timer
                    self.pinbased_controls &= !(1 << 6);
                    vmwrite(Vmcs::PinBasedControls, self.pinbased_controls);
                }
            }
            
            // Flush any registers which may have changed during execution
            for (byte, status) in self.guest_regs.dirtied.iter().enumerate() {
                let st = status.get();
                if st == 0 { continue; }
                for bit in 0..8 {
                    if (st & (1 << bit)) != 0 {
                        let idx = byte * 8 + bit;
                        if idx < Register::NumRegisters as usize {
                            self.guest_regs.flush_reg(idx);
                        }
                    }
                }
            }
            
            let it = cpu::rdtsc();

            llvm_asm!(r#"

                // Save host state
                mov [rcx +  0 * 8], rax
                mov [rcx +  1 * 8], rbx
                mov [rcx +  2 * 8], rcx
                mov [rcx +  3 * 8], rdx
                mov [rcx +  5 * 8], rbp
                mov [rcx +  6 * 8], rsi
                mov [rcx +  7 * 8], rdi
                mov [rcx +  8 * 8], r8
                mov [rcx +  9 * 8], r9
                mov [rcx + 10 * 8], r10
                mov [rcx + 11 * 8], r11
                mov [rcx + 12 * 8], r12
                mov [rcx + 13 * 8], r13
                mov [rcx + 14 * 8], r14
                mov [rcx + 15 * 8], r15
                fxsave64 [rcx + 0x400]

                // Save host state register
                push rcx

                // Save the guest state register
                push rdx

                // Save HOST_RSP
                mov rax, 0x6c14
                vmwrite rax, rsp

                // Save HOST_RIP
                mov rax, 0x6c16
                lea rbx, [rip + 1f]
                vmwrite rax, rbx

                // Load the guest floating point regs
                fxrstor64 [rdx + 0x400]

                // Check if we should be using vmlaunch or vmresume
                // These flags can persist during the guest GPR loads
                test edi, edi

                // Load the guest GPRs
                mov rax, [rdx +  0 * 8]
                mov rbx, [rdx +  1 * 8]
                mov rcx, [rdx +  2 * 8]
                mov rbp, [rdx +  5 * 8]
                mov rsi, [rdx +  6 * 8]
                mov rdi, [rdx +  7 * 8]
                mov r8,  [rdx +  8 * 8]
                mov r9,  [rdx +  9 * 8]
                mov r10, [rdx + 10 * 8]
                mov r11, [rdx + 11 * 8]
                mov r12, [rdx + 12 * 8]
                mov r13, [rdx + 13 * 8]
                mov r14, [rdx + 14 * 8]
                mov r15, [rdx + 15 * 8]
                mov rdx, [rdx +  3 * 8]

                // If `resume` is `true` then use resume, otherwise use launch
                jnz 2f

                vmlaunch
                
                // Should never be hit unless vmlaunch failed
                int3

            2:
                vmresume

                // Should never be hit unless vmresume failed
                int3

            1:
                // Save the VM exit rdx
                push rdx

                // Restore the guest register state pointer
                mov rdx, [rsp + 8]
                mov [rdx +  0 * 8], rax
                mov [rdx +  1 * 8], rbx
                mov [rdx +  2 * 8], rcx
                mov [rdx +  5 * 8], rbp
                mov [rdx +  6 * 8], rsi
                mov [rdx +  7 * 8], rdi
                mov [rdx +  8 * 8], r8
                mov [rdx +  9 * 8], r9
                mov [rdx + 10 * 8], r10
                mov [rdx + 11 * 8], r11
                mov [rdx + 12 * 8], r12
                mov [rdx + 13 * 8], r13
                mov [rdx + 14 * 8], r14
                mov [rdx + 15 * 8], r15
                fxsave64 [rdx + 0x400]

                // Get the saved rdx from above and save it in to the guest
                // state
                pop rcx
                mov [rdx + 3 * 8], rcx

                // Pop off the guest and host register pointers
                pop rdx
                pop rcx

                // Load the host state
                mov rax, [rcx +  0 * 8]
                mov rbx, [rcx +  1 * 8]
                mov rdx, [rcx +  3 * 8]
                mov rbp, [rcx +  5 * 8]
                mov rsi, [rcx +  6 * 8]
                mov rdi, [rcx +  7 * 8]
                mov r8,  [rcx +  8 * 8]
                mov r9,  [rcx +  9 * 8]
                mov r10, [rcx + 10 * 8]
                mov r11, [rcx + 11 * 8]
                mov r12, [rcx + 12 * 8]
                mov r13, [rcx + 13 * 8]
                mov r14, [rcx + 14 * 8]
                mov r15, [rcx + 15 * 8]
                mov rcx, [rcx +  2 * 8]
                fxrstor64 [rcx + 0x400]

            "# ::
            "{rcx}"(&mut self.host_regs),
            "{rdx}"(&mut self.guest_regs),
            "{edi}"(self.launched as u32) :
            "memory", "rax", "rbx", "cc" : "intel", "volatile");

            // Mark that nothing is cached anymore (dirtied is already clear
            // from the prior flushes)
            self.guest_regs.cached.iter_mut().for_each(|x| x.set(0));

            // Record the time spent in the VM
            vm_cycles = cpu::rdtsc() - it;

            // Sync CR2 now as the OS may change it during page faults
            self.set_reg(Register::Cr2, cpu::read_cr2());
        
            core!().enable_interrupts();
        }

        // Mark that this VM has launched
        self.launched = true;

        // Parse the VM exit information
        let vmexit = match unsafe { vmread(Vmcs::ExitReason) } {
            0 => {
                // Exception or NMI
                let int_info = unsafe {
                    vmread(Vmcs::InterruptionInformation)
                };
               
                // Convert the interrupt vector into an exception
                let mut exception: Exception = (int_info as u8).into();

                if let Exception::GeneralProtectionFault(ref mut info) =
                        exception {
                    *info = unsafe {
                        vmread(Vmcs::InterruptionErrorCode)
                    };
                }

                // If this exception was a page fault, store the faulting
                // address information.
                if let Exception::PageFault {
                    ref mut addr,
                    ref mut present,
                    ref mut write,
                    ref mut user,
                    ref mut exec,
                } = exception {
                    // Get the faulting address from the exit qualification
                    *addr = VirtAddr(unsafe {
                        vmread(Vmcs::ExitQualification)
                    });

                    // Get the error for the exception
                    let error = unsafe {
                        vmread(Vmcs::InterruptionErrorCode)
                    };

                    // Extract the access fault information from the fault
                    *present = (error & (1 << 0)) != 0;
                    *write   = (error & (1 << 1)) != 0;
                    *user    = (error & (1 << 2)) != 0;
                    *exec    = (error & (1 << 4)) != 0;
                }

                VmExit::Exception(exception)
            }
            1 => VmExit::ExternalInterrupt,
            16 => {
                let inst_len = unsafe {
                    vmread(Vmcs::VmExitInstructionLength)
                };
                VmExit::Rdtsc { inst_len }
            }
            28 => {
                // Control register access

                // Get the exit qualification
                let exit_qual = unsafe { vmread(Vmcs::ExitQualification) };
                let cr  = (exit_qual & 0xf) as u8;
                let typ = (exit_qual >> 4) & 3;
                let gpr = ((exit_qual >> 8) & 0xf) as u8;

                let inst_len = unsafe {
                    vmread(Vmcs::VmExitInstructionLength)
                };

                match typ {
                    0 => {
                        // Move to a control register
                        VmExit::WriteCr { cr, gpr, inst_len }
                    }
                    1 => {
                        // Move from a control register
                        VmExit::ReadCr { cr, gpr, inst_len }
                    }
                    _ => panic!("Unexpected read/write to control register"),
                }
            }
            31 => {
                // Read an MSR
                let inst_len = unsafe {
                    vmread(Vmcs::VmExitInstructionLength)
                };
                VmExit::ReadMsr { inst_len }
            }
            32 => {
                // Write an MSR
                let inst_len = unsafe {
                    vmread(Vmcs::VmExitInstructionLength)
                };
                VmExit::WriteMsr { inst_len }
            }
            48 => {
                // EPT violation
                
                // Get the exit qualification
                let exit_qual = unsafe { vmread(Vmcs::ExitQualification) };

                // Extract information about the type of EPT violation
                let read  = (exit_qual & (1 << 0)) != 0;
                let write = (exit_qual & (1 << 1)) != 0;
                let exec  = (exit_qual & (1 << 2)) != 0;

                unsafe {
                    VmExit::EptViolation {
                        addr: PhysAddr(vmread(Vmcs::GuestPhysicalAddress)),
                        read,
                        write,
                        exec,
                    }
                }
            }
            52 => VmExit::PreemptionTimer,
            62 => VmExit::PmlFull,
            x @ _ => unimplemented!("Unhandled VM exit code {} @ {:#x}\n",
                                    x, self.reg(Register::Rip)),
        };

        (vmexit, vm_cycles)
    }
}

