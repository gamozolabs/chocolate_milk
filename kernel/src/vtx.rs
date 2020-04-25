//! Intel VT-x extensions support
//!
//! To enable nested VT-x in KVM do the following:
//!
//! modprobe -r kvm_intel
//! modprobe kvm_intel nested=1

use core::mem::size_of;
use core::sync::atomic::Ordering;
use page_table::{VirtAddr, PageTable};
use crate::mm::{PhysicalMemory, PhysContig};
use crate::interrupts::Tss;

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
    HostSysenterCS = 0x4c00,

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
}

/// Floating point state from an `fxsave` instruction
#[derive(Debug, Clone, Copy)]
#[repr(C, align(16))]
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

/// General purpose register state
#[derive(Default, Debug, Clone, Copy)]
#[repr(C, align(16))]
pub struct RegisterState {
    pub rax: u64, 
    pub rbx: u64, 
    pub rcx: u64, 
    pub rdx: u64, 
    pub rsp: u64, 
    pub rbp: u64, 
    pub rsi: u64, 
    pub rdi: u64, 
    pub r8:  u64, 
    pub r9:  u64, 
    pub r10: u64, 
    pub r11: u64, 
    pub r12: u64, 
    pub r13: u64, 
    pub r14: u64, 
    pub r15: u64, 
    pub rip: u64, 
    pub rfl: u64,

    pub fxsave: FxSave,
}

/// An x86 exception
#[derive(Debug)]
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
    GeneralProtectionFault,
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
            13 => Exception::GeneralProtectionFault,
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
#[derive(Debug)]
pub enum VmExit {
    Exception(Exception),
    ExternalInterrupt,
}

/// A virtual machine using Intel VT-x extensions
pub struct Vm {
    /// The VMCS for this VM
    vmcs: PhysContig<[u8; 4096]>,

    /// Tracks if the VM controls and unchanging host and guest state has been
    /// initialized
    init: bool,

    /// Host registers
    host_regs: RegisterState,

    /// Page table for the guest virtual space
    pub page_table: PageTable,

    /// Guest registers
    pub guest_regs: RegisterState,

    /// Tracks if this VM is currently launched (thus, `vmresume` should be
    /// used)
    launched: bool,
}

impl Vm {
    /// Create a new virtual machine for running 64-bit ring-3 userland
    /// snapshots
    pub fn new_user() -> Vm {
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
        
        // Create a new empty page table for the 64-bit guest
        let mut pmem = PhysicalMemory;
        let page_table = PageTable::new_tracking(&mut pmem);

        Vm {
            vmcs: vmcs,
            init: false,
            host_regs:  RegisterState::default(),
            guest_regs: RegisterState::default(),
            launched:   false,
            page_table,
        }
    }

    /// Run the VM
    pub fn run(&mut self) -> VmExit {
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
                let pin_on  = (1 << 0) | (1 << 3);
                let pin_off = 0;

                // On entry we want:
                // Load debug controls (required on Skylake)
                // 64-bit guest
                let entry_on = (1 << 2) | (1 << 9);

                // On entry we don't want:
                // Load IA32_PERF_GLOBAL_CTRL
                // Load IA32_PAT
                // Load IA32_EFER
                // Load IA32_BNDCFGS
                // Load IA32_RTIT_CTL
                // Load CET state
                let entry_off = (1 << 13) | (1 << 14) |
                    (1 << 15) | (1 << 16) | (1 << 18) | (1 << 20);

                // On exit we want:
                // Host is 64-bit
                // Save debug controls
                let exit_on = (1 << 2) | (1 << 9);
                
                // On exit we don't want:
                // Load IA32_PERF_GLOBAL_CTRL
                // Save IA32_PAT
                // Load IA32_PAT
                // Save IA32_EFER
                // Load IA32_EFER
                // Clear IA32_BNDCFGS
                // Clear IA32_RTIT_CTL
                // Load CET state
                let exit_off = (1 << 12) | (1 << 18) | (1 << 19) |
                    (1 << 20) | (1 << 21) | (1 << 23) | (1 << 25) | (1 << 28);

                // Validate that desired bits can be what was desired
                {
                    let checks = &[
                        (entry_ctrl0, entry_ctrl1, entry_on, entry_off),
                        (exit_ctrl0, exit_ctrl1, exit_on, exit_off),
                        (pinbased_ctrl0, pinbased_ctrl1, pin_on, pin_off),
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
                vmwrite(Vmcs::ProcBasedControls,
                             procbased_minimum);
                vmwrite(Vmcs::ProcBasedControls2,
                             proc2based_minimum);
                vmwrite(Vmcs::ExitControls, 
                            exit_minimum | exit_on);
                vmwrite(Vmcs::EntryControls, 
                            entry_minimum | entry_on);

                // Exit on all exceptions
                vmwrite(Vmcs::ExceptionBitmap, !0);

                // Write in the host state which will not change per run

                // Set host selectors
                vmwrite(Vmcs::HostESSel, cpu::read_es() as u64);
                vmwrite(Vmcs::HostCSSel, cpu::read_cs() as u64);
                vmwrite(Vmcs::HostSSSel, cpu::read_ss() as u64);
                vmwrite(Vmcs::HostDSSel, cpu::read_ds() as u64);
                vmwrite(Vmcs::HostFSSel, cpu::read_fs() as u64);
                vmwrite(Vmcs::HostGSSel, cpu::read_gs() as u64);
                vmwrite(Vmcs::HostTRSel, cpu::read_tr() as u64);
                vmwrite(Vmcs::HostSysenterCS, 0);

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

                // Set up guest state

                vmwrite(Vmcs::GuestESSel,   0x33);
                vmwrite(Vmcs::GuestCSSel,   0x2f);
                vmwrite(Vmcs::GuestSSSel,   0x33);
                vmwrite(Vmcs::GuestDSSel,   0x33);
                vmwrite(Vmcs::GuestFSSel,   0x33);
                vmwrite(Vmcs::GuestGSSel,   0x33);
                vmwrite(Vmcs::GuestLDTRSel, 0);
                vmwrite(Vmcs::GuestTRSel,   0x38);
                
                vmwrite(Vmcs::GuestVmcsLinkPtr, !0);
                vmwrite(Vmcs::GuestIa32DebugControl, 0);

                vmwrite(Vmcs::GuestESLimit,   0);
                vmwrite(Vmcs::GuestCSLimit,   0);
                vmwrite(Vmcs::GuestSSLimit,   0);
                vmwrite(Vmcs::GuestDSLimit,   0);
                vmwrite(Vmcs::GuestFSLimit,   0);
                vmwrite(Vmcs::GuestGSLimit,   0);
                vmwrite(Vmcs::GuestLDTRLimit, 0);
                vmwrite(Vmcs::GuestTRLimit,   0);
                vmwrite(Vmcs::GuestGDTRLimit, 0);
                vmwrite(Vmcs::GuestIDTRLimit, 0);
                
                vmwrite(Vmcs::GuestESAccessRights,   0x000f3);
                vmwrite(Vmcs::GuestCSAccessRights,   0x020fb);
                vmwrite(Vmcs::GuestSSAccessRights,   0x000f3);
                vmwrite(Vmcs::GuestDSAccessRights,   0x000f3);
                vmwrite(Vmcs::GuestFSAccessRights,   0x000f3);
                vmwrite(Vmcs::GuestGSAccessRights,   0x000f3);
                vmwrite(Vmcs::GuestLDTRAccessRights, 0x10000);
                vmwrite(Vmcs::GuestTRAccessRights,   0x0008b);

                vmwrite(Vmcs::GuestInterruptabilityState, 0);
                vmwrite(Vmcs::GuestActivityState, 0);
                vmwrite(Vmcs::GuestSMBase, 0);
                vmwrite(Vmcs::GuestIa32SysenterCs, 0);

                vmwrite(Vmcs::GuestCr0, cpu::read_cr0());
                vmwrite(Vmcs::GuestCr3, self.page_table.table().0);
                vmwrite(Vmcs::GuestCr4, cpu::read_cr4());
                
                vmwrite(Vmcs::GuestESBase,   0);
                vmwrite(Vmcs::GuestCSBase,   0);
                vmwrite(Vmcs::GuestSSBase,   0);
                vmwrite(Vmcs::GuestDSBase,   0);
                vmwrite(Vmcs::GuestFSBase,   0);
                vmwrite(Vmcs::GuestGSBase,   0);
                vmwrite(Vmcs::GuestLDTRBase, 0);
                vmwrite(Vmcs::GuestTRBase,
                        &*interrupts.tss as *const Tss as u64);
                vmwrite(Vmcs::GuestGDTRBase, interrupts.gdt.as_ptr() as u64);
                vmwrite(Vmcs::GuestIDTRBase, interrupts.idt.as_ptr() as u64);
                
                vmwrite(Vmcs::GuestDr7, 0x400);

                vmwrite(Vmcs::GuestPendingDebugExceptions, 0);

                vmwrite(Vmcs::GuestIa32SysenterEsp, 0);
                vmwrite(Vmcs::GuestIa32SysenterEip, 0);
            }
            
            // We have initialized the VM
            self.init = true;
        }

        unsafe {
            vmwrite(Vmcs::GuestRsp, self.guest_regs.rsp);
            vmwrite(Vmcs::GuestRip, self.guest_regs.rip);

            // Set guest rflags. Make sure the reserved bit is set and
            // interrupts are always enabled
            vmwrite(Vmcs::GuestRflags,
                    self.guest_regs.rfl | (1 << 1) | (1 << 9));
        }

        unsafe {
            // Make sure the fxsave starts at `0x90` from the `guest_regs`
            assert!((&self.guest_regs.fxsave as *const _ as usize -
                     &self.guest_regs as *const _ as usize) == 0x90);

            // Sanity check our `FxSave` structure shape
            assert!(core::mem::size_of::<FxSave>() == 512,
                "Whoa, fxsave broken");
        
            core!().disable_interrupts();

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
                fxsave64 [rcx + 0x90]

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
                fxrstor64 [rdx + 0x90]

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
                fxsave64 [rdx + 0x90]

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
                fxrstor64 [rcx + 0x90]

            "# ::
            "{rcx}"(&mut self.host_regs),
            "{rdx}"(&mut self.guest_regs),
            "{edi}"(self.launched as u32) :
            "memory", "rax", "rbx" : "intel", "volatile");
        
            core!().enable_interrupts();
        }

        // Mark that this VM has launched
        self.launched = true;
        
        // Restore VM guest state into our Rust-usable guest state structure
        unsafe {
            self.guest_regs.rsp = vmread(Vmcs::GuestRsp);
            self.guest_regs.rip = vmread(Vmcs::GuestRip);
            self.guest_regs.rfl = vmread(Vmcs::GuestRflags);
        }

        // Parse the VM exit information
        let vmexit = match unsafe { vmread(Vmcs::ExitReason) } {
            0 => {
                // Exception or NMI
                let int_info = unsafe {
                    vmread(Vmcs::InterruptionInformation)
                };
               
                // Convert the interrupt vector into an exception
                let mut exception: Exception = (int_info as u8).into();

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
            x @ _ => unimplemented!("Unhandled VM exit code {}\n", x),
        };

        vmexit
    }
}

