//! Routines and structures to perform 16-bit calls from this 32-bit bootloader

/// All general-purpose registers for 32-bit x86
#[derive(Default, Debug)]
#[repr(C)]
pub struct RegisterState {
    pub eax: u32,
    pub ecx: u32,
    pub edx: u32,
    pub ebx: u32,
    pub esp: u32,
    pub ebp: u32,
    pub esi: u32,
    pub edi: u32,
    pub efl: u32,
    pub es:  u16,
    pub ds:  u16,
    pub fs:  u16,
    pub gs:  u16,
    pub ss:  u16,
}

extern {
    /// Invokes a real mode software interrupt `int_number` with a given
    /// register state
    ///
    /// The register state is swapped into the registers before the software
    /// interrupt. After the software interrupt completes the register state
    /// will be saved back into `regs` such that the results of the real mode
    /// interrupt can be observed.
    pub fn invoke_realmode(int_number: u8, regs: *mut RegisterState);

    /// Invokes a PXE handler using the calling conventions that PXE uses
    ///
    /// Takes a `seg:off` to the PXE 16-bit API (provided in the !PXE
    /// structure), performs a PXE opcode call `pxe_call`, and provides a
    /// pointer to a parameter at `param_seg:param_off`
    pub fn pxecall(seg: u16, off: u16, pxe_call: u16,
                   param_seg: u16, param_off: u16);
}

