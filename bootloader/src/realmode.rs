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
    pub fn invoke_realmode(int_number: u8, regs: *mut RegisterState);
    pub fn pxecall(seg: u16, off: u16, pxe_call: u16,
                   param_seg: u16, param_off: u16);
}

