use core::mem::ManuallyDrop;
use alloc::vec::Vec;
use alloc::boxed::Box;

/// Type for an interrupt gate for 64-bit mode
const X64_INTERRUPT_GATE: u32 = 0xe;

/// Descriptor pointer used to load with `lidt` and `lgdt`
#[repr(C, packed)]
struct TablePtr(u16, u64);

/// A 64-bit TSS data structure
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct Tss {
	reserved1:   u32,
	rsp:         [u64; 3],
	reserved2:   u64,
	ist:         [u64; 7],
	reserved3:   u64,
	reserved4:   u16,
	iopb_offset: u16,
}

/// A raw IDT entry, which is valid when placed in an IDT in this 
/// representation
#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct IDTEntry(u32, u32, u32, u32);

impl IDTEntry {
    /// Construct a new in-memory representation of an IDT entry. This will
    /// take the `cs:offset` to the handler address, the `ist` for the
    /// interrupt stack table index, the `typ` of the IDT gate entry and the
    /// `dpl` of the IDT entry.
    fn new(cs: u16, offset: u64, ist: u32, typ: u32, dpl: u32) -> Self {
        assert!(ist <  8, "Invalid IDTEntry IST");
        assert!(typ < 32, "Invalid IDTEntry type");
        assert!(dpl <  4, "Invalid IDTEntry dpl");

        IDTEntry(
            ((cs as u32) << 16) | (offset & 0xffff) as u32,
            ((offset & 0xffff0000) as u32) | (1 << 15) |
                (dpl << 13) | (typ << 8) | ist,
            (offset >> 32) as u32,
            0,
        )
    }
}

/// Switch to a kernel-based GDT, load a TSS with a critical stack for
/// #DF, #MC, and NMI interrupts. Then set up a IDT with all interrupts passing
/// through to the `interrupt_handler` Rust function.
pub unsafe fn init() {
    // Create a new, empty TSS
	let mut tss: ManuallyDrop<Box<Tss>> =
        ManuallyDrop::new(Box::new(Tss::default()));

    // Create a 32 KiB critical stack for use during #DF, #MC, and NMI
    let crit_stack: ManuallyDrop<Vec<u8>> = ManuallyDrop::new(
        Vec::with_capacity(32 * 1024));
    tss.ist[0] = crit_stack.as_ptr() as u64 + crit_stack.capacity() as u64;
    
    // Create GDT in the kernel context
    let mut gdt: ManuallyDrop<Vec<u64>> = ManuallyDrop::new(vec![
	    0x0000000000000000, // 0x0000 | Null descriptor
	    0x00009a007c00ffff, // 0x0008 | 16-bit, present, code, base 0x7c00
	    0x000092000000ffff, // 0x0010 | 16-bit, present, data, base 0
	    0x00cf9a000000ffff, // 0x0018 | 32-bit, present, code, base 0
	    0x00cf92000000ffff, // 0x0020 | 32-bit, present, data, base 0
	    0x00209a0000000000, // 0x0028 | 64-bit, present, code, base 0
	    0x0000920000000000, // 0x0030 | 64-bit, present, data, base 0
    ]);

    // Create the task pointer in the GDT
    let tss_base = &**tss as *const Tss as u64;
    let tss_low = 0x890000000000 | (((tss_base >> 24) & 0xff) << 56) |
        ((tss_base & 0xffffff) << 16) |
        (core::mem::size_of::<Tss>() as u64 - 1);
    let tss_high = tss_base >> 32;

    // Add the TSS entry into the GDT
    gdt.push(tss_low);
    gdt.push(tss_high);

    // Create the pointer to the GDT for `lgdt` to load
    let gdt_ptr = TablePtr(
        core::mem::size_of_val(&gdt[..]) as u16 - 1,
        gdt.as_ptr() as u64,
    );

    // Update to use a GDT in the current virtual space
    asm!(r#"
            // Load the GDT
            lgdt [$0]

            // Load the TSS
            mov cx, 0x38
            ltr cx
    "# :: "r"(&gdt_ptr as *const TablePtr) : "memory", "rcx" :
        "volatile", "intel");
    
    // Create a new IDT
    let mut idt = ManuallyDrop::new(Vec::with_capacity(256));

    for int_id in 0..256 {
        // Determine the IST entry to use for this vector
        let ist = match int_id {
            2 | 8 | 18 => {
                // NMI, #DF, #MC use the IST
                1
            }

            // Just use the existing stack
            _ => 0,
        };

        idt.push(IDTEntry::new(0x28, INT_HANDLERS[int_id] as u64,
                               ist, X64_INTERRUPT_GATE, 0));
    }

    // Make sure the entire IDT is present, as we never have a partial IDT in
    // this implementation.
    assert!(core::mem::size_of_val(&idt[..]) == 4096);
    
    // The IDT pointer which has the (limit, address of IDT)
    let idt_ptr = TablePtr(0xfff, idt.as_ptr() as u64);
  
    // Load the IDT!
    asm!("lidt [$0]" :: "r"(&idt_ptr as *const TablePtr) :
         "memory" : "volatile", "intel");
}

/// Shape of a raw 64-bit interrupt frame
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct InterruptFrame {
	pub rip:    usize,
	pub cs:     usize,
	pub rflags: usize,
	pub rsp:    usize,
	pub ss:     usize,
}

/// Structure containing all registers at the state of the interrupt
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct AllRegs {
    pub xmm15: u128,
    pub xmm14: u128,
    pub xmm13: u128,
    pub xmm12: u128,
    pub xmm11: u128,
    pub xmm10: u128,
    pub xmm9:  u128,
    pub xmm8:  u128,
    pub xmm7:  u128,
    pub xmm6:  u128,
    pub xmm5:  u128,
    pub xmm4:  u128,
    pub xmm3:  u128,
    pub xmm2:  u128,
    pub xmm1:  u128,
    pub xmm0:  u128,

    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9:  u64,
    pub r8:  u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
}

/// Entry point for all interrupts and exceptions
#[no_mangle]
pub unsafe extern fn interrupt_handler(
        number: usize, frame: &mut InterruptFrame, error: usize,
        regs: &mut AllRegs) {
    print!(
r#"Interrupt {:#x}, error code {:#x}
Registers at exception:
    rax {:016x} rcx {:016x} rdx {:016x} rbx {:016x}
    rsp {:016x} rbp {:016x} rsi {:016x} rdi {:016x}
    r8  {:016x} r9  {:016x} r10 {:016x} r11 {:016x}
    r12 {:016x} r13 {:016x} r14 {:016x} r15 {:016x}
    rfl {:016x}
    rip {:016x}

    xmm0  {:032x}
    xmm1  {:032x}
    xmm2  {:032x}
    xmm3  {:032x}
    xmm4  {:032x}
    xmm5  {:032x}
    xmm6  {:032x}
    xmm7  {:032x}
    xmm8  {:032x}
    xmm9  {:032x}
    xmm10 {:032x}
    xmm11 {:032x}
    xmm12 {:032x}
    xmm13 {:032x}
    xmm14 {:032x}
    xmm15 {:032x}
"#,
        number, error,

        regs.rax,  regs.rcx, regs.rdx, regs.rbx,
        frame.rsp, regs.rbp, regs.rsi, regs.rdi,
        regs.r8,   regs.r9,  regs.r10, regs.r11,
        regs.r12,  regs.r13, regs.r14, regs.r15,
        frame.rflags,
        frame.rip,

        regs.xmm0,  regs.xmm1,  regs.xmm2,  regs.xmm3,
        regs.xmm4,  regs.xmm5,  regs.xmm6,  regs.xmm7,
        regs.xmm8,  regs.xmm9,  regs.xmm10, regs.xmm11,
        regs.xmm12, regs.xmm13, regs.xmm14, regs.xmm15);
    
    panic!("Fatal exception");
}

const INT_HANDLERS: [unsafe extern fn(); 256] = [
    vec_interrupt_0,  vec_interrupt_1,  vec_interrupt_2,
    vec_interrupt_3,  vec_interrupt_4,  vec_interrupt_5,
    vec_interrupt_6,  vec_interrupt_7,  vec_interrupt_8,
    vec_interrupt_9,  vec_interrupt_10,  vec_interrupt_11,
    vec_interrupt_12,  vec_interrupt_13,  vec_interrupt_14,
    vec_interrupt_15,  vec_interrupt_16,  vec_interrupt_17,
    vec_interrupt_18,  vec_interrupt_19,  vec_interrupt_20,
    vec_interrupt_21,  vec_interrupt_22,  vec_interrupt_23,
    vec_interrupt_24,  vec_interrupt_25,  vec_interrupt_26,
    vec_interrupt_27,  vec_interrupt_28,  vec_interrupt_29,
    vec_interrupt_30,  vec_interrupt_31,  vec_interrupt_32,
    vec_interrupt_33,  vec_interrupt_34,  vec_interrupt_35,
    vec_interrupt_36,  vec_interrupt_37,  vec_interrupt_38,
    vec_interrupt_39,  vec_interrupt_40,  vec_interrupt_41,
    vec_interrupt_42,  vec_interrupt_43,  vec_interrupt_44,
    vec_interrupt_45,  vec_interrupt_46,  vec_interrupt_47,
    vec_interrupt_48,  vec_interrupt_49,  vec_interrupt_50,
    vec_interrupt_51,  vec_interrupt_52,  vec_interrupt_53,
    vec_interrupt_54,  vec_interrupt_55,  vec_interrupt_56,
    vec_interrupt_57,  vec_interrupt_58,  vec_interrupt_59,
    vec_interrupt_60,  vec_interrupt_61,  vec_interrupt_62,
    vec_interrupt_63,  vec_interrupt_64,  vec_interrupt_65,
    vec_interrupt_66,  vec_interrupt_67,  vec_interrupt_68,
    vec_interrupt_69,  vec_interrupt_70,  vec_interrupt_71,
    vec_interrupt_72,  vec_interrupt_73,  vec_interrupt_74,
    vec_interrupt_75,  vec_interrupt_76,  vec_interrupt_77,
    vec_interrupt_78,  vec_interrupt_79,  vec_interrupt_80,
    vec_interrupt_81,  vec_interrupt_82,  vec_interrupt_83,
    vec_interrupt_84,  vec_interrupt_85,  vec_interrupt_86,
    vec_interrupt_87,  vec_interrupt_88,  vec_interrupt_89,
    vec_interrupt_90,  vec_interrupt_91,  vec_interrupt_92,
    vec_interrupt_93,  vec_interrupt_94,  vec_interrupt_95,
    vec_interrupt_96,  vec_interrupt_97,  vec_interrupt_98,
    vec_interrupt_99,  vec_interrupt_100,  vec_interrupt_101,
    vec_interrupt_102,  vec_interrupt_103,  vec_interrupt_104,
    vec_interrupt_105,  vec_interrupt_106,  vec_interrupt_107,
    vec_interrupt_108,  vec_interrupt_109,  vec_interrupt_110,
    vec_interrupt_111,  vec_interrupt_112,  vec_interrupt_113,
    vec_interrupt_114,  vec_interrupt_115,  vec_interrupt_116,
    vec_interrupt_117,  vec_interrupt_118,  vec_interrupt_119,
    vec_interrupt_120,  vec_interrupt_121,  vec_interrupt_122,
    vec_interrupt_123,  vec_interrupt_124,  vec_interrupt_125,
    vec_interrupt_126,  vec_interrupt_127,  vec_interrupt_128,
    vec_interrupt_129,  vec_interrupt_130,  vec_interrupt_131,
    vec_interrupt_132,  vec_interrupt_133,  vec_interrupt_134,
    vec_interrupt_135,  vec_interrupt_136,  vec_interrupt_137,
    vec_interrupt_138,  vec_interrupt_139,  vec_interrupt_140,
    vec_interrupt_141,  vec_interrupt_142,  vec_interrupt_143,
    vec_interrupt_144,  vec_interrupt_145,  vec_interrupt_146,
    vec_interrupt_147,  vec_interrupt_148,  vec_interrupt_149,
    vec_interrupt_150,  vec_interrupt_151,  vec_interrupt_152,
    vec_interrupt_153,  vec_interrupt_154,  vec_interrupt_155,
    vec_interrupt_156,  vec_interrupt_157,  vec_interrupt_158,
    vec_interrupt_159,  vec_interrupt_160,  vec_interrupt_161,
    vec_interrupt_162,  vec_interrupt_163,  vec_interrupt_164,
    vec_interrupt_165,  vec_interrupt_166,  vec_interrupt_167,
    vec_interrupt_168,  vec_interrupt_169,  vec_interrupt_170,
    vec_interrupt_171,  vec_interrupt_172,  vec_interrupt_173,
    vec_interrupt_174,  vec_interrupt_175,  vec_interrupt_176,
    vec_interrupt_177,  vec_interrupt_178,  vec_interrupt_179,
    vec_interrupt_180,  vec_interrupt_181,  vec_interrupt_182,
    vec_interrupt_183,  vec_interrupt_184,  vec_interrupt_185,
    vec_interrupt_186,  vec_interrupt_187,  vec_interrupt_188,
    vec_interrupt_189,  vec_interrupt_190,  vec_interrupt_191,
    vec_interrupt_192,  vec_interrupt_193,  vec_interrupt_194,
    vec_interrupt_195,  vec_interrupt_196,  vec_interrupt_197,
    vec_interrupt_198,  vec_interrupt_199,  vec_interrupt_200,
    vec_interrupt_201,  vec_interrupt_202,  vec_interrupt_203,
    vec_interrupt_204,  vec_interrupt_205,  vec_interrupt_206,
    vec_interrupt_207,  vec_interrupt_208,  vec_interrupt_209,
    vec_interrupt_210,  vec_interrupt_211,  vec_interrupt_212,
    vec_interrupt_213,  vec_interrupt_214,  vec_interrupt_215,
    vec_interrupt_216,  vec_interrupt_217,  vec_interrupt_218,
    vec_interrupt_219,  vec_interrupt_220,  vec_interrupt_221,
    vec_interrupt_222,  vec_interrupt_223,  vec_interrupt_224,
    vec_interrupt_225,  vec_interrupt_226,  vec_interrupt_227,
    vec_interrupt_228,  vec_interrupt_229,  vec_interrupt_230,
    vec_interrupt_231,  vec_interrupt_232,  vec_interrupt_233,
    vec_interrupt_234,  vec_interrupt_235,  vec_interrupt_236,
    vec_interrupt_237,  vec_interrupt_238,  vec_interrupt_239,
    vec_interrupt_240,  vec_interrupt_241,  vec_interrupt_242,
    vec_interrupt_243,  vec_interrupt_244,  vec_interrupt_245,
    vec_interrupt_246,  vec_interrupt_247,  vec_interrupt_248,
    vec_interrupt_249,  vec_interrupt_250,  vec_interrupt_251,
    vec_interrupt_252,  vec_interrupt_253,  vec_interrupt_254,
    vec_interrupt_255,
];

extern {
	fn vec_interrupt_0();
	fn vec_interrupt_1();
	fn vec_interrupt_2();
	fn vec_interrupt_3();
	fn vec_interrupt_4();
	fn vec_interrupt_5();
	fn vec_interrupt_6();
	fn vec_interrupt_7();
	fn vec_interrupt_8();
	fn vec_interrupt_9();
	fn vec_interrupt_10();
	fn vec_interrupt_11();
	fn vec_interrupt_12();
	fn vec_interrupt_13();
	fn vec_interrupt_14();
	fn vec_interrupt_15();
	fn vec_interrupt_16();
	fn vec_interrupt_17();
	fn vec_interrupt_18();
	fn vec_interrupt_19();
	fn vec_interrupt_20();
	fn vec_interrupt_21();
	fn vec_interrupt_22();
	fn vec_interrupt_23();
	fn vec_interrupt_24();
	fn vec_interrupt_25();
	fn vec_interrupt_26();
	fn vec_interrupt_27();
	fn vec_interrupt_28();
	fn vec_interrupt_29();
	fn vec_interrupt_30();
	fn vec_interrupt_31();
	fn vec_interrupt_32();
	fn vec_interrupt_33();
	fn vec_interrupt_34();
	fn vec_interrupt_35();
	fn vec_interrupt_36();
	fn vec_interrupt_37();
	fn vec_interrupt_38();
	fn vec_interrupt_39();
	fn vec_interrupt_40();
	fn vec_interrupt_41();
	fn vec_interrupt_42();
	fn vec_interrupt_43();
	fn vec_interrupt_44();
	fn vec_interrupt_45();
	fn vec_interrupt_46();
	fn vec_interrupt_47();
	fn vec_interrupt_48();
	fn vec_interrupt_49();
	fn vec_interrupt_50();
	fn vec_interrupt_51();
	fn vec_interrupt_52();
	fn vec_interrupt_53();
	fn vec_interrupt_54();
	fn vec_interrupt_55();
	fn vec_interrupt_56();
	fn vec_interrupt_57();
	fn vec_interrupt_58();
	fn vec_interrupt_59();
	fn vec_interrupt_60();
	fn vec_interrupt_61();
	fn vec_interrupt_62();
	fn vec_interrupt_63();
	fn vec_interrupt_64();
	fn vec_interrupt_65();
	fn vec_interrupt_66();
	fn vec_interrupt_67();
	fn vec_interrupt_68();
	fn vec_interrupt_69();
	fn vec_interrupt_70();
	fn vec_interrupt_71();
	fn vec_interrupt_72();
	fn vec_interrupt_73();
	fn vec_interrupt_74();
	fn vec_interrupt_75();
	fn vec_interrupt_76();
	fn vec_interrupt_77();
	fn vec_interrupt_78();
	fn vec_interrupt_79();
	fn vec_interrupt_80();
	fn vec_interrupt_81();
	fn vec_interrupt_82();
	fn vec_interrupt_83();
	fn vec_interrupt_84();
	fn vec_interrupt_85();
	fn vec_interrupt_86();
	fn vec_interrupt_87();
	fn vec_interrupt_88();
	fn vec_interrupt_89();
	fn vec_interrupt_90();
	fn vec_interrupt_91();
	fn vec_interrupt_92();
	fn vec_interrupt_93();
	fn vec_interrupt_94();
	fn vec_interrupt_95();
	fn vec_interrupt_96();
	fn vec_interrupt_97();
	fn vec_interrupt_98();
	fn vec_interrupt_99();
	fn vec_interrupt_100();
	fn vec_interrupt_101();
	fn vec_interrupt_102();
	fn vec_interrupt_103();
	fn vec_interrupt_104();
	fn vec_interrupt_105();
	fn vec_interrupt_106();
	fn vec_interrupt_107();
	fn vec_interrupt_108();
	fn vec_interrupt_109();
	fn vec_interrupt_110();
	fn vec_interrupt_111();
	fn vec_interrupt_112();
	fn vec_interrupt_113();
	fn vec_interrupt_114();
	fn vec_interrupt_115();
	fn vec_interrupt_116();
	fn vec_interrupt_117();
	fn vec_interrupt_118();
	fn vec_interrupt_119();
	fn vec_interrupt_120();
	fn vec_interrupt_121();
	fn vec_interrupt_122();
	fn vec_interrupt_123();
	fn vec_interrupt_124();
	fn vec_interrupt_125();
	fn vec_interrupt_126();
	fn vec_interrupt_127();
	fn vec_interrupt_128();
	fn vec_interrupt_129();
	fn vec_interrupt_130();
	fn vec_interrupt_131();
	fn vec_interrupt_132();
	fn vec_interrupt_133();
	fn vec_interrupt_134();
	fn vec_interrupt_135();
	fn vec_interrupt_136();
	fn vec_interrupt_137();
	fn vec_interrupt_138();
	fn vec_interrupt_139();
	fn vec_interrupt_140();
	fn vec_interrupt_141();
	fn vec_interrupt_142();
	fn vec_interrupt_143();
	fn vec_interrupt_144();
	fn vec_interrupt_145();
	fn vec_interrupt_146();
	fn vec_interrupt_147();
	fn vec_interrupt_148();
	fn vec_interrupt_149();
	fn vec_interrupt_150();
	fn vec_interrupt_151();
	fn vec_interrupt_152();
	fn vec_interrupt_153();
	fn vec_interrupt_154();
	fn vec_interrupt_155();
	fn vec_interrupt_156();
	fn vec_interrupt_157();
	fn vec_interrupt_158();
	fn vec_interrupt_159();
	fn vec_interrupt_160();
	fn vec_interrupt_161();
	fn vec_interrupt_162();
	fn vec_interrupt_163();
	fn vec_interrupt_164();
	fn vec_interrupt_165();
	fn vec_interrupt_166();
	fn vec_interrupt_167();
	fn vec_interrupt_168();
	fn vec_interrupt_169();
	fn vec_interrupt_170();
	fn vec_interrupt_171();
	fn vec_interrupt_172();
	fn vec_interrupt_173();
	fn vec_interrupt_174();
	fn vec_interrupt_175();
	fn vec_interrupt_176();
	fn vec_interrupt_177();
	fn vec_interrupt_178();
	fn vec_interrupt_179();
	fn vec_interrupt_180();
	fn vec_interrupt_181();
	fn vec_interrupt_182();
	fn vec_interrupt_183();
	fn vec_interrupt_184();
	fn vec_interrupt_185();
	fn vec_interrupt_186();
	fn vec_interrupt_187();
	fn vec_interrupt_188();
	fn vec_interrupt_189();
	fn vec_interrupt_190();
	fn vec_interrupt_191();
	fn vec_interrupt_192();
	fn vec_interrupt_193();
	fn vec_interrupt_194();
	fn vec_interrupt_195();
	fn vec_interrupt_196();
	fn vec_interrupt_197();
	fn vec_interrupt_198();
	fn vec_interrupt_199();
	fn vec_interrupt_200();
	fn vec_interrupt_201();
	fn vec_interrupt_202();
	fn vec_interrupt_203();
	fn vec_interrupt_204();
	fn vec_interrupt_205();
	fn vec_interrupt_206();
	fn vec_interrupt_207();
	fn vec_interrupt_208();
	fn vec_interrupt_209();
	fn vec_interrupt_210();
	fn vec_interrupt_211();
	fn vec_interrupt_212();
	fn vec_interrupt_213();
	fn vec_interrupt_214();
	fn vec_interrupt_215();
	fn vec_interrupt_216();
	fn vec_interrupt_217();
	fn vec_interrupt_218();
	fn vec_interrupt_219();
	fn vec_interrupt_220();
	fn vec_interrupt_221();
	fn vec_interrupt_222();
	fn vec_interrupt_223();
	fn vec_interrupt_224();
	fn vec_interrupt_225();
	fn vec_interrupt_226();
	fn vec_interrupt_227();
	fn vec_interrupt_228();
	fn vec_interrupt_229();
	fn vec_interrupt_230();
	fn vec_interrupt_231();
	fn vec_interrupt_232();
	fn vec_interrupt_233();
	fn vec_interrupt_234();
	fn vec_interrupt_235();
	fn vec_interrupt_236();
	fn vec_interrupt_237();
	fn vec_interrupt_238();
	fn vec_interrupt_239();
	fn vec_interrupt_240();
	fn vec_interrupt_241();
	fn vec_interrupt_242();
	fn vec_interrupt_243();
	fn vec_interrupt_244();
	fn vec_interrupt_245();
	fn vec_interrupt_246();
	fn vec_interrupt_247();
	fn vec_interrupt_248();
	fn vec_interrupt_249();
	fn vec_interrupt_250();
	fn vec_interrupt_251();
	fn vec_interrupt_252();
	fn vec_interrupt_253();
	fn vec_interrupt_254();
	fn vec_interrupt_255();
}

global_asm!(r#"
.intel_syntax

.macro XMMPUSH reg
    sub    rsp, 16
    movdqu [rsp], \reg
.endm

.macro XMMPOP reg
    movdqu \reg, [rsp]
    add    rsp, 16
.endm

.extern interrupt_handler

enter_rust:
	push rax
	push rbx
	push qword ptr [r15 + 0x10]
	push qword ptr [r15 + 0x08]
	push rsi
	push rdi
	push rbp
	push qword ptr [r15 + 0x00]
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push qword ptr [r15 + 0x18]

    XMMPUSH xmm0
    XMMPUSH xmm1
    XMMPUSH xmm2
    XMMPUSH xmm3
    XMMPUSH xmm4
    XMMPUSH xmm5
    XMMPUSH xmm6
    XMMPUSH xmm7
    XMMPUSH xmm8
    XMMPUSH xmm9
    XMMPUSH xmm10
    XMMPUSH xmm11
    XMMPUSH xmm12
    XMMPUSH xmm13
    XMMPUSH xmm14
    XMMPUSH xmm15

    // Save the current stack pointer for the 4th argument
    mov  r9, rsp

    // Save the stack, allocate register homing space, and align the stack
    mov  rbp, rsp
    sub  rsp, 0x20
    and  rsp, ~0xf

	// Call the rust interrupt handler
	call interrupt_handler

    // Restore the stack
    mov rsp, rbp

    XMMPOP xmm15
    XMMPOP xmm14
    XMMPOP xmm13
    XMMPOP xmm12
    XMMPOP xmm11
    XMMPOP xmm10
    XMMPOP xmm9
    XMMPOP xmm8
    XMMPOP xmm7
    XMMPOP xmm6
    XMMPOP xmm5
    XMMPOP xmm4
    XMMPOP xmm3
    XMMPOP xmm2
    XMMPOP xmm1
    XMMPOP xmm0

	pop qword ptr [r15 + 0x18]
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop qword ptr [r15 + 0x00]
	pop rbp
	pop rdi
	pop rsi
	pop qword ptr [r15 + 0x08]
	pop qword ptr [r15 + 0x10]
	pop rbx
	pop rax
	ret

.macro define_int_handler int_id, has_error_code
.global vec_interrupt_\int_id
vec_interrupt_\int_id:
    push r15
	push rcx
	push rdx
	push r8

    // Save off our "special" frame registers
    mov r15, rsp

.if \has_error_code
	mov  ecx, \int_id
	lea  rdx, [rsp+0x28]
	mov  r8,  [rsp+0x20]
	
	// 16-byte align the stack
	sub rsp, 8
.else
	mov ecx, \int_id
	lea rdx, [rsp+0x20]
	mov r8,  0
.endif

	call enter_rust
	
.if \has_error_code
	// Remove alignment from before
	add rsp, 8
.endif

	pop r8
	pop rdx
	pop rcx
    pop r15

.if \has_error_code
	// 'pop' off the error code
	add rsp, 8
.endif

	iretq
.endm

define_int_handler 0, 0
define_int_handler 1, 0
define_int_handler 2, 0
define_int_handler 3, 0
define_int_handler 4, 0
define_int_handler 5, 0
define_int_handler 6, 0
define_int_handler 7, 0
define_int_handler 8, 1
define_int_handler 9, 0
define_int_handler 10, 1
define_int_handler 11, 1
define_int_handler 12, 1
define_int_handler 13, 1
define_int_handler 14, 1
define_int_handler 15, 0
define_int_handler 16, 0
define_int_handler 17, 1
define_int_handler 18, 0
define_int_handler 19, 0
define_int_handler 20, 0
define_int_handler 21, 0
define_int_handler 22, 0
define_int_handler 23, 0
define_int_handler 24, 0
define_int_handler 25, 0
define_int_handler 26, 0
define_int_handler 27, 0
define_int_handler 28, 0
define_int_handler 29, 0
define_int_handler 30, 0
define_int_handler 31, 0
define_int_handler 32, 0
define_int_handler 33, 0
define_int_handler 34, 0
define_int_handler 35, 0
define_int_handler 36, 0
define_int_handler 37, 0
define_int_handler 38, 0
define_int_handler 39, 0
define_int_handler 40, 0
define_int_handler 41, 0
define_int_handler 42, 0
define_int_handler 43, 0
define_int_handler 44, 0
define_int_handler 45, 0
define_int_handler 46, 0
define_int_handler 47, 0
define_int_handler 48, 0
define_int_handler 49, 0
define_int_handler 50, 0
define_int_handler 51, 0
define_int_handler 52, 0
define_int_handler 53, 0
define_int_handler 54, 0
define_int_handler 55, 0
define_int_handler 56, 0
define_int_handler 57, 0
define_int_handler 58, 0
define_int_handler 59, 0
define_int_handler 60, 0
define_int_handler 61, 0
define_int_handler 62, 0
define_int_handler 63, 0
define_int_handler 64, 0
define_int_handler 65, 0
define_int_handler 66, 0
define_int_handler 67, 0
define_int_handler 68, 0
define_int_handler 69, 0
define_int_handler 70, 0
define_int_handler 71, 0
define_int_handler 72, 0
define_int_handler 73, 0
define_int_handler 74, 0
define_int_handler 75, 0
define_int_handler 76, 0
define_int_handler 77, 0
define_int_handler 78, 0
define_int_handler 79, 0
define_int_handler 80, 0
define_int_handler 81, 0
define_int_handler 82, 0
define_int_handler 83, 0
define_int_handler 84, 0
define_int_handler 85, 0
define_int_handler 86, 0
define_int_handler 87, 0
define_int_handler 88, 0
define_int_handler 89, 0
define_int_handler 90, 0
define_int_handler 91, 0
define_int_handler 92, 0
define_int_handler 93, 0
define_int_handler 94, 0
define_int_handler 95, 0
define_int_handler 96, 0
define_int_handler 97, 0
define_int_handler 98, 0
define_int_handler 99, 0
define_int_handler 100, 0
define_int_handler 101, 0
define_int_handler 102, 0
define_int_handler 103, 0
define_int_handler 104, 0
define_int_handler 105, 0
define_int_handler 106, 0
define_int_handler 107, 0
define_int_handler 108, 0
define_int_handler 109, 0
define_int_handler 110, 0
define_int_handler 111, 0
define_int_handler 112, 0
define_int_handler 113, 0
define_int_handler 114, 0
define_int_handler 115, 0
define_int_handler 116, 0
define_int_handler 117, 0
define_int_handler 118, 0
define_int_handler 119, 0
define_int_handler 120, 0
define_int_handler 121, 0
define_int_handler 122, 0
define_int_handler 123, 0
define_int_handler 124, 0
define_int_handler 125, 0
define_int_handler 126, 0
define_int_handler 127, 0
define_int_handler 128, 0
define_int_handler 129, 0
define_int_handler 130, 0
define_int_handler 131, 0
define_int_handler 132, 0
define_int_handler 133, 0
define_int_handler 134, 0
define_int_handler 135, 0
define_int_handler 136, 0
define_int_handler 137, 0
define_int_handler 138, 0
define_int_handler 139, 0
define_int_handler 140, 0
define_int_handler 141, 0
define_int_handler 142, 0
define_int_handler 143, 0
define_int_handler 144, 0
define_int_handler 145, 0
define_int_handler 146, 0
define_int_handler 147, 0
define_int_handler 148, 0
define_int_handler 149, 0
define_int_handler 150, 0
define_int_handler 151, 0
define_int_handler 152, 0
define_int_handler 153, 0
define_int_handler 154, 0
define_int_handler 155, 0
define_int_handler 156, 0
define_int_handler 157, 0
define_int_handler 158, 0
define_int_handler 159, 0
define_int_handler 160, 0
define_int_handler 161, 0
define_int_handler 162, 0
define_int_handler 163, 0
define_int_handler 164, 0
define_int_handler 165, 0
define_int_handler 166, 0
define_int_handler 167, 0
define_int_handler 168, 0
define_int_handler 169, 0
define_int_handler 170, 0
define_int_handler 171, 0
define_int_handler 172, 0
define_int_handler 173, 0
define_int_handler 174, 0
define_int_handler 175, 0
define_int_handler 176, 0
define_int_handler 177, 0
define_int_handler 178, 0
define_int_handler 179, 0
define_int_handler 180, 0
define_int_handler 181, 0
define_int_handler 182, 0
define_int_handler 183, 0
define_int_handler 184, 0
define_int_handler 185, 0
define_int_handler 186, 0
define_int_handler 187, 0
define_int_handler 188, 0
define_int_handler 189, 0
define_int_handler 190, 0
define_int_handler 191, 0
define_int_handler 192, 0
define_int_handler 193, 0
define_int_handler 194, 0
define_int_handler 195, 0
define_int_handler 196, 0
define_int_handler 197, 0
define_int_handler 198, 0
define_int_handler 199, 0
define_int_handler 200, 0
define_int_handler 201, 0
define_int_handler 202, 0
define_int_handler 203, 0
define_int_handler 204, 0
define_int_handler 205, 0
define_int_handler 206, 0
define_int_handler 207, 0
define_int_handler 208, 0
define_int_handler 209, 0
define_int_handler 210, 0
define_int_handler 211, 0
define_int_handler 212, 0
define_int_handler 213, 0
define_int_handler 214, 0
define_int_handler 215, 0
define_int_handler 216, 0
define_int_handler 217, 0
define_int_handler 218, 0
define_int_handler 219, 0
define_int_handler 220, 0
define_int_handler 221, 0
define_int_handler 222, 0
define_int_handler 223, 0
define_int_handler 224, 0
define_int_handler 225, 0
define_int_handler 226, 0
define_int_handler 227, 0
define_int_handler 228, 0
define_int_handler 229, 0
define_int_handler 230, 0
define_int_handler 231, 0
define_int_handler 232, 0
define_int_handler 233, 0
define_int_handler 234, 0
define_int_handler 235, 0
define_int_handler 236, 0
define_int_handler 237, 0
define_int_handler 238, 0
define_int_handler 239, 0
define_int_handler 240, 0
define_int_handler 241, 0
define_int_handler 242, 0
define_int_handler 243, 0
define_int_handler 244, 0
define_int_handler 245, 0
define_int_handler 246, 0
define_int_handler 247, 0
define_int_handler 248, 0
define_int_handler 249, 0
define_int_handler 250, 0
define_int_handler 251, 0
define_int_handler 252, 0
define_int_handler 253, 0
define_int_handler 254, 0
define_int_handler 255, 0

.att_syntax

"#);

