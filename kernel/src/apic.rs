//! Local APIC implementation providing support to access the APIC in either
//! xapic or x2apic mode depending on what is supported

use core::mem::size_of;
use core::convert::TryInto;

use crate::mm::alloc_virt_addr_4k;
use crate::interrupts::{InterruptFrame, AllRegs};

use page_table::{PageType, PAGE_NX, PAGE_WRITE, PAGE_PRESENT};
use page_table::PAGE_CACHE_DISABLE;

/// The x2apic enable bit in the `IA32_APIC_BASE` MSR
const IA32_APIC_BASE_EXTD: u64 = 1 << 10;

/// The global enable bit in the `IA32_APIC_BASE` MSR
const IA32_APIC_BASE_EN: u64 = 1 << 11;

/// MSR for the IA32_APIC_BASE
const IA32_APIC_BASE: u32 = 0x1b;

/// Physical address we want the local APIC to be mapped at
const APIC_BASE: u64 = 0xfee0_0000;

/// Interrupt vector to program the APIC time to use
const APIC_TIMER_VECTOR: u8 = 0xe0;

/// The mask bit for LVT entries
const LVT_MASK: u32 = 1 << 16;

/// APIC registers (offsets into MMIO space)
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Register {
    /// APIC ID register
    ApicId = 0x20,
    
    /// End-of-interrupt register
    EndOfInterrupt = 0xb0,

    /// Spurious interrupt vector register (also has the software enable bits)
    SpuriousInterruptVector = 0xf0,

    /// In-Service Register bits 0..31
    Isr0 = 0x100,

    /// In-Service Register bits 32..63
    Isr1 = 0x110,
    
    /// In-Service Register bits 64..95
    Isr2 = 0x120,

    /// In-Service Register bits 96..127
    Isr3 = 0x130,

    /// In-Service Register bits 128..159
    Isr4 = 0x140,
    
    /// In-Service Register bits 160..191
    Isr5 = 0x150,
    
    /// In-Service Register bits 192..223
    Isr6 = 0x160,

    /// In-Service Register bits 224..255
    Isr7 = 0x170,
    
    /// Interrupt Request Register bits 0..31
    Irr0 = 0x200,

    /// Interrupt Request Register bits 32..63
    Irr1 = 0x210,
    
    /// Interrupt Request Register bits 64..95
    Irr2 = 0x220,

    /// Interrupt Request Register bits 96..127
    Irr3 = 0x230,

    /// Interrupt Request Register bits 128..159
    Irr4 = 0x240,
    
    /// Interrupt Request Register bits 160..191
    Irr5 = 0x250,
    
    /// Interrupt Request Register bits 192..223
    Irr6 = 0x260,

    /// Interrupt Request Register bits 224..255
    Irr7 = 0x270,

    /// LVT for the APIC timer
    LvtTimer = 0x320,

    /// APIC initial count register for APIC timer
    InitialCount = 0x380,

    /// APIC divide counter register for the APIC timer
    DivideConfiguration = 0x3e0,
}

/// All of the stateful fields of the APIC timer
#[derive(Default)]
struct TimerState {
    /// Divide configuration register
    dcr: u32,

    /// Initial count register
    icr: u32,

    /// Timer LVT entry
    lvt: u32,
}

/// A local APIC instance
pub struct Apic {
    /// The current operating mode of the APIC
    mode: ApicMode,

    /// Original state of the `IA32_APIC_BASE`
    orig_ia32_apic_base: u64,

    /// Original state of the SVR register (offset 0xf0)
    orig_svr: u32,

    /// Original I/O port 0xa1 contents (PIC interrupt masks)
    orig_pic_a1: u8,

    /// Original I/O port 0x21 contents (PIC interrupt masks)
    orig_pic_21: u8,

    /// Original APIC timer state
    orig_timer_state: TimerState,
}

/// The different modes of the APIC
enum ApicMode {
    /// APIC has been set to normal APIC mode
    Apic(&'static mut [u32]),

    /// APIC supports and has been programmed to use x2apic mode
    X2Apic,
}

impl Apic {
    /// Get the APIC ID of the current running core
    pub fn apic_id(&self) -> u32 {
        // Read the APIC ID register
        let apic_id = unsafe { self.read_apic(Register::ApicId) };

        // Adjust the APIC ID based on the current APIC mode
        match &self.mode {
            ApicMode::Apic(_) => apic_id >> 24,
            ApicMode::X2Apic  => apic_id,
        }
    }

    /// Send a raw inter-processor interrupt to a specific APIC ID
    /// It is up to the caller to make sure the `dest_apic_id` is valid and
    /// the IPI is a valid IPI type/format.
    pub unsafe fn ipi(&mut self, dest_apic_id: u32, ipi: u32) {
        // Convert the destination APIC ID into the correct location based on
        // the APIC mode
        let dest_apic_id = match &self.mode {
            ApicMode::Apic(_) => dest_apic_id << 24,
            ApicMode::X2Apic  => dest_apic_id,
        };

        // Construct the IPI command and send it!
        self.write_icr(((dest_apic_id as u64) << 32) | ipi as u64);
    }

    /// Write a value to the APIC's ICR
    /// This is a special case from `write_apic` as this writes a single 64-bit
    /// value in x2apic mode, but uses 2 32-bit registers in APIC mode.
    unsafe fn write_icr(&mut self, val: u64) {
        match &mut self.mode {
            ApicMode::Apic(mapping) => {
                // Write the high part
                core::ptr::write_volatile(&mut mapping[0x310 / 4],
                                          (val >> 32) as u32);

                // Write the low part, causing the interrupt to be sent
                core::ptr::write_volatile(&mut mapping[0x300 / 4],
                                          (val >>  0) as u32);
            }
            ApicMode::X2Apic => {
                // Write the entire 64-bit value in one shot to MSR 0x830
                cpu::wrmsr(0x830, val);
            }
        }
    }

    /// Read a value from a given APIC `register`
    pub unsafe fn read_apic(&self, register: Register) -> u32 {
        // Convert the register enum to the actual MMIO offset
        let offset = register as usize;

        match &self.mode {
            ApicMode::Apic(mapping) => {
                // Read the value using the APIC memory map
                core::ptr::read_volatile(&mapping[offset / 4])
            }
            ApicMode::X2Apic => {
                // Read the value using the x2apic MSRs
                cpu::rdmsr(0x800 + (offset as u32 / 16)) as u32
            }
        }
    }

    /// Write a `val` to the APIC for a given APIC `register`. If the APIC is
    /// currently in x2apic mode, then this write will use the MSRs.
    unsafe fn write_apic(&mut self, register: Register, val: u32) {
        // Convert the register enum to the actual MMIO offset
        let offset = register as usize;

        match &mut self.mode {
            ApicMode::Apic(mapping) => {
                // Write the value using the APIC memory map
                core::ptr::write_volatile(&mut mapping[offset / 4], val);
            }
            ApicMode::X2Apic => {
                // Write the value using the x2apic MSRs
                cpu::wrmsr(0x800 + (offset as u32 / 16), val as u64);
            }
        }
    }

    /// Returns the 256-bits of interrupt request register state
    /// Array is [low 128 bits, high 128 bits]
    pub unsafe fn irr(&self) -> [u128; 2] {
        // Storage for the 256-bits of data
        let mut irr: [u8; 32] = [0; 32];

        // Values to load
        let to_load = [
            Register::Irr0, Register::Irr1, Register::Irr2, Register::Irr3,
            Register::Irr4, Register::Irr5, Register::Irr6, Register::Irr7,
        ];

        // Read all the registers into `irr`
        for (ii, &reg) in to_load.iter().enumerate() {
            irr[ii * size_of::<u32>()..(ii + 1) * size_of::<u32>()]
                .copy_from_slice(&self.read_apic(reg).to_le_bytes());
        }

        // Turn the 32 `u8`s into 2 `u128`s
        [
            u128::from_le_bytes(irr[..16].try_into().unwrap()),
            u128::from_le_bytes(irr[16..].try_into().unwrap()),
        ]
    }
    
    /// Returns the 256-bits of in-service register state
    /// Array is [low 128 bits, high 128 bits]
    pub unsafe fn isr(&self) -> [u128; 2] {
        // Storage for the 256-bits of data
        let mut isr: [u8; 32] = [0; 32];

        // Values to load
        let to_load = [
            Register::Isr0, Register::Isr1, Register::Isr2, Register::Isr3,
            Register::Isr4, Register::Isr5, Register::Isr6, Register::Isr7,
        ];

        // Read all the registers into `isr`
        for (ii, &reg) in to_load.iter().enumerate() {
            isr[ii * size_of::<u32>()..(ii + 1) * size_of::<u32>()]
                .copy_from_slice(&self.read_apic(reg).to_le_bytes());
        }

        // Turn the 32 `u8`s into 2 `u128`s
        [
            u128::from_le_bytes(isr[..16].try_into().unwrap()),
            u128::from_le_bytes(isr[16..].try_into().unwrap()),
        ]
    }

    /// Handler for APIC timer interrupts
    unsafe fn timer_interrupt(_number: u8, _frame: &mut InterruptFrame,
                              _error: u64, _regs: &mut AllRegs) -> bool {
        crate::panic::attempt_soft_reboot();

        true
    }

    /// Signal the end of an interrupt
    pub unsafe fn eoi() {
        // It's important this function works without getting any locks as the
        // APIC may need to be accessed in an NMI, which we can't control if
        // an APIC lock is held.
        //
        // The execution flow for a lock-less requirement is as such:
        //
        // BSP panics -> draining pending interrupts with sending EOIs which
        //               requires access to the APIC for the EOIs when the
        //               panic may have occurred during a section of code with
        //               the APIC locked.
        
        // Get access to the APIC without needing the lock. This is safe in
        // all situations as we issue one EOI wrmsr which is "atomic" WRT other
        // interrupts.
        let apic = &mut *core!().apic().shatter();

        if let Some(apic) = apic {
            apic.write_apic(Register::EndOfInterrupt, 0);
        }
    }

    /// Enable the APIC timer
    pub unsafe fn enable_timer(&mut self) {
        const PERIODIC_MODE: u32 = 1 << 17;

        // Disable the timer by setting the initial count to zero
        self.write_apic(Register::InitialCount, 0);
        
        {
            // Register an interrupt handler for `APIC_TIMER_VECTOR`
            core!().interrupts().lock().as_mut().unwrap().add_handler(
                APIC_TIMER_VECTOR, Self::timer_interrupt, true);
        }

        // Set the timer divide register to divide by 2 (0 means 2)
        self.write_apic(Register::DivideConfiguration, 0);

        // Program the APIC timer to periodic mode and use interrupt vector
        // `APIC_TIMER_VECTOR`
        self.write_apic(Register::LvtTimer,
                        PERIODIC_MODE | APIC_TIMER_VECTOR as u32);
        
        // Program the initial count, this will be decremented until it hits
        // zero. At which point an interrupt through the APIC timer LVT entry
        // will be fired
        self.write_apic(Register::InitialCount, 10_000_000);
    }
    
    /// Disable the APIC timer
    #[allow(unused)]
    pub unsafe fn disable_timer(&mut self) {
        // Mask timer interrupts
        self.write_apic(Register::LvtTimer,
            LVT_MASK | self.read_apic(Register::LvtTimer));

        // Disable the timer by setting the initial count to zero
        self.write_apic(Register::InitialCount, 0);
        
        // Deregister an interrupt handler for `APIC_TIMER_VECTOR`
        core!().interrupts().lock().as_mut().unwrap().remove_handler(
            APIC_TIMER_VECTOR, Self::timer_interrupt);
    }

    /// Reset the APIC to the original state it was in before we took control
    /// of it.
    /// This is used during soft reboots
    pub unsafe fn reset(&mut self) {
        // Mask timer interrupts
        self.write_apic(Register::LvtTimer,
            LVT_MASK | self.read_apic(Register::LvtTimer));

        // It is possible that we're dropping the `Apic` from a timer
        // interrupt handler. In this case, there may be an interrupt which
        // is currently in the servicing state. We will EOI on behalf of
        // the timer as we're tearing down.
        loop {
            // Get the current interrupt vectors being serviced
            let isr = self.isr();

            if isr[0] == 0 && isr[1] == 0 {
                // No interrupts are being serviced
                break;
            }

            // At this point, we know there is at least one interrupt
            // being serviced. EOI the APIC, and try again
            Self::eoi();
        }
        
        // Put the interrupt handler into draining mode
        crate::interrupts::DRAINING_EOIS
            .store(true, core::sync::atomic::Ordering::SeqCst);

        // At this point the APIC has been software disabled. Check if
        // there are any pending interrupts that we may have caused, and
        // drain them from the pendings.
        loop {
            let irr     = self.irr();
            let can_eoi = crate::interrupts::eoi_required();

            // Check if there are any pending interrupts that we have
            // registered EOI-expecting handlers for.
            let pending_handleable =
                (irr[0] & can_eoi[0]) != 0 || (irr[1] & can_eoi[1]) != 0;

            if !pending_handleable {
                // Nothing more to handle, break out of the loop
                break;
            }

            // Unconditionally enable interrupts
            cpu::enable_interrupts();
        }

        // Unconditionally disable interrupts as we may have enabled them
        // during the drain process.
        cpu::disable_interrupts();
        
        // Restore the original APIC timer state
        {
            // Load the original state, ending in the initial count
            self.write_apic(Register::DivideConfiguration, 
                            self.orig_timer_state.dcr);
            self.write_apic(Register::LvtTimer,
                            self.orig_timer_state.lvt);
            self.write_apic(Register::InitialCount,
                            self.orig_timer_state.icr);
        }

        // Load the original SVR
        self.write_apic(Register::SpuriousInterruptVector, self.orig_svr);
        
        // We do this assert when we first launch the APIC. The BIOS should
        // never be disabling the APIC. We just added this assert here as
        // an additional check incase we end up removing the other code.
        // This should never fail.
        assert!((self.orig_ia32_apic_base & IA32_APIC_BASE_EN) != 0,
            "Disabling the APIC is not supported");

        // Restore the original `IA32_APIC_BASE` to its original state.
        // Preserving the x2apic mode if we upgraded it, as downgrading
        // the x2apic requires going to fully disabled and back, which
        // may or may not be supported on the processor.
        // The x2apic is fully compatible with the xapic and leaving the
        // x2apic enabled should still work as expected during soft
        // reboot.
        cpu::wrmsr(IA32_APIC_BASE,
                   self.orig_ia32_apic_base |
                   if let ApicMode::X2Apic = self.mode {
                       IA32_APIC_BASE_EXTD
                   } else { 0 });

        // Reload the PIC's initial state
        // Without this iPXE on QEMU-KVM is unable to timeout during a
        // failed PXE transfer.
        cpu::out8(0xa1, self.orig_pic_a1);
        cpu::out8(0x21, self.orig_pic_21);
    }
}

/// Initialize the local APIC for the current running core. This will enable
/// the APIC, and if supported, will enable the x2apic.
pub unsafe fn init() {
    // Make sure the APIC base is valid
    assert!(APIC_BASE > 0 && APIC_BASE == (APIC_BASE & 0x0000_000f_ffff_f000),
            "Invalid APIC base address");

    // Get access to and make sure the APIC has not yet been initialized
    let mut apic = core!().apic().lock();
    assert!(apic.is_none(), "APIC was already initialized");

    // Get the CPU features for this system
    let cpu_features = cpu::get_cpu_features();

    // We require that the APIC is supported on this system
    assert!(cpu_features.apic, "APIC is not available on this system");

    // Enable and normalize the APIC base
    let (orig_ia32_apic_base, orig_pic_a1, orig_pic_21) = {
        // Load the previous IA32_APIC_BASE
        let orig_ia32_apic_base = cpu::rdmsr(IA32_APIC_BASE);

        // We require that the APIC is globally enabled when we get execution.
        // Re-enabling a globally disabled APIC is not always supported
        // (per-microarchitecture support). Thus, the BIOS never should be
        // globally disabling it.
        assert!((orig_ia32_apic_base & IA32_APIC_BASE_EN) != 0,
            "APIC was disabled during BIOS");
        
        // Mask off the old base address for the APIC
        let apic_base = orig_ia32_apic_base & !0x0000_000f_ffff_f000;

        // Or in the APIC base that we want to use
        let apic_base = apic_base | APIC_BASE;

        // Enable the xAPIC unconditionally
        let apic_base = apic_base | IA32_APIC_BASE_EN;

        // Enable the x2apic if supported
        let apic_base = apic_base | if cpu_features.x2apic {
            IA32_APIC_BASE_EXTD
        } else { 0 };

        // Save the old PIC state
        let orig_pic_a1 = cpu::in8(0xa1);
        let orig_pic_21 = cpu::in8(0x21);
       
        // Disable the PIC by masking off all interrupts from it
        cpu::out8(0xa1, 0xff);
        cpu::out8(0x21, 0xff);

        // Reprogram the APIC with the new settings.
        cpu::wrmsr(IA32_APIC_BASE, apic_base);

        (orig_ia32_apic_base, orig_pic_a1, orig_pic_21)
    };

    let mode = if !cpu_features.x2apic {
        // If we're in normal xAPIC mode, we want to virtually map in the
        // APIC physical memory as uncacheable and update the APIC enum state
      
        // Get a virtual address capable of holding a 4 KiB mapping
        let vaddr = alloc_virt_addr_4k(4096);
        
        // Get access to physical memory allocations
        let mut pmem = crate::mm::PhysicalMemory;

        // Get access to the current page table
        let mut page_table = core!().boot_args.page_table.lock();
        let page_table = page_table.as_mut().unwrap();

        let mapping = {
            // Map `vaddr` to the APIC base, as non-executable, writable,
            // readable, and cache disabled
            page_table.map_raw(&mut pmem, vaddr, PageType::Page4K,
                               APIC_BASE | PAGE_NX | PAGE_WRITE | 
                               PAGE_CACHE_DISABLE | PAGE_PRESENT)
                .expect("Failed to map in APIC to virtual memory");

            // Convert the APIC virtual memory into a Rust slice
            core::slice::from_raw_parts_mut(vaddr.0 as *mut u32, 1024)
        };

        ApicMode::Apic(mapping)
    } else {
        // x2apic is supported
        ApicMode::X2Apic
    };

    // Wrap up the mode in the APIC structure
    let mut new_apic = Apic {
        mode,
        orig_ia32_apic_base,
        orig_pic_21,
        orig_pic_a1,
        orig_svr: 0,
        orig_timer_state: Default::default(),
    };

    // Save off the original SVR
    new_apic.orig_svr = new_apic.read_apic(Register::SpuriousInterruptVector);

    // Save the original APIC timer state
    new_apic.orig_timer_state = TimerState {
        dcr: new_apic.read_apic(Register::DivideConfiguration),
        icr: new_apic.read_apic(Register::InitialCount),
        lvt: new_apic.read_apic(Register::LvtTimer),
    };

    // Software enable the APIC, set spurious interrupt vector to 0xff
    new_apic.write_apic(
        Register::SpuriousInterruptVector, (1 << 8) | 0xff);

    // Program the core's APIC ID
    core!().set_apic_id(new_apic.apic_id());

    // Set the core's APIC reference
    *apic = Some(new_apic);
}

