//! Panic handlers and soft reboots for the kernel

use core::fmt::Write;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicPtr, AtomicBool, Ordering};

use crate::acpi::{self, ApicState};
use crate::apic::Apic;
use crate::core_locals::CoreLocals;

use serial::SerialPort;
use page_table::PhysAddr;

/// Holds a pointer to a pending panic. When a non-core-0 core panics, it will
/// place its `PanicInfo` pointer into here, NMI the core 0, and then halt
/// forever.
static PANIC_PENDING: AtomicPtr<PanicInfo> =
    AtomicPtr::new(core::ptr::null_mut());

/// Records if a soft reboot has been requested. If it has been, we will
/// soft reboot as soon as we can.
static SOFT_REBOOT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Attempt a soft reboot by checking to see if there is a command on the
/// serial port to soft reboot.
pub unsafe fn attempt_soft_reboot() {
    // Attempt to get a byte from the serial port
    let byte = core!().boot_args.serial.lock().as_mut().unwrap().read_byte();

    // Check if we got a 'Z' from the serial port.
    if let Some(b'Z') = byte {
        // Request a soft reboot
        SOFT_REBOOT_REQUESTED.store(true, Ordering::SeqCst);

        // Force a panic
        panic!("Soft reboot requested from timer");
    }
}

/// Disable all cores on the system, making sure they check in when they stop
pub unsafe fn disable_all_cores(apic: &mut Apic) {
    // Make sure we're on the BSP
    assert!(core!().id == 0, "Disable all cores only allowed on BSP");

    // Only do this if we have a valid APIC initialized
    if let Some(our_apic_id) = core!().apic_id() {
        // Send an NMI to all cores, waiting for it to respond
        for apic_id in 0..acpi::MAX_CORES as u32 {
            // Don't NMI ourself
            if apic_id == our_apic_id { continue; }

            let state = acpi::core_state(apic_id);
            if state == ApicState::Online {
                // Send this core an NMI to cause it to halt
                apic.ipi(apic_id, (1 << 14) | (4 << 8));
                while acpi::core_state(apic_id) != ApicState::Halted {}
            }
        }
    }
}

/// INIT all processors, shutdown the kernel, download a new kernel, and boot
/// into it without resetting the actual CPU.
pub unsafe fn soft_reboot(apic: &mut Apic) -> ! {
    // Get access to the soft reboot address as well as the trampoline page
    // table.
    let soft_reboot = core!().boot_args.soft_reboot_addr_ref()
        .load(Ordering::SeqCst);
    let trampoline_cr3 = PhysAddr(core!().boot_args.trampoline_page_table_ref()
        .load(Ordering::SeqCst));

    // Compute the virtual address of the soft reboot entry point based
    // on the physical address
    let vaddr = boot_args::KERNEL_PHYS_WINDOW_BASE + soft_reboot;

    // Disable all other cores
    disable_all_cores(apic);
    
    {
        // VMXOFF if we're in VMX root operation
        let vmxon_lock = core!().vmxon_region().lock();
        if let Some(_) = &*vmxon_lock {
            // Disable VMX root operation
            llvm_asm!("vmxoff" :::: "intel", "volatile");
        }
    }

    // Destroy all devices which are handled by drivers
    crate::pci::destroy_devices();

    // Destroy all the core locals, this will drop anything we've initialized
    // for this core, like the APIC. Causing it to get reset to the original
    // boot state.
    let core_addr: *mut CoreLocals =
        core!() as *const CoreLocals as *mut CoreLocals;
    core::ptr::drop_in_place(core_addr);
    
    // Convert the soft reboot virtual address into a function pointer that
    // takes one `PhysAddr` argument, which is the trampoline cr3
    let soft_reboot =
        *(&vaddr as *const u64 as *const extern fn(PhysAddr) -> !);

    // Perform the soft reboot!
    soft_reboot(trampoline_cr3);
}

/// Panic implementation for the kernel
#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    // Disable interrupts, we're never coming back from this point.
    unsafe { core!().disable_interrupts(); }

    if core!().id == 0 {
        // If we had a panic on the BSP, we handle it quite uniquely. We'll
        // shut down all other processors by sending them NMIs and waiting for
        // them to check into a halted state.
        
        let our_info: *const PanicInfo = info;

        let other_info: *const PanicInfo =
            PANIC_PENDING.load(Ordering::SeqCst);
        
        let apic = unsafe {
            // Forcibly get access to the current APIC. This is likely safe in
            // almost every situation as the APIC is not very stateful.
            let apic = &mut *core!().apic().shatter();
            let apic = apic.as_mut().unwrap();
            
            // Disable all other cores, waiting for them to check-in notifying
            // us that they've gone into a permanent halt state.
            disable_all_cores(apic);

            apic
        };

        // Create our emergency serial port. We disabled all other cores so
        // we re-initialize the serial port to make sure it's in a sane state.
        let serial = unsafe {
            SerialPort::new(
                (boot_args::KERNEL_PHYS_WINDOW_BASE + 0x400) as *const u16)
        };
        
        /// Structure for holding the emergency serial port which is
        /// reinitialized and prepared for exclusive access during this panic.
        pub struct EmergencySerial(SerialPort);

        impl core::fmt::Write for EmergencySerial {
            fn write_str(&mut self, st: &str) -> core::fmt::Result {
                self.0.write(st.as_bytes());
                Ok(())
            }
        }

        // Wrap up the serial driver in our writer
        let mut eserial = EmergencySerial(serial);
 
        // Create some space, in case we're splicing an existing line
        let _ = write!(eserial, "\n\n\n");
        
        // Print information about the panic(s)
        for &(message, info) in &[
            ("Panic reported by other core", other_info),
            ("Local panic", our_info),
        ] {
            // Skip potentially null info
            if info.is_null() { continue; }

            // Get Rust access to the panic info
            let info: &PanicInfo = unsafe { &*info };

            let _ = write!(eserial, "=== PANIC | {} =============\n", message);
            
            if let Some(loc) = info.location() {
                let _ = write!(eserial, "At {}:{}:{}\n",
                    loc.file(), loc.line(), loc.column());
            }
            
            if let Some(msg) = info.message() {
                let _ = write!(eserial, "{}\n", msg);
            }
        }

        // Wait for a soft reboot to be requested
        while SOFT_REBOOT_REQUESTED.load(Ordering::SeqCst) != true {
            if eserial.0.read_byte() == Some(b'Z') {
                SOFT_REBOOT_REQUESTED.store(true, Ordering::SeqCst);
            }
        }

        // Start a soft reboot
        let _ = write!(eserial, "Starting soft reboot...\n");
        unsafe { soft_reboot(apic); }
    } else {
        // Save the panic info for this core
        PANIC_PENDING.store(info as *const _ as *mut _, Ordering::SeqCst);

        unsafe {
            // Forcibly get access to the current APIC. This is likely safe in
            // almost every situation as the APIC is not very stateful.
            let apic = &mut *core!().apic().shatter();
            let apic = apic.as_mut().unwrap();

            // Notify the BSP that we paniced by sending it an NMI
            apic.ipi(0, (1 << 14) | (4 << 8));
        }

        // Halt forever
        cpu::halt();
    }
}

