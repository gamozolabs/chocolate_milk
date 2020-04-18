use core::fmt::Write;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicPtr, Ordering};

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

/// Attempt a soft reboot by checking to see if there is a command on the
/// serial port to soft reboot.
pub unsafe fn attempt_soft_reboot() {
    // Only allow soft reboots from core 0
    if core!().id != 0 { return; }

    // Attempt to get a byte from the serial port
    let byte = core!().boot_args.serial.try_lock()
        .map(|mut x| x.as_mut().unwrap().read_byte()).flatten();

    // Check if we got a 'Z' from the serial port.
    if let Some(b'Z') = byte {
        // Soft reboot!
        let mut apic = core!().apic.lock();
        soft_reboot(apic.as_mut().unwrap());
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
    let soft_reboot = core!().boot_args.soft_reboot_addr
        .load(Ordering::SeqCst);
    let trampoline_cr3 = PhysAddr(core!().boot_args.trampoline_page_table
        .load(Ordering::SeqCst));

    // Compute the virtual address of the soft reboot entry point based
    // on the physical address
    let vaddr = boot_args::KERNEL_PHYS_WINDOW_BASE + soft_reboot;

    // Disable all other cores
    disable_all_cores(apic);

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

#[panic_handler]
pub fn panic(info: &PanicInfo) -> ! {
    // Disable interrupts, we're never coming back from this point.
    core!().disable_interrupts();
    cpu::delay(5_000_000_000);

    if core!().id == 0 {
        let our_info: *const PanicInfo = info;

        let other_info: *const PanicInfo =
            PANIC_PENDING.load(Ordering::SeqCst);
        
        let apic = unsafe {
            // Forcibly get access to the current APIC. This is likely safe in
            // almost every situation as the APIC is not very stateful.
            let apic = &mut *core!().apic.shatter();
            let apic = apic.as_mut().unwrap();
            
            // Disable all other cores
            disable_all_cores(apic);

            apic
        };
        
        // Lock the old serial port so nobody can use it anymore. This is just
        // to prevent accidential use of the old serial driver since we create
        // a new one.
        //let _old_serial = core!().boot_args.serial.try_lock();

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
        
        unsafe {
            soft_reboot(apic);
        }
 
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

        for apic_id in 0..acpi::MAX_CORES as u32 {
            let state = acpi::core_state(apic_id);
            if state != ApicState::None {
                let _ =
                    write!(eserial, "Apic {:#06x} | {:?}\n", apic_id, state);
            }
        }

        loop {
            if eserial.0.read_byte() == Some(b'Z') {
                let _ = write!(eserial, "Soft reboot requested\n");
                unsafe { soft_reboot(apic); }
            }
        }
    } else {
        // Save the panic info for this core
        PANIC_PENDING.store(info as *const _ as *mut _, Ordering::SeqCst);

        unsafe {
            // Forcibly get access to the current APIC. This is likely safe in
            // almost every situation as the APIC is not very stateful.
            let apic = &mut *core!().apic.shatter();
            let apic = apic.as_mut().unwrap();

            // Notify the BSP that we paniced by sending it an NMI
            apic.ipi(0, (1 << 14) | (4 << 8));
        }

        // Halt forever
        cpu::halt();
    }
}

