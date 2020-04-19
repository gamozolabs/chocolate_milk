//! Handler for PCI-based devices

use core::any::Any;
use core::mem::size_of;
use alloc::vec::Vec;
use alloc::boxed::Box;
use lockcell::LockCell;

use crate::core_locals::LockInterrupts;

/// An driver for a device. There are multiple instances of a driver for each
/// device the driver handled during the probe process.
pub trait Device: Any {
    /// Invoked on a device when we're doing a soft reboot. This may be called
    /// from an exceptionally hostile environment (eg. inside of a panic inside
    /// of an NMI exception). The goal of this function for a driver is to
    /// attempt to reset the device to state which will not disrupt the system
    /// during the soft reboot process.
    ///
    /// When a soft reboot happens, things like DMA and interrupts on any
    /// device should absolutely be turned off. Resetting the device fully in
    /// many situations is ideal. The device should be set to a state that
    /// shortly after the new kernel is reloaded, the device can be
    /// re-initialized with the standard device probe process.
    ///
    /// This will be invoked on the device regardless of locks, thus the
    /// device needs to be able to handle that a previous user of the device
    /// may have been interrupted mid-use.
    unsafe fn purge(&mut self);
}

/// If `true` verbose PCI device enumeration will be displayed
const DEBUG_PCI_DEVICES: bool = true;

/// Different types for PCI BARs
#[derive(Clone, Copy)]
#[repr(u32)]
pub enum BarType {
    /// 32-bit BAR
    Bits32 = 0,

    /// 64-bit BAR
    Bits64 = 2,
}

impl From<u32> for BarType {
    fn from(val: u32) -> Self {
        match val {
            0 => BarType::Bits32,
            2 => BarType::Bits64,
            _ => panic!("Invalid BAR type"),
        }
    }
}

/// Type used for PCI device probes to attempt to handle a device
type ProbeFunction = fn(&PciDevice) -> Option<Box<dyn Device>>;

/// List of all driver probe routines on the system. If they return `Some` then
/// we successfully found a driver and thus we'll register it in the
/// `DEVICES` database
const DRIVERS: &[ProbeFunction] = &[
    crate::e1000::probe,
];

/// I/O port for the PCI configuration space window address
const PCI_CONFIG_ADDRESS: u16 = 0xcf8;

/// I/O port for the PCI configuration space window data
const PCI_CONFIG_DATA: u16 = 0xcfc;

/// Enable bit for accessing the `0xcf8` I/O port
const PCI_ADDRESS_ENABLE: u32 = 1 << 31;

/// List of all devices which have been handled by a driver
///
/// This is a list of all of the driver structures returned by the successful
/// `probe` routines from the `DRIVERS` list.
static DEVICES: LockCell<Vec<Box<dyn Device>>, LockInterrupts> =
    LockCell::new(Vec::new());

/// Common PCI header for the PCI configuration space of any device or bridge
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PciHeader {
    pub vendor_id:       u16,
    pub device_id:       u16,
    pub command:         u16,
    pub status:          u16,
    pub revision:        u8,
    pub prog_if:         u8,
    pub subclass:        u8,
    pub class:           u8,
    pub cache_line_size: u8,
    pub latency_timer:   u8,
    pub header_type:     u8,
    pub bist:            u8,
}

/// Configuration space for a PCI device
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PciDevice {
    /// Standard PCI configuration space header
    pub header: PciHeader,

    pub bar0:                  u32,
    pub bar1:                  u32,
    pub bar2:                  u32,
    pub bar3:                  u32,
    pub bar4:                  u32,
    pub bar5:                  u32,
    pub cardbus_cis_pointer:   u32,
    pub subsystem_vendor_id:   u16,
    pub subsystem_device_id:   u16,
    pub expansion_rom_address: u32,
    pub capabilities:          u8,
    pub reserved:              [u8; 7],
    pub interrupt_line:        u8,
    pub interrupt_pin:         u8,
    pub min_grant:             u8,
    pub max_latency:           u8,
}

/// Enumerate all PCI devices on the system and initialize drivers for any
/// supported devices.
pub unsafe fn init() {
    // For each possible bus ID
    for bus in 0..256 {
        // For each possible device ID
        for device in 0..32 {
            // For each possible function ID
            'next_function: for function in 0..8 {
                // Compute the address to select this BDF combination
                let addr = PCI_ADDRESS_ENABLE | (bus << 16) | (device << 11) |
                    (function << 8);

                // Select the address and read the device and vendor ID
                cpu::out32(PCI_CONFIG_ADDRESS, addr);
                let did_vid = cpu::in32(PCI_CONFIG_DATA);

                // Extract the vendor and device ID
                let vendor_id = (did_vid >>  0) as u16;
                let device_id = (did_vid >> 16) as u16;

                // If the device is not present, the VID and DID will be
                // all `f`s, thus we can skip to the next device
                if vendor_id == 0xffff && device_id == 0xffff {
                    continue;
                }

                // Read the PCI configuration header
                let mut header =
                    [0u32; size_of::<PciHeader>() / size_of::<u32>()];
                for (rid, register) in header.iter_mut().enumerate() { 
                    // Set the window to the register we want to read and read
                    // the value
                    cpu::out32(PCI_CONFIG_ADDRESS,
                               addr | (rid * size_of::<u32>()) as u32);
                    *register = cpu::in32(PCI_CONFIG_DATA);
                }

                // Convert the header to our `PciHeader` structure
                let header: PciHeader = core::ptr::read_unaligned(
                    header.as_ptr() as *const PciHeader);

                // Skip non-device PCI entries (skips things like PCI bridges)
                if header.header_type != 0 {
                    continue;
                }

                // Read the PCI configuration
                let mut device =
                    [0u32; size_of::<PciDevice>() / size_of::<u32>()];
                for (rid, register) in device.iter_mut().enumerate() { 
                    // Set the window to the register we want to read and read
                    // the value
                    cpu::out32(PCI_CONFIG_ADDRESS,
                               addr | (rid * size_of::<u32>()) as u32);
                    *register = cpu::in32(PCI_CONFIG_DATA);
                }

                // Convert the device to our `PciDevice` structure
                let device: PciDevice = core::ptr::read_unaligned(
                    device.as_ptr() as *const PciDevice);

                if DEBUG_PCI_DEVICES {
                    print!("PCI device | {:#06x}:{:#06x} | {:#06x}:{:#06x}\n",
                           device.header.vendor_id,
                           device.header.device_id,
                           device.subsystem_vendor_id,
                           device.subsystem_device_id);
                }

                // Attempt to find a driver for this device
                for probe in DRIVERS {
                    if let Some(driver) = probe(&device) {
                        // Found a handler, go to the next function during the
                        // PCI enumeration
                        DEVICES.lock().push(driver);
                        continue 'next_function;
                    }
                }
            }
        }
    }
}

/// Drop all devices in the `DEVICES` list, causing the devices to have their
/// `Drop` handlers invoked
///
/// This will drop the devices regardless of the current device lock, thus
/// this is very unsafe and must only be done when we're doing a soft reboot
/// and all other cores have been disabled.
pub unsafe fn destroy_devices() {
    let devices = &mut *DEVICES.shatter();
    for device in devices {
        device.purge();
    }
}

