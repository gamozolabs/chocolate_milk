//! A basic 8250A serial driver for x86

#![no_std]

/// A collection of 4 8250A serial ports, as seen on IBM PC systems. These are
/// the 4 serial ports which are identified by the BIOS, and thus it is limited
/// to just COM1-COM4.
#[repr(C)]
pub struct SerialPort {
    devices: [Option<u16>; 4],
}

impl SerialPort {
    /// Initialize the serial ports on the system to 115200n1. This should only
    /// ever be called once, hence, it is marked unsafe.
    /// `bda_base` is the virtual address of the BIOS data area. This is at
    /// physical address `0x400`, however it's up to the caller to make sure
    /// that `bda_base` is the virtual address which represents this.
    pub unsafe fn new(bda_base: *const u16) -> Self {
        // Create a new serial port driver
        let mut ret = SerialPort {
            devices: [None; 4]
        };

        // Go through each possible COM port
        for (com_id, device) in ret.devices.iter_mut().enumerate() {
            // Get the COM port I/O address from the BIOS data area (BDA)
            let port = *bda_base.offset(com_id as isize);

            // If the port address is zero, it is not present as reported by
            // the BIOS
            if port == 0 {
                // Serial port is not present
                *device = None;
                continue;
            }

            // Initialize the serial port to a known state
            cpu::out8(port + 1, 0x00); // Disable all interrupts
            cpu::out8(port + 3, 0x80); // Enable DLAB
            cpu::out8(port + 0, 0x01); // Low byte divisor (115200 baud)
            cpu::out8(port + 1, 0x00); // High byte divisor
            cpu::out8(port + 3, 0x03); // 8 bits, 1 stop bit, no parity
            cpu::out8(port + 4, 0x03); // RTS/DSR set

            // Save that we found and initialized a serial port
            *device = Some(port);
        }

        // Drain the all serial ports of all inbound bytes
        while let Some(_) = ret.read_byte() {}

        ret
    }

    /// Read a byte from whatever COM port has a byte available
    pub fn read_byte(&mut self) -> Option<u8> {
        // Go through each device
        for port in &self.devices {
            // If the device is present
            if let &Some(port) = port {
                unsafe {
                    // Check if there is a byte available
                    if (cpu::in8(port + 5) & 1) == 0 {
                        // No byte available
                        continue;
                    }

                    // Read the byte that was present on this port
                    return Some(cpu::in8(port));
                }
            }
        }

        // No bytes available
        None
    }

    /// Write a byte to a COM port
    fn write_byte(&mut self, port: usize, byte: u8) {
        // Write a CR prior to all LFs
        if byte == b'\n' { self.write_byte(port, b'\r'); }

        // Check if this COM port exists
        if let Some(&Some(port)) = self.devices.get(port) {
            unsafe {
                // Wait for the output buffer to be ready
                while (cpu::in8(port + 5) & 0x20) == 0 {}

                // Write the byte!
                cpu::out8(port, byte);
            }
        }
    }

    /// Write bytes to all known serial devices
    pub fn write(&mut self, bytes: &[u8]) {
        // Go through each byte
        for &byte in bytes {
            // Broadcast the byte to all present devices
            for com_id in 0..self.devices.len() {
                self.write_byte(com_id, byte);
            }
        }
    }
}

