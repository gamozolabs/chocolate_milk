//! Intel 1gbit network card driver

use core::mem::size_of;
use core::ptr::{read_volatile, write_volatile};
use alloc::vec::Vec;
use alloc::boxed::Box;

use page_table::{PAGE_NX, PAGE_CACHE_DISABLE};
use page_table::{PhysAddr, VirtAddr, PageType, PAGE_PRESENT, PAGE_WRITE};

use crate::mm::{alloc_virt_addr_4k, PhysContig};
use crate::net::{NetDriver, NetDevice, Packet, PacketLease};
use crate::pci::{Device, PciDevice, BarType};

/// Number of receive descriptors to allocate per device (max is 256)
const NUM_RX_DESCS: usize = 8;

/// Number of transmit descriptors to allocate per device (max is 256)
const NUM_TX_DESCS: usize = 16;

/// Network register offsets
///
/// These may vary slightly between each Intel NIC, thus we have a different
/// register list for each.
#[derive(Clone, Copy)]
struct NicRegisters {
    /// If `true`, this NIC requires setting the transmit and receive queue
    /// enable bits in the RXDCTL and TXDCTL (bits 25)
    queue_enable: bool,

    /// Device control register
    ctrl: usize,

    /// Interrupt mask clear
    imc: usize,

    /// Receive descriptor base low
    rdbal: usize,
    
    /// Receive descriptor base high
    rdbah: usize,
    
    /// Receive descriptor length
    rdlen: usize,
    
    /// Receive descriptor head
    rdh: usize,
    
    /// Receive descriptor tail
    rdt: usize,
    
    /// Transmit descriptor base low
    tdbal: usize,
    
    /// Transmit descriptor base high
    tdbah: usize,
    
    /// Transmit descriptor length
    tdlen: usize,
    
    /// Transmit descriptor head
    tdh: usize,
    
    /// Transmit descriptor tail
    tdt: usize,

    /// Receive address low for the 0th entry in the table
    ral0: usize,
    
    /// Receive address high for the 0th entry in the table
    rah0: usize,

    /// Receive control
    rctl: usize,

    /// Transmit control
    tctl: usize,

    /// Receive descriptor control
    rxdctl: usize,

    /// Transmit descriptor control
    txdctl: usize,
}

/// Checks to see if the PCI device being probed is a device that we can handle
/// with our driver
pub fn probe(device: &PciDevice) -> Option<Box<dyn Device>> {
    const E1000_REGS: NicRegisters = NicRegisters {
        queue_enable: false,
        ctrl:   0x0000,
        imc:    0x00d8,
        rdbal:  0x2800,
        rdbah:  0x2804,
        rdlen:  0x2808,
        rdh:    0x2810,
        rdt:    0x2818,
        tdbal:  0x3800,
        tdbah:  0x3804,
        tdlen:  0x3808,
        tdh:    0x3810,
        tdt:    0x3818,
        ral0:   0x5400,
        rah0:   0x5404,
        rctl:   0x0100,
        tctl:   0x0400,
        rxdctl: 0x2828,
        txdctl: 0x3828,
    };
    
    /// The different (vendor, device IDs) we support
    const HANDLED_DEVICES: &[(u16, u16, NicRegisters)] = &[
        // 82540EM Gigabit Ethernet Controller "e1000"
        (0x8086, 0x100e, E1000_REGS),

        // 82574L Gigabit Network Connection "e1000e"
        (0x8086, 0x10d3, E1000_REGS),

        // I210 Gigabit Network Connection
        (0x8086, 0x1533, NicRegisters {
            queue_enable: true,
            ctrl:   0x0000,
            imc:    0x00d8,
            rdbal:  0x2800,
            rdbah:  0x2804,
            rdlen:  0x2808,
            rdh:    0x2810,
            rdt:    0x2818,
            tdbal:  0x3800,
            tdbah:  0x3804,
            tdlen:  0x3808,
            tdh:    0x3810,
            tdt:    0x3818,
            ral0:   0x5400,
            rah0:   0x5404,
            rctl:   0x0100,
            tctl:   0x0400,
            rxdctl: 0x2828,
            txdctl: 0x3828,
        }),
    ];

    // Check if we can handle this device
    for &(vid, did, regs) in HANDLED_DEVICES {
        // Check if the VID:DID match what we support
        if device.header.vendor_id == vid && device.header.device_id == did {
            // Create the new device
            return Some(Box::new(
                NetDevice::new(Box::new(IntelGbit::new(*device, regs)))
            ));
        }
    }

    // Device is not handled
    None
}

/// Legacy receive descriptor
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
struct LegacyRxDesc {
    buffer:   u64,
    len:      u16,
    checksum: u16,
    status:   u8,
    errors:   u8,
    special:  u16,
}

/// Legacy transmit descriptor
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
struct LegacyTxDesc {
    buffer:   u64,
    len:      u16,
    cso:      u8,
    cmd:      u8,
    status:   u8,
    css:      u8,
    special:  u16,
}

/// Intel gigabit network driver
struct IntelGbit {
    /// Per-NIC registers for the different registers we use
    regs: NicRegisters,

    /// Memory mapped I/O for this device
    /// These devices map 128 KiB of memory
    mmio: &'static mut [u32; 32 * 1024],

    /// Virtually mapped RX descriptors
    rx_descriptors: PhysContig<[LegacyRxDesc; NUM_RX_DESCS]>,

    /// Receive buffers corresponding to their descriptors
    rx_buffers: Vec<Packet>,

    /// Current index of the receive buffer which is next-in-line to get a
    /// packet from the NIC
    rx_head: usize,
    
    /// Virtually mapped TX descriptors
    tx_descriptors: PhysContig<[LegacyTxDesc; NUM_TX_DESCS]>,

    /// Current index of the next free transmit buffer slot
    tx_head: usize,

    /// Free list of packets
    packets: Vec<Packet>,

    /// Mac address of this device
    mac: [u8; 6],
}

impl<'a> IntelGbit {
    fn new(device: PciDevice, regs: NicRegisters) -> Self {
        // The BAR0 should be a memory bar
        assert!((device.bar0 & 1) == 0,
            "Intel gbit BAR0 was not a memory BAR");

        // Get the type of memory bar
        let bar_type = BarType::from((device.bar0 >> 1) & 3);

        // Get the physical address of the memory for this NIC
        let bar = match bar_type {
            BarType::Bits32 => {
                // 32-bit BAR is just in-place, mask off the BAR type bits
                PhysAddr((device.bar0 & 0xffff_fff0) as u64)
            },
            BarType::Bits64 => {
                // Compute the 64-bit BAR by grabing both BAR0 and BAR1
                let low_bits = (device.bar0 & 0xffff_fff0) as u64;
                PhysAddr(((device.bar1 as u64) << 32) | low_bits)
            },
        };

        // Not sure if this can ever happen, but make sure the physical address
        // is 4 KiB aligned
        assert!((bar.0 & 0xfff) == 0, "Non-4 KiB aligned Intel gbit nic?!");

        // Map in the physical MMIO space into uncacheable virtual memory
        let mmio = {
            // Get a virtual address capable of holding a 128 KiB mapping
            let vaddr = alloc_virt_addr_4k(128 * 1024);
            
            // Get access to physical memory allocations
            let mut pmem = crate::mm::PhysicalMemory;

            // Get access to the current page table
            let mut page_table = core!().boot_args.page_table.lock();
            let page_table = page_table.as_mut().unwrap();

            // Map in the 128 KiB of MMIO space into virtual memory based on
            // the `vaddr` we allocated above
            for paddr in (bar.0..bar.0.checked_add(128 * 1024).unwrap())
                    .step_by(4096) {
                // Compute the offset into MMIO space
                let offset = paddr - bar.0;

                unsafe {
                    page_table.map_raw(&mut pmem, VirtAddr(vaddr.0 + offset),
                                       PageType::Page4K,
                                       paddr | PAGE_NX | PAGE_WRITE | 
                                       PAGE_CACHE_DISABLE | PAGE_PRESENT)
                        .expect("Failed to map in Intel gbit MMIO to \
                                 virtual memory");
                }
            }

            // Box up the MMIO space
            unsafe {
                &mut *(vaddr.0 as *mut [u32; 32 * 1024])
            }
        };

        // Make sure that the descriptor tables fit on a single page. They're
        // 16-byte entries thus we make sure that we never use more than 256
        // entries per table.
        // RX and TX descriptor tables must also be divisible by 8 for their
        // number of entries as a require of the 128-byte cache line sizes
        // implemented in the NIC.
        assert!(NUM_RX_DESCS <= 256 && (NUM_RX_DESCS % 8) == 0 &&
                NUM_RX_DESCS > 0 &&
                NUM_TX_DESCS <= 256 && (NUM_TX_DESCS % 8) == 0 &&
                NUM_TX_DESCS > 0,
            "Invalid Intel gbit constant configuration");

        // Create the RX descriptors
        let mut rx_descriptors =
            PhysContig::new([LegacyRxDesc::default(); NUM_RX_DESCS]);

        // Create the RX buffers
        let mut rx_buffers = Vec::new();
        for ii in 0..rx_descriptors.len() {
            // Allocate a new packet buffer
            let rx_buf = Packet::new();

            // Store the packet buffer in the descriptor table
            rx_descriptors[ii].buffer = rx_buf.phys_addr().0;

            // Save the reference to the buffer
            rx_buffers.push(rx_buf);
        }
        
        // Create the TX descriptors
        let tx_descriptors =
            PhysContig::new([LegacyTxDesc::default(); NUM_TX_DESCS]);
        
        // Create the NIC
        let mut nic = IntelGbit {
            regs,
            mmio,
            rx_descriptors,
            rx_buffers,
            rx_head: 0,
            tx_descriptors,
            tx_head: 0,
            packets: Vec::with_capacity(128),
            mac: [0u8; 6],
        };

        unsafe {
            // Reset the NIC
            nic.write(nic.regs.ctrl, nic.read(nic.regs.ctrl) | (1 << 26));

            // Wait for the reset to clear
            while (nic.read(nic.regs.ctrl) & (1 << 26)) != 0 {}

            // Write all `f`s to the IMC to disable all interrupts
            nic.write(nic.regs.imc, !0);
            
            if nic.regs.queue_enable {
                // Enable RX and TX queues if the NIC requires this enablement
                nic.write(nic.regs.rxdctl,
                          (1 << 25) | nic.read(nic.regs.rxdctl));
                nic.write(nic.regs.txdctl,
                          (1 << 25) | nic.read(nic.regs.txdctl));
            }

            // Initialize the NIC for receive
            {
                // Program the receive descriptor base
                nic.write(nic.regs.rdbah,
                    (nic.rx_descriptors.phys_addr().0 >> 32) as u32); // high
                nic.write(nic.regs.rdbal,
                    (nic.rx_descriptors.phys_addr().0 >>  0) as u32); // low

                // Write in the size of the RX descriptor queue
                let queue_size = core::mem::size_of_val(
                    &nic.rx_descriptors[..]);
                nic.write(nic.regs.rdlen, queue_size as u32);

                // Set the RX head
                nic.write(nic.regs.rdh, 0);

                // Set the RX tail
                nic.write(nic.regs.rdt, nic.rx_descriptors.len() as u32 - 1);
            }

            // Initialize the NIC for transmit
            {
                // Program the transmit descriptor base
                nic.write(nic.regs.tdbah,
                    (nic.tx_descriptors.phys_addr().0 >> 32) as u32); // high
                nic.write(nic.regs.tdbal,
                    (nic.tx_descriptors.phys_addr().0 >>  0) as u32); // low

                // Write in the size of the TX descriptor queue
                let queue_size = core::mem::size_of_val(
                    &nic.tx_descriptors[..]);
                nic.write(nic.regs.tdlen, queue_size as u32);
            
                // Set the TX head
                nic.write(nic.regs.tdh, 0);

                // Set the TX tail
                nic.write(nic.regs.tdt, 0);
            }

            // Read the receive address high and low for the first entry
            // in the RX MAC filter. We assume this holds the MAC address of
            // this NIC
            let ral = nic.read(nic.regs.ral0);
            let rah = nic.read(nic.regs.rah0);
            let mut mac = [0u8; 6];
            assert!((rah & (1 << 31)) != 0, "Whoa, couldn't get MAC");
            mac[0..4].copy_from_slice(&ral.to_le_bytes());
            mac[4..6].copy_from_slice(&(rah as u16).to_le_bytes());
            nic.mac = mac;

            // Strip ethernet CRC, 2 KiB RX buffers,
            // and accept broadcast packets, and enable RX
            nic.write(nic.regs.rctl, (1 << 26) | (1 << 15) | (1 << 1));
            
            // Enable TX
            nic.write(nic.regs.tctl, 1 << 1);
        }

        nic
    }

    /// Read from the MMIO Intel register at `reg_offset`. This is the offset
    /// into MMIO space in bytes, not the register ID
    unsafe fn read(&self, reg_offset: usize) -> u32 {
        let reg = reg_offset / size_of::<u32>();
        core::ptr::read_volatile(&self.mmio[reg])
    }

    /// Write `val` to the MMIO Intel register at `reg_offset`. This is the
    /// offset into MMIO space in bytes, not the register ID
    unsafe fn write(&mut self, reg_offset: usize, val: u32) {
        let reg = reg_offset / size_of::<u32>();
        core::ptr::write_volatile(&mut self.mmio[reg], val);
    }
}

impl NetDriver for IntelGbit {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    
    fn recv<'a, 'b: 'a>(&'b mut self) -> Option<PacketLease<'a>> {
        unsafe {
            // Check if there is a packet that is ready to read
            let present = (read_volatile(
                &self.rx_descriptors[self.rx_head].status) & 1) != 0;
            if !present {
                // No packet present
                return None;
            }

            // Get the length of the rxed buffer and copy into the caller
            // supplied buffer
            let rxed = read_volatile(
                &self.rx_descriptors[self.rx_head].len) as usize;

            // Allocate a new packet for this descriptor
            let mut packet = self.allocate_packet();

            // Get the physical address of the new packet
            let new_packet_phys = packet.phys_addr();

            // Swap in the new packet in place of the old packet in the
            // buffer list
            core::mem::swap(&mut packet,
                            &mut self.rx_buffers[self.rx_head]);

            // Clear the status to put this descriptor back up for use
            write_volatile(&mut self.rx_descriptors[self.rx_head],
               LegacyRxDesc {
                   buffer: new_packet_phys.0,
                   ..Default::default()
               });
            
            // Let the NIC know this buffer is available for use again
            self.write(self.regs.rdt, self.rx_head as u32);

            // Bump the RX head
            self.rx_head = (self.rx_head + 1) % self.rx_descriptors.len();
            
            // Set the length of the packet
            packet.set_len(rxed);

            // Return out a lease to this packet
            Some(PacketLease::new(self, packet))
        }
    }
    
    fn send(&mut self, packet: Packet) {
        unsafe {
            // Compute the tail index for this transmit
            let tail = (self.tx_head + 1) % self.tx_descriptors.len();

            // Fill in the TX descriptor
            write_volatile(&mut self.tx_descriptors[self.tx_head],
                LegacyTxDesc {
                    buffer: packet.phys_addr().0,
                    cmd:    (1 << 3) | (1 << 1) | (1 << 0),
                    len:    packet.raw().len() as u16,
                    ..Default::default()
                });

            // Bump the tail pointer on the NIC
            self.write(self.regs.tdt, tail as u32);

            // Wait for the NIC to actually transmit the packet
            while (read_volatile(
                &self.tx_descriptors[self.tx_head].status) & 1) == 0 {}

            // Bump the TX head as we've used this slot
            self.tx_head = tail;

            // Put the packet onto our free list
            self.release_packet(packet);
        }
    }

    fn allocate_packet(&mut self) -> Packet {
        self.packets.pop().unwrap_or(Packet::new())
    }

    fn release_packet(&mut self, packet: Packet) {
        // If we have room in our free list, push the packet into it.
        // Otherwise, we'll just free the packet entirely, putting it back up
        // for use for the whole system
        if self.packets.len() < self.packets.capacity() {
            // Put the packet back into the free list
            self.packets.push(packet);
        }
    }
}

