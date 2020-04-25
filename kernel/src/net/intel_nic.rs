//! Intel network card driver(s) for both 1gbit and 10gbit

use core::mem::size_of;
use core::ptr::{read_volatile, write_volatile};
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::boxed::Box;

use lockcell::LockCell;
use page_table::{PAGE_NX, PAGE_CACHE_DISABLE};
use page_table::{PhysAddr, VirtAddr, PageType, PAGE_PRESENT, PAGE_WRITE};

use crate::mm::{alloc_virt_addr_4k, PhysContig};
use crate::net::{NetDriver, NetDevice, Packet, PacketLease};
use crate::pci::{PciDevice, BarType};
use crate::core_locals::LockInterrupts;

/// Number of receive descriptors to allocate per device (max is 256)
const NUM_RX_DESCS: usize = 256;

/// Number of transmit descriptors to allocate per device (max is 256)
const NUM_TX_DESCS: usize = 256;

/// Network register offsets
///
/// These may vary slightly between each Intel NIC, thus we have a different
/// register list for each.
#[derive(Clone, Copy)]
struct NicRegisters {
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
    rctl: Option<usize>,

    /// Transmit control
    tctl: Option<usize>,

    /// Receive descriptor control
    rxdctl: Option<usize>,

    /// Receive control (x540)
    rxctrl: Option<usize>,

    /// Transmit descriptor control
    txdctl: Option<usize>,

    /// Split receive control register
    srrctl: Option<usize>,

    /// DMA transmit control
    dmatxctl: Option<usize>,

    /// Filter control register
    fctrl: Option<usize>,

    /// Extended control
    ctrl_ext: Option<usize>,
}

/// Checks to see if the PCI device being probed is a device that we can handle
/// with our driver
pub fn probe(device: &PciDevice) -> Option<Arc<NetDevice>> {
    const E1000_REGS: NicRegisters = NicRegisters {
        ctrl:     0x0000,
        imc:      0x00d8,
        rdbal:    0x2800,
        rdbah:    0x2804,
        rdlen:    0x2808,
        rdh:      0x2810,
        rdt:      0x2818,
        tdbal:    0x3800,
        tdbah:    0x3804,
        tdlen:    0x3808,
        tdh:      0x3810,
        tdt:      0x3818,
        ral0:     0x5400,
        rah0:     0x5404,
        rctl:     Some(0x0100),
        tctl:     Some(0x0400),
        rxdctl:   None,
        txdctl:   None,
        srrctl:   None,
        dmatxctl: None,
        fctrl:    None,
        rxctrl:   None,
        ctrl_ext: None,
    };
    
    /// The different (vendor, device IDs) we support
    const HANDLED_DEVICES: &[(u16, u16, NicRegisters)] = &[
        // 82540EM Gigabit Ethernet Controller "e1000"
        (0x8086, 0x100e, E1000_REGS),

        // 82574L Gigabit Network Connection "e1000e"
        (0x8086, 0x10d3, E1000_REGS),

        // I210 Gigabit Network Connection
        (0x8086, 0x1533, NicRegisters {
            ctrl:     0x0000,
            imc:      0x00d8,
            rdbal:    0x2800,
            rdbah:    0x2804,
            rdlen:    0x2808,
            rdh:      0x2810,
            rdt:      0x2818,
            tdbal:    0x3800,
            tdbah:    0x3804,
            tdlen:    0x3808,
            tdh:      0x3810,
            tdt:      0x3818,
            ral0:     0x5400,
            rah0:     0x5404,
            rctl:     Some(0x0100),
            tctl:     Some(0x0400),
            rxdctl:   Some(0x2828),
            txdctl:   Some(0x3828),
            srrctl:   None,
            dmatxctl: None,
            fctrl:    None,
            rxctrl:   None,
            ctrl_ext: Some(0x0018),
        }),

        // Ethernet Converged Network Adapter X540-T1
        (0x8086, 0x1528, NicRegisters {
            ctrl:     0x0000,
            imc:      0x0888, // Technically the EIMC
            rdbal:    0x1000,
            rdbah:    0x1004,
            rdlen:    0x1008,
            rdh:      0x1010,
            rdt:      0x1018,
            tdbal:    0x6000,
            tdbah:    0x6004,
            tdlen:    0x6008,
            tdh:      0x6010,
            tdt:      0x6018,
            ral0:     0xa200,
            rah0:     0xa204,
            rctl:     None,
            tctl:     None,
            rxdctl:   Some(0x1028),
            txdctl:   Some(0x6028),
            srrctl:   Some(0x1014),
            dmatxctl: Some(0x4a80),
            fctrl:    Some(0x5080),
            rxctrl:   Some(0x3000),
            ctrl_ext: Some(0x0018),
        })
    ];

    // Check if we can handle this device
    for &(vid, did, regs) in HANDLED_DEVICES {
        // Check if the VID:DID match what we support
        if device.header.vendor_id == vid && device.header.device_id == did {
            // Create the new device
            return Some(
                NetDevice::new(Box::new(IntelGbit::new(*device, regs)))
            );
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

/// Transmit logic state
struct TxState {
    /// Virtually mapped TX descriptors
    descriptors: PhysContig<[LegacyTxDesc; NUM_TX_DESCS]>,
    
    /// Packets held by the transmit descriptors. When the descriptor is free
    /// these will be `None`
    buffers: Vec<Option<Packet>>,

    /// Current index of the transmit descriptors that has not yet been sent
    head: usize,
    
    /// Current index of the transmit descriptors that has been sent
    tail: usize,
}

/// Receive logic state
struct RxState {
    /// Virtually mapped RX descriptors
    descriptors: PhysContig<[LegacyRxDesc; NUM_RX_DESCS]>,

    /// Receive buffers corresponding to their descriptors
    buffers: Vec<Packet>,

    /// Current index of the receive buffer which is next-in-line to get a
    /// packet from the NIC
    head: usize,
}

/// Intel gigabit network driver
struct IntelGbit {
    /// Per-NIC registers for the different registers we use
    regs: NicRegisters,

    /// Memory mapped I/O for this device
    /// These devices map 128 KiB of memory
    mmio: &'static mut [u32; 32 * 1024],

    /// Receive logic state
    rx_state: LockCell<RxState, LockInterrupts>,

    /// Transmit logic state
    tx_state: LockCell<TxState, LockInterrupts>,

    /// Free list of packets
    packets: LockCell<Vec<Packet>, LockInterrupts>,

    /// Mac address of this device
    mac: [u8; 6],
}

impl<'a> IntelGbit {
    fn new(device: PciDevice, regs: NicRegisters) -> Self {
        // The BAR0 should be a memory bar
        assert!((device.bar0 & 1) == 0,
            "Intel NIC BAR0 was not a memory BAR");

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
        assert!((bar.0 & 0xfff) == 0, "Non-4 KiB aligned Intel NIC?!");

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
                        .expect("Failed to map in Intel NIC MMIO to \
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
            "Invalid Intel NIC constant configuration");

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
            rx_state: LockCell::new_no_preempt(RxState {
                descriptors: rx_descriptors,
                buffers:     rx_buffers,
                head:        0,
            }),
            tx_state: LockCell::new_no_preempt(TxState {
                descriptors: tx_descriptors,
                head:        0,
                tail:        0, 
                buffers:     (0..NUM_TX_DESCS).map(|_| None).collect(),
            }),
            packets: LockCell::new_no_preempt(
                         Vec::with_capacity(NUM_TX_DESCS + NUM_RX_DESCS)),
            mac: [0u8; 6],
        };

        unsafe {
            // Write all `f`s to the IMC to disable all interrupts
            nic.write(nic.regs.imc, !0);

            // Reset the NIC
            nic.write(nic.regs.ctrl, nic.read(nic.regs.ctrl) | (1 << 26));

            // Wait for the reset to clear
            while (nic.read(nic.regs.ctrl) & (1 << 26)) != 0 {}
	        crate::time::sleep(20000);

            // Write all `f`s to the IMC to disable all interrupts
            nic.write(nic.regs.imc, !0);
 
            if let Some(dmatxctl) = nic.regs.dmatxctl {
                // DMA transmit enable
                nic.write(dmatxctl, nic.read(dmatxctl) | 1);
            }
           
            if let Some(ctrl_ext) = nic.regs.ctrl_ext {
                // Disable no snoop globally
                nic.write(ctrl_ext, 1 << 16);
            }

            // Initialize the NIC for receive
            {
                let rx_state = nic.rx_state.lock();

                // Program the receive descriptor base
                nic.write(nic.regs.rdbah,
                    (rx_state.descriptors.phys_addr().0 >> 32) as u32); // high
                nic.write(nic.regs.rdbal,
                    (rx_state.descriptors.phys_addr().0 >>  0) as u32); // low

                // Write in the size of the RX descriptor queue
                let queue_size = core::mem::size_of_val(
                    &rx_state.descriptors[..]);
                nic.write(nic.regs.rdlen, queue_size as u32);
                
                if let Some(fctrl) = nic.regs.fctrl {
                    // Accept broadcast packets
                    nic.write(fctrl, 1 << 10);
                }

                if let Some(srrctl) = nic.regs.srrctl {
                    // Program the receive control
                    // Drop enable, legacy descriptors, 2 KiB packets
                    nic.write(srrctl, (1 << 28) | (4 << 8) | (2 << 0));
                }
                
                if let Some(rxdctl) = nic.regs.rxdctl {
                    // Enable the RX queue
                    nic.write(rxdctl, (1 << 25) | nic.read(rxdctl));
                    while (nic.read(rxdctl) & (1 << 25)) == 0 {}
                }
                
                // Set the RX head and tail
                nic.write(nic.regs.rdh, 0);
                nic.write(nic.regs.rdt, rx_state.descriptors.len() as u32 - 1);
            
                if let Some(rxctrl) = nic.regs.rxctrl {
                    // Enable receives by setting RXCTRL.RXEN
                    nic.write(rxctrl, 1);
                }

                if let Some(rctl) = nic.regs.rctl {
                    // Strip ethernet CRC, 2 KiB RX buffers,
                    // and accept broadcast packets, and enable RX
                    nic.write(rctl, (1 << 26) | (1 << 15) | (1 << 1));
                }
            }

            // Initialize the NIC for transmit
            {
                let tx_state = nic.tx_state.lock();

                // Program the transmit descriptor base
                nic.write(nic.regs.tdbah,
                    (tx_state.descriptors.phys_addr().0 >> 32) as u32); // high
                nic.write(nic.regs.tdbal,
                    (tx_state.descriptors.phys_addr().0 >>  0) as u32); // low

                // Write in the size of the TX descriptor queue
                let queue_size = core::mem::size_of_val(
                    &tx_state.descriptors[..]);
                nic.write(nic.regs.tdlen, queue_size as u32);
                
                if let Some(txdctl) = nic.regs.txdctl {
                    // Enable the TX queue
                    nic.write(txdctl, (1 << 25) | nic.read(txdctl));
                    while (nic.read(txdctl) & (1 << 25)) == 0 {}
                }
 
                // Set the TX head and tail
                nic.write(nic.regs.tdh, 0);
                nic.write(nic.regs.tdt, 0);

                if let Some(tctl) = nic.regs.tctl {
                    // Enable TX
                    nic.write(tctl, 1 << 1);
                }
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
    unsafe fn write(&self, reg_offset: usize, val: u32) {
        let reg = reg_offset / size_of::<u32>();
        core::ptr::write_volatile(
            &self.mmio[reg] as *const u32 as *mut u32, val);
    }
}

impl NetDriver for IntelGbit {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    
    fn recv<'a, 'b: 'a>(&'b self) -> Option<PacketLease<'a>> {
        // Get access to the RX state
        let mut rx_state = self.rx_state.lock();

        unsafe {
            // Check if there is a packet that is ready to read
            let status = read_volatile(
                &rx_state.descriptors[rx_state.head].status);
            if (status & 1) == 0 {
                // No packet present
                return None;
            }
            
            // Make sure there were no RX errors
            let errors = read_volatile(
                &rx_state.descriptors[rx_state.head].errors);
            assert!(errors == 0);

            // Get the length of the rxed buffer and copy into the caller
            // supplied buffer
            let rxed = read_volatile(
                &rx_state.descriptors[rx_state.head].len) as usize;

            // Allocate a new packet for this descriptor
            let mut packet = self.allocate_packet();

            // Get the physical address of the new packet
            let new_packet_phys = packet.phys_addr();

            // Swap in the new packet in place of the old packet in the
            // buffer list
            let head = rx_state.head;
            core::mem::swap(&mut packet,
                            &mut rx_state.buffers[head]);

            // Clear the status to put this descriptor back up for use
            write_volatile(&mut rx_state.descriptors[head],
               LegacyRxDesc {
                   buffer: new_packet_phys.0,
                   ..Default::default()
               });
            
            // Let the NIC know this buffer is available for use again
            self.write(self.regs.rdt, rx_state.head as u32);

            // Bump the RX head
            rx_state.head = (rx_state.head + 1) % rx_state.descriptors.len();
            
            // Set the length of the packet
            packet.set_len(rxed);

            // Return out a lease to this packet
            Some(PacketLease::new(self, packet))
        }
    }
    
    fn send(&self, mut packet: Packet, flush: bool) {
        // Get access to the transmit state
        let mut tx_state = self.tx_state.lock();

        // Set the packet length to 64 bytes minimum
        if packet.len() < 64 {
            packet.set_len(64);
        }

        // Check for sent packets by the NIC
        loop {
            // Determine number of queued packets
            let queued = tx_state.tail - tx_state.head;
            if queued < (tx_state.descriptors.len() - 1) {
                // Queue has room for our packet
                break;
            }

            // No room for the packet in the queue, update the head for each
            // packet which was sent by the NIC previously.
            for end in (tx_state.head..tx_state.tail).rev() {
                // Get the status for the queued packet at the head
                let head_idx = end % tx_state.descriptors.len();
                let status = unsafe {
                    read_volatile(&tx_state.descriptors[head_idx].status)
                };

                // Check if the packet at the head has been sent by the NIC
                if (status & 1) != 0 {
                    tx_state.head = end + 1;
                    break;
                }
            }
        }

        // Get the index for the tail
        let tail_idx = tx_state.tail % tx_state.descriptors.len();
        
        // Fill in the TX descriptor
        tx_state.descriptors[tail_idx] =
            LegacyTxDesc {
                buffer: packet.phys_addr().0,
                cmd:    (1 << 3) | (1 << 1) | (1 << 0),
                len:    packet.len() as u16,
                ..Default::default()
            };
 
        // Swap the new packet into the TX buffer list
        let mut packet = Some(packet);
        core::mem::swap(&mut packet, &mut tx_state.buffers[tail_idx]);

        // Free the old packet, if we replaced an existing packet
        if let Some(old_packet) = packet {
            // Put the packet onto our free list
            self.release_packet(old_packet);
        }

        // Increment the tail
        tx_state.tail = tx_state.tail.wrapping_add(1);

        if flush || (tx_state.tail - tx_state.head) ==
                    (tx_state.descriptors.len() - 1) {
            unsafe {
                self.write(self.regs.tdt,
                    (tx_state.tail % tx_state.descriptors.len()) as u32);
            }
        }
    }

    fn allocate_packet(&self) -> Packet {
        self.packets.lock().pop().unwrap_or_else(|| Packet::new())
    }

    fn release_packet(&self, packet: Packet) {
        let mut packets = self.packets.lock();

        // If we have room in our free list, push the packet into it.
        // Otherwise, we'll just free the packet entirely, putting it back up
        // for use for the whole system
        if packets.len() < packets.capacity() {
            // Put the packet back into the free list
            packets.push(packet);
        }
    }
}

