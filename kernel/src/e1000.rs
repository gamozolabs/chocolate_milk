//! Intel 1gbit network card driver

use core::mem::size_of;
use core::ptr::{read_volatile, write_volatile};
use core::alloc::Layout;
use alloc::vec::Vec;
use alloc::boxed::Box;
use page_table::{PhysAddr, VirtAddr, PageType, PAGE_PRESENT, PAGE_WRITE};
use page_table::{PAGE_NX, PAGE_CACHE_DISABLE};

use crate::mm::alloc_virt_addr_4k;
use crate::pci::{Device, PciDevice, BarType};

/// Number of receive descriptors to allocate per device (max is 256)
const NUM_RX_DESCS: usize = 256;

/// Number of transmit descriptors to allocate per device (max is 256)
const NUM_TX_DESCS: usize = 256;

/// Checks to see if the PCI device being probed is a device that we can handle
/// with our driver
pub fn probe(device: &PciDevice) -> Option<Box<dyn Device>> {
    /// The different (vendor, device IDs) we support
    const HANDLED_DEVICES: &[(u16, u16)] = &[
        (0x8086, 0x100e), // 82540EM Gigabit Ethernet Controller "e1000"
        //(0x8086, 0x10d3), // 82574L Gigabit Network Connection "e1000e"
        //(0x8086, 0x1533), // I210 Gigabit Network Connection
    ];

    // Check if we can handle this device
    for &(vid, did) in HANDLED_DEVICES {
        // Check if the VID:DID match what we support
        if device.header.vendor_id == vid && device.header.device_id == did {
            // Create the new device
            return Some(Box::new(IntelGbit::new(*device)));
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
    /// PCI configuration space saved during the probe process
    #[allow(unused)]
    pci_device: PciDevice,

    /// Memory mapped I/O for this device
    /// These devices map 128 KiB of memory
    mmio: &'static mut [u32; 32 * 1024],

    /// Virtually mapped RX descriptors
    rx_descriptors: &'static mut [LegacyRxDesc; 256],

    /// Physical address of `rx_descriptors`
    rx_descriptors_phys: PhysAddr,

    /// Receive buffers corresponding to their descriptors
    rx_buffers: Vec<&'static mut [u8; 2048]>,

    /// Current index of the receive buffer which is next-in-line to get a
    /// packet from the NIC
    rx_head: usize,
    
    /// Virtually mapped TX descriptors
    tx_descriptors: &'static mut [LegacyTxDesc; 256],

    /// Physical address of `tx_descriptors`
    tx_descriptors_phys: PhysAddr,

    /// Transmit buffers corresponding to their descriptors
    tx_buffers: Vec<&'static mut [u8; 2048]>,

    /// Current index of the next free transmit buffer slot
    tx_head: usize,

    /// Mac address of this device
    mac: [u8; 6],
}

impl IntelGbit {
    fn new(device: PciDevice) -> Self {
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

        // Allocate a value in physical memory, making sure it is 4 KiB aligned
        fn alloc_phys<T>(val: T) -> (PhysAddr, &'static mut T) {
            use page_table::PhysMem;

            // Get access to physical memory allocations
            let mut pmem = crate::mm::PhysicalMemory;
            
            // Get access to the current page table
            let mut page_table = core!().boot_args.page_table.lock();
            let page_table = page_table.as_mut().unwrap();

            // Make sure the allocation fits in a single page
            assert!(size_of::<T>() > 0 && size_of::<T>() <= 4096,
                "Invalid alloc phys size");
            
            // Allocate a virtual address for this mapping
            let vaddr = alloc_virt_addr_4k(4096);

            // Allocate a page for this allocation
            let paddr =
                pmem.alloc_phys(Layout::from_size_align(4096, 4096).unwrap());

            unsafe {
                // Map the memory as RW
                page_table.map_raw(&mut pmem, vaddr,
                                   PageType::Page4K,
                                   paddr.0 | PAGE_NX | PAGE_WRITE | 
                                   PAGE_PRESENT)
                    .expect("Failed to allocated uncacheable memory");

                // Initialize the memory
                core::ptr::write(vaddr.0 as *mut T, val);
            }

            // Return out the pmem and the virtual mapping of it
            (paddr, unsafe { &mut *(vaddr.0 as *mut T) })
        }

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
        let (rx_descriptors_phys, rx_descriptors) =
            alloc_phys([LegacyRxDesc::default(); NUM_RX_DESCS]);

        // Create the RX buffers
        let mut rx_buffers = Vec::new();
        for ii in 0..rx_descriptors.len() {
            // Allocate a new packet buffer
            let (rx_buf_phys, rx_buf) = alloc_phys([0u8; 2048]);

            // Store the packet buffer in the descriptor table
            rx_descriptors[ii].buffer = rx_buf_phys.0;

            // Save the reference to the buffer
            rx_buffers.push(rx_buf);
        }
        
        // Create the TX descriptors
        let (tx_descriptors_phys, tx_descriptors) =
            alloc_phys([LegacyTxDesc::default(); NUM_RX_DESCS]);

        // Create the TX buffers
        let mut tx_buffers = Vec::new();
        for ii in 0..tx_descriptors.len() {
            // Allocate a new packet buffer
            let (tx_buf_phys, tx_buf) = alloc_phys([0u8; 2048]);

            // Store the packet buffer in the descriptor table
            tx_descriptors[ii].buffer = tx_buf_phys.0;

            // Save the reference to the buffer
            tx_buffers.push(tx_buf);
        }
        
        // Create the NIC
        let mut nic = IntelGbit {
            pci_device: device,
            mmio,
            rx_descriptors,
            rx_descriptors_phys,
            rx_buffers,
            rx_head: 0,
            tx_descriptors,
            tx_descriptors_phys,
            tx_buffers,
            tx_head: 0,
            mac: [0u8; 6],
        };

        unsafe {
            // Reset the NIC
            nic.write(0, nic.read(0) | (1 << 26));

            // Wait for the reset to clear
            while (nic.read(0) & (1 << 26)) != 0 {}

            // Write all `f`s to the IMC to disable all interrupts
            nic.write(0xd8, !0);

            // Initialize the NIC for receive
            {
                // Program the receive descriptor base
                nic.write(0x2800,
                          (nic.rx_descriptors_phys.0 >>  0) as u32); // low
                nic.write(0x2804,
                          (nic.rx_descriptors_phys.0 >> 32) as u32); // high

                // Write in the size of the RX descriptor queue
                let queue_size = core::mem::size_of_val(nic.rx_descriptors);
                nic.write(0x2808, queue_size as u32);

                // Set the RX head
                nic.write(0x2810, 0);

                // Set the RX tail
                nic.write(0x2818, nic.rx_descriptors.len() as u32 - 1);
            }
             
            // Initialize the NIC for transmit
            {
                // Program the transmit descriptor base
                nic.write(0x3800,
                          (nic.tx_descriptors_phys.0 >>  0) as u32); // low
                nic.write(0x3804,
                          (nic.tx_descriptors_phys.0 >> 32) as u32); // high

                // Write in the size of the TX descriptor queue
                let queue_size = core::mem::size_of_val(nic.tx_descriptors);
                nic.write(0x3808, queue_size as u32);
            
                // Set the TX head
                nic.write(0x3810, 0);

                // Set the TX tail
                nic.write(0x3818, 0);
            }

            // Read the receive address high and low for the first entry
            // in the RX MAC filter. We assume this holds the MAC address of
            // this NIC
            let ral = nic.read(0x5400);
            let rah = nic.read(0x5404);
            let mut mac = [0u8; 6];
            assert!((rah & (1 << 31)) != 0, "Whoa, couldn't get MAC");
            mac[0..4].copy_from_slice(&ral.to_le_bytes());
            mac[4..6].copy_from_slice(&(rah as u16).to_le_bytes());
            nic.mac = mac;
            
            // Enable RX, and accept broadcast packets
            nic.write(0x100, (1 << 15) | (1 << 1));
            
            // Enable TX
            nic.write(0x400, 1 << 1);
        }

        nic
    }

    /// Receive a raw ethernet frame from the NIC
    #[allow(unused)]
    pub fn recv(&mut self, buffer: &mut [u8]) -> Option<usize> {
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
            let rxed =
                read_volatile(&self.rx_descriptors[self.rx_head].len) as usize;
            buffer[..rxed].copy_from_slice(
                &self.rx_buffers[self.rx_head][..rxed]);

            // Clear the status to put the buffer back up for use
            write_volatile(&mut self.rx_descriptors[self.rx_head].status, 0);

            // Let the NIC know this buffer is available for use again
            self.write(0x2818, self.rx_head as u32);

            // Bump the RX head
            self.rx_head = (self.rx_head + 1) % self.rx_descriptors.len();
        
            Some(rxed)
        }
    }

    /// Transmit a raw ethernet frame with the FCS automatially inserted by
    /// the NIC
    #[allow(unused)]
    pub fn send(&mut self, payload: &[u8]) {
        unsafe {
            // Compute the tail index for this transmit
            let tail = (self.tx_head + 1) % self.tx_descriptors.len();

            // Fill in the TX descriptor
            write_volatile(&mut self.tx_descriptors[self.tx_head].cmd,
                           (1 << 1) | (1 << 0));
            write_volatile(&mut self.tx_descriptors[self.tx_head].len,
                           payload.len() as u16);

            // Copy the payload into the transmit buffer
            self.tx_buffers[self.tx_head][..payload.len()]
                .copy_from_slice(payload);

            // Bump the tail pointer on the NIC
            self.write(0x3818, tail as u32);

            // Bump the TX head as we've used this slot
            self.tx_head = tail;

            // Wait for the NIC to actaully transmit the packet
            while self.read(0x3810) != tail as u32 {}
        }
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

impl Device for IntelGbit {
    unsafe fn purge(&mut self) {
    }
}

