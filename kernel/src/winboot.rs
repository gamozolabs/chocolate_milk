use core::convert::TryInto;
use page_table::{PhysAddr, PageType};
use crate::time;
use crate::vtx::{VmExit, Register, CpuMode};
use crate::net::netmapping::NetMapping;
use crate::fuzz_session::{BasicRegisterState, Worker, Segment, Address};

/// Drive index to be used with bios int 13h calls
const DRIVE_INDEX: u8 = 0x80;

pub fn main() {
    // Halt all other cores
    if core!().id != 0 { cpu::halt(); }

    // Netmap the disk image
    let it = cpu::rdtsc();
    let disk = NetMapping::new("192.168.101.1:1911",
                               "winboot/windows.img", true)
        .expect("Failed to netmap disk");
    let disk_load_time = time::elapsed(it);

    print!("Disk was loaded in {:.4} seconds\n", disk_load_time);

    // Create a worker
    let mut worker = Worker::new(1, None);
    
    // Set the debug control and EFER
    worker.set_reg(Register::DebugCtl, 0);
    worker.set_reg(Register::Efer,     0);

    // Set the selectors
    worker.set_reg(Register::Es,   0);
    worker.set_reg(Register::Cs,   0);
    worker.set_reg(Register::Ss,   0);
    worker.set_reg(Register::Ds,   0);
    worker.set_reg(Register::Fs,   0);
    worker.set_reg(Register::Gs,   0);
    worker.set_reg(Register::Ldtr, 0);
    worker.set_reg(Register::Tr,   0);

    // Set the selector bases
    worker.set_reg(Register::EsBase,   0);
    worker.set_reg(Register::CsBase,   0);
    worker.set_reg(Register::SsBase,   0);
    worker.set_reg(Register::DsBase,   0);
    worker.set_reg(Register::FsBase,   0);
    worker.set_reg(Register::GsBase,   0);
    worker.set_reg(Register::LdtrBase, 0);
    worker.set_reg(Register::TrBase,   0);
    worker.set_reg(Register::GdtrBase, 0);
    worker.set_reg(Register::IdtrBase, 0);
    
    // Set the selector limits
    worker.set_reg(Register::EsLimit,   0xffff);
    worker.set_reg(Register::CsLimit,   0xffff);
    worker.set_reg(Register::SsLimit,   0xffff);
    worker.set_reg(Register::DsLimit,   0xffff);
    worker.set_reg(Register::FsLimit,   0xffff);
    worker.set_reg(Register::GsLimit,   0xffff);
    worker.set_reg(Register::LdtrLimit, 0xffff);
    worker.set_reg(Register::TrLimit,   0xffff);
    worker.set_reg(Register::GdtrLimit, 0xffff);
    worker.set_reg(Register::IdtrLimit, 0xffff);
    
    // Set the selector limits
    worker.set_reg(Register::EsAccessRights,   0x93);
    worker.set_reg(Register::CsAccessRights,   0x93);
    worker.set_reg(Register::SsAccessRights,   0x93);
    worker.set_reg(Register::DsAccessRights,   0x93);
    worker.set_reg(Register::FsAccessRights,   0x93);
    worker.set_reg(Register::GsAccessRights,   0x93);
    worker.set_reg(Register::LdtrAccessRights, 0x82);
    worker.set_reg(Register::TrAccessRights,   0x83);
    
    worker.set_reg(Register::Cr0, 0x20);
    worker.set_reg(Register::Cr3, 0);
    worker.set_reg(Register::Cr4, 0x2000);

    worker.set_reg(Register::Dr7, 0x400);

    worker.set_reg(Register::Rdx,    DRIVE_INDEX as u64);
    worker.set_reg(Register::Rip,    0x7c00);
    worker.set_reg(Register::Rflags, 2);

    {
        let ept = worker.vm_mut().ept_mut();
        ept.map(PhysAddr(0), 1024 * 1024, PageType::Page4K,
            true, true, true).unwrap();
    }

    /// Base address to inject our BIOS, must be 16-byte aligned
    const BIOS_BASE: u64 = 0xf0000;

    // Start the pointer to our BIOS, where we write out random code we
    // want to be resident inside the guest
    let mut bios = 0xf0000;

    // Program the IVT to point to our BIOS
    for ivt in 0..256 {
        // Offset
        worker.write_phys(PhysAddr(ivt * 4 + 0),
            bios - BIOS_BASE).unwrap();

        // Segment
        worker.write_phys(PhysAddr(ivt * 4 + 2),
            (BIOS_BASE >> 4) as u16).unwrap();
        
        // Write in a vmcall and iret
        worker.write_phys_from(PhysAddr(bios), b"\x0f\x01\xc1\xcf").unwrap();
        bios += 4;
    }

    worker.write_phys_from(PhysAddr(0x7c00), &disk[..512]).unwrap();

    'vm_loop: loop {
        let (vmexit, _) = worker.vm_mut().run();

        match vmexit {
            VmExit::VmCall => {
                // VM call comes from our fake BIOS, determine the software
                // interrupt number based on the RIP value
                // Since we base our fake BIOS at f000:0000, the RIP values
                // for each software interrupt will be spaced by 4 bytes each
                // (vmcall instruction is 3 bytes, iret is 1).
                // Thus, RIP / 4 == BIOS interrupt code
                let rip = worker.reg(Register::CsBase) +
                    worker.reg(Register::Rip);

                // Check if this vmcall resides in our fake BIOS and we're in
                // real mode
                if worker.vm_mut().cpu_mode() != CpuMode::Real ||
                        rip < BIOS_BASE || rip >= bios {
                    break 'vm_loop;
                }

                // Determine the interrupt code
                let int = worker.reg(Register::Rip) / 4;

                // Read the iret frame
                let mut ipcs = [0u8; 6];
                let sp = worker.reg(Register::Rsp) as u16;
                if worker.read_addr(Address::PhysicalSegOff {
                    seg: Segment::Ss,
                    off: sp as u64,
                }, &mut ipcs).is_none() { break 'vm_loop; }

                // Get the CS:IP and flags from the iret frame
                let ip = u16::from_le_bytes(ipcs[0..2].try_into().unwrap());
                let cs = u16::from_le_bytes(ipcs[2..4].try_into().unwrap());
                let mut fl =
                    u16::from_le_bytes(ipcs[4..6].try_into().unwrap());

                if false {
                    print!("Got BIOS interrupt {:#x?} from {:04x}:{:04x}\n",
                           int, cs, ip);
                }

                let ah = worker.reg(Register::Ah);
                let dl = worker.reg(Register::Dl);

                match int {
                    0x10 if ah == 0x0e => {
                        // INT 10h AH=0Eh: Write Text in Teletype Mode
                        //
                        // In:
                        //
                        //   AH = 0x0e
                        //   AL = ASCII character
                        //   BH = Page number (text modes)
                        //   BL = forgeround pixel color (graphics modes)
                        //
                        // Out:
                        //
                        //   Nothing

                        // Get the ASCII character to write
                        let chr = worker.reg(Register::Al) as u8;
                        print!("{}", chr as char);
                    }
                    0x13 if ah == 0x00 => {
                        // INT 13h AH=00h: Reset Disk System
                        //
                        // In:
                        //
                        //   AH = 0x00
                        //   DL = drive index
                        //
                        // Out:
                        //
                        //   CF = Set on error
                        //   AH = Return code

                        if dl as u8 == DRIVE_INDEX {
                            // Clear error
                            fl &= !1;
                        } else {
                            // Set error
                            fl |= 1;
                        }
                    }
                    0x13 if ah == 0x41 => {
                        // INT 13h AH=41h: Check Extensions Present
                        //
                        // In:
                        //
                        //   AH = 0x41
                        //   DL = drive index
                        //   BX = 0x55AA
                        //
                        // Out:
                        //
                        //   CF = Set on not present, clear if present
                        //   AH = Error code or version number
                        //   BX = 0xAA55
                        //   CX = 1 if packet structure access supported
                   
                        // First, set the error flag by setting CF
                        fl |= 1;

                        if dl as u8 == DRIVE_INDEX {
                            // Set BX with the magic
                            worker.set_reg(Register::Bx, 0xaa55);
                            
                            // Set CX to indicate we support extended
                            worker.set_reg(Register::Cx, 1);

                            // Clear CF indicating we support extended reads
                            fl &= !1;
                        }
                    }
                    0x13 if ah == 0x42 => {
                        // INT 13h AH=42h: Extended Read Sectors From Drive
                        //
                        // In:
                        //
                        //   AH    = 0x42
                        //   DL    = drive index
                        //   DS:SI = Pointer to disk address packet
                        //
                        // Out:
                        //
                        //   CF = Set on error, clear on success
                        //   AH = Return code
                       
                        let mut handle = || -> Option<()> {
                            let mut dap = [0u8; 16];
                            let si = worker.reg(Register::Si);
                            worker.read_addr(Address::PhysicalSegOff {
                                seg: Segment::Ds,
                                off: si,
                            }, &mut dap)?;

                            // Make sure the DAP length is 16 bytes and the
                            // unused SBZ field is zero
                            if &dap[0..2] != b"\x10\x00" {
                                return None;
                            }

                            // Get the number of bytes to read
                            let num_bytes = (u16::from_le_bytes(dap[2..4]
                                .try_into().unwrap()) as usize) * 512;
                            
                            // Get the data buffer seg:off
                            let off = u16::from_le_bytes(dap[4..6]
                                .try_into().unwrap());
                            let seg = u16::from_le_bytes(dap[6..8]
                                .try_into().unwrap());

                            // Get the LBA for where the read should occur
                            let lba = u64::from_le_bytes(dap[8..16]
                                .try_into().unwrap()).checked_mul(512)?
                                as usize;
               
                            // Compute the linear physical address for the
                            // destination buffer
                            let addr = PhysAddr((seg << 4)
                                                .wrapping_add(off) as u64);
                            let disk_chunk = disk.get(lba..lba + num_bytes)?;
                            worker.write_phys_from(addr, disk_chunk)?;
                            
                            print!("Read from {:#x} into {:04x}:{:04x} of {} \
                                bytes\n", lba, seg, off, num_bytes);

                            Some(())
                        };

                        if handle().is_some() {
                            // Clear CF indiciating success
                            fl &= !1;
                        } else {
                            // Set CF indiciating error
                            fl |= 1;
                        }
                    }
                    x @ _ => {
                        print!("{}\n", BasicRegisterState::from_register_state(
                            worker.vm_mut().active_register_state()));
                        unimplemented!("BIOS interrupt {:#x?}", x);
                    }
                }

                // Advance RIP past the vmcall, now it will execute the iret
                worker.mod_reg(Register::Rip, |x| x + 3);
                
                // Update the iret frame
                let mut ipcs = [0u8; 6];
                ipcs[0..2].copy_from_slice(&ip.to_le_bytes());
                ipcs[2..4].copy_from_slice(&cs.to_le_bytes());
                ipcs[4..6].copy_from_slice(&fl.to_le_bytes());
                if worker.write_addr(Address::PhysicalSegOff {
                    seg: Segment::Ss,
                    off: sp as u64,
                }, &ipcs).is_none() { break 'vm_loop; }
                continue 'vm_loop;
            }
            VmExit::ExternalInterrupt => {
                continue 'vm_loop;
            }
            _ => {
                print!("Unhandled vmexit {:#x?}\n", vmexit);
            }
        }
    
        // If we fall through, we failed to handle the vmexit
        break 'vm_loop;
    }

    print!("{}\n", BasicRegisterState::from_register_state(
        worker.vm_mut().active_register_state()));
}

