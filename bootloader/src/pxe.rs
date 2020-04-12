//! Routines for using the real-mode PXE APIs as provided by the BIOS and/or
//! option ROMs

use core::convert::TryInto;
use alloc::vec::Vec;

use crate::realmode::{invoke_realmode, pxecall, RegisterState};

use lockcell::LockCell;

/// A guard to prevent multiple uses of the PXE API at the same time
static PXE_GUARD: LockCell<()> = LockCell::new(());

/// Convert a 16-bit `seg:off` pointer into a linear address
fn segoff_to_linear(seg: u16, off: u16) -> usize {
    ((seg as usize) << 4) + off as usize
}

/// Download a file with the `filename` over TFTP with the PXE 16-bit API
pub fn download<P: AsRef<[u8]>>(filename: P) -> Option<Vec<u8>> {
    // Lock access to PXE
    let _guard = PXE_GUARD.lock();

    // Convert the filename to a slice of bytes
    let filename: &[u8] = filename.as_ref();

    // Invoke the PXE installation check with int 0x1a
    let mut regs = RegisterState::default();
    regs.eax = 0x5650;
    unsafe { invoke_realmode(0x1a, &mut regs); }

    // Check that the PXE API responded as expected and CF has been cleared
    if regs.eax as u16 != 0x564e || (regs.efl & 1) != 0 {
        return None;
    }

    // Get the linear address to the PXENV+ structure
    let pxenv = segoff_to_linear(regs.es, regs.ebx as u16);
    let pxenv = unsafe {
        core::slice::from_raw_parts(pxenv as *const u8, 0x2c)
    };

    // Extract the fields we need to validate the PXENV+ structure
    let signature = &pxenv[..6];
    let length    = pxenv[0x8];
    let checksum  = pxenv.iter().fold(0u8, |acc, &x| acc.wrapping_add(x));

    // Check for correctness
    if signature != b"PXENV+" || length != 0x2c || checksum != 0 {
        return None;
    }

    // Get the pointer to the !PXE structure
    let off = u16::from_le_bytes(pxenv[0x28..0x2a].try_into().ok()?);
    let seg = u16::from_le_bytes(pxenv[0x2a..0x2c].try_into().ok()?);
    let pxe = segoff_to_linear(seg, off);
    let pxe = unsafe {
        core::slice::from_raw_parts(pxe as *const u8, 0x58)
    };

    // Extract the fields we need to validate the !PXE structure
    let signature = &pxe[..4];
    let length    = pxe[4];
    let checksum  = pxe.iter().fold(0u8, |acc, &x| acc.wrapping_add(x));

    // Check for correctness
    if signature != b"!PXE" || length != 0x58 || checksum != 0 {
        return None;
    }

    // Get the 16-bit PXE API entry point
    let ep_off = u16::from_le_bytes(pxe[0x10..0x12].try_into().ok()?);
    let ep_seg = u16::from_le_bytes(pxe[0x12..0x14].try_into().ok()?);
    
    // According to the spec "CS must not be 0000h"
    if ep_seg == 0 {
        return None;
    }

    // Determine the server IP from the cached information used during the PXE
    // boot process. We grab the DHCP ACK packet and extract the server IP
    // field from it.
    let server_ip: [u8; 4] = {
        const PXE_OPCODE_GET_CACHED_INFO: u16 = 0x71;
        const PXENV_PACKET_TYPE_DHCP_ACK: u16 = 2;

        #[derive(Default)]
        #[repr(C)]
        struct GetCachedInfo {
            status:       u16,
            packet_type:  u16,
            buffer_size:  u16,
            buffer_off:   u16,
            buffer_seg:   u16,
            buffer_limit: u16,
        }

        // Buffer to hold the DHCP ACK packet
        let mut pkt_buf = [0u8; 128];

        // Request the DHCP ACK packet
        let mut st = GetCachedInfo::default();
        st.packet_type = PXENV_PACKET_TYPE_DHCP_ACK;
        st.buffer_size = pkt_buf.len() as u16;
        st.buffer_seg  = 0;
        st.buffer_off  = &mut pkt_buf as *mut _ as u16;
        unsafe {
            pxecall(ep_seg, ep_off, PXE_OPCODE_GET_CACHED_INFO,
                0, &mut st as *mut _ as u16);
        }

        // Make sure this call was successful
        if st.status != 0 {
            return None;
        }

        // Extract the server IP
        pkt_buf[0x14..0x18].try_into().ok()?
    };

    print!("TFTP Server IP: {}.{}.{}.{}\n",
                   server_ip[0], server_ip[1], server_ip[2], server_ip[3]);

    // Get the file size for the next stage
    let file_size = {
        const PXE_OPCODE_TFTP_GET_FILE_SIZE: u16 = 0x25;

        #[repr(C, packed)]
        struct GetFileSize {
            status:     u16,
            server_ip:  [u8; 4],
            gateway_ip: [u8; 4],
            filename:   [u8; 128],
            file_size:  u32,
        }

        // Create the file size request
        let mut st = GetFileSize {
            status:     0,
            server_ip:  server_ip, 
            gateway_ip: [0; 4],
            filename:   [0; 128],
            file_size:  0,
        };

        // Check to see if we have enough room for the filename and null
        // terminator
        if filename.len() + 1 > st.filename.len() {
            return None;
        }

        // Copy in the file name
        st.filename[..filename.len()].copy_from_slice(filename);

        // Do the request
        unsafe {
            pxecall(ep_seg, ep_off, PXE_OPCODE_TFTP_GET_FILE_SIZE,
                0, &mut st as *mut _ as u16);
        }

        // Check that the call was successful
        if st.status != 0 {
            return None;
        }

        st.file_size as usize
    };

    print!("Requested file \"{}\" is {} bytes\n",
        core::str::from_utf8(filename).ok()?, file_size);

    // Open the file
    {
        const PXE_OPCODE_TFTP_OPEN: u16 = 0x20;

        #[repr(C)]
        struct TftpOpen {
            status:      u16,
            server_ip:   [u8; 4],
            gateway_ip:  [u8; 4],
            filename:    [u8; 128],
            tftp_port:   u16,
            packet_size: u16,
        }
        
        // Create the file open request
        let mut st = TftpOpen {
            status:      0,
            server_ip:   server_ip, 
            gateway_ip:  [0; 4],
            filename:    [0; 128],
            tftp_port:   69u16.to_be(),
            packet_size: 512,
        };

        // Check to see if we have enough room for the filename and null
        // terminator
        if filename.len() + 1 > st.filename.len() {
            return None;
        }

        // Copy in the file name
        st.filename[..filename.len()].copy_from_slice(filename);
        
        // Do the request
        unsafe {
            pxecall(ep_seg, ep_off, PXE_OPCODE_TFTP_OPEN,
                0, &mut st as *mut _ as u16);
        }

        // Check that the call was successful
        if st.status != 0 || st.packet_size != 512 {
            return None;
        }
    }

    // Read the file
    let mut download = Vec::with_capacity(file_size);
    loop {
        const PXE_OPCODE_TFTP_READ: u16 = 0x22;

        #[repr(C)]
        struct TftpRead {
            status:        u16,
            packet_number: u16,
            bytes_read:    u16,
            buffer_off:    u16,
            buffer_seg:    u16,
        }

        // Enough room to hold the packet size requested during open, which
        // we use the minimum 512 byte size
        let mut read_buf = [0u8; 512];

        // Create the read request
        let mut st = TftpRead {
            status:        0,
            packet_number: 0,
            bytes_read:    0,
            buffer_off:    &mut read_buf as *mut _ as u16,
            buffer_seg:    0,
        };
        
        // Do the request
        unsafe {
            pxecall(ep_seg, ep_off, PXE_OPCODE_TFTP_READ,
                0, &mut st as *mut _ as u16);
        }

        // Get the number of bytes read
        let bread = st.bytes_read as usize;
        
        // Check that the call was successful
        if st.status != 0 || bread > read_buf.len() {
            return None;
        }

        // Make sure we don't overflow our allocation. This can happen if the
        // file has changed since we got the size. We'll just fail here rather
        // than causing re-allocs which are not handled well with our
        // high-fragmentation bootloader heap.
        if download.len() + bread > download.capacity() {
            return None;
        }

        // Record the downloaded bytes
        download.extend_from_slice(&read_buf[..bread]);

        // Check to see if this was the final packet, indicated by a partial
        // packet
        if bread < read_buf.len() {
            break;
        }
    }

    // Close file
    {
        const PXE_OPCODE_TFTP_CLOSE: u16 = 0x21;

        // Create a status for returning
        let mut status: u16 = 0;
        
        // Do the request
        unsafe {
            pxecall(ep_seg, ep_off, PXE_OPCODE_TFTP_CLOSE,
                0, &mut status as *mut _ as u16);
        }
        
        // Check that the call was successful
        if status != 0 {
            return None;
        }
    }

    Some(download)
}

