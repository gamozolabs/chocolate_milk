//! The worlds #1 TCP implementation

use core::convert::TryInto;
use crate::time;
use crate::net::{Ip, ETHTYPE_IPV4, IPPROTO_TCP};
use crate::net::{Packet, NetDevice, NetAddress};
use crate::core_locals::LockInterrupts;
use alloc::sync::Arc;
use alloc::collections::VecDeque;
use noodle::Writer;
use lockcell::LockCell;

/// Maximum number of bytes to use for TCP windows
const WINDOW_SIZE: u16 = 65535;

/// Number of microseconds to wait before timing out on a SYN-ACK response
const CONNECT_TIMEOUT: u64 = 100_000;

/// TCP final flag (indicates last packet from sender)
pub const TCP_FIN: u16 = 1 << 0;

/// TCP synchronize flag (indicates a request to synchronize sequence numbers)
pub const TCP_SYN: u16 = 1 << 1;

/// TCP reset flag (reset a TCP connection)
pub const TCP_RST: u16 = 1 << 2;

/// TCP push flag (indicates the buffered data should be flushed to the
/// application)
pub const TCP_PSH: u16 = 1 << 3;

/// TCP acknoledge (marks that the acknowledge field of the TCP packet is
/// valid)
pub const TCP_ACK: u16 = 1 << 4;

/// TCP connection
pub struct TcpConnection(Arc<LockCell<TcpConnectionInt, LockInterrupts>>);

/// TCP connection
pub struct TcpConnectionInt {
    /// Reference to the network device we are a bound on
    device: Arc<NetDevice>,

    /// TCP receive window
    window: VecDeque<u8>,

    /// Address of the remote server
    server: NetAddress,

    /// Tracks if the connection is established
    connection_established: bool,

    /// Current sequence
    seq: u32,

    /// Current acknowledge
    ack: u32,

    /// Last observed sequence number from the remote side
    remote_seq: u32,

    /// Last observed acknowledge number from the remote side
    remote_ack: u32,

    /// Last observed window size from the remote side
    remote_window: u16,

    /// Remote MSS sent by the server
    remote_mss: u32,

    /// Port we are bound to
    port: u16,
}

impl TcpConnectionInt {
    /// Handle a packet which is destined for our window
    pub fn discard(&mut self, tcp: &Tcp) {
        if self.connection_established == false {
            return;
        }

        if tcp.flags & TCP_ACK == 0 {
            // All packets should be acks at this point
            return;
        }
        
        // Drop packets that are not in order
        if tcp.seq != self.ack { return; }
        
        // Get remainder of bytes in our window
        let window_rem = WINDOW_SIZE as usize - self.window.len();

        if tcp.payload.len() > window_rem {
            // Can't store something larger than our window
            return;
        }

        // Get number of unacknowledged bytes
        let unacked = self.seq.wrapping_sub(self.remote_ack);

        // Get the amount of bytes that this ack would increase
        // the ack count by
        let ack_increase = tcp.ack.wrapping_sub(self.remote_ack);
        if ack_increase > unacked {
            // Acknowledged bytes that were not sent by us
            return;
        }

        // Update the server state
        self.remote_seq    = tcp.seq;
        self.remote_ack    = tcp.ack;
        self.remote_window = tcp.window;
    
        // Extend the window
        self.window.extend(tcp.payload);

        // Update the ack to indicate we read the bytes
        self.ack = self.remote_seq
            .wrapping_add(tcp.payload.len() as u32);

        // Ack everything so far
        let mut packet = self.device.allocate_packet();
        {
            // Create a new TCP packet
            packet.create_tcp(
                &self.server, TCP_ACK,
                self.seq, self.ack,
                (WINDOW_SIZE as usize - self.window.len()) as u16,
                &[]);
        }

        // Send the packet
        self.device.send(packet, true);
    }
}

impl TcpConnection {
    /// Send a payload over the TCP connection
    /// Currently this returns `Some(())` if and only if all bytes are sent.
    /// If the send never completes, this function never returns.
    pub fn send(&self, buf: &[u8]) -> Option<()> {
        // Get access to the device as a new `Arc`
        let device = self.0.lock().device.clone();

        // Pointer to the data to send
        let mut ptr = &buf[..];

        // Timeout on acks
        let mut timeout = !0;

        loop {
            {
                // Get mutable access to the TCP connection
                let mut conn = self.0.lock();

                if cpu::rdtsc() >= timeout {
                    // We didn't get an ack in a timely manner and we either
                    // have no window left, or we have sent everything and
                    // we're waiting for the final ack

                    // Compute how much we have sent so far
                    let sent = buf.len() - ptr.len();

                    // Get the number of unacknowledged bytes
                    let unacked =
                        conn.seq.wrapping_sub(conn.remote_ack) as usize;

                    // Rewind the pointer
                    ptr = &buf[sent - unacked..];

                    // Set sequence back to old sequence
                    conn.seq = conn.remote_ack;
                }

                if let Some(pkt) = device.recv() {
                    if let Some(tcp) = pkt.tcp() {
                        if tcp.dst_port != conn.port {
                            // Packet wasn't for us
                            device.discard(pkt);
                            core::mem::drop(conn);
                            continue;
                        }

                        if tcp.flags & TCP_ACK == 0 {
                            // All packets should be acks at this point
                            continue;
                        }

                        // Get number of unacknowledged bytes
                        let unacked = conn.seq.wrapping_sub(conn.remote_ack);

                        // Get the amount of bytes that this ack would increase
                        // the ack count by
                        let ack_increase =
                            tcp.ack.wrapping_sub(conn.remote_ack);
                        if ack_increase > unacked {
                            // Acknowledged bytes that were not sent
                            continue;
                        }

                        // Drop out-of-order packets
                        if tcp.seq != conn.ack {
                            continue;
                        }

                        // Update the server state
                        conn.remote_seq    = tcp.seq;
                        conn.remote_ack    = tcp.ack;
                        conn.remote_window = tcp.window;
                        
                        if ptr.len() == 0 && conn.remote_ack == conn.seq {
                            // Everything has been written and has been acked
                            return Some(());
                        }
                    } else {
                        // Packet was not TCP, discard it
                        core::mem::drop(conn);
                        device.discard(pkt);
                    }
                }
            }
            
            // Get mutable access to the TCP connection
            let mut conn = self.0.lock();
                
            // Cap the MSS to a reasonable size
            let mss = core::cmp::min(conn.remote_mss as usize, 1560);

            // Compute the number of unacknowledged bytes by the remote end
            let unacked = conn.seq.wrapping_sub(conn.remote_ack) as usize;

            // Compute the number of bytes the remote server is capable of
            // accepting from this point, and make sure it does not exceed the
            // size of the buffer we want to send
            let remain = core::cmp::min(ptr.len(),
                (conn.remote_window as usize).saturating_sub(unacked));

            if remain == 0 {
                // We either have no window available to send anything, or we
                // have sent everything and we're waiting for the final ack
                continue;
            }

            // Iterate through `mss` size chunks in the `remain` of the buffer
            let mut iter = ptr[..remain].chunks(mss);
            while let Some(chunk) = iter.next() {
                // Allocate a packet
                let mut packet = device.allocate_packet();

                {
                    // Create a new TCP packet
                    let mut packet = packet.create_tcp(
                        &conn.server,
                        TCP_ACK | if iter.len() == 0 { TCP_PSH } else { 0 },
                        conn.seq, conn.ack,
                        (WINDOW_SIZE as usize - conn.window.len()) as u16,
                        &[]);

                    // Write in the chunk
                    packet.write(chunk);
                }

                // Update our sequence
                conn.seq = conn.seq.wrapping_add(chunk.len() as u32);

                // Send the packet
                device.send(packet, iter.len() == 0);
            }

            // Advance the pointer reflecting what we sent
            ptr = &ptr[remain..];

            // Set a timeout to wait for a window update
            timeout = time::future(1_000);
        }
    }

    /// Receives data until `buf` is full
    /// Doesn't return `Some(())` unless all bytes are successfuly read,
    /// currently this never times out if the data does not all get received
    pub fn recv(&self, buf: &mut [u8]) -> Option<()> {
        // Get a new reference to the device to break some lifetimes
        let device = self.0.lock().device.clone();

        // Get a pointer to the buffer
        let mut ptr = &mut buf[..];

        while ptr.len() > 0 {
            // Get mutable access to the TCP connection
            let mut conn = self.0.lock();

            {
                // Compute the number of bytes to consume
                let consumeable = core::cmp::min(conn.window.len(), ptr.len());
                for ii in 0..consumeable {
                    ptr[ii] = conn.window.pop_front().unwrap();
                }

                // Advance the pointer
                ptr = &mut ptr[consumeable..];
            }

            // Satisfied recv from the window
            if ptr.len() == 0 { break; }

            if let Some(pkt) = device.recv() {
                if let Some(tcp) = pkt.tcp() {
                    if tcp.dst_port != conn.port {
                        // Packet wasn't for us
                        core::mem::drop(conn);
                        device.discard(pkt);
                        continue;
                    }

                    if tcp.flags & TCP_ACK == 0 {
                        // All packets should be acks at this point
                        continue;
                    }
                    
                    // Get number of unacknowledged bytes
                    let unacked = conn.seq.wrapping_sub(conn.remote_ack);

                    // Get the amount of bytes that this ack would increase
                    // the ack count by
                    let ack_increase = tcp.ack.wrapping_sub(conn.remote_ack);
                    if ack_increase > unacked {
                        // Acknowledged bytes that were not sent by us
                        continue;
                    }
                
                    // If this is the next packet we are expecting
                    if tcp.seq == conn.ack {
                        // Update the server state
                        conn.remote_seq    = tcp.seq;
                        conn.remote_ack    = tcp.ack;
                        conn.remote_window = tcp.window;

                        // Update the ack to indicate we read the bytes
                        conn.ack = conn.remote_seq
                            .wrapping_add(tcp.payload.len() as u32);

                        // Compute the number of bytes to copy
                        let to_copy = core::cmp::min(ptr.len(),
                            tcp.payload.len());

                        // Copy the bytes in
                        ptr[..to_copy].copy_from_slice(
                            &tcp.payload[..to_copy]);

                        // Advance the pointer
                        ptr = &mut ptr[to_copy..];

                        // Check if there was a remainder of data
                        if tcp.payload.len() > to_copy {
                            // Get a slice to the remainder of data
                            let remainder = &tcp.payload[to_copy..];

                            // Make sure we don't overflow our window size
                            if remainder.len() + conn.window.len() <=
                                    WINDOW_SIZE as usize {
                                // Add the remainder to our TCP window
                                conn.window.extend(&tcp.payload[to_copy..]);
                            }
                        }
                    }

                    // Ack everything so far
                    let mut packet = device.allocate_packet();
                    {
                        // Create a new TCP packet
                        packet.create_tcp(
                            &conn.server, TCP_ACK,
                            conn.seq, conn.ack,
                            (WINDOW_SIZE as usize - conn.window.len()) as u16,
                            &[]);
                    }

                    // Send the packet
                    device.send(packet, true);
                } else {
                    // Packet wasnt TCP, discard it
                    core::mem::drop(conn);
                    device.discard(pkt);
                }
            }
        }

        Some(())
    }
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        let (device, port) = {
            // Get access to the TCP connection for a brief moment to get the
            // port and the device
            let conn = self.0.lock();
            (conn.device.clone(), conn.port)
        };

        // Remove the connection from the TCP connections
        let mut tcp_connections = device.tcp_connections.lock();
        tcp_connections.remove(&port)
            .expect("Failed to remove TCP port that was bound!?");
    }
}

impl NetDevice {
    /// Attempt to connect to a TCP server
    pub fn tcp_connect(cur: Arc<NetDevice>, server: &str)
            -> Option<TcpConnection> {
        // Break some lifetimes by getting a new device reference
        let device = cur.clone();
            
        // Try a bunch of different ports, looking for a free one
        'rebind: for _ in 0..100000 {
            // Get a unique port number in the range of `49152` and `65535`
            // inclusive
            let port = (cpu::rdtsc() % (65536 - 49152) + 49152) as u16;

            // Resolve the address for the server using ARP
            let server = NetAddress::resolve(&cur, port, server)?;

            let ret = {
                // Attempt to reserve the port
                let mut tcp_connections = cur.tcp_connections.lock();
                if tcp_connections.contains_key(&port) {
                    continue;
                }

                // Create the TCP connection
                let ret = Arc::new(LockCell::new(TcpConnectionInt {
                    window: VecDeque::with_capacity(WINDOW_SIZE as usize),
                    device:        cur.clone(),
                    seq:           cpu::rdtsc() as u32,
                    ack:           0,
                    server:        server,
                    remote_seq:    0,
                    remote_ack:    0,
                    remote_window: 0,
                    remote_mss:    536,
                    port:          port,
                    connection_established: false,
                }));

                // Insert the TCP connection
                tcp_connections.insert(port, ret.clone());
                TcpConnection(ret)
            };

            {
                // Send the SYN
                let mut conn = ret.0.lock();
                let mut packet = device.allocate_packet();
                {
                    // Create a new TCP packet
                    packet.create_tcp(
                        &conn.server, TCP_SYN, conn.seq, 0,
                        (WINDOW_SIZE as usize - conn.window.len()) as u16,
                        &[2, 4, 0x5, 0x8c]);
                }
                device.send(packet, true);
                
                // Update the sequence number by 1 since we sent a SYN
                conn.seq = conn.seq.wrapping_add(1);
            }

            // Compute the TSC value at the timeout
            let timeout = time::future(CONNECT_TIMEOUT);
            loop {
                // Wait for the SYN-ACK
                let mut conn = ret.0.lock();

                // Check if we have timed out
                if cpu::rdtsc() >= timeout {
                    continue 'rebind;
                }

                if let Some(pkt) = device.recv() {
                    if let Some(tcp) = pkt.tcp() {
                        if tcp.dst_port != conn.port {
                            // Packet wasn't for us
                            core::mem::drop(conn);
                            device.discard(pkt);
                            continue;
                        }

                        if tcp.flags & TCP_ACK == 0 {
                            // All packets should be acks at this point
                            continue;
                        }

                        // Make sure the sequence is what we expect
                        if tcp.ack != conn.seq {
                            continue;
                        }

                        if tcp.flags & TCP_RST != 0 {
                            // Active connection rejection
                            return None;
                        }

                        // Make sure this is a SYN response
                        if tcp.flags & TCP_SYN != 0 {
                            conn.remote_seq    = tcp.seq;
                            conn.remote_ack    = tcp.ack;
                            conn.remote_window = tcp.window;
                            break;
                        } else {
                            // Unexpected packet
                            continue;
                        }
                    } else {
                        // Packet wasn't TCP, discard it
                        core::mem::drop(conn);
                        device.discard(pkt);
                    }
                }
            }

            {
                // Ack the SYN-ACK
                let mut conn = ret.0.lock();
                let mut packet = device.allocate_packet();
                {
                    // Create a new TCP packet
                    conn.remote_seq = conn.remote_seq.wrapping_add(1);
                    conn.ack = conn.remote_seq;
                    packet.create_tcp(
                        &conn.server, TCP_ACK, conn.seq, conn.ack,
                        (WINDOW_SIZE as usize - conn.window.len()) as u16,
                        &[]);
                }
                device.send(packet, true);
            
                // Connection is now established
                conn.connection_established = true;
            }
            
            return Some(ret);
        }

        // Could not get a connection
        None
    }
}

/// A parsed TCP packet
#[derive(Debug)]
pub struct Tcp<'a> {
    /// IP header for the packet
    pub ip: Ip<'a>,

    pub src_port: u16,
    pub dst_port: u16,
    pub seq:      u32,
    pub ack:      u32,
    pub window:   u16,
    pub flags:    u16,

    /// TCP packet payload
    pub payload: &'a [u8],
}

impl Packet {
    /// Parse a TCP packet
    pub fn tcp(&self) -> Option<Tcp> {
        let ip = self.ip()?;

        // Make sure the minimal size for an TCP header is present
        if ip.payload.len() < 20 || ip.protocol != IPPROTO_TCP {
            return None;
        }

        // Get the TCP flags
        let flags = u16::from_be_bytes(ip.payload[0xc..0xe].try_into().ok()?);

        // Compute the size of the TCP header in bytes
        let data_offset = (flags >> 12) * 4;
        if data_offset < 20 {
            // Bad TCP header size
            return None;
        }

        Some(Tcp {
            src_port: u16::from_be_bytes(ip.payload[0..0x2].try_into().ok()?),
            dst_port: u16::from_be_bytes(ip.payload[2..0x4].try_into().ok()?),
            seq:      u32::from_be_bytes(ip.payload[4..0x8].try_into().ok()?),
            ack:      u32::from_be_bytes(ip.payload[8..0xc].try_into().ok()?),
            
            flags:  flags,
            window: u16::from_be_bytes(ip.payload[0xe..0x10].try_into().ok()?),

            payload: &ip.payload[data_offset as usize..],

            ip: ip,
        })
    }

    /// Create a new TCP packet
    #[inline]
    pub fn create_tcp<'a, 'b: 'a>(&'b mut self, addr: &'a NetAddress,
                                  flags: u16, seq: u32, ack: u32, window: u16,
                                  options: &'a [u8])
            -> TcpBuilder<'a> {
        assert!(options.len() % 4 == 0 && options.len() <= 40,
            "Invalid options for TCP header");

        TcpBuilder {
            packet:      self,
            addr:        addr,
            tcp_payload: 0,
            flags:       flags,
            seq:         seq,
            ack:         ack,
            window:      window,
            options:     options,
        }
    }
}

/// Builder for creating TCP packets in place. When this is dropped, the packet
/// lengths and checksums will be computed and populated.
pub struct TcpBuilder<'a> {
    /// Reference to the packet we are building in
    packet: &'a mut Packet,

    /// Number of bytes currently in the TCP payload
    tcp_payload: usize,

    /// Address to construct the packet with
    addr: &'a NetAddress,

    /// TCP flags to use for the packet
    flags: u16,

    /// Sequence number field
    seq: u32,

    /// Acknowledge field
    ack: u32,

    /// Window size
    window: u16,

    /// TCP options to add
    options: &'a [u8],
}

impl<'a> TcpBuilder<'a> {
    /// Reserve `size` bytes in the TCP payload, return a mutable slice to the
    /// bytes of the payload
    pub fn reserve(&mut self, size: usize) -> Option<&mut [u8]> {
        // Make sure this fits within the packet
        if self.tcp_payload.checked_add(size)? > 1456 {
            return None;
        }

        // Update the payload size
        self.tcp_payload += size;

        // Return a slice to the reserved area
        Some(&mut self.packet.raw[
             14 + 20 + 20 + self.options.len() + self.tcp_payload - size..
             14 + 20 + 20 + self.options.len() + self.tcp_payload
        ])
    }
}

impl<'a> Writer for TcpBuilder<'a> {
    fn write(&mut self, buf: &[u8]) -> Option<()> {
        // Make sure this fits within the packet
        if self.tcp_payload.checked_add(buf.len())? > 1456 {
            return None;
        }

        // Copy the buffer into the packet
        self.packet.raw[
            14 + 20 + 20 + self.options.len() + self.tcp_payload..
            14 + 20 + 20 + self.options.len() + self.tcp_payload + buf.len()
        ].copy_from_slice(buf);

        // Update the length of the TCP payload
        self.tcp_payload += buf.len();

        // Success!
        Some(())
    }
}

impl<'a> Drop for TcpBuilder<'a> {
    fn drop(&mut self) {
        {
            // Set up the ethernet header
            let eth = &mut self.packet.raw[..14];
            eth[0x0..0x6].copy_from_slice(&self.addr.dst_eth);
            eth[0x6..0xc].copy_from_slice(&self.addr.src_eth);
            eth[0xc..0xe].copy_from_slice(&ETHTYPE_IPV4.to_be_bytes());
        }
        
        {
            // Set up the IP header
            let ip = &mut self.packet.raw[14..14 + 20];

            // Set IPv4 as version and 20 byte header
            ip[0] = 0x45;

            // No DSCP and ECN
            ip[1] = 0;

            // Copy in the total length of the IP packet
            let ip_size = (20 + 20 + self.options.len() +
                           self.tcp_payload) as u16;
            ip[2..4].copy_from_slice(&ip_size.to_be_bytes());

            // Identification, flags, and fragment offset are all zero
            ip[4..8].copy_from_slice(&[0; 4]);

            // TTL is set to 64 (seems to be standard)
            ip[8] = 64;

            // Protocol is TCP
            ip[9] = IPPROTO_TCP;

            // Initialize the checksum to zero
            ip[10..12].copy_from_slice(&[0; 2]);

            // Copy in the source and dest IPs
            ip[12..16].copy_from_slice(&self.addr.src_ip.0.to_be_bytes());
            ip[16..20].copy_from_slice(&self.addr.dst_ip.0.to_be_bytes());

            // Compute the checksum and fill in the checksum field
            let checksum = Packet::checksum(0, ip);
            ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        }

        {
            // Set up the TCP header
            let tcp = &mut self.packet.raw[
                14 + 20..14 + 20 + 20 + self.options.len()];
            
            // Make the pseudo header for the checksum
            let mut pseudo = [0u8; 12];
            pseudo[0..4].copy_from_slice(&self.addr.src_ip.0.to_be_bytes());
            pseudo[4..8].copy_from_slice(&self.addr.dst_ip.0.to_be_bytes());
            pseudo[8..].copy_from_slice(&(((IPPROTO_TCP as u32) << 16) |
                                          (20 + self.options.len() as u32 +
                                           self.tcp_payload as u32))
                                        .to_be_bytes());

            // Copy in the source and dest ports
            tcp[0..2].copy_from_slice(&self.addr.src_port.to_be_bytes());
            tcp[2..4].copy_from_slice(&self.addr.dst_port.to_be_bytes());

            // Sequence number
            tcp[0x04..0x08].copy_from_slice(&self.seq.to_be_bytes());

            // Acknowledgement number
            tcp[0x08..0x0c].copy_from_slice(&self.ack.to_be_bytes());

            // Flags & data offset
            let header_size = (20 + self.options.len()) / 4;
            let flags = ((header_size as u16) << 12) | self.flags;
            tcp[0x0c..0x0e].copy_from_slice(&flags.to_be_bytes());

            // Window size
            tcp[0x0e..0x10].copy_from_slice(&self.window.to_be_bytes());
            
            // Checksum
            tcp[0x10..0x12].copy_from_slice(&(!Packet::checksum(0, &pseudo))
                                            .to_be_bytes());
            
            // Urgent pointer
            tcp[0x12..0x14].copy_from_slice(&0u16.to_be_bytes());

            // Copy in the options
            tcp[0x14..0x14 + self.options.len()].copy_from_slice(self.options);
        }

        // Set the length of the packet
        self.packet.set_len(14 + 20 + 20 + self.options.len() +
                            self.tcp_payload);

        // Indicate we need a TCP checksum inserted
        self.packet.tcp_checksum((14 + 20, 14 + 20 + 16));
    }
}

