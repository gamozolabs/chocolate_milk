//! The worlds #1 TCP implementation

use core::convert::TryInto;
use crate::time;
use crate::net::{Ip, ETHTYPE_IPV4, IPPROTO_TCP};
use crate::net::{Packet, NetDevice, NetAddress};
use crate::core_locals::LockInterrupts;
use alloc::sync::Arc;
use alloc::collections::VecDeque;
use noodle::{Reader, Writer};
use lockcell::LockCell;

/// Maximum number of bytes to use for TCP windows
const WINDOW_SIZE: u16 = 65535;

/// Number of microseconds to wait before timing out on a SYN-ACK response
const CONNECT_TIMEOUT: u64 = 1_000_000;

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

/// States of a TCP connection
#[derive(PartialEq, Eq)]
enum TcpState {
    /// Connection is closed
    Closed,

    /// We've sent the initial SYN and are awaiting a SYN-ACK
    SynSent,

    /// We have sent an ACK in response to a SYN-ACK
    /// It's possible we get another SYN-ACK in this state in the case that
    /// the ACK we responded with was dropped
    Established,
}

/// TCP connection
pub struct TcpConnectionInt {
    /// Reference to the network device we are a bound on
    device: Arc<NetDevice>,

    /// TCP receive window
    window: VecDeque<u8>,

    /// Address of the remote server
    server: NetAddress,

    /// Tracks the state of the TCP connection
    state: TcpState,

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
        // Handle the packet
        self.handle_packet(tcp, None);
    }

    /// Handle a packet we got from the remote side
    ///
    /// This could be a packet providing us with new data, or simply just an
    /// ack of data we sent it. We should handle all cases of any TCP packet
    /// we get here.
    ///
    /// If `window_bypass` is `Some`, it contains a reference to a slice of
    /// bytes which will directly receive any bytes that are received during
    /// packet handling. If the received bytes exceeds this buffer, the
    /// remaining bytes will go into the connection's window buffer.
    ///
    /// This window bypass allows us to directly copy packet bytes into the
    /// user's buffer in the common-case, rather than taking a middle step
    /// through the connection window.
    pub fn handle_packet(&mut self, tcp: &Tcp,
                         window_bypass: Option<&mut [u8]>) -> Option<usize> {
        // The caller should filter to make sure it doesn't handle packets for
        // another port. This gives the caller the opportunity to discard the
        // packet back to the network stack.
        assert!(self.port == tcp.dst_port);

        // Nothing to do
        if self.state == TcpState::Closed {
            return None;
        }

        // We only ever expect acks at this point
        if tcp.flags & TCP_ACK == 0 {
            return None;
        }

        // Get number of unacknowledged bytes, this tells us how much we have
        // sent the remote end, but we're waiting for them to acknowledge them
        let unacked = self.seq.wrapping_sub(self.remote_ack);

        // See how much the remote ack is advancing the state
        let ack_increase = tcp.ack.wrapping_sub(self.remote_ack);

        // Make sure the remote end is not acknowledging bytes that were never
        // sent. If it was, drop the packet.
        if ack_increase > unacked {
            return None;
        }
         
        // Drop out-of-order packets, this is going to be extremely rare in
        // the environment we run in, it's just not worth the extra complexity.
        if self.state == TcpState::Established && tcp.seq != self.ack {
            return None;
        }
        
        // Tracks the number of bytes copied into the window bypass
        let mut copied = 0;

        // Tracks if we need to send an ack
        let mut needs_ack = false;

        // Check if the packet contains any data
        if self.state == TcpState::Established && tcp.payload.len() > 0 {
            // Compute how much room our window has left
            let window_rem = WINDOW_SIZE as usize - self.window.len();

            // Drop packets that exceed our window, the remote side should
            // never send more than our window.
            // Even if we have a window bypass, we still want to validate
            // against our broadcast window, not our true capacity.
            if tcp.payload.len() > window_rem {
                return None;
            }

            // Get a slice referencing the payload from this packet
            let mut payload = &tcp.payload[..];

            // Check if the user directly wants bytes
            if let Some(window_bypass) = window_bypass {
                // Determine the smaller of the two slices
                let to_copy = core::cmp::min(window_bypass.len(),
                    payload.len());

                // Copy whatever we can into the window bypass
                window_bypass[..to_copy].copy_from_slice(&payload[..to_copy]);

                // Track the number of copied bytes into the window bypass
                copied = to_copy;

                // Advance the payload pointer
                payload = &payload[to_copy..];
            }

            // Save the data into our window
            self.window.extend(payload);
        
            // Update the ack to indicate we read the bytes
            self.ack = self.ack.wrapping_add(tcp.payload.len() as u32);
            needs_ack = true;
        }

        // Check if this packet may be a SYN-ACK which we are waiting for
        if (self.state == TcpState::SynSent ||
                self.state == TcpState::Established) &&
                tcp.flags & TCP_SYN != 0 {
            // If we just acked a SYN, update the connection state
            self.state = TcpState::Established;

            // Set our ack state to the server's sequence + 1
            self.ack = tcp.seq.wrapping_add(1);
            needs_ack = true;
        }

        // Send an ack if needed
        if needs_ack {
            let mut packet = self.device.allocate_packet();
            {
                packet.create_tcp(
                    &self.server, TCP_ACK, self.seq, self.ack,
                    (WINDOW_SIZE as usize - self.window.len()) as u16, &[]);
            }
            self.device.send(packet, true);
        }

        // Update the server state to the most recent packet information
        self.remote_seq    = tcp.seq;
        self.remote_ack    = tcp.ack;
        self.remote_window = tcp.window;

        // Return number of bytes copied into the window bypass
        Some(copied)
    }
}

impl TcpConnection {
    /// Send a payload over the TCP connection
    /// Currently this returns `Some(())` if and only if all bytes are sent.
    /// If the send never completes, this function never returns.
    pub fn send(&self, buf: &[u8]) -> Option<()> {
        let mut device = None;

        // Pointer to the data to send
        let mut ptr = &buf[..];

        // Timeout on acks
        let mut timeout = !0;

        loop {
            {
                // Get mutable access to the TCP connection
                let mut conn = self.0.lock();
                if conn.state != TcpState::Established { return None; }

                // Create a copy of the device to break some lifetime issues
                // Probably a better way to do this
                if device.is_none() {
                    device = Some(conn.device.clone());
                }

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

                if ptr.len() == 0 && conn.remote_ack == conn.seq {
                    // Everything has been written and has been acked
                    return Some(());
                }

                if let Some(pkt) = device.as_ref().unwrap().recv() {
                    if let Some(tcp) = pkt.tcp() {
                        // Check if this packet is destined for our port
                        if tcp.dst_port != conn.port {
                            // Packet wasn't for us
                            core::mem::drop(conn);
                            device.as_ref().unwrap().discard(pkt);
                            continue;
                        }
        
                        // Handle the packet we received
                        conn.handle_packet(&tcp, None);
                    } else {
                        // Packet was not TCP, discard it
                        core::mem::drop(conn);
                        device.as_ref().unwrap().discard(pkt);
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
                let mut packet = device.as_ref().unwrap().allocate_packet();

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
                device.as_ref().unwrap().send(packet, iter.len() == 0);
            }

            // Advance the pointer reflecting what we sent
            ptr = &ptr[remain..];

            // Set a timeout to wait for a window update
            timeout = time::future(1_000);
        }
    }

    /// Receives data from the TCP connection
    pub fn recv(&self, buf: &mut [u8]) -> Option<usize> {
        // Get a pointer to the buffer
        let mut ptr = &mut buf[..];

        // Get mutable access to the TCP connection
        let mut conn = self.0.lock();
        if conn.state != TcpState::Established { return None; }

        {
            // Compute the number of bytes to consume
            let consumeable = core::cmp::min(conn.window.len(), ptr.len());
            for ii in 0..consumeable {
                ptr[ii] = conn.window.pop_front().unwrap();
            }

            // Advance the pointer
            ptr = &mut ptr[consumeable..];
        }

        // Only attempt to recv a packet from the NIC if we have more to read
        if ptr.len() > 0 {
            let device = conn.device.clone();
            if let Some(pkt) = device.recv() {
                if let Some(tcp) = pkt.tcp() {
                    if tcp.dst_port != conn.port {
                        // Packet wasn't for us
                        core::mem::drop(conn);
                        device.discard(pkt);
                    } else {
                        // Handle the packet we RXed
                        if let Some(copied) =
                                conn.handle_packet(&tcp, Some(&mut ptr)) {
                            ptr = &mut ptr[copied..];
                        }
                    }
                } else {
                    // Packet wasnt TCP, discard it
                    core::mem::drop(conn);
                    device.discard(pkt);
                }
            };
        }

        let remain = ptr.len();
        Some(buf.len() - remain)
    }
}

impl Reader for TcpConnection {
    fn read(&mut self, buf: &mut [u8]) -> Option<usize> {
        self.recv(buf)
    }
}

impl Writer for TcpConnection {
    fn write(&mut self, buf: &[u8]) -> Option<()> {
        self.send(buf)
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
                let rand_seq = cpu::rdtsc() as u32;
                let ret = Arc::new(LockCell::new(TcpConnectionInt {
                    window: VecDeque::with_capacity(WINDOW_SIZE as usize),
                    device:        cur.clone(),
                    seq:           rand_seq,
                    ack:           0,
                    server:        server,
                    remote_seq:    0,
                    remote_ack:    rand_seq,
                    remote_window: 0,
                    remote_mss:    536,
                    port:          port,
                    state:         TcpState::Closed,
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

                // Update TCP state
                conn.state = TcpState::SynSent;
            }

            // Compute the TSC value at the timeout
            let timeout = time::future(CONNECT_TIMEOUT);
            loop {
                // Wait for the SYN-ACK
                let mut conn = ret.0.lock();
                        
                // Break if we've established the connection
                if conn.state == TcpState::Established {
                    break;
                }

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

                        // Handle the inbound packet
                        conn.handle_packet(&tcp, None);
                    } else {
                        // Packet wasn't TCP, discard it
                        core::mem::drop(conn);
                        device.discard(pkt);
                    }
                }
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
            let checksum = !Packet::checksum(0, ip);
            ip[10..12].copy_from_slice(&checksum.to_ne_bytes());
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
            
            // Zero out the initial checksum value
            tcp[0x10..0x12].copy_from_slice(&[0u8; 2]);
            
            // Urgent pointer
            tcp[0x12..0x14].copy_from_slice(&0u16.to_be_bytes());

            // Copy in the options
            tcp[0x14..0x14 + self.options.len()].copy_from_slice(self.options);
            
            // Checksum
            let csum = Packet::checksum(0, &pseudo);
            let csum = Packet::checksum(csum as u32, &self.packet.raw[
                14 + 20.. 
                14 + 20 + 20 + self.options.len() + self.tcp_payload]);
            self.packet.raw[14 + 20 + 0x10..14 + 20 + 0x12]
                .copy_from_slice(&(!csum).to_ne_bytes());
        }

        // Set the length of the packet
        self.packet.set_len(14 + 20 + 20 + self.options.len() +
                            self.tcp_payload);
    }
}

