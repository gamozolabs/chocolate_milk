//! A UDP protocol implementation

use core::convert::TryInto;
use alloc::sync::Arc;
use alloc::collections::VecDeque;

use crate::time;
use crate::net::{Ip, NetAddress, Packet, NetDevice, IPPROTO_UDP, ETHTYPE_IPV4};

use noodle::Writer;

/// Number of packets which will be buffered for each UDP port which is bound
/// on the system. This allows packets to be received even when we're not
/// directly receiving them.
const PACKET_BUFFER_SLOTS: usize = 128;

impl NetDevice {
    /// Allocate a new unused private port
    pub fn bind_udp(cur: Arc<Self>) -> Option<UdpBind> {
        for _ in 0..100000 {
            // Get a unique port number in the range of `49152` and `65535`
            // inclusive
            let port = (cpu::rdtsc() % (65536 - 49152) + 49152) as u16;

            // Attempt to bind to the UDP port
            if let Some(bind) = Self::bind_udp_port(cur.clone(), port) {
                return Some(bind);
            }
        }

        None
    }

    /// Bind to listen for all UDP packets destined to `port`
    pub fn bind_udp_port(cur: Arc<Self>, port: u16) -> Option<UdpBind> {
        // Get access to the UDP binds
        let mut udp_binds = cur.udp_binds.lock();

        // Check to see if someone already is listening on this port
        if !udp_binds.contains_key(&port) {
            // Nobody is listening, allocate a new bind queue
            udp_binds.insert(port,
                             VecDeque::with_capacity(PACKET_BUFFER_SLOTS));

            // Release the lock on the UDP binds
            core::mem::drop(udp_binds);

            // Return out the UDP bind
            Some(UdpBind {
                device: cur,
                port,
            })
        } else {
            // Someone already is bound to this port
            None
        }
    }

    /// Unbind from a UDP port
    fn unbind_udp(&self, port: u16) {
        // Get access to the UDP binds
        let queued_packets = self.udp_binds.lock().remove(&port).unwrap();
        
        // Give the packet back to the driver
        for packet in queued_packets {
            self.driver.release_packet(packet);
        }
    }
    
    /// Receive a UDP packet destined to a specific port
    fn recv_udp<T, F>(&self, port: u16, func: &mut F) -> Option<T>
            where F: FnMut(&Packet, Udp) -> Option<T> {
        {
            // Get access to the UDP binds
            let mut udp_binds = self.udp_binds.lock();

            // Get access to the UDP queue for this port
            let ent = udp_binds.get_mut(&port).unwrap();
            if !ent.is_empty() {
                let packet = ent.pop_front().unwrap();
                let ret = func(&packet, packet.udp().unwrap());
                self.driver.release_packet(packet);
                return ret;
            }
        }

        // Recv a packet, it could be any raw packet
        let packet = self.recv()?;
            
        // Attempt to parse the packet as UDP
        if let Some(udp) = packet.udp() {
            // Packet was UDP
            if udp.dst_port == port {
                func(&*packet, udp)
            } else {
                // Was not destined to our port
                self.discard(packet);
                None
            }
        } else {
            // Packet was not UDP, discard it
            self.discard(packet);
            None
        }
    }
}

impl Packet {
    /// Extract the UDP information from the payload, validating all layers
    pub fn udp(&self) -> Option<Udp> {
        // Parse the IP information from the header
        let ip = self.ip()?;

        if ip.protocol != IPPROTO_UDP {
            return None;
        }

        // Get the UDP header
        let header = ip.payload.get(0..8)?;

        // Parse the header
        let src_port = u16::from_be_bytes(header[0..2].try_into().ok()?);
        let dst_port = u16::from_be_bytes(header[2..4].try_into().ok()?);
        let length   = u16::from_be_bytes(header[4..6].try_into().ok()?);

        // Validate the length
        if length < 8 || length as usize > ip.payload.len() {
            return None;
        }

        // Return out the UDP information
        Some(Udp {
            payload: &ip.payload[8..length as usize],
            src_port,
            dst_port,
            ip,
        })
    }

    /// Create a new raw UDP packet
    /// Returns the index into the packet where the message should be placed.
    #[inline]
    pub fn create_udp<'a, 'b: 'a>(&'b mut self, addr: &'a NetAddress)
            -> UdpBuilder<'a> {
        // Return the index of where to populate the message payload
        UdpBuilder {
            packet:      self,
            addr:        addr,
            udp_payload: 0,
        }
    }
}

/// UDP bound port
pub struct UdpBind {
    /// Reference to the network device we are a bound on
    device: Arc<NetDevice>,

    /// Port we are bound to
    port: u16,
}

impl UdpBind {
    /// Attempt to receive a UDP packet on the bound port
    #[allow(unused)]
    pub fn recv<T, F>(&self, mut func: F) -> Option<T>
            where F: FnMut(&Packet, Udp) -> Option<T> {
        self.device.recv_udp(self.port, &mut func)
    }

    /// Attempts to receive a UDP packet on the bound port in a loop for a
    /// given `timeout` in microseconds
    pub fn recv_timeout<T, F>(&self, timeout: u64, mut func: F) -> Option<T> 
            where F: FnMut(&Packet, Udp) -> Option<T> {
        // Compute the TSC value at the timeout
        let timeout = time::future(timeout);

        loop {
            // Check if we have timed out
            if cpu::rdtsc() >= timeout { return None; }

            if let Some(val) = self.device.recv_udp(self.port, &mut func) {
                return Some(val);
            }
        }
    }

    /// Gets the port number this UDP bind is bound to
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get access to the `NetDevice` that this `UdpBind` is bound to
    pub fn device(&self) -> &NetDevice {
        &*self.device
    }
}

impl Drop for UdpBind {
    fn drop(&mut self) {
        // Unbind from the UDP port
        self.device.unbind_udp(self.port);
    }
}

/// A parsed UDP header + payload
#[derive(Debug)]
pub struct Udp<'a> {
    /// IP header for the packet
    pub ip: Ip<'a>,
    
    /// Destination port (in host order, eg: 50 = port 50)
    pub dst_port: u16,
    
    /// Source port (in host order, eg: 50 = port 50)
    pub src_port: u16,

    /// Raw payload of the UDP packet
    pub payload: &'a [u8],
}

/// Builder for creating UDP packets in place. When this is dropped, the packet
/// lengths and checksums will be computed and populated.
pub struct UdpBuilder<'a> {
    /// Reference to the packet we are building in
    packet: &'a mut Packet,

    /// Number of bytes currently in the UDP payload
    udp_payload: usize,

    /// Address to construct the packet with
    addr: &'a NetAddress,
}

impl<'a> UdpBuilder<'a> {
    /// Reserve `size` bytes in the UDP payload, return a mutable slice to the
    /// bytes of the payload
    pub fn reserve(&mut self, size: usize) -> Option<&mut [u8]> {
        // Make sure this fits within the packet
        if self.udp_payload.checked_add(size)? > 1472 {
            return None;
        }

        // Update the payload size
        self.udp_payload += size;

        // Return a slice to the reserved area
        Some(&mut self.packet.raw[
             14 + 20 + 8 + self.udp_payload - size..
             14 + 20 + 8 + self.udp_payload
        ])
    }
}

impl<'a> Writer for UdpBuilder<'a> {
    fn write(&mut self, buf: &[u8]) -> Option<()> {
        // Make sure this fits within the packet
        if self.udp_payload.checked_add(buf.len())? > 1472 {
            return None;
        }

        // Copy the buffer into the packet
        self.packet.raw[
            14 + 20 + 8 + self.udp_payload..
            14 + 20 + 8 + self.udp_payload + buf.len()
        ].copy_from_slice(buf);

        // Update the length of the UDP payload
        self.udp_payload += buf.len();

        // Success!
        Some(())
    }
}

impl<'a> Drop for UdpBuilder<'a> {
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
            let ip_size = (20 + 8 + self.udp_payload) as u16;
            ip[2..4].copy_from_slice(&ip_size.to_be_bytes());

            // Identification, flags, and fragment offset are all zero
            ip[4..8].copy_from_slice(&[0; 4]);

            // TTL is set to 64 (seems to be standard)
            ip[8] = 64;

            // Protocol is UDP
            ip[9] = IPPROTO_UDP;

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
            // Set up the UDP header
            let udp = &mut self.packet.raw[14 + 20..14 + 20 + 8];

            // Copy in the source and dest ports
            udp[0..2].copy_from_slice(&self.addr.src_port.to_be_bytes());
            udp[2..4].copy_from_slice(&self.addr.dst_port.to_be_bytes());

            // Compute and copy in the UDP size + header
            let udp_size = (8 + self.udp_payload) as u16;
            udp[4..6].copy_from_slice(&udp_size.to_be_bytes());

            // No checksum (not required for IPv4)
            udp[6..8].copy_from_slice(&[0; 2]);
        }

        // Set the length of the packet
        self.packet.set_len(14 + 20 + 8 + self.udp_payload);
    }
}

