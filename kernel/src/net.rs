//! Driver agnostic networking utilities

pub mod arp;
pub mod dhcp;
pub mod intel_nic;
pub mod netmapping;

use core::sync::atomic::{AtomicU32, Ordering};
use core::fmt::{self, Formatter, Debug};
use core::convert::TryInto;
use core::ops::{Deref, DerefMut};

use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};

use crate::time;
use crate::pci::Device;
use crate::mm::PhysContig;
use crate::net::dhcp::Lease;
use crate::core_locals::LockInterrupts;

use noodle::Writer;
use lockcell::LockCell;
use page_table::PhysAddr;

/// List of all network devices with valid DHCP leases on the system
static NET_DEVICES: LockCell<Vec<Arc<NetDevice>>, LockInterrupts> =
    LockCell::new(Vec::new());

/// IPv4 ethernet frame type
const ETHTYPE_IPV4: u16 = 0x0800;

/// UDP protocol for the IP header
const IPPROTO_UDP: u8 = 0x11;

/// UDP/TCP address
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NetAddress {
    pub src_eth:  [u8; 6],
    pub dst_eth:  [u8; 6],
    pub src_ip:   Ipv4Addr,
    pub dst_ip:   Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl NetAddress {
    /// Convert a `src_port` and destination string in the form "1.2.3.4:1337"
    /// into a `NetAddress`
    pub fn resolve(device: &NetDevice, src_port: u16, dst: &str)
            -> Option<NetAddress> {
        let mut iter = dst.split(":");
        let dst_ip   = Ipv4Addr::from(iter.next().unwrap());
        let dst_port = u16::from_str_radix(iter.next().unwrap(), 10)
            .expect("Invalid UDP address:port string");
        assert!(iter.next().is_none(), "Invalid UDP address:port string");

        Some(NetAddress {
            src_eth:  device.mac(),
            dst_eth:  device.arp(dst_ip)?,
            src_ip:   device.dhcp_lease.lock().as_ref().unwrap().client_ip,
            dst_ip:   dst_ip,
            src_port: src_port,
            dst_port: dst_port,
        })
    }
}

/// IPv4 address
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(C)]
pub struct Ipv4Addr(u32);

impl From<u32> for Ipv4Addr {
    fn from(val: u32) -> Self { Ipv4Addr(val) }
}

impl From<&str> for Ipv4Addr {
    fn from(val: &str) -> Self {
        let mut bytes = [0u8; 4];

        assert!(val.split(".").count() == 4, "Invalid IPv4 address");

        for (ii, component) in val.split(".").enumerate() {
            bytes[ii] = u8::from_str_radix(component, 10)
                .expect("Invalid IPv4 address");
        }

        Ipv4Addr(u32::from_be_bytes(bytes))
    }
}

impl From<Ipv4Addr> for u32 {
    fn from(val: Ipv4Addr) -> Self { val.0 }
}

impl Debug for Ipv4Addr {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        let ip = self.0.to_be_bytes();
        write!(fmt, "{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
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

/// An implementation for a network device. This holds packet queues and has
/// an underlying driver to send and recv from.
pub struct NetDevice {
    /// Driver that provides raw RX and TX to the network
    driver: Box<dyn NetDriver>,

    /// MAC address for the network card
    mac: [u8; 6],

    /// The DHCP lease that was obtained during `init`. May be `None` if no
    /// DHCP lease was obtained
    pub dhcp_lease: LockCell<Option<Lease>, LockInterrupts>,

    /// Next dynamic port to give out for use as an ephemeral port. This value
    /// will just increment from 0 thus the user should add `49152` to the base
    /// and mod to cap the range to `65535`. This is the recommended range
    /// by IANA to use for dynamically allocated ports.
    dynamic_port: AtomicU32,

    /// Packet queues for bound UDP ports
    ///
    /// When packets are parsed and they're valid UDP packets to existing bound
    /// UDP ports, we will store the packets in these lists
    udp_binds: LockCell<BTreeMap<u16, VecDeque<Packet>>, LockInterrupts>,
}

impl NetDevice {
    /// Get the least condended network device on the system
    pub fn get() -> Option<Arc<Self>> {
        // Least contended network device on the system
        let mut ret: Option<Arc<Self>> = None;

        // Go through all network devices on the system looking for the least
        // contended network device
        for net_device in NET_DEVICES.lock().iter() {
            // Compute the current best strong count for a net device. We
            // subtract 1 because storing it in `ret` increases the strong
            // count unconditonally by 1.
            let cur_best_strong_count =
                ret.as_ref().map(|x| Arc::strong_count(x) - 1).unwrap_or(!0);

            // If the network device we're iterating has fewer references than
            // the current best strong count, then we want to use that network
            // device.
            if Arc::strong_count(&net_device) < cur_best_strong_count {
                ret = Some(net_device.clone());
            }
        }

        ret
    }

    /// Wrap up a driver in a `NetDevice`
    fn new(driver: Box<dyn NetDriver>) -> Arc<Self> {
        // Create a new `NetDevice`
        let nd = NetDevice {
            mac:          driver.mac(),
            udp_binds:    LockCell::new_no_preempt(BTreeMap::new()),
            driver:       driver,
            dhcp_lease:   LockCell::new_no_preempt(None),
            dynamic_port: AtomicU32::new(0),
        };
        
        // Wrap up the network device in an `Arc`
        let nd = Arc::new(nd);

        // Attempt to get a DHCP lease for this device
        let lease = dhcp::get_lease(nd.clone());

        {
            // Assign the lease
            let mut dhcp_lease = nd.dhcp_lease.lock();
            *dhcp_lease = lease;

            // Check to see if we got a DHCP lease
            if dhcp_lease.is_some() {
                // Save this network device to the list of network devices
                NET_DEVICES.lock().push(nd.clone());
            }
        }

        nd
    }

    /// Allocate a new unused private port
    pub fn bind_udp(cur: Arc<Self>) -> Option<UdpBind> {
        for _ in 0..(65536 - 49152) {
            // Get a unique port number in the range of `49152` and `65535`
            // inclusive
            let port = (cur.dynamic_port.fetch_add(1, Ordering::SeqCst) %
                (65536 - 49152) + 49152) as u16;

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
            udp_binds.insert(port, VecDeque::new());

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

    /// Receive a raw packet from the network
    pub fn recv(&self) -> Option<PacketLease> {
        self.driver.recv().and_then(|packet| {
            // We want to automatically respond to ARPs
            if let Some(lease) = self.dhcp_lease.lock().as_ref() {
                let our_ip = lease.client_ip;
                if let Some(arp) = packet.arp() {
                    if arp.hw_type == arp::HWTYPE_ETHERNET &&
                            arp.proto_type == ETHTYPE_IPV4 &&
                            arp.hw_size    == 6 &&
                            arp.proto_size == 4 &&
                            arp.opcode     == arp::Opcode::Request as u16 &&
                            arp.target_ip  == our_ip {
                        // Reply to the ARP
                        self.arp_reply(lease.client_ip,
                                       arp.sender_ip, arp.sender_mac);
                        return None;
                    }
                }
            }
        
            Some(packet)
        })
    }

    /// Receive a UDP packet destined to a specific port
    fn recv_udp<T, F>(&self, port: u16, func: &mut F) -> Option<T>
            where F: FnMut(&Packet, Udp) -> Option<T> {
        // Get access to the UDP binds
        let mut udp_binds = self.udp_binds.lock();

        {
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
                // Wasn't for us, attempt to save it to an existing bind
                udp_binds.get_mut(&udp.dst_port).map(|x| {
                    x.push_back(PacketLease::take(packet));
                });
                None
            }
        } else {
            // Packet was not UDP, drop it
            None
        }
    }
    
    /// Send a raw frame over the network containing the bytes `packet`. This
    /// `packet` does not include the FCS, that must be computed or inserted
    /// by the driver.
    pub fn send(&self, packet: Packet, flush: bool) {
        self.driver.send(packet, flush);
    }

    /// Allocate a new packet for use
    pub fn allocate_packet(&self) -> Packet {
        self.driver.allocate_packet()
    }

    /// Get the MAC address for this network device
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }
}

impl Device for NetDevice {
    unsafe fn purge(&self) {
        // TODO
        //panic!("Implement purge for net device");
    }
}

/// Driver-implemented trait to get generic access to network card RX and TX
pub trait NetDriver {
    /// Gets the MAC address of the hardware
    fn mac(&self) -> [u8; 6];

    /// Recv a raw frame from the network and return ownership of the raw
    /// physical buffer that was used for the DMA of the packet
    ///
    /// The received packet length should not include the FCS and the FCS
    /// should be validated by the driver
    fn recv<'a, 'b: 'a>(&'b self) -> Option<PacketLease<'a>>;

    /// Send a raw frame over the network containing the bytes `packet`. This
    /// `packet` does not include the FCS, that must be computed or inserted
    /// by the driver.
    fn send(&self, packet: Packet, flush: bool);
    
    /// Get a packet from the NIC's packet free list. This allows us to give
    /// ownership of a packet during the `send` process, which the NIC can then
    /// use for whatever it needs. And we can get back packets from the NIC
    /// when we need a packet.
    ///
    /// It is strongly recommended that a NIC implements it's own packet free
    /// list as creating and freeing packets requires physical memory
    /// allocations and virtual memory mappings
    fn allocate_packet(&self) -> Packet {
        // By default, create a new packet out of the global allocator
        Packet::new()
    }

    /// When the network stack is done with a packet lease, it will give it
    /// back to the NIC that it got the packet from.
    fn release_packet(&self, _packet: Packet) {
        // By default, do nothing with the packet, causing it to get freed back
        // to the global allocator
    }
}

/// A parsed ethernet header + payload
#[derive(Debug)]
pub struct Ethernet<'a> {
    /// Destination MAC address
    pub dst_mac: [u8; 6],

    /// Source MAC address
    pub src_mac: [u8; 6],

    /// Type of the ethernet payload
    pub typ: u16,

    /// Raw bytes following the ethernet header
    pub payload: &'a [u8],
}

/// A parsed IP header + payload
#[derive(Debug)]
pub struct Ip<'a> {
    /// Ethernet header for the packet
    pub eth: Ethernet<'a>,

    /// Source IP address (in host order, eg. 0xc0000000 is 192.0.0.0)
    pub src_ip: Ipv4Addr,

    /// Destination IP address (in host order, eg. 0xc0000000 is 192.0.0.0)
    pub dst_ip: Ipv4Addr,

    /// Protocol for the IP payload
    pub protocol: u8,

    /// Raw payload of the IP packet
    pub payload: &'a [u8],
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
            let checksum = Packet::checksum(0, ip);
            ip[10..12].copy_from_slice(&checksum.to_be_bytes());
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

/// A physically and virtually allocated packet that can easily be put into
/// and taken from DMA buffers directly from NICs.
/// 
/// The memory will always be 4 KiB aligned, and contiguous in physical memory.
pub struct Packet {
    /// Physically contiguous allocation which can hold a packet. This must be
    /// large enough for all of our network drivers to place directly in
    /// their ring buffers. This is a 4 KiB aligned allocation and should work
    /// in any NIC DMA
    raw: PhysContig<[u8; 4096]>,

    /// Size of the `raw` member, in bytes
    length: usize,
}

impl Packet {
    /// Creates new physical storage for a packet
    pub fn new() -> Packet {
        Packet {
            raw:    PhysContig::new([0u8; 4096]),
            length: 0,
        }
    }

    /// Compute a ones-complement checksum
    fn checksum(mut checksum: u32, bytes: &[u8]) -> u16 {
        // Go through each 2-byte pair in the payload
        for ii in (0..bytes.len() & !1).step_by(2) {
            checksum = checksum.wrapping_add(u16::from_ne_bytes(
                bytes[ii..ii + 2].try_into().unwrap()
            ) as u32);
        }

        // Finally, add the extra byte if there was a non-mod-2 payload
        // size
        if (bytes.len() % 2) != 0 {
            checksum = checksum.wrapping_add(
                ((bytes[bytes.len() - 1] as u16) << 0) as u32);
        }

        // Carry over the carries and invert the whole thing
        let checksum = (checksum & 0xffff).wrapping_add(checksum >> 16);
        let checksum = (checksum & 0xffff).wrapping_add(checksum >> 16);
        (!(checksum as u16)).to_be()
    }

    /// Parse the ethernet header
    pub fn eth(&self) -> Option<Ethernet> {
        let raw = self.raw();

        Some(Ethernet {
            dst_mac: raw.get(0x0..0x6)?.try_into().ok()?,
            src_mac: raw.get(0x6..0xc)?.try_into().ok()?,
            typ:     u16::from_be_bytes(raw.get(0xc..0xe)?.try_into().ok()?),
            payload: raw.get(0xe..)?,
        })
    }
    
    /// Parse the IP header
    pub fn ip(&self) -> Option<Ip> {
        // Parse the ethernet information from the header
        let eth = self.eth()?;
        
        // If the ethernet frame wasn't indicating an IPv4 packet, return
        // `None`
        if eth.typ != ETHTYPE_IPV4 {
            return None;
        }

        // IPv4 headers always at least 20 bytes
        let header = eth.payload.get(..20)?;

        // Parse the IP version and header length (in 32-bit values)
        let version = (header[0] >> 4) & 0xf;
        let ihl     = (header[0] >> 0) & 0xf;

        // Validate the IP version and header length
        // We don't support options, so we only allow 20 byte headers
        if version != 4 || ihl != 5 { return None; }

        // Get the length of the header + the payload
        let total_length = u16::from_be_bytes(header[2..4].try_into().ok()?);

        // Get the flags from the packet
        let flags = (header[6] >> 5) & 7;

        // Bit 0 is reserved as zero
        // Bit 1 is don't fragment
        // Bit 2 is more fragments
        // Make sure that the reserved bit and more fragments are clear as we
        // do not support fragmentation.
        if (flags & 0b101) != 0 {
            return None;
        }

        // Get the fragment offset
        let frag_offset = u16::from_be_bytes(
            header[6..8].try_into().ok()?) & 0x1fff;
        if frag_offset != 0 { return None; }

        // Get the protocol
        let protocol = header[9];

        // Get the source and dest IPs
        let src_ip =
            u32::from_be_bytes(header[12..16].try_into().ok()?).into();
        let dst_ip =
            u32::from_be_bytes(header[16..20].try_into().ok()?).into();

        // Validate the total length
        if total_length < 20 || total_length as usize > eth.payload.len() {
            return None;
        }        

        // Check the checksum
        if Self::checksum(0, &header) != 0 {
            return None;
        }

        // Return out the parsed IP information
        Some(Ip {
            src_ip,
            dst_ip,
            protocol,
            payload: &eth.payload[20..total_length as usize],
            eth,
        })
    }

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

        /*
        // Checksum is optional in IPv4, so we ignore it
        let orig_checksum = u16::from_be_bytes(header[6..8].try_into().ok()?);

        // Check if the checksum is used
        if orig_checksum != 0 {
            // If the checksum is used, it is non-zero, thus we should check
            // the checksum.
            
            // Pseudo header
            let src_ip = ip.src_ip.0.to_be_bytes();
            let dst_ip = ip.dst_ip.0.to_be_bytes();
            let proto  = ip.protocol as u16;
            let length = length;

            // Start the checksum
            let mut checksum = 0u32;
        
            // Add the source IP to the checksum
            checksum = checksum.wrapping_add(
                u16::from_ne_bytes(src_ip[0..2].try_into().ok()?) as u32);
            checksum = checksum.wrapping_add(
                u16::from_ne_bytes(src_ip[2..4].try_into().ok()?) as u32);
            
            // Add the dest IP to the checksum
            checksum = checksum.wrapping_add(
                u16::from_ne_bytes(dst_ip[0..2].try_into().ok()?) as u32);
            checksum = checksum.wrapping_add(
                u16::from_ne_bytes(dst_ip[2..4].try_into().ok()?) as u32);

            // Finish up the psuedo header with the protocol and length
            checksum = checksum.wrapping_add((proto  as u16).to_be() as u32);
            checksum = checksum.wrapping_add((length as u16).to_be() as u32);

            // Checksum in the actual UDP header + payload
            if Self::checksum(checksum, ip.payload) != 0 {
                return None;
            }
        }*/

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

    /// Gets the physical address for the packet
    pub fn phys_addr(&self) -> PhysAddr {
        self.raw.phys_addr()
    }

    /// Get the length of the raw payload
    #[inline]
    pub fn len(&self) -> usize {
        self.length
    }

    /// Get the raw packet contents
    #[inline]
    pub fn raw(&self) -> &[u8] {
        &self.raw[..self.length]
    }

    /// Get the raw packet contents as mutable
    #[inline]
    pub fn raw_mut(&mut self) -> &mut [u8] {
        &mut self.raw[..self.length]
    }

    /// Set the length of the internally held bytes
    #[inline]
    pub fn set_len(&mut self, len: usize) {
        assert!(len <= 1514 && len <= self.raw.len(),
            "set_len() on packet OOB");
        self.length = len;
    }
}

/// A lease of a packet
///
/// This allows Rust-based drop handling to allow a NIC to get access back to
/// a packet it leased out during a `recv()`.
///
/// When a `Drop` occurs on a `PacketLease` the packet will be given back to
/// the `owner` of the packet via the `NetDriver::release_packet()` function
pub struct PacketLease<'a> {
    /// Owner of the packet
    owner: &'a dyn NetDriver,

    /// Packet that was leased out
    packet: Option<Packet>,
}

impl<'a> PacketLease<'a> {
    /// Create a new packet lease with `owner` as the owner of the packet.
    /// When this packet lease goes out of scope, the `owner` will get the
    /// packet back
    pub fn new(owner: &'a dyn NetDriver,
               packet: Packet) -> PacketLease {
        PacketLease {
            owner,
            packet: Some(packet),
        }
    }

    /// Take the packet from the lease without giving it back to the device
    pub fn take(mut lease: Self) -> Packet {
        lease.packet.take().unwrap()
    }
}

impl<'a> Drop for PacketLease<'a> {
    fn drop(&mut self) {
        if let Some(packet) = self.packet.take() {
            self.owner.release_packet(packet);
        }
    }
}

impl<'a> Deref for PacketLease<'a> {
    type Target = Packet;
    fn deref(&self) -> &Self::Target { self.packet.as_ref().unwrap() }
}

impl<'a> DerefMut for PacketLease<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.packet.as_mut().unwrap()
    }
}

