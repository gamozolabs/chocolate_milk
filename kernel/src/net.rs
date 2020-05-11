//! Driver agnostic networking utilities

pub mod udp;
pub mod tcp;
pub mod arp;
pub mod dhcp;
pub mod intel_nic;
pub mod netmapping;

use core::fmt::{self, Formatter, Debug};
use core::convert::TryInto;
use core::ops::{Deref, DerefMut};

use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};

use crate::pci::Device;
use crate::mm::PhysContig;
use crate::net::tcp::TcpConnectionInt;
use crate::net::dhcp::Lease;
use crate::core_locals::LockInterrupts;

use lockcell::LockCell;
use page_table::PhysAddr;

/// List of all network devices with valid DHCP leases on the system
static NET_DEVICES: LockCell<Vec<Arc<NetDevice>>, LockInterrupts> =
    LockCell::new(Vec::new());

/// IPv4 ethernet frame type
const ETHTYPE_IPV4: u16 = 0x0800;

/// UDP protocol for the IP header
const IPPROTO_UDP: u8 = 0x11;

/// TCP protocol for the IP header
const IPPROTO_TCP: u8 = 0x6;

/// UDP/TCP address
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
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

    /// Packet queues for bound UDP ports
    ///
    /// When packets are parsed and they're valid UDP packets to existing bound
    /// UDP ports, we will store the packets in these lists
    udp_binds: LockCell<BTreeMap<u16, VecDeque<Packet>>, LockInterrupts>,
    
    /// Active TCP connections
    tcp_connections: LockCell<BTreeMap<u16,
        Arc<LockCell<TcpConnectionInt, LockInterrupts>>>,
        LockInterrupts>,
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
            mac:             driver.mac(),
            udp_binds:       LockCell::new(BTreeMap::new()),
            tcp_connections: LockCell::new(BTreeMap::new()),
            driver:          driver,
            dhcp_lease:      LockCell::new(None),
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

    /// Discard a packet which was unhandled and thus may need to be handled
    /// by another driver which is expecting it
    pub fn discard(&self, packet: PacketLease) {
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
                    return;
                }
            }
        }

        // Handle inbound UDP packets that we have bound ports for
        if let Some(udp) = packet.udp() {
            // Get access to UDP binds
            let mut udp_binds = self.udp_binds.lock();

            // Check if we have a bind for this port
            if let Some(bind) = udp_binds.get_mut(&udp.dst_port) {
                if bind.len() < bind.capacity() {
                   // Add the packet to the queue for this port
                   bind.push_back(PacketLease::take(packet));
                } else {
                    // Drop the packet if there is no room for it, we don't
                    // want to use all our memory dynamically for buffering
                    // packets
                }

                return;
            }
        }

        // Handle inbound TCP packets we have bound ports for
        if let Some(tcp) = packet.tcp() {
            // Get access to TCP connections
            let mut tcp_connections = self.tcp_connections.lock();

            // Check if we have a connection for this port
            if let Some(conn) = tcp_connections.get_mut(&tcp.dst_port) {
                let conn = conn.clone();
                core::mem::drop(tcp_connections);
                conn.lock().discard(&tcp);
                return;
            }
        }
    }

    /// Receive a raw packet from the network
    pub fn recv(&self) -> Option<PacketLease> {
        self.driver.recv()
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
        self.driver.reset();
    }
}

/// Driver-implemented trait to get generic access to network card RX and TX
pub trait NetDriver: Send + Sync {
    /// Forceably reset the NIC, this is to disable it fully before we soft
    /// reboot
    unsafe fn reset(&self);

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
        checksum as u16
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

        // Return out the parsed IP information
        Some(Ip {
            src_ip,
            dst_ip,
            protocol,
            payload: &eth.payload[20..total_length as usize],
            eth,
        })
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

