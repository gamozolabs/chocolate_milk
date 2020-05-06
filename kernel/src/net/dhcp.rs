//! DHCPv4 client implementation

use core::mem::size_of;
use core::convert::TryInto;
use alloc::vec::Vec;
use alloc::sync::Arc;
use crate::net::{NetDevice, Packet, Ipv4Addr, NetAddress};
use crate::net::udp::Udp;

/// Amount of time to wait for a DHCP response from the server in microseconds.
/// If the DHCP process takes longer than this we will give up and return
/// `None` from lease
const DHCP_TIMEOUT: u64 = 5_000_000;

/// The magic DHCP cookie
const DHCP_COOKIE: u32 = 0x63825363;

#[derive(Debug, Clone, Copy)]
pub struct Lease {
    pub client_ip:    Ipv4Addr,
    pub server_ip:    Ipv4Addr,
    pub broadcast_ip: Option<Ipv4Addr>,
    pub subnet_mask:  Option<Ipv4Addr>,
}

/// DHCP protocol header
#[derive(Clone, Copy, Default, Debug)]
#[repr(C, packed)]
struct Header {
    op:     u8,
    htype:  u8,
    hlen:   u8,
    hops:   u8,
    xid:    u32,
    secs:   u16,
    flags:  u16,
    ciaddr: u32,
    yiaddr: u32,
    siaddr: u32,
    giaddr: u32,
    chaddr: [u8;  16],
    name:   [u64; 64 / 8],
    file:   [u64; 128 / 8],
    cookie: u32,
}

/// DHCP opcode
#[repr(u8)]
enum Opcode {
    /// Boot request
    Request = 1,

    /// Boot reply
    Reply = 2,
}

/// DHCP hardware type
#[repr(u8)]
enum HardwareType {
    /// 10mb ethernet
    Ethernet = 1,
}

/// DHCP message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum MessageType {
    Discover = 1,
    Offer    = 2,
    Request  = 3,
    Ack      = 5,
    Invalid  = 0xff,
}

impl From<u8> for MessageType {
    fn from(val: u8) -> Self {
        match val {
            1 => MessageType::Discover,
            2 => MessageType::Offer,
            3 => MessageType::Request,
            5 => MessageType::Ack,
            _ => MessageType::Invalid,
        }
    }
}

/// Different DHCP options
#[derive(Debug, PartialEq, Eq)]
enum DhcpOption<'a> {
    SubnetMask(u32),
    BroadcastIp(u32),
    RequestedIp(u32),
    LeaseTime(u32),
    MessageType(MessageType),
    ServerIp(u32),
    ParameterRequestList(&'a [u8]),
    RenewalTime(u32),
    Unknown(u8, &'a [u8]),
    End,
}

/// DHCP options to their IDs
#[repr(u8)]
enum DhcpOptionId {
    SubnetMask           =   1,
    BroadcastIp          =  28,
    RequestedIp          =  50,
    LeaseTime            =  51,
    MessageType          =  53,
    ServerIp             =  54,
    ParameterRequestList =  55,
    RenewalTime          =  58,
    End                  = 255,
}

impl<'a> DhcpOption<'a> {
    /// Parse a DHCP option from a raw message, updating the message pointer
    /// to reflect the number of parsed bytes
    fn parse(ptr: &mut &'a [u8]) -> Option<DhcpOption<'a>> {
        // Get the header for the option
        let code    = *ptr.get(0)?;
        let len     = *ptr.get(1)? as usize;
        let payload = ptr.get(2..2 + len)?;

        // Parse the option
        let ret = Some(match code {
            1 => {
                DhcpOption::SubnetMask(
                    u32::from_be_bytes(payload.try_into().ok()?))
            }
            28 => {
                DhcpOption::BroadcastIp(
                    u32::from_be_bytes(payload.try_into().ok()?))
            }
            50 => {
                DhcpOption::RequestedIp(
                    u32::from_be_bytes(payload.try_into().ok()?))
            }
            51 => {
                DhcpOption::LeaseTime(
                    u32::from_be_bytes(payload.try_into().ok()?))
            }
            53 => {
                DhcpOption::MessageType(
                    u8::from_be_bytes(payload.try_into().ok()?).into())
            }
            54 => {
                DhcpOption::ServerIp(
                    u32::from_be_bytes(payload.try_into().ok()?))
            }
            55 => {
                DhcpOption::ParameterRequestList(payload)
            }
            58 => {
                DhcpOption::RenewalTime(
                    u32::from_be_bytes(payload.try_into().ok()?))
            }
            255 => {
                // Terminate the list of options
                *ptr = &ptr[ptr.len()..];
                return Some(DhcpOption::End);
            }
            x @ _ => DhcpOption::Unknown(x, payload),
        });

        // Update the pointer reflecting what we consumed
        *ptr = &ptr[2 + len..];

        ret
    }

    /// Serialize a DHCP option by appending it to `buffer`
    fn serialize(&self, buffer: &mut Vec<u8>) {
        match self {
            DhcpOption::SubnetMask(mask) => {
                buffer.push(DhcpOptionId::SubnetMask as u8);
                buffer.push(4);
                buffer.extend_from_slice(&mask.to_be_bytes())
            }
            DhcpOption::BroadcastIp(addr) => {
                buffer.push(DhcpOptionId::BroadcastIp as u8);
                buffer.push(4);
                buffer.extend_from_slice(&addr.to_be_bytes())
            }
            DhcpOption::RequestedIp(addr) => {
                buffer.push(DhcpOptionId::RequestedIp as u8);
                buffer.push(4);
                buffer.extend_from_slice(&addr.to_be_bytes())
            }
            DhcpOption::LeaseTime(time) => {
                buffer.push(DhcpOptionId::LeaseTime as u8);
                buffer.push(4);
                buffer.extend_from_slice(&time.to_be_bytes())
            }
            DhcpOption::MessageType(typ) => {
                buffer.push(DhcpOptionId::MessageType as u8);
                buffer.push(1);
                buffer.push(*typ as u8);
            }
            DhcpOption::ServerIp(addr) => {
                buffer.push(DhcpOptionId::ServerIp as u8);
                buffer.push(4);
                buffer.extend_from_slice(&addr.to_be_bytes())
            }
            DhcpOption::ParameterRequestList(parameters) => {
                buffer.push(DhcpOptionId::ParameterRequestList as u8);
                buffer.push(parameters.len().try_into().unwrap());
                buffer.extend_from_slice(parameters);
            }
            DhcpOption::RenewalTime(time) => {
                buffer.push(DhcpOptionId::RenewalTime as u8);
                buffer.push(4);
                buffer.extend_from_slice(&time.to_be_bytes())
            }
            DhcpOption::Unknown(typ, payload) => {
                buffer.push(*typ as u8);
                buffer.push(payload.len().try_into().unwrap());
                buffer.extend_from_slice(payload);
            }
            DhcpOption::End => {
                buffer.push(DhcpOptionId::End as u8);
            }
        }
    }
}

/// Parse a DHCP packet
fn parse_dhcp_packet<'a>(xid: u32, udp: Udp<'a>) ->
        Option<(Header, Vec<DhcpOption<'a>>)> {
    // Get the UDP message
    let message = udp.payload;

    // Cast the header to a DHCP header
    let header = message.get(..size_of::<Header>())?;
    let header = unsafe { &*(header.as_ptr() as *const Header) };

    // XID did not match expected
    if header.xid != xid {
        return None;
    }

    // Sanity check some parts of the DHCP message
    if header.op != Opcode::Reply as u8 ||
            header.htype != HardwareType::Ethernet as u8 ||
            header.hlen != 6 ||
            header.cookie != DHCP_COOKIE.to_be() {
        return None;
    }

    // Parse out the options
    let mut options = &message[size_of::<Header>()..];
    let mut dhcp_options = Vec::new();
    while options.len() > 0 {
        // Attempt to parse the option
        if let Some(option) = DhcpOption::parse(&mut options) {
            // Option was valid, store it
            dhcp_options.push(option);
        } else {
            // Stop on the first invalid option
            break;
        }
    }

    Some((*header, dhcp_options))
}

/// Create a DHCP rquest packet
fn create_dhcp_packet(packet: &mut Packet, xid: u32,
                      mac: [u8; 6], options: &[u8]) {
    // Initialize the packet for a UDP DHCP packet
    let addr = NetAddress {
        src_eth:  mac,
        dst_eth:  [0xff; 6],
        src_ip:   0.into(),
        dst_ip:   (!0).into(),
        src_port: 68,
        dst_port: 67,
    };
    let mut pkt = packet.create_udp(&addr);

    // Reserve room in the packet for the header and the DHCP options
    let dhcp_header = pkt.reserve(size_of::<Header>() + options.len())
        .unwrap();

    {
        // Cast the header to a DHCP header
        let header: &mut Header = unsafe {
            &mut *(dhcp_header.as_mut_ptr() as *mut Header)
        };

        // Initialize the header to zeros
        *header = Header::default();

        // Fill in the part of the request that we care about
        header.op    = Opcode::Request as u8;
        header.htype = HardwareType::Ethernet as u8;
        header.hlen  = 6;
        header.xid   = xid;

        // Copy in our client hardware address (our MAC address)
        header.chaddr[..6].copy_from_slice(&mac);

        // Copy in the DHCP cookie
        header.cookie = DHCP_COOKIE.to_be();
    }
    
    {
        // Get access to the DHCP options
        let dhcp_options = &mut dhcp_header
            [size_of::<Header>()..size_of::<Header>() + options.len()];
        dhcp_options.copy_from_slice(&options);
    }
}

pub fn get_lease(device: Arc<NetDevice>) -> Option<Lease> {
    // Get a "unique" transaction ID
    let xid = cpu::rdtsc() as u32;

    // Save off our devices MAC address
    let mac = device.mac();

    // Bind to UDP port 68
    let bind = NetDevice::bind_udp_port(device.clone(), 68)
        .expect("Could not bind to port 68 for dhcp");

    // Construct the DHCP options for the discover
    let mut options = Vec::new();
    DhcpOption::MessageType(MessageType::Discover).serialize(&mut options);
    DhcpOption::ParameterRequestList(&[
        DhcpOptionId::MessageType as u8,
        DhcpOptionId::ServerIp as u8,
    ]).serialize(&mut options);
    DhcpOption::End.serialize(&mut options);
    
    // Send the DHCP discover
    let mut packet = device.allocate_packet();
    create_dhcp_packet(&mut packet, xid, mac, &options);
    device.send(packet, true);

    // Things we hope to maybe find in a DHCP offer
    let mut offer_ip:  Option<Ipv4Addr> = None;
    let mut server_ip: Option<Ipv4Addr> = None;

    bind.recv_timeout(DHCP_TIMEOUT, |_pkt, udp| {
        // Check that the destination is us
        if udp.ip.eth.dst_mac != mac { return None; }

        // Parse the DHCP packet
        let (header, options) = parse_dhcp_packet(xid, udp)?;

        // Check if this is an offer
        options.iter()
            .find(|x| x == &&DhcpOption::MessageType(MessageType::Offer))?;

        // Save the offer IP
        offer_ip = Some(u32::from_be(header.yiaddr).into());

        // Save the server IP if it was present
        server_ip = options.iter().find_map(|x| {
            if let DhcpOption::ServerIp(ip) = x {
                Some((*ip).into())
            } else { None }
        });

        Some(())
    })?;

    // Attempt to get the offer IP and server IP
    let offer_ip  = offer_ip?;
    let server_ip = server_ip?;
    
    // Create options for the request
    options.clear();
    DhcpOption::MessageType(MessageType::Request).serialize(&mut options);
    DhcpOption::RequestedIp(offer_ip.into()).serialize(&mut options);
    DhcpOption::ServerIp(server_ip.into()).serialize(&mut options);
    DhcpOption::ParameterRequestList(&[
        DhcpOptionId::MessageType as u8,
        DhcpOptionId::BroadcastIp as u8,
        DhcpOptionId::SubnetMask  as u8,
    ]).serialize(&mut options);
    DhcpOption::End.serialize(&mut options);
    
    // Send the DHCP request
    let mut packet = device.allocate_packet();
    create_dhcp_packet(&mut packet, xid, mac, &options);
    device.send(packet, true);

    // Things we hope to get from the DHCP ACK
    let mut broadcast_ip = None;
    let mut subnet_mask  = None;
    
    // Wait for the DHCP ACK
    bind.recv_timeout(DHCP_TIMEOUT, |_pkt, udp| {
        // Check that the destination is us
        if udp.ip.eth.dst_mac != mac { return None; }

        // Parse the DHCP packet
        let (_header, options) = parse_dhcp_packet(xid, udp)?;

        // Check if this is an ack
        options.iter()
            .find(|x| x == &&DhcpOption::MessageType(MessageType::Ack))?;

        // Save the broadcast IP if it was present
        broadcast_ip = options.iter().find_map(|x| {
            if let DhcpOption::BroadcastIp(ip) = x {
                Some((*ip).into())
            } else { None }
        });
        
        // Save the subnet mask if it was present
        subnet_mask = options.iter().find_map(|x| {
            if let DhcpOption::SubnetMask(ip) = x {
                Some((*ip).into())
            } else { None }
        });

        Some(())
    })?;

    Some(Lease {
        client_ip: offer_ip,
        server_ip,
        broadcast_ip,
        subnet_mask
    })
}

