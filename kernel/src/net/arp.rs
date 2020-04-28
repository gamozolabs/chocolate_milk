//! Implementation of the ARP protocol

use core::convert::TryInto;
use crate::time;
use super::{Packet, Ipv4Addr, NetDevice, ETHTYPE_IPV4, Ethernet};

/// Ethernet type for ARPs
const ETHTYPE_ARP: u16 = 0x0806;

/// Hardware type for ethernet
pub const HWTYPE_ETHERNET: u16 = 1;

/// ARP opcodes
#[repr(u16)]
pub enum Opcode {
    Request = 1,
    Reply   = 2,
}

impl NetDevice {
    /// Resolve the MAC address for the `ip` using the `NetDevice`
    pub fn arp<T: Into<Ipv4Addr>>(&self, ip: T) -> Option<[u8; 6]> {
        // Convert the requested IP into an `Ipv4Addr`
        let request_ip: Ipv4Addr = ip.into();
        
        // Get our own IP
        let our_ip = self.dhcp_lease.lock().as_ref().unwrap().client_ip;

        'send_arp: for _ in 0..10000 {
            // Allocate a packet
            let mut packet = self.allocate_packet();

            // Set the length to the size of an ARP
            packet.set_len(42);

            let raw = packet.raw_mut();
            
            {
                // Set up the ethernet header
                let eth = &mut raw[..14];
                eth[0x0..0x6].copy_from_slice(&[0xff; 6]);
                eth[0x6..0xc].copy_from_slice(&self.mac());
                eth[0xc..0xe].copy_from_slice(&ETHTYPE_ARP.to_be_bytes());
            }
            
            {
                // Set up the ARP
                let arp = &mut raw[14..42];

                // Set the hardware and protocol types
                arp[0..2].copy_from_slice(&HWTYPE_ETHERNET.to_be_bytes());
                arp[2..4].copy_from_slice(&ETHTYPE_IPV4.to_be_bytes());

                // Set the hardware and protocol sizes
                arp[4] = 6;
                arp[5] = 4;

                // Set the opcode
                arp[6..8].copy_from_slice(&(Opcode::Request as u16)
                                          .to_be_bytes());

                // Set the sender MAC and IP
                arp[ 8..14].copy_from_slice(&self.mac());
                arp[14..18].copy_from_slice(&our_ip.0.to_be_bytes());
                
                // Set the target MAC and IP
                arp[18..24].copy_from_slice(&[0; 6]);
                arp[24..28].copy_from_slice(&request_ip.0.to_be_bytes());
            }

            // Send the ARP
            self.send(packet, true);

            let timeout = time::future(100_000);
            loop {
                if cpu::rdtsc() >= timeout {
                    continue 'send_arp;
                }

                if let Some(packet) = self.recv() {
                    if let Some(arp) = packet.arp() {
                        if arp.hw_type == HWTYPE_ETHERNET &&
                                arp.proto_type == ETHTYPE_IPV4 &&
                                arp.hw_size    == 6 &&
                                arp.proto_size == 4 &&
                                arp.opcode     == Opcode::Reply as u16 &&
                                arp.sender_ip  == request_ip &&
                                arp.target_ip  == our_ip &&
                                arp.target_mac == self.mac() {
                            return Some(arp.sender_mac);
                        }
                    }
                }
            }
        }

        // Never got a response
        None
    }

    /// Construct a reply ARP from ourselves
    pub fn arp_reply(&self, our_ip: Ipv4Addr,
                     target_ip: Ipv4Addr, target_mac: [u8; 6]) {
        // Allocate a packet
        let mut packet = self.allocate_packet();

        // Set the length to the size of an ARP
        packet.set_len(42);

        let raw = packet.raw_mut();
        
        {
            // Set up the ethernet header
            let eth = &mut raw[..14];
            eth[0x0..0x6].copy_from_slice(&target_mac);
            eth[0x6..0xc].copy_from_slice(&self.mac());
            eth[0xc..0xe].copy_from_slice(&ETHTYPE_ARP.to_be_bytes());
        }
        
        {
            // Set up the ARP
            let arp = &mut raw[14..42];

            // Set the hardware and protocol types
            arp[0..2].copy_from_slice(&HWTYPE_ETHERNET.to_be_bytes());
            arp[2..4].copy_from_slice(&ETHTYPE_IPV4.to_be_bytes());

            // Set the hardware and protocol sizes
            arp[4] = 6;
            arp[5] = 4;

            // Set the opcode
            arp[6..8].copy_from_slice(&(Opcode::Reply as u16)
                                      .to_be_bytes());

            // Set the sender MAC and IP
            arp[ 8..14].copy_from_slice(&self.mac());
            arp[14..18].copy_from_slice(&our_ip.0.to_be_bytes());
            
            // Set the target MAC and IP
            arp[18..24].copy_from_slice(&target_mac);
            arp[24..28].copy_from_slice(&target_ip.0.to_be_bytes());
        }

        // Send the ARP
        self.send(packet, true);
    }
}

/// A IPv4 ethernet ARP packet
#[derive(Debug)]
pub struct Arp<'a> {
    pub eth: Ethernet<'a>,

    pub hw_type:    u16,
    pub proto_type: u16,
    pub hw_size:    u8,
    pub proto_size: u8,
    pub opcode:     u16,
    pub sender_mac: [u8; 6],
    pub sender_ip:  Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip:  Ipv4Addr,
}

impl Packet {
    /// Parse the packet into an `Arp` if it is a IPv4 ethernet Arp
    pub fn arp(&self) -> Option<Arp> {
        // Get the ethernet header
        let eth = self.eth()?;

        // Make sure this is an ARP
        if eth.typ != ETHTYPE_ARP || eth.payload.len() < 28 {
            return None;
        }

        // Get the ethernet payload
        let pl = eth.payload;

        Some(Arp {
            eth:        eth,
            hw_type:    u16::from_be_bytes(pl[0..2].try_into().unwrap()),
            proto_type: u16::from_be_bytes(pl[2..4].try_into().unwrap()),
            hw_size:    pl[4],
            proto_size: pl[5],
            opcode:     u16::from_be_bytes(pl[6..8].try_into().unwrap()),
            sender_mac: pl[8..14].try_into().unwrap(),
            sender_ip:  Ipv4Addr::from(
                u32::from_be_bytes(pl[14..18].try_into().unwrap())),
            target_mac: pl[18..24].try_into().unwrap(),
            target_ip:  Ipv4Addr::from(
                u32::from_be_bytes(pl[24..28].try_into().unwrap())),
        })
    }
}

