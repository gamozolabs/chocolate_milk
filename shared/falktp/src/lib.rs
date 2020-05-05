//! Falk transfer protocol

#![no_std]

extern crate alloc;

use core::mem::size_of;
use core::convert::TryInto;
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::borrow::Cow;
use alloc::string::String;
use noodle::*;

noodle!(serialize, deserialize,
    #[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
    pub struct CoverageRecord<'a> {
        pub module: Option<Cow<'a, Arc<String>>>,
        pub offset: u64,
    }
);

noodle!(serialize, deserialize,
/// Messages sent to and from the server for network mapped files
#[derive(Debug)]
pub enum ServerMessage<'a> {
    /// Request a file ID for a filename on the server. This will cause the
    /// file to get loaded into memory on the server and persisted with the
    /// same ID.
    GetFileId(Cow<'a, str>),

    /// If getting the file ID failed, this will be sent back by the server
    FileIdErr,

    /// Returns the file ID and length of the requested filename from a
    /// `GetFileId()` if the file exists on the server
    FileId {
        /// File ID
        id: u64,

        /// Size of the file (in bytes)
        size: usize,
    },

    /// Request a read of an opened file
    Read {
        /// File identifier from a successful `OpenRequest`
        id: u64,

        /// Offset (in bytes) into the file to request to read
        offset: usize,

        /// Size (in bytes) to request
        size: usize,
    },

    /// Indicates that the read is valid, and there are UDP frames following
    /// this packet containing the raw bytes for the `size` requested.
    ReadOk,

    /// Indicates that reading the file failed
    ReadErr,

    /// Log in as a new fuzzer
    Login(u64, u32),

    /// Acknowledge a login
    LoginAck(u64, u32),
    
    /// Report new coverage to the server
    ReportCoverage(Cow<'a, CoverageRecord<'a>>),
    
    /// Acknowledge coverage was reported
    ReportCoverageAck(Cow<'a, CoverageRecord<'a>>),

    /// Report new statistics (always the totals)
    ReportStatistics {
        fuzz_cases:   u64,
        total_cycles: u64,
        vm_cycles:    u64,
        reset_cycles: u64,
    },
});

/// Different types of messages we send in our reliable UDP implementation
#[repr(u8)]
enum MessageType {
    /// Start a transfer
    StartTransfer = 15,

    /// Message contains a data packet
    Data = 25,

    /// Message is an acknowledge of a receive
    Ack = 93,
}

/// Window size to use during packetizing sessions
const WINDOW_SIZE: usize = 512 * 1024;

/// Maximum size for a UDP datagram (may vary based on your actual network)
const DATAGRAM_SIZE: usize = 32;

/// A generic trait which allows OS-agnostic datagram transmission and recption
pub trait DatagramTransceiver {
    /// Send a datagram to the network, ensuring the OS network stack is
    /// flushed if `flush` is `true`
    fn send(&mut self, data: &[u8], flush: bool);

    /// Recv a datagram from the network, returning `None` on a timeout. The
    /// implementor of this decides the timeout by the nature of when `None`
    /// is returned
    fn recv<T, F: FnMut(&[u8]) -> Option<T>>(&mut self, func: F) -> Option<T>;

    /// Transmit the entirity of `payload` using `self`
    fn send_message(&mut self, payload: &[u8]) {
        // Buffer for datagrams
        let mut buf = [0u8; DATAGRAM_SIZE];

        // Number of acknowledged bytes
        let mut acknowledged = 0usize;

        // Loop while there's something to transmit
        while acknowledged < payload.len() {
            // If we're restarting, initiate with a start transfer message
            if acknowledged == 0 {
                // Start a new transfer
                buf[0] = MessageType::StartTransfer as u8;
                buf[1..1 + size_of::<u64>()]
                    .copy_from_slice(&(payload.len() as u64).to_le_bytes());
                self.send(&buf[..size_of::<u64>() + 1], true);
            }

            // Compute the size of the window to transmit
            let window_size = core::cmp::min(
                payload.len() - acknowledged, WINDOW_SIZE);
            
            /// Size of a data message header
            const DATA_MESSAGE_HEADER: usize = 1 + size_of::<u64>();

            /// Maximum size of a data message payload
            const DATA_MESSAGE_PAYLOAD: usize =
                DATAGRAM_SIZE - DATA_MESSAGE_HEADER;

            // Make sure we can fit the header in a datagram, and at least one
            // byte of data
            assert!(DATAGRAM_SIZE > DATA_MESSAGE_HEADER,
                    "DATAGRAM_SIZE is too short");
            
            // Determine the number of datagrams we must send
            let num_chunks =
                (window_size + (DATA_MESSAGE_PAYLOAD - 1)) /
                DATA_MESSAGE_PAYLOAD;

            // Send the data in chunks
            let mut send_ptr = acknowledged;
            for (ii, chunk) in
                    payload[acknowledged..acknowledged + window_size]
                    .chunks(DATA_MESSAGE_PAYLOAD).enumerate() {
                // Construct the message with the header
                buf[0] = MessageType::Data as u8;
                buf[1..1 + size_of::<u64>()]
                    .copy_from_slice(&(send_ptr as u64).to_le_bytes());
                buf[DATA_MESSAGE_HEADER..DATA_MESSAGE_HEADER + chunk.len()]
                    .copy_from_slice(chunk);

                // Send the packet, flushing only on the last packet
                self.send(&buf[..DATA_MESSAGE_HEADER + chunk.len()],
                    ii == num_chunks - 1);

                // Update the send pointer
                send_ptr += chunk.len();
            }

            // Wait for the acknowledge
            if self.recv(|pkt| {
                // Compute the amount of acknowledged bytes that we're
                // expecting as a reply
                let new_ack = acknowledged + window_size;

                // Make sure this is an ack
                if *pkt.get(0)? != MessageType::Ack as u8 {
                    return None;
                }

                if u64::from_le_bytes(pkt.get(1..)?.try_into().ok()?) ==
                        new_ack as u64 {
                    // Woo! We got the expected ack
                    Some(())
                } else {
                    // Yikes, we got a packet but it wasn't the right ack
                    None
                }
            }).is_some() {
                // Advance the acknowledge if we got a valid ack
                acknowledged += window_size;
            }
        }
    }

    /// Receive an entire message from the server
    fn recv_message(&mut self, buf: &mut Vec<u8>) -> Option<()> {
        // Number of bytes we have acknowledged to the server
        let mut acknowledged = 0usize;

        // Loop until we've received and acknowledged everything
        while acknowledged < size {
            // Clear the existing message and reserve enough space for the new
            // payload
            buf.clear();
            buf.reserve(size);

            // Number of bytes we've received this message
            let mut rxed = 0usize;

            // Compute the number of bytes we're expecting to receive
            let expecting = core::cmp::min(size - acknowledged, WINDOW_SIZE);

            // Loop for this window
            while rxed < expecting {
                // Receive some data
                self.recv(|data| {
                    // Update the number of rxed bytes
                    rxed += data.len();

                    // It's possible the other end transmits more than we're
                    // expecting, in which case, we're just gonna return
                    // failure.
                    if rxed > expecting {
                        return None;
                    }

                    // Extend the buffer by this data size
                    buf.extend_from_slice(data);
                    Some(())
                });
            }

            // Update acknowledged counter
            acknowledged += rxed;

            // Send the acknowledge counter
            self.send(&(acknowledged as u64).to_le_bytes(), true);
        }

        Some(())
    }
}

