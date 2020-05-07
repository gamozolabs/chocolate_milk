//! Falk transfer protocol

#![no_std]

extern crate alloc;

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
pub enum ServerMessage<'a> {
    /// Request a file ID for a filename on the server. This will cause the
    /// file to get loaded into memory on the server and persisted with the
    /// same ID.
    GetFileId(Cow<'a, str>),

    /// Returns the file ID and length of the requested filename from a
    /// `GetFileId()` if the file exists on the server
    FileId {
        /// File ID
        id: u64,

        /// Size of the file (in bytes)
        size: usize,
    },

    /// Request a read of an opened file
    ReadPage {
        /// File identifier from a successful `OpenRequest`
        id: u64,

        /// Offset (in bytes) into the file to request to read
        offset: usize,
    },

    /// Indicates that the read is valid, and there are UDP frames following
    /// this packet containing the raw bytes for the `size` requested.
    ReadPageResponse([u8; 4096]),

    /// Log in as a new fuzzer
    Login(u64, u32),

    /// Report new coverage to the server
    ReportCoverage(Cow<'a, CoverageRecord<'a>>),

    /// Report new statistics (always the totals)
    ReportStatistics {
        fuzz_cases:   u64,
        total_cycles: u64,
        vm_cycles:    u64,
        reset_cycles: u64,
    },
});

