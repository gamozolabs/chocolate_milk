//! Falk transfer protocol

#![no_std]

extern crate alloc;

use core::fmt;
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

impl<'a> fmt::Display for CoverageRecord<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(module) = &self.module {
            if self.offset != 0 {
                write!(f, "{}+{:#x}", module, self.offset)
            } else {
                write!(f, "{}", module)
            }
        } else {
            write!(f, "{:#x}", self.offset)
        }
    }
}

noodle!(serialize, deserialize,
    #[derive(Clone, PartialEq, Eq, Debug, PartialOrd, Ord)]
    pub struct InputRecord<'a> {
        pub hash:  u128,
        pub input: Cow<'a, Arc<Vec<u8>>>,
    }
);

noodle!(serialize, deserialize,
/// Messages sent to and from the server for network mapped files
pub enum ServerMessage<'a> {
    /// Request a file ID for a filename on the server. This will cause the
    /// file to get loaded into memory on the server and persisted with the
    /// same ID.
    GetFileId(Cow<'a, str>),

    /// File requested for open was invalid and thus was rejected
    BadFile,

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

    /// Report new coverage
    Coverage(Cow<'a, [CoverageRecord<'a>]>),
    
    /// Report new inputs
    Inputs(Cow<'a, [InputRecord<'a>]>),

    /// Report new statistics (always the totals)
    ReportStatistics {
        fuzz_cases:    u64,
        total_cycles:  u64,
        vm_cycles:     u64,
        reset_cycles:  u64,
        inject_cycles: u64,
        vm_exits:      u64,

        // Memory stats
        allocs:      u64,
        frees:       u64,
        phys_free:   u64,
        phys_total:  u64,
    },

    /// Trace of all RIPs during an execution
    Trace(Cow<'a, [u64]>),

    /// Report a new "unique" crash to the server
    Crash {
        modoff:   CoverageRecord<'a>,
        cpl:      u8,
        typ:      CrashType,
        regstate: Cow<'a, str>
    },

    /// The server has sent any messages related to syncing and the client
    /// should resume fuzzing.
    SyncComplete,
});

noodle!(serialize, deserialize,
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum PageFaultType {
        /// Fault occurred between -1MiB and 1MiB of vaddr space
        Null,

        /// Fault happened in non-null memory
        High,
    }
);

noodle!(serialize, deserialize,
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum CrashType {
        DivideError,
        DebugException,
        NMI,
        Breakpoint,
        Overflow,
        BoundRangeExceeded,
        InvalidOpcode,
        DeviceNotAvailable,
        DoubleFault,
        CoprocessorSegmentOverrun,
        InvalidTSS,
        SegmentNotPresent,
        StackSegmentFault,
        GeneralProtectionFault,
        PageFault {
            typ:   PageFaultType,
            read:  bool,
            write: bool,
            exec:  bool,
        },
        FloatingPointError,
        AlignmentCheck,
        MachineCheck,
        SimdFloatingPointException,
        VirtualizationException,
        ControlProtectionException,
    }
);

