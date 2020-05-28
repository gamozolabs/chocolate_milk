//! An very lightweight ACPI implementation for extracting basic information
//! about CPU topography and NUMA memory regions

use core::mem::size_of;
use core::sync::atomic::{AtomicU32, Ordering, AtomicU8};
use core::convert::TryInto;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

use crate::mm;
use rangeset::{RangeSet, Range};
use page_table::PhysAddr;

/// Maximum number of cores allowed on the system
pub const MAX_CORES: usize = 1024;

/// Different states for APICs to be in
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ApicState {
    /// The core has checked in with the kernel and is actively running
    Online = 1,

    /// The core has been launched by the kernel, but has not yet registered
    /// with the kernel
    Launched = 2,

    /// The core is present but has not yet been launched
    Offline = 3,
    
    /// This APIC ID does not exist
    None = 4,

    /// This APIC ID has disabled interrupts and halted forever
    Halted = 5,
}

impl From<u8> for ApicState {
    /// Convert a raw `u8` into an `ApicState`
    fn from(val: u8) -> ApicState {
        match val {
            1 => ApicState::Online,
            2 => ApicState::Launched,
            3 => ApicState::Offline,
            4 => ApicState::None,
            5 => ApicState::Halted,
            _ => panic!("Invalid ApicState from `u8`"),
        }
    }
}

/// Tracks the total number of cores detected on the system based on ACPI.
/// Until ACPI has been initialized, this number will be zero
static TOTAL_CORES: AtomicU32 = AtomicU32::new(0);

/// List of all valid APICs on the system. The APIC ID is the index into the
/// array, the array entry `AtomicU8` is the `u8` representation of an
/// `ApicState` enum
static APICS: [AtomicU8; MAX_CORES] =
    [AtomicU8::new(ApicState::None as u8); MAX_CORES];

/// Mappings of APIC IDs to their memory domains
pub static APIC_TO_DOMAIN: [AtomicU8; MAX_CORES] =
    [AtomicU8::new(0); MAX_CORES];

/// Set the current execution state of a given APIC ID
pub unsafe fn set_core_state(apic_id: u32, state: ApicState) {
    // Forcibly update the state of the core
    APICS[apic_id as usize].store(state as u8, Ordering::SeqCst);
}

/// Gets the APIC state for a given APIC ID
pub fn core_state(apic_id: u32) -> ApicState {
    // Get the current state and convert it into an `ApicState`
    APICS[apic_id as usize].load(Ordering::SeqCst).into()
}

/// Check in that the current core has booted
pub fn core_checkin() {
    /// Number of cores which have checked in
    static CORES_CHECKED_IN: AtomicU32 = AtomicU32::new(0);

    // Transition from launched to online
    let old_state = APICS[core!().apic_id().unwrap() as usize]
        .compare_and_swap(ApicState::Launched as u8,
                          ApicState::Online   as u8,
                          Ordering::SeqCst);

    if core!().id == 0 {
        // BSP should already be marked online
        assert!(old_state == ApicState::Online as u8,
                "BSP not marked online in APIC state");
    } else {
        // Make sure that we only ever go from launched to online, any other
        // transition is invalid
        assert!(old_state == ApicState::Launched as u8,
                "Invalid core state transition");
    }

    // Check in!
    CORES_CHECKED_IN.fetch_add(1, Ordering::SeqCst);

    // Wait for all cores to be checked in
    while CORES_CHECKED_IN.load(Ordering::SeqCst) != num_cores() {}
}

/// Get the total number of cores present on this system
#[allow(unused)]
pub fn num_cores() -> u32 {
    let count = TOTAL_CORES.load(Ordering::SeqCst);
    assert!(count > 0, "total_cores() not ready until ACPI is initialized");
    count
}

/// In-memory representation of an RSDP ACPI structure
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Rsdp {
    signature:         [u8; 8],
    checksum:          u8,
    oem_id:            [u8; 6],
    revision:          u8,
    rsdt_addr:         u32,
}

/// In-memory representation of an Extended RSDP ACPI structure
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct RsdpExtended {
    descriptor:        Rsdp,
    length:            u32,
    xsdt_addr:         u64,
    extended_checksum: u8,
    reserved:          [u8; 3],
}

/// In-memory representation of an ACPI table header
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Header {
    signature:        [u8; 4],
    length:           u32,
    revision:         u8,
    checksum:         u8,
    oemid:            [u8; 6],
    oem_table_id:     u64,
    oem_revision:     u32,
    creator_id:       u32,
    creator_revision: u32,
}

/// Parse a standard ACPI table header. This will parse out the header,
/// validate the checksum and length, and return a physical address and size
/// of the payload following the header.
unsafe fn parse_header(addr: PhysAddr) -> (Header, PhysAddr, usize) {
    // Read the header
    let head = mm::read_phys::<Header>(addr);

    // Get the number of bytes for the table
    let payload_len = head.length
        .checked_sub(size_of::<Header>() as u32)
        .expect("Integer underflow on table length");

    // Check the checksum for the table
    let sum = (addr.0..addr.0 + head.length as u64)
        .fold(0u8, |acc, paddr| {
            acc.wrapping_add(mm::read_phys(PhysAddr(paddr as u64)))
        });
    assert!(sum == 0, "Table checksum invalid {:?}",
            core::str::from_utf8(&head.signature));

    // Return the parsed header
    (head, PhysAddr(addr.0 + size_of::<Header>() as u64), payload_len as usize)
}

/// Initialize the ACPI subsystem. Mainly looking for APICs and memory maps.
/// Brings up all cores on the system
pub unsafe fn init() {
    // Specification says we have to scan the first 1 KiB of the EBDA and the
    // range from 0xe0000 to 0xfffff

    // Get the pointer to the EBDA from the BDA
    let ebda = mm::read_phys::<u16>(PhysAddr(0x40e)) as u64;

    // Compute the regions we need to scan for the RSDP
    let regions = [
        // First 1 KiB of the EBDA
        (ebda, ebda + 1024 - 1),

        // From 0xe0000 to 0xfffff
        (0xe0000, 0xfffff)
    ];

    // Holds the RSDP structure if found
    let mut rsdp = None;

    'rsdp_search: for &(start, end) in &regions {
        // 16-byte align the start address upwards
        let start = (start + 0xf) & !0xf;

        // Go through each 16 byte offset in the range specified
        for paddr in (start..=end).step_by(16) {
            // Compute the end address of RSDP structure
            let struct_end = start + size_of::<Rsdp>() as u64 - 1;

            // Break out of the scan if we are out of bounds of this region
            if struct_end > end {
                break;
            }

            // Read the table
            let table = mm::read_phys::<Rsdp>(PhysAddr(paddr));
            if &table.signature != b"RSD PTR " {
                continue;
            }
            
            // Read the tables bytes so we can checksum it
            let table_bytes = mm::read_phys::
                <[u8; size_of::<Rsdp>()]>(PhysAddr(paddr));

            // Checksum the table
            let sum = table_bytes.iter()
                .fold(0u8, |acc, &x| acc.wrapping_add(x));
            if sum != 0 {
                continue;
            }

            // Checksum the extended RSDP if needed
            if table.revision > 0 {
                // Read the tables bytes so we can checksum it
                const N: usize = size_of::<RsdpExtended>();
                let extended_bytes = mm::read_phys::<[u8; N]>(PhysAddr(paddr));

                // Checksum the table
                let sum = extended_bytes.iter()
                    .fold(0u8, |acc, &x| acc.wrapping_add(x));
                if sum != 0 {
                    continue;
                }
            }

            rsdp = Some(table);
            break 'rsdp_search;
        }
    }

    // Get access to the RSDP
    let rsdp = rsdp.expect("Failed to find RSDP for ACPI");

    // Parse out the RSDT
    let (rsdt, rsdt_payload, rsdt_size) =
        parse_header(PhysAddr(rsdp.rsdt_addr as u64));

    // Check the signature and 
    assert!(&rsdt.signature == b"RSDT", "RSDT signature mismatch");
    assert!((rsdt_size % size_of::<u32>()) == 0,
        "Invalid table size for RSDT");
    let rsdt_entries = rsdt_size / size_of::<u32>();

    // Set up the structures we're interested as parsing out as `None` as some
    // of them may or may not be present.
    let mut apics          = None;
    let mut apic_domains   = None;
    let mut memory_domains = None;

    // Go through each table described by the RSDT
    for entry in 0..rsdt_entries {
        // Get the physical address of the RSDP table entry
        let entry_paddr = rsdt_payload.0 as usize + entry * size_of::<u32>();

        // Get the pointer to the table
        let table_ptr: u32 = mm::read_phys(PhysAddr(entry_paddr as u64));

        // Get the signature for the table
        let signature: [u8; 4] = mm::read_phys(PhysAddr(table_ptr as u64));

        if &signature == b"APIC" {
            // Parse the MADT
            assert!(apics.is_none(), "Multiple MADT ACPI table entries");
            apics = Some(parse_madt(PhysAddr(table_ptr as u64)));
        } else if &signature == b"SRAT" {
            // Parse the SRAT
            assert!(apic_domains.is_none() && memory_domains.is_none(),
                "Multiple SRAT ACPI table entries");
            let (ad, md) = parse_srat(PhysAddr(table_ptr as u64));
            apic_domains   = Some(ad);
            memory_domains = Some(md);
        }
    }

    if let (Some(ad), Some(md)) = (apic_domains, memory_domains) {
        // Register APIC to domain mappings
        for (&apic, &node) in ad.iter() {
            APIC_TO_DOMAIN[apic as usize].store(node.try_into().unwrap(),
                Ordering::Relaxed);
        }

        // Notify the memory manager of the known APIC -> NUMA mappings
        crate::mm::register_numa_nodes(ad, md);
    }

    // Set the total core count based on the number of detected APICs on the
    // system. If no APICs were mentioned by ACPI, then we can simply say there
    // is only one core.
    TOTAL_CORES.store(apics.as_ref().map(|x| x.len() as u32).unwrap_or(1),
                      Ordering::SeqCst);

    // Initialize the state of all the known APICs
    if let Some(apics) = &apics {
        for &apic_id in apics {
            APICS[apic_id as usize].store(ApicState::Offline as u8,
                                          Ordering::SeqCst);
        }
    }

    // Set that our core is online
    APICS[core!().apic_id().unwrap() as usize]
        .store(ApicState::Online as u8, Ordering::SeqCst);

    // Launch all other cores
    if let Some(valid_apics) = apics {
        // Get exclusive access to the APIC for this core
        let mut apic = core!().apic().lock();
        let apic = apic.as_mut().unwrap();

        // Go through all APICs on the system
        for apic_id in valid_apics {
            // We don't want to start ourselves
            if core!().apic_id().unwrap() == apic_id { continue; }

            // Mark the core as launched
            set_core_state(apic_id, ApicState::Launched);

            // Launch the core
            apic.ipi(apic_id, 0x4500);
            apic.ipi(apic_id, 0x4608);
            apic.ipi(apic_id, 0x4608);

            // Wait for the core to come online
            while core_state(apic_id) != ApicState::Online {}
        }
    }
}

/// Parse the MADT out of the ACPI tables
/// Returns a vector of all usable APIC IDs
unsafe fn parse_madt(ptr: PhysAddr) -> Vec<u32> {
    // Parse the MADT header
    let (_header, payload, size) = parse_header(ptr);

    // Skip the local interrupt controller address and the flags to get the
    // physical address of the ICS
    let mut ics = PhysAddr(payload.0 + 4 + 4);
    let end = payload.0 + size as u64;

    // Create a new structure to hold the APICs that are usable
    let mut apics = Vec::new();

    loop {
        /// Processor is ready for use
        const APIC_ENABLED: u32 = 1 << 0;

        /// Processor may be enabled at runtime (IFF ENABLED is zero),
        /// otherwise this bit is RAZ
        const APIC_ONLINE_CAPABLE: u32 = 1 << 1;

        // Make sure there's room for the type and the length
        if ics.0 + 2 > end { break; }

        // Parse out the type and the length of the ICS entry
        let typ: u8 = mm::read_phys(PhysAddr(ics.0 + 0));
        let len: u8 = mm::read_phys(PhysAddr(ics.0 + 1));

        // Make sure there's room for this structure
        if ics.0 + len as u64 > end { break; }
        assert!(len >= 2, "Bad length for MADT ICS entry");

        match typ {
            0 => {
                // LAPIC entry
                assert!(len == 8, "Invalid LAPIC ICS entry");

                // Read the APIC ID
                let apic_id: u8  = mm::read_phys(PhysAddr(ics.0 + 3));
                let flags:   u32 = mm::read_phys(PhysAddr(ics.0 + 4));

                // If the processor is enabled, or can be enabled, log it as
                // a valid APIC
                if (flags & APIC_ENABLED) != 0 ||
                        (flags & APIC_ONLINE_CAPABLE) != 0 {
                    apics.push(apic_id as u32);
                }
            }
            9 => {
                // x2apic entry
                assert!(len == 16, "Invalid x2apic ICS entry");

                // Read the APIC ID
                let apic_id: u32 = mm::read_phys(PhysAddr(ics.0 + 4));
                let flags:   u32 = mm::read_phys(PhysAddr(ics.0 + 8));

                // If the processor is enabled, or can be enabled, log it as
                // a valid APIC
                if (flags & APIC_ENABLED) != 0 ||
                        (flags & APIC_ONLINE_CAPABLE) != 0 {
                    apics.push(apic_id);
                }
            }
            _ => {
                // Don't really care for now
            }
        }

        // Go to the next ICS entry
        ics = PhysAddr(ics.0 + len as u64);
    }

    apics
}

/// Parse the SRAT out of the ACPI tables
/// Returns a tuple of (apic -> domain, memory domain -> phys_ranges)
unsafe fn parse_srat(ptr: PhysAddr) ->
        (BTreeMap<u32, u32>, BTreeMap<u32, RangeSet>) {
    // Parse the SRAT header
    let (_header, payload, size) = parse_header(ptr);

    // Skip the 12 reserved bytes to get to the SRA structure
    let mut sra = PhysAddr(payload.0 + 4 + 8);
    let end = payload.0 + size as u64;

    // Mapping of proximity domains to their memory ranges
    let mut memory_affinities:
        BTreeMap<u32, RangeSet> = BTreeMap::new();
    
    // Mapping of APICs to their proximity domains
    let mut apic_affinities: BTreeMap<u32, u32> = BTreeMap::new();

    loop {
        /// The entry is enabled and present. Some BIOSes may staticially
        /// allocate these table regions, thus the flags indicate whether the
        /// entry is actually present or not.
        const FLAGS_ENABLED: u32 = 1 << 0;

        // Make sure there's room for the type and the length
        if sra.0 + 2 > end { break; }

        // Parse out the type and the length of the ICS entry
        let typ: u8 = mm::read_phys(PhysAddr(sra.0 + 0));
        let len: u8 = mm::read_phys(PhysAddr(sra.0 + 1));

        // Make sure there's room for this structure
        if sra.0 + len as u64 > end { break; }
        assert!(len >= 2, "Bad length for SRAT SRA entry");

        match typ {
            0 => {
                // Local APIC
                assert!(len == 16, "Invalid APIC SRA entry");

                // Extract the fields we care about
                let domain_low:  u8      = mm::read_phys(PhysAddr(sra.0 + 2));
                let domain_high: [u8; 3] = mm::read_phys(PhysAddr(sra.0 + 9));
                let apic_id:     u8      = mm::read_phys(PhysAddr(sra.0 + 3));
                let flags:       u32     = mm::read_phys(PhysAddr(sra.0 + 4));

                // Parse the domain low and high parts into an actual `u32`
                let domain = [domain_low,
                    domain_high[0], domain_high[1], domain_high[2]];
                let domain = u32::from_le_bytes(domain);

                // Log the affinity record
                if (flags & FLAGS_ENABLED) != 0 {
                    assert!(apic_affinities.insert(apic_id as u32, domain)
                            .is_none(), "Duplicate LAPIC affinity domain");
                }
            }
            1 => {
                // Memory affinity
                assert!(len == 40, "Invalid memory affinity SRA entry");

                // Extract the fields we care about
                let domain: u32      = mm::read_phys(PhysAddr(sra.0 +  2));
                let base:   PhysAddr = mm::read_phys(PhysAddr(sra.0 +  8));
                let size:   u64      = mm::read_phys(PhysAddr(sra.0 + 16));
                let flags:  u32      = mm::read_phys(PhysAddr(sra.0 + 28));

                // Only process ranges with a non-zero size (observed on
                // polar and grizzly that some ranges were 0 size)
                if size > 0 {
                    // Log the affinity record
                    if (flags & FLAGS_ENABLED) != 0 {
                        memory_affinities.entry(domain).or_insert_with(|| {
                            RangeSet::new()
                        }).insert(Range {
                            start: base.0,
                            end:   base.0.checked_add(size.checked_sub(1)
                                                      .unwrap()).unwrap()
                        });
                    }
                }
            }
            2 => {
                // Local x2apic
                assert!(len == 24, "Invalid x2apic SRA entry");

                // Extract the fields we care about
                let domain:  u32 = mm::read_phys(PhysAddr(sra.0 +  4));
                let apic_id: u32 = mm::read_phys(PhysAddr(sra.0 +  8));
                let flags:   u32 = mm::read_phys(PhysAddr(sra.0 + 12));

                // Log the affinity record
                if (flags & FLAGS_ENABLED) != 0 {
                    assert!(apic_affinities.insert(apic_id, domain)
                            .is_none(), "Duplicate APIC affinity domain");
                }
            }
            _ => {
            }
        }
        
        // Go to the next ICS entry
        sra = PhysAddr(sra.0 + len as u64);
    }

    (apic_affinities, memory_affinities)
}

