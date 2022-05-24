//! A fuzz session, a collective session of workers collaborating on fuzzing
//! a given target

pub mod windows;

use core::fmt;
use core::any::Any;
use core::arch::asm;
use core::mem::size_of;
use core::cell::Cell;
use core::convert::TryInto;
use core::sync::atomic::{AtomicU64, Ordering};
use core::alloc::Layout;
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;

use crate::mm;
use crate::time;
use crate::ept::{EPT_READ, EPT_WRITE, EPT_EXEC, EPT_DIRTY, EPT_USER_EXEC};
use crate::ept::{EPT_ACCESSED, EPT_MEMTYPE_WB};
use crate::net::NetDevice;
use crate::net::tcp::TcpConnection;
use crate::vtx::*;
use crate::net::netmapping::NetMapping;
use crate::core_locals::LockInterrupts;
use crate::paging::*;

use aht::Aht;
use falktp::{CoverageRecord, InputRecord, ServerMessage, CrashType};
use falktp::PageFaultType;
use noodle::*;
use falkhash::FalkHasher;
use lockcell::LockCell;
use atomicvec::AtomicVec;
use page_table::{PhysAddr, VirtAddr, PhysMem, PageType, Mapping};

/// Number of microseconds to wait before syncing worker statistics into the
/// `FuzzTarget`
///
/// This is used to reduce the frequency which workers sync with the master,
/// to cut down on the lock contention
const STATISTIC_SYNC_INTERVAL: u64 = 10_000;

/// When `true`, the guest RIPs will be stored in a frequency database,
/// allowing visibility into where the guest is spending its CPU time
const GUEST_PROFILING: bool = false;

/// If enabled, the guest is single stepped and all RIPs are logged during
/// execution. This is incredibly slow and memory intensive, use for debugging.
const GUEST_TRACING: bool = true;

/// When set, the APIC will be monitored for writes. This is not done yet, do
/// not use!
const ENABLE_APIC: bool = false;

/// Trait to allow conversion of slices of bytes to primitives and back
/// generically
pub unsafe trait Primitive: Default + Sized {
    fn cast(&self) -> &[u8];
    fn cast_mut(&mut self) -> &mut [u8];
}

macro_rules! primitive {
    ($ty:ty) => {
        unsafe impl Primitive for $ty {
            fn cast(&self) -> &[u8] {
                unsafe {
                    core::slice::from_raw_parts(
                        self as *const $ty as *const u8, size_of::<$ty>())
                }
            }
            
            fn cast_mut(&mut self) -> &mut [u8] {
                unsafe {
                    core::slice::from_raw_parts_mut(
                        self as *mut $ty as *mut u8, size_of::<$ty>())
                }
            }
        }
    }
}

primitive!(u8);
primitive!(u16);
primitive!(u32);
primitive!(u64);
primitive!(u128);
primitive!(i8);
primitive!(i16);
primitive!(i32);
primitive!(i64);
primitive!(i128);

pub trait Enlightenment: Send + Sync {
    /// Request that enlightenment returns the module list for the current
    /// execution state of the worker
    ///
    /// If a module list is parsed, this returns a map of base addresses of
    /// modules to the (end address (inclusive), module name)
    fn get_module_list(&mut self, worker: &mut Worker) ->
        Option<BTreeMap<u64, (u64, Arc<String>)>>;
}

/// Different types of paging modes
#[derive(Clone, Copy, Debug)]
pub enum PagingMode {
    /// 32-bit paging without PAE
    Bits32,

    /// 32-bit paging with PAE
    Bits32Pae,

    /// 4-level 64-bit paging
    Bits64,
}

/// Different x86 segments
#[derive(Clone, Copy)]
pub enum Segment {
    Es,
    Ds,
    Fs,
    Gs,
    Ss,
    Cs,
}

/// Different addresses for x86
#[derive(Clone, Copy)]
pub enum Address {
    /// Physical linear address
    PhysicalLinear {
        addr: u64
    },

    /// Physical address with a segment base and an offset
    PhysicalSegOff {
        seg: Segment,
        off: u64,
    },

    /// Virtual address with a segment base, offset, paging mode, and a page
    /// table
    Virtual {
        seg:  Segment,
        off:  u64,
        mode: PagingMode,
        cr3:  u64
    },

    /// Linear address with a paging mode and a page table
    Linear {
        addr: u64,
        mode: PagingMode,
        cr3:  u64
    },
}

/// A random number generator based off of xorshift64
pub struct Rng(Cell<u64>);

impl Rng {
    /// Create a new randomly seeded `Rng`
    pub fn new() -> Self {
        let rng = Rng(Cell::new(((core!().id as u64) << 48) | cpu::rdtsc()));
        for _ in 0..1000 { rng.rand(); }
        rng
    }

    /// Get the next random number from the random number generator
    pub fn rand(&self) -> usize {
        let orig_seed = self.0.get();

        let mut seed = orig_seed;
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 43;
        self.0.set(seed);

        orig_seed as usize
    }
}

/// Statistics collected about number of fuzz cases and VM exits
///
/// This structure is synced on `STATISTIC_SYNC_INTERVAL` from the workers to
/// the master `FuzzTarget`. This interval based syncing ensures that the
/// lock contention is kept low, regardless of number of fuzz cases or cores.
#[derive(Default, Debug)]
pub struct Statistics {
    /// Number of fuzz cases performed on the target
    fuzz_cases: u64,

    /// Number of cycles spent resetting the VM
    reset_cycles: u64,

    /// Number of cycles spent injecting the fuzz case
    inject_cycles: u64,

    /// Total cycles spent fuzzing
    total_cycles: u64,

    /// Number of cycles spent inside the VM
    vm_cycles: u64,

    /// Number of VM exits
    vm_exits: u64,
}

impl Statistics {
    /// Sync the statistics in `self` into `master`, resetting `self`'s
    /// statistics back to 0 such that the syncing cycle can repeat.
    fn sync_into(&mut self, master: &mut Statistics) {
        // Merge number of fuzz cases
        master.fuzz_cases += self.fuzz_cases;
        master.reset_cycles += self.reset_cycles;
        master.inject_cycles += self.inject_cycles;
        master.vm_cycles += self.vm_cycles;
        master.total_cycles += self.total_cycles;
        master.vm_exits += self.vm_exits;

        // Reset our statistics
        *self = Default::default();
    }
}

/// Network backed VM memory information
pub struct NetBacking<'a> {
    /// Raw guest physical memory backing the snasphot
    memory: Arc<NetMapping<'a>>,
    
    /// Mapping of physical region base to offset into `memory` and the end
    /// (inclusive) of the region
    phys_ranges: BTreeMap<u64, (usize, u64)>,
}

struct Backing<'a> {
    /// A master to this backing
    master: Option<Arc<Backing<'a>>>,

    /// Network mapped memory for the VM
    network_mem: Option<Arc<NetBacking<'a>>>,
    
    /// Raw virtual machine that this worker uses
    pub vm: Vm,
}

impl<'a> Backing<'a> {
    /// Attempts to get a slice to the page backing `gpaddr` in host
    /// addressable memory
    fn get_page(&self, gpaddr: PhysAddr) -> Option<VirtAddr> {
        // Validate alignment
        assert!(gpaddr.0 & 0xfff == 0,
                "get_page() requires an aligned guest physical address");

        // Attempt to translate the page, it is possible it has not yet been
        // mapped and we need to page it in from the network mapped storage in
        // the `FuzzTarget`
        let translation = self.vm.ept().translate(gpaddr);
        if let Some(Mapping { page: Some(orig_page), .. }) = translation {
            Some(VirtAddr(unsafe {
                mm::slice_phys_mut(orig_page.0, 4096).as_ptr() as u64
            }))
        } else {
            if let Some(master) = &self.master {
                master.get_page(gpaddr)
            } else if let Some(netmem) = &self.network_mem {
                // Find the region which may contain our address
                let (phys_base, (offset, end)) = netmem.phys_ranges
                    .range(..=gpaddr.0).next_back()?;

                // Make sure our address falls in the region
                if gpaddr.0 < *phys_base || gpaddr.0 > *end {
                    return None;
                }

                // Compute the offset into the memory based on our offset into
                // the region
                let offset = offset
                    .checked_add((gpaddr.0 - phys_base) as usize)?;
                assert!(offset & 0xfff == 0, "Whoa, page offset not aligned");

                // Get a slice to the memory backing this requested region
                let data = netmem.memory.get(offset..offset + 4096)?;
                Some(VirtAddr(data.as_ptr() as u64))
            } else {
                // Nobody can provide the memory for us, it's not present
                None
            }
        }
    }

    /// Translate a physical address for the guest into a physical address on
    /// the host. If `write` is set, the translation will occur for a write
    /// access, and thus the copy-on-write will be performed on the page if
    /// needed to satisfy the write.
    ///
    /// If the physical address is not valid for the guest, this will return
    /// `None`.
    ///
    /// The translation will only be valid for the page the `gpaddr` resides in
    /// The returned physical address will have the offset from the physical
    /// address applied. Such that a request for physical address `0x13371337`
    /// would return a physical address ending in `0x337`
    fn translate(&mut self, gpaddr: PhysAddr, _read: bool, _write: bool,
                 _exec: bool, pml: &mut Vec<u64>) -> Option<PhysAddr> {
        // XXX:
        // CoW seems to really hurt perf, not sure why yet, might be related
        // to locks or invept causing thrashing on other cores.
        let write = true;

        // Get access to physical memory
        let mut pmem = mm::PhysicalMemory;
        
        // Align the guest physical address
        let align_gpaddr = PhysAddr(gpaddr.0 & !0xfff);
        
        // Attempt to translate the page, it is possible it has not yet been
        // mapped and we need to page it in from the network mapped storage in
        // the `FuzzTarget`
        let translation = if !write {
            self.vm.ept().translate(align_gpaddr)
        } else {
            self.vm.ept_mut().translate_int(align_gpaddr, write, false)
        };
        
        // First, determine if we need to perform a CoW or make a mapping for
        // an unmapped page
        if let Some(Mapping {
                pte: Some(pte), page: Some((orig_page, _, ent)), .. }) =
                    translation {
            // Page is mapped, it is possible it needs to be promoted to
            // writable
            let page_writable =
                (unsafe { mm::read_phys::<u64>(pte) } & EPT_WRITE) != 0;

            // If the page is writable, and this is is a write, OR if the
            // operation is not a write, then the existing allocation can
            // satisfy the translation request.
            if (write && page_writable) || !write {
                if write {
                    // Check if the dirty bit was previously clear
                    if (ent & EPT_DIRTY) == 0 {
                        // Log that this page has been dirtied to the PML
                        pml.push(align_gpaddr.0);
                        
                        // Set that the TLB should be flushed on next VM entry
                        // as we changed dirty bits
                        self.vm.ept_dirty = true;
                    }
                }

                return Some(PhysAddr(orig_page.0 + (gpaddr.0 & 0xfff)));
            }
        }

        // At this stage, we either must perform a CoW or map an unmapped page

        // Get the original contents of the page
        let orig_page_gpaddr = if let Some(master) = &self.master {
            // Get the page from the master
            master.get_page(align_gpaddr)?
        } else if let Some(_) = &self.network_mem {
            self.get_page(align_gpaddr)?
        } else {
            // Page is not present, and cannot be filled from the master or
            // network memory
            return None;
        };

        // Look up the physical page backing for the mapping

        // Touch the page to make sure it's present
        unsafe { core::ptr::read_volatile(orig_page_gpaddr.0 as *const u8); }
        
        let orig_page = {
            // Get access to the host page table
            let mut page_table = core!().boot_args.page_table.lock();
            let page_table = page_table.as_mut().unwrap();

            // Translate the mapping virtual address into a physical
            // address
            //
            // This will always succeed as we touched the memory above
            let (page, offset, _) =
                page_table.translate(&mut pmem, orig_page_gpaddr)
                    .map(|x| x.page).flatten()
                    .expect("Whoa, memory page not mapped?!");
            PhysAddr(page.0 + offset)
        };

        // Get a slice to the original read-only page
        let ro_page = unsafe { mm::slice_phys_mut(orig_page, 4096) };

        let page = if let Some(Mapping { pte: Some(pte), page: Some(_), .. }) =
                translation {
            // Promote the original page via CoW
                
            // Allocate a new page
            let page = pmem.alloc_phys(
                Layout::from_size_align(4096, 4096).unwrap()).unwrap();

            // Get mutable access to the underlying page
            let psl = unsafe { mm::slice_phys_mut(page, 4096) };

            // Copy in the bytes to initialize the page from the network
            // mapped memory
            psl.copy_from_slice(&ro_page);

            // Promote the page via CoW
            unsafe {
                mm::write_phys(pte, 
                    page.0 | EPT_WRITE | EPT_READ | EPT_EXEC | EPT_USER_EXEC |
                    EPT_DIRTY | EPT_ACCESSED);

                // Log that this page has been dirtied to the PML
                pml.push(align_gpaddr.0);

                // Mapping changed, we must invalidate the TLB on next VM
                // entry
                self.vm.ept_dirty = true;
            }

            page
        } else {
            // Page was not mapped
            if write {
                // Page needs to be CoW-ed from the network mapped file

                // Allocate a new page
                let page = pmem.alloc_phys(
                    Layout::from_size_align(4096, 4096).unwrap()).unwrap();

                // Get mutable access to the underlying page
                let psl = unsafe { mm::slice_phys_mut(page, 4096) };

                // Copy in the bytes to initialize the page from the network
                // mapped memory
                psl.copy_from_slice(&ro_page);

                unsafe {
                    // Map in the page as RWX, WB, and already dirtied and
                    // accessed (since we're getting write access to it)
                    self.vm.ept_mut().map_raw(align_gpaddr,
                        PageType::Page4K,
                        page.0 | EPT_READ | EPT_WRITE | EPT_EXEC |
                        EPT_USER_EXEC | EPT_MEMTYPE_WB | EPT_DIRTY |
                        EPT_ACCESSED)
                        .unwrap();
               
                    // Memory was dirtied
                    pml.push(align_gpaddr.0);
                }

                // Return the physical address of the new page
                page
            } else {
                // Page is only being accessed for read. Alias the guest's
                // physical memory directly into the network mapped page as
                // read-only
                
                unsafe {
                    // Map in the page as read-only into the guest page table
                    self.vm.ept_mut().map_raw(align_gpaddr,
                        PageType::Page4K,
                        orig_page.0 | EPT_READ | EPT_EXEC | EPT_USER_EXEC |
                        EPT_MEMTYPE_WB)
                        .unwrap();
                }

                // Return the physical address of the backing page
                orig_page
            }
        };
        
        // Return the host physical address of the requested guest physical
        // address
        Some(PhysAddr(page.0 + (gpaddr.0 & 0xfff)))
    }
}

noodle!(serialize, deserialize,
    /// A simple register state which is what is relayed to the server on
    /// crashes This should just be a rarely-changing structure we can send to
    /// and from the server
    pub struct BasicRegisterState {
        rax: u64,
        rcx: u64,
        rdx: u64,
        rbx: u64,
        rsp: u64,
        rbp: u64,
        rsi: u64,
        rdi: u64,
        r8:  u64,
        r9:  u64,
        r10: u64,
        r11: u64,
        r12: u64,
        r13: u64,
        r14: u64,
        r15: u64,
        rip: u64,
        rfl: u64,
        cr2: u64,
        cr3: u64,
    }
);

impl BasicRegisterState {
    pub fn from_register_state(rs: &mut RegisterState) -> Self {
        BasicRegisterState {
            rax: rs.reg(Register::Rax),
            rcx: rs.reg(Register::Rcx),
            rdx: rs.reg(Register::Rdx),
            rbx: rs.reg(Register::Rbx),
            rsp: rs.reg(Register::Rsp),
            rbp: rs.reg(Register::Rbp),
            rsi: rs.reg(Register::Rsi),
            rdi: rs.reg(Register::Rdi),
            r8:  rs.reg(Register::R8),
            r9:  rs.reg(Register::R9),
            r10: rs.reg(Register::R10),
            r11: rs.reg(Register::R11),
            r12: rs.reg(Register::R12),
            r13: rs.reg(Register::R13),
            r14: rs.reg(Register::R14),
            r15: rs.reg(Register::R15),
            rip: rs.reg(Register::Rip),
            rfl: rs.reg(Register::Rflags),
            cr2: rs.reg(Register::Cr2),
            cr3: rs.reg(Register::Cr3),
        }
    }
}

impl fmt::Display for BasicRegisterState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
r#"rax {:016x} rcx {:016x} rdx {:016x} rbx {:016x}
rsp {:016x} rbp {:016x} rsi {:016x} rdi {:016x}
r8  {:016x} r9  {:016x} r10 {:016x} r11 {:016x}
r12 {:016x} r13 {:016x} r14 {:016x} r15 {:016x}
rfl {:016x}
rip {:016x}
cr2 {:016x} cr3 {:016x}"#,
            self.rax, self.rcx, self.rdx, self.rbx,
            self.rsp, self.rbp, self.rsi, self.rdi,
            self.r8,  self.r9,  self.r10, self.r11,
            self.r12, self.r13, self.r14, self.r15,
            self.rfl,
            self.rip,
            self.cr2, self.cr3)
    }
}

/// A VM worker which is likely part of a large fuzzing group
pub struct Worker<'a> {
    /// The enlightenment which can be used to resolve OS-specific information
    enlightenment: Option<Box<dyn Enlightenment>>,

    /// The backing of the VM, this has the registers and memory for the
    /// worker
    backing: Backing<'a>,

    /// The fuzz session this worker belongs to
    session: Option<Arc<FuzzSession<'a>>>,
    
    /// Random number generator seed
    pub rng: Rng,

    /// Fuzz input for the fuzz case
    pub fuzz_input: Option<Vec<u8>>,

    /// Local worker statistics, to be merged into the fuzz session on an
    /// interval
    stats: Statistics,

    /// `rdtsc` time of the next statistic sync
    sync: u64,

    /// Unique worker identifier
    worker_id: u64,

    /// A connection to the server
    server: Option<BufferedIo<TcpConnection>>,

    /// A hasher which can be used to generate 128-bit hashes
    hasher: FalkHasher,

    /// List of all modules for all cr3s
    /// Maps from base address to module, to end of module (inclusive) and the
    /// module name
    module_list: BTreeMap<u64, BTreeMap<u64, (u64, Arc<String>)>>,

    /// Page modification log of dirtied physical memory pages
    pml: Vec<u64>,

    /// Mapping of guest physical addresses to their original final level
    /// EPT pointer, backing EPT page, and backing master page
    /// This allows skipping the traversal of EPT tables on resets, as the
    /// dirty bits and page copies can be done entirly with this information
    page_cache: BTreeMap<PhysAddr, (*mut u64, VirtAddr, VirtAddr)>,

    /// Mapping of guest (page table, rip) pairs to their frequencies of being
    /// observed during preemption timers
    profiling: BTreeMap<(u64, u64), u64>,
    
    /// Vector to hold all RIPs executed when `GUEST_TRACING` is enabled
    trace: Vec<u64>,
}

impl<'a> Worker<'a> {
    /// Create a new empty VM
    pub fn new(cpus: usize, memory: Option<Arc<NetBacking<'a>>>) -> Self {
        Worker {
            backing: Backing {
                master:      None,
                network_mem: memory,
                vm:          Vm::new(cpus),
            },
            rng:            Rng::new(),
            stats:          Statistics::default(),
            sync:           0,
            session:        None,
            worker_id:      !0,
            module_list:    BTreeMap::new(),
            fuzz_input:     Some(Vec::new()),
            server:         None,
            hasher:         FalkHasher::new(),
            enlightenment:  None,
            pml:            Vec::new(),
            page_cache:     BTreeMap::new(),
            profiling:      BTreeMap::new(),
            trace:          Vec::new(),
        }
    }
    
    /// Create a new VM forked from a master
    fn fork(cpus: usize, session: Arc<FuzzSession<'a>>,
            master: Arc<Backing<'a>>, worker_id: u64) -> Self {
        // Create a new VM with the masters guest registers as the current
        // register state
        let mut vm = Vm::new(cpus);
        vm.guest_regs.copy_regs_from(&master.vm.guest_regs);

        // Create the new VM referencing the master
        Worker {
            backing: Backing {
                master:      Some(master),
                network_mem: None,
                vm:          vm,
            },
            rng:            Rng::new(),
            stats:          Statistics::default(),
            sync:           0,
            session:        Some(session),
            worker_id:      worker_id,
            module_list:    BTreeMap::new(),
            server:         None,
            fuzz_input:     Some(Vec::new()),
            hasher:         FalkHasher::new(),
            enlightenment:  None,
            pml:            Vec::new(),
            page_cache:     BTreeMap::new(),
            profiling:      BTreeMap::new(),
            trace:          Vec::new(),
        }
    }

    /// Switch to another CPU context
    #[inline]
    pub fn switch_cpu(&mut self, cpu: usize) {
        // Switch CPUs
        self.backing.vm.switch_cpu(cpu);
    }
    
    /// Get the current active CPU
    #[inline]
    pub fn active_cpu(&self) -> usize {
        self.backing.vm.active_cpu()
    }

    /// Get the number of CPUs for this VM
    #[inline]
    pub fn cpus(&self) -> usize {
        self.backing.vm.cpus()
    }

    /// Get a register from the guest VM context
    #[inline]
    pub fn reg(&mut self, reg: Register) -> u64 {
        self.backing.vm.reg(reg)
    }
    
    /// Set a register in the guest VM context
    #[inline]
    pub fn set_reg(&mut self, reg: Register, val: u64) {
        self.backing.vm.set_reg(reg, val)
    }
    
    /// Modify a register and return the newly updated value
    #[inline]
    pub fn mod_reg<F>(&mut self, reg: Register, func: F) -> u64
            where F: FnOnce(u64) -> u64 {
        self.backing.vm.mod_reg(reg, func)
    }

    /// Get the current CPL
    #[inline]
    pub fn cpl(&mut self) -> u8 {
        (self.reg(Register::Cs) as u8) & 3
    }
    
    /// Gets access to the VM backing this worker
    #[inline]
    pub fn vm_mut(&mut self) -> &mut Vm {
        &mut self.backing.vm
    }

    /// Get a unique context identifier
    /// The kernel will always resolve to !0, if we're not in kernel mode then
    /// we will use the current cr3
    #[inline]
    pub fn context_id(&mut self) -> u64 {
        if self.cpl() == 0 {
            !0
        } else {
            self.reg(Register::Cr3) & 0xffffffffff000
        }
    }

    /// Set the enlightenment to use for this guest
    pub fn enlighten(&mut self, enlightenment: Option<Box<dyn Enlightenment>>){
        self.enlightenment = enlightenment;
    }

    /// Get a random existing input
    pub fn rand_input(&self) -> Option<&[u8]> {
        // Get access to the session
        let session = self.session.as_ref().unwrap();

        // Get the number of inputs in the database
        let inputs = session.inputs.len();

        if inputs > 0 {
            // Get a random input
            session.inputs.get(self.rng.rand() % inputs).map(|x| x.as_slice())
        } else {
            // No inputs in the DB yet
            None
        }
    }
    
    /// This routine can be used to map in a single page full of zeros as
    /// read-only. This can be used to nop out things like the HPET
    pub fn map_zeroed_readonly_page(&mut self, paddr: PhysAddr) {
        assert!(paddr.0 & 0xfff == 0);

        // Get access to physical memory
        let mut pmem = mm::PhysicalMemory;

        // Allocate a new page
        let page = pmem.alloc_phys(
            Layout::from_size_align(4096, 4096).unwrap()).unwrap();

        // Get mutable access to the underlying page
        let psl = unsafe { mm::slice_phys_mut(page, 4096) };
        psl.iter_mut().for_each(|x| *x = 0);

        unsafe {
            // Map the page as read-only
            self.backing.vm.ept_mut().map_raw(paddr,
                PageType::Page4K,
                page.0 | EPT_READ | EPT_MEMTYPE_WB )
                .unwrap();
        }
    }

    /// Resolve a `rip` into a `CoverageRecord`. This will attempt to enlighten
    /// if the module does not resolve.
    pub fn resolve_module<'b>(&mut self, rip: u64) -> CoverageRecord<'b> {
        let mut modoff = self.resolve_module_int(rip);
        if modoff.0.is_none() && self.enlightenment.is_some() {
            // Get the current context ID
            let pt = self.context_id();

            // Check if we have a module list for this process
            if !self.module_list.contains_key(&pt) {
                // Oooh, go try to get the module list for this
                // process

                // Request the module list from enlightenment
                let mut enl = self.enlightenment.take().unwrap();
                if let Some(ml) = enl.get_module_list(self) {
                    // Save the module list for the process
                    self.module_list.insert(pt, ml);
                
                    // Re-resolve the module + offset
                    modoff = self.resolve_module_int(rip);
                }

                self.enlightenment = Some(enl);
            }
        }

        CoverageRecord {
            module: modoff.0.map(|x| Cow::Owned(x)),
            offset: modoff.1,
        }
    }

    /// Report coverage from the current context
    pub fn report_coverage(&mut self, session: &FuzzSession) -> bool {
        let rip = self.reg(Register::Rip);
        let modoff = self.resolve_module(rip);
        let input = self.fuzz_input.as_ref().unwrap();
        session.report_coverage(Some((input, &self.hasher)), &modoff)
    }

    /// Perform a single fuzz case to completion
    pub fn fuzz_case(&mut self, context: &mut dyn Any) -> VmExit {
        let fuzz_start = cpu::rdtsc();
        
        // Start a timer
        let it = cpu::rdtsc();

        // Get access to the session
        let mut session = self.session.take().unwrap();

        // Get access to the master
        let master = self.backing.master.as_mut().unwrap();

        // Tracks a list of pending interrupt vectors which need to be
        // delivered to the VM (in order)
        let mut pending_interrupts: VecDeque<(usize, u8)> = VecDeque::new();

        // Tracks that we're single stepping for an APIC write
        let mut apic_write = None;

        // Reset memory to its original state
        for &paddr in self.pml.iter() {
            let paddr = PhysAddr(paddr);

            if ENABLE_APIC && paddr == PhysAddr(0xfee00000) {
                continue;
            }

            // Get the original page from the master
            let pc = &mut self.page_cache;
            let vm = &mut self.backing.vm;
            let (ept_entry, page, orig_page) = *pc.entry(paddr)
                .or_insert_with(|| {
                    // Translate our page
                    let walk = vm.ept_mut()
                        .translate_int(paddr, false, false).unwrap();
                    let pte  = walk.pte.unwrap();
                    let page = walk.page.unwrap().0;
            
                    // Convert physical addresses into virtual ones
                    let pte = unsafe {
                        mm::slice_phys_mut(pte,
                                           core::mem::size_of::<u64>() as u64)
                    };
                    let page = unsafe { mm::slice_phys_mut(page, 4096) };

                    (
                        pte.as_ptr() as *mut u64,
                        VirtAddr(page.as_ptr() as u64),
                        master.get_page(paddr)
                            .expect("Dirtied page without master!?")
                    )
                });

            unsafe {
                // Clear the dirty bit on the EPT entry
                core::ptr::write(ept_entry,
                                 core::ptr::read(ept_entry) & !EPT_DIRTY); 
            }

            unsafe {
                // Copy the original page into the modified copy of the page
                asm!(
                    "mov rcx, 4096 / 8",
                    "rep movsq",
                    inout("rdi") page.0 => _,
                    inout("rsi") orig_page.0 => _,
                    out("rcx") _,
                );
            }
        }

        if self.pml.len() > 0 {
            // Set that the EPT TLB must be invalidated (since we changed dirty
            // bit states)
            self.backing.vm.ept_dirty = true;

            // Clear the PML as everything has been cleaned
            self.pml.clear();
        }
       
        // Load the original snapshot registers
        self.backing.vm.guest_regs.copy_regs_from(&master.vm.guest_regs);

        // Reset the VMCS state, this also invalidates the TLB entries since
        // we have now changed the paging structures with EPT above
        self.backing.vm.reset();
        
        self.stats.reset_cycles += cpu::rdtsc() - it;

        let it = cpu::rdtsc();

        // Invoke the injection callback
        if let Some(inject) = session.inject {
            self.session = Some(session);
            inject(self, context);
            session = self.session.take().unwrap();
        }
        
        self.stats.inject_cycles += cpu::rdtsc() - it;

        // Compute the timeout
        let timeout = session.timeout.map(|x| time::future(x)).unwrap_or(!0);

        // Tracks how many single steps we should do for coverage gathering
        let mut single_steps = 0;

        // Stores the register state of the VM during the last page fault
        let mut last_page_fault:
            Option<(CoverageRecord, VmExit, BasicRegisterState, u8)> = None;

        if GUEST_TRACING {
            // Clear the execution trace
            self.trace.clear();
        }

        let vmexit = 'vm_loop: loop {
            if cpu::rdtsc() >= timeout {
                break 'vm_loop VmExit::Timeout;
            }

            if GUEST_TRACING {
                // Always enable single stepping if `GUEST_TRACING` is true
                single_steps = 1;
            }

            if pending_interrupts.len() > 0 {
                // Switch to the CPU we want to interrupt
                if let Some((cpu, _)) = pending_interrupts.front() {
                    self.switch_cpu(*cpu);
                }

                // If there's a pending interrupt, request interrupt window
                // exiting
                let pbc = self.reg(Register::ProcBasedControls);
                self.set_reg(Register::ProcBasedControls, pbc | (1 << 2));
            } else {
                let pbc = self.reg(Register::ProcBasedControls);
                self.set_reg(Register::ProcBasedControls, pbc & !(1 << 2));
            }

            // Single step when requested
            if apic_write.is_some() || single_steps > 0 {
                let pbc = self.reg(Register::ProcBasedControls);
                self.set_reg(Register::ProcBasedControls, pbc | (1 << 27));
                single_steps -= 1;
            } else {
                let pbc = self.reg(Register::ProcBasedControls);
                self.set_reg(Register::ProcBasedControls, pbc & !(1 << 27));
            }

            // Set the pre-emption timer for randomly breaking into the VM
            // to enforce timeouts and get random coverage sampling
            self.backing.vm.preemption_timer = 
                Some(self.rng.rand() as u32 % 100000);

            // Run the VM until a VM exit
            let (vmexit, vm_cycles) = self.backing.vm.run();
            self.stats.vm_exits  += 1;
            self.stats.vm_cycles += vm_cycles;

            match vmexit {
                VmExit::Rdtsc { inst_len } => {
                    let tsc = self.backing.vm.guest_regs.tsc;
                    self.set_reg(Register::Rax, (tsc >>  0) & 0xffffffff);
                    self.set_reg(Register::Rdx, (tsc >> 32) & 0xffffffff);

                    // Advance the TSC a bit
                    self.backing.vm.guest_regs.tsc += 1000;

                    let rip = self.reg(Register::Rip);
                    self.set_reg(Register::Rip, rip.wrapping_add(inst_len));
                    continue 'vm_loop;
                }
                VmExit::EptViolation { addr, read, write, exec } => {
                    if ENABLE_APIC && write &&
                            (addr.0 & !0xfff) == 0xfee0_0000 {
                        // Write was to the APIC, set that we're tracking a
                        // write to the APIC, which will cause us to single
                        // step
                        apic_write = Some(addr);
        
                        unsafe {
                            // Promote the page to writable, and then we single
                            // step to observe the written value
                            let pte =
                                self.backing.vm.ept_mut().translate(addr)
                                .unwrap().pte.unwrap();
                            mm::write_phys(pte,
                                mm::read_phys::<u64>(pte) | EPT_WRITE);
                            self.backing.vm.ept_dirty = true;
                        }

                        // Handle the exit as we promoted the APIC page to RW
                        continue 'vm_loop;
                    }

                    if self.backing.translate(addr, read, write, exec,
                                              &mut self.pml).is_some() {
                        continue 'vm_loop;
                    }
                }
                VmExit::PmlFull => {
                    // Log the PML buffer to our growable buffer
                    self.pml.extend_from_slice(self.backing.vm.pml());

                    // Reset the PML to empty
                    self.set_reg(Register::PmlIndex, 511);
                    continue 'vm_loop;
                }
                VmExit::ExternalInterrupt => {
                    // Host interrupt happened, ignore it
                    continue 'vm_loop;
                }
                VmExit::Exception(Exception::PageFault { addr, .. }) => {
                    // Hook, but also re-inject page faults
                    let ii = self.reg(Register::ExitInterruptionInformation);
                    let ic = self.reg(Register::ExitInterruptionErrorCode);
                    let il = self.reg(Register::ExitInstructionLength);
                    self.set_reg(Register::EntryInterruptionInformation, ii);
                    self.set_reg(Register::EntryInterruptionErrorCode,   ic);
                    self.set_reg(Register::EntryInstructionLength,       il);
                    self.set_reg(Register::Cr2, addr.0);

                    let rip = self.reg(Register::Rip);
                    last_page_fault = Some((
                        self.resolve_module(rip),
                        vmexit,
                        BasicRegisterState::from_register_state(
                            self.backing.vm.active_register_state()),
                        self.cpl()));
                    continue 'vm_loop;
                }
                VmExit::Exception(Exception::Breakpoint) => {
                    let rip = self.reg(Register::Rip);
                    if rip == 0xfffff80429bd04b3 {
                        let (cr, vm, rs, cpl) =
                            last_page_fault.as_ref().unwrap();
                        self.report_crash(&session, cr, vm, rs, *cpl);
                        //break 'vm_loop vmexit;
                    }
                }
                VmExit::Exception(Exception::NMI) => {
                    unsafe {
                        // NMI ourselves
                        asm!("int 2");
                        cpu::halt();
                    }
                }
                VmExit::Exception(_) => {
                    let rip      = self.reg(Register::Rip);
                    let modoff   = self.resolve_module(rip);
                    let cpl      = self.cpl();
                    let regstate = BasicRegisterState::from_register_state(
                        self.backing.vm.active_register_state());
                    self.report_crash(&session, &modoff, &vmexit, &regstate,
                                      cpl);
                    //break 'vm_loop vmexit;
                }
                VmExit::ReadMsr { inst_len } => {
                    // Get the MSR ID we're reading
                    let msr = self.reg(Register::Rcx);

                    // Get the MSR value
                    let val = match msr as u32 {
                        IA32_FS_BASE => self.reg(Register::FsBase),
                        IA32_GS_BASE => self.reg(Register::GsBase),
                        IA32_KERNEL_GS_BASE => {
                            self.reg(Register::KernelGsBase)
                        }
                        _ => panic!("Unexpected MSR read {:#x} @ {:#x}\n",
                                    msr, self.reg(Register::Rip)),
                    };

                    // Set the low and high parts of the result
                    self.set_reg(Register::Rax, (val >>  0) as u32 as u64);
                    self.set_reg(Register::Rdx, (val >> 32) as u32 as u64);

                    let rip = self.reg(Register::Rip);
                    self.set_reg(Register::Rip, rip.wrapping_add(inst_len));
                    continue 'vm_loop;
                }
                VmExit::WriteMsr { inst_len } => {
                    // Get the MSR ID we're writing
                    let msr = self.reg(Register::Rcx);

                    // Get the value we're writing
                    let val = (self.reg(Register::Rdx) << 32) |
                        self.reg(Register::Rax);

                    // Get the MSR value
                    match msr as u32 {
                        IA32_FS_BASE => {
                            self.set_reg(Register::FsBase, val);
                        }
                        IA32_GS_BASE => {
                            self.set_reg(Register::GsBase, val);
                        }
                        IA32_KERNEL_GS_BASE => {
                            self.set_reg(Register::KernelGsBase, val);
                        }
                        _ => panic!("Unexpected MSR write {:#x} @ {:#x}\n",
                                    msr, self.reg(Register::Rip)),
                    }

                    // Advance PC
                    let rip = self.reg(Register::Rip);
                    self.set_reg(Register::Rip, rip.wrapping_add(inst_len));
                    continue 'vm_loop;
                }
                VmExit::WriteCr { cr, gpr, inst_len } => {
                    // Get the GPR source for the write
                    let gpr = match gpr {
                         0 => self.reg(Register::Rax),
                         1 => self.reg(Register::Rcx),
                         2 => self.reg(Register::Rdx),
                         3 => self.reg(Register::Rbx),
                         4 => self.reg(Register::Rsp),
                         5 => self.reg(Register::Rbp),
                         6 => self.reg(Register::Rsi),
                         7 => self.reg(Register::Rdi),
                         8 => self.reg(Register::R8),
                         9 => self.reg(Register::R9),
                        10 => self.reg(Register::R10),
                        11 => self.reg(Register::R11),
                        12 => self.reg(Register::R12),
                        13 => self.reg(Register::R13),
                        14 => self.reg(Register::R14),
                        15 => self.reg(Register::R15),
                        _ => panic!("Invalid GPR for write CR"),
                    };

                    // Update the CR
                    match cr {
                        0 => self.set_reg(Register::Cr0, gpr),
                        3 => {
                            self.set_reg(Register::Cr3, gpr);
                        },
                        4 => self.set_reg(Register::Cr4, gpr),
                        _ => panic!("Invalid CR register for write CR"),
                    }
                    
                    // Advance RIP to the next instruction
                    let rip = self.reg(Register::Rip);
                    self.set_reg(Register::Rip, rip.wrapping_add(inst_len));
                    continue 'vm_loop;
                }
                VmExit::ReadCr { cr, gpr, inst_len } => {
                    // Get the CR that should be read
                    let cr = match cr {
                        0 => self.reg(Register::Cr0),
                        3 => self.reg(Register::Cr3),
                        4 => self.reg(Register::Cr4),
                        _ => panic!("Invalid CR register for read CR"),
                    };

                    match gpr {
                         0 => self.set_reg(Register::Rax, cr),
                         1 => self.set_reg(Register::Rcx, cr),
                         2 => self.set_reg(Register::Rdx, cr),
                         3 => self.set_reg(Register::Rbx, cr),
                         4 => self.set_reg(Register::Rsp, cr),
                         5 => self.set_reg(Register::Rbp, cr),
                         6 => self.set_reg(Register::Rsi, cr),
                         7 => self.set_reg(Register::Rdi, cr),
                         8 => self.set_reg(Register::R8,  cr),
                         9 => self.set_reg(Register::R9,  cr),
                        10 => self.set_reg(Register::R10, cr),
                        11 => self.set_reg(Register::R11, cr),
                        12 => self.set_reg(Register::R12, cr),
                        13 => self.set_reg(Register::R13, cr),
                        14 => self.set_reg(Register::R14, cr),
                        15 => self.set_reg(Register::R15, cr),
                        _ => panic!("Invalid GPR for read CR"),
                    }

                    // Advance RIP to the next instruction
                    let rip = self.reg(Register::Rip);
                    self.set_reg(Register::Rip, rip.wrapping_add(inst_len));
                    continue 'vm_loop;
                }
                VmExit::InterruptWindow => {
                    let (cpu, int) = pending_interrupts.pop_front().unwrap();
                    assert!(cpu == self.active_cpu());
                    self.set_reg(
                        Register::EntryInterruptionInformation,
                        (1 << 31) | (int as u64));
                    continue 'vm_loop;
                }
                VmExit::MonitorTrap => {
                    if self.report_coverage(&session) {
                        single_steps = 100;
                    }

                    if let Some(addr) = apic_write {
                        unsafe {
                            // Demote the APIC page back to read-only
                            let trans =
                                self.backing.vm.ept_mut().translate(addr)
                                .unwrap();
                            let pte = trans.pte.unwrap();
                            let page = trans.page.unwrap().0;

                            let val = mm::read_phys::<u64>(
                                PhysAddr(page.0 + (addr.0 & 0xfff)));
                            /*
                            print!("APIC write from {} to {:#x} {:#x} with \
                                   {:#x}\n",
                                   self.active_cpu(),
                                   self.reg(Register::Rip),
                                   addr.0, val);*/

                            if addr == PhysAddr(0xfee0_0300) {
                                let delivery_mode   = (val >>  8) & 7;
                                let _logical_dst    = (val >> 11) & 1 != 0;
                                let delivery_status = (val >> 12) & 1 != 0;
                                let level           = (val >> 14) & 1 != 0;
                                let level_triggered = (val >> 15) & 1 != 0;
                                let _dest_shorthand = (val >> 18) & 3;

                                // We emulate so little, only IPI-to-self and
                                // only fixed delivery mode (no NMI, etc)
                                assert!(
                                        !level && !level_triggered &&
                                        !delivery_status &&
                                        delivery_mode == 0);

                                // Request delivery of the interrupt
                                for cpu in 0..self.cpus() {
                                    pending_interrupts.push_back(
                                        (cpu, val as u8));
                                }

                                self.set_reg(Register::PendingDebug, 0);
                                self.set_reg(Register::ActivityState, 0);
                                self.set_reg(
                                    Register::InterruptabilityState, 0);

                                self.set_reg(
                                    Register::EntryInterruptionInformation, 0);
                                self.set_reg(
                                    Register::EntryInterruptionErrorCode, 0);
                                self.set_reg(
                                    Register::EntryInstructionLength, 0);
                                self.set_reg(
                                    Register::ExitInterruptionInformation, 0);
                                self.set_reg(
                                    Register::ExitInterruptionErrorCode, 0);
                                self.set_reg(
                                    Register::ExitInstructionLength, 0);
                            }

                            // Clear the backing APIC page
                            mm::slice_phys_mut(page, 4096)
                                .iter_mut().for_each(|x| *x = 0);

                            // Clear the writable bit
                            mm::write_phys(pte,
                                mm::read_phys::<u64>(pte) & !EPT_WRITE);

                            self.backing.vm.ept_dirty = true;
                        }

                        // No longer in APIC write state
                        apic_write = None;
                    }

                    if GUEST_TRACING {
                        // Log all RIPs executed when in tracing mode
                        let rip = self.reg(Register::Rip);
                        self.trace.push(rip);
                    }
                    continue 'vm_loop;
                }
                VmExit::PreemptionTimer => {
                    if self.report_coverage(&session) {
                        single_steps = 100;
                    }

                    if GUEST_PROFILING {
                        let rip = self.reg(Register::Rip);
                        let cr3 = self.reg(Register::Cr3);
                        *self.profiling.entry((rip, cr3)).or_insert(0) += 1;
                    }

                    continue 'vm_loop;
                }
                _ => {},
            }
            
            // Attempt to handle the vmexit with the user's callback
            if let Some(vmexit_filter) = session.vmexit_filter {
                if vmexit_filter(self, &vmexit) {
                    continue 'vm_loop;
                }
            }

            // Unhandled VM exit, break
            break 'vm_loop vmexit;
        };

        // Get the remainder in the PML. Since the PML index is 511 when the
        // list is empty, we should add 1 so it becomes 512. This would cause
        // the slice to be [512..512], and thus empty, when the list is
        // empty. This also handles the situation where the PML index
        // decrements to 0xffff (as mentioned in the manual), as the index will
        // become zero, causing us to extend the _entire_ size of thet PML,
        // which is the correct behavior
        let pml_index =
            (self.reg(Register::PmlIndex) as u16).wrapping_add(1);
        self.pml.extend_from_slice(
            &self.backing.vm.pml()[pml_index as usize..]);

        // Update number of fuzz cases
        self.stats.fuzz_cases += 1;

        // Sync the local statistics into the master on an interval
        self.stats.total_cycles += cpu::rdtsc() - fuzz_start;
        if cpu::rdtsc() >= self.sync {
            /*
            unsafe {
                static mut STATS: [u64; 4] = [0; 4];
                STATS[core!().id as usize / 64] |= 1 << (core!().id % 64);
                if core!().id == 0 {
                    print!("{:016x?}\n", STATS);
                    STATS = [0; 4];
                }
            }
            //print!("{:5} {:10}\n", core!().id, self.stats.fuzz_cases);*/

            if GUEST_PROFILING {
                // Sum up all frequencies in the profiling structure
                let sum: u64 = self.profiling.values().sum();

                for ((cr3, rip), &freq) in self.profiling.iter() {
                    // Compute the percentage of time at this location
                    let freq = freq as f64 / sum as f64;

                    if freq > 0.02 {
                        print!("{:3} {:#018x} {:#018x} {:10.6}\n", 
                            core!().id, cr3, rip, freq);
                    }
                }
            }

            self.stats.sync_into(&mut session.stats.lock());
            if self.worker_id == 0 {
                // Report to the server
                session.report_statistics(self.server.as_mut().unwrap());
            }

            // Set the next sync time
            self.sync = time::future(STATISTIC_SYNC_INTERVAL);
        }

        if GUEST_TRACING {
            // Report the guest trace
            ServerMessage::Trace(
                Cow::Borrowed(self.trace.as_slice())
            ).serialize(self.server.as_mut().unwrap()).unwrap();
        }

        self.session = Some(session);
        vmexit
    }

    /// Report a crash to the server
    pub fn report_crash(&mut self, session: &FuzzSession, cr: &CoverageRecord,
                        vmexit: &VmExit, regstate: &BasicRegisterState,
                        cpl: u8) {
        let ct = match vmexit {
            VmExit::Exception(Exception::DivideError) => CrashType::DivideError,
            VmExit::Exception(Exception::DebugException) =>
                CrashType::DebugException,
            VmExit::Exception(Exception::NMI) => CrashType::NMI,
            VmExit::Exception(Exception::Breakpoint) => CrashType::Breakpoint,
            VmExit::Exception(Exception::Overflow) => CrashType::Overflow,
            VmExit::Exception(Exception::BoundRangeExceeded) =>
                CrashType::BoundRangeExceeded,
            VmExit::Exception(Exception::InvalidOpcode) =>
                CrashType::InvalidOpcode,
            VmExit::Exception(Exception::DeviceNotAvailable) =>
                CrashType::DeviceNotAvailable,
            VmExit::Exception(Exception::DoubleFault) => CrashType::DoubleFault,
            VmExit::Exception(Exception::CoprocessorSegmentOverrun) =>
                CrashType::CoprocessorSegmentOverrun,
            VmExit::Exception(Exception::InvalidTSS) => CrashType::InvalidTSS,
            VmExit::Exception(Exception::SegmentNotPresent) =>
                CrashType::SegmentNotPresent,
            VmExit::Exception(Exception::StackSegmentFault) =>
                CrashType::StackSegmentFault,
            VmExit::Exception(Exception::GeneralProtectionFault(..)) =>
                CrashType::GeneralProtectionFault,
            VmExit::Exception(Exception::PageFault { write, exec, addr, .. }) =>
            {
                CrashType::PageFault {
                    typ: if (addr.0 as i64).abs() < (1024 * 1024) {
                        PageFaultType::Null
                    } else {
                        PageFaultType::High
                    },
                    read:  if !write && !exec { true } else { false },
                    write: *write,
                    exec:  *exec,
                }
            }
            VmExit::Exception(Exception::FloatingPointError) =>
                CrashType::FloatingPointError,
            VmExit::Exception(Exception::AlignmentCheck) =>
                CrashType::AlignmentCheck,
            VmExit::Exception(Exception::MachineCheck) =>
                CrashType::MachineCheck,
            VmExit::Exception(Exception::SimdFloatingPointException) =>
                CrashType::SimdFloatingPointException,
            VmExit::Exception(Exception::VirtualizationException) =>
                CrashType::VirtualizationException,
            VmExit::Exception(Exception::ControlProtectionException) =>
                CrashType::ControlProtectionException,
            _ => panic!("Did not know how to report crash {:?}", vmexit),
        };

        let record = session.crashes.entry_or_insert(
            &(regstate.rip, ct), regstate.rip as usize, || Box::new(()));
        if record.inserted() {
            let server = self.server.as_mut().unwrap();
            ServerMessage::Crash {
                modoff:   cr.clone(),
                cpl:      cpl,
                typ:      ct,
                regstate: Cow::Owned(format!("{}", regstate))
            }.serialize(server).unwrap();
            server.flush().unwrap();
        }
    }

    /// Attempt to resolve the `addr` into a module + offset based on the
    /// current `module_list`
    pub fn resolve_module_int(&mut self, addr: u64)
            -> (Option<Arc<String>>, u64) {
        // Get the current context id
        let pt = self.context_id();

        // Get the module list for the current process
        if let Some(modlist) = self.module_list.get(&pt) {
            if let Some((base, (end, name))) =
                    modlist.range(..=addr).next_back() {
                if addr <= *end {
                    (Some(name.clone()), addr - base)
                } else {
                    (None, addr)
                }
            } else {
                (None, addr)
            }
        } else {
            (None, addr)
        }
    }

    /// Get the base address for a given segment
    pub fn seg_base(&mut self, segment: Segment) -> u64 {
        match segment {
            Segment::Es => self.reg(Register::EsBase),
            Segment::Ds => self.reg(Register::DsBase),
            Segment::Fs => self.reg(Register::FsBase),
            Segment::Gs => self.reg(Register::GsBase),
            Segment::Ss => self.reg(Register::SsBase),
            Segment::Cs => self.reg(Register::CsBase),
        }
    }

    /// Reads memory using the `addr` provided
    pub fn read_addr(&mut self, addr: Address, mut buf: &mut [u8])
            -> Option<()> {
        // Nothing to do in the 0 byte case
        if buf.len() == 0 { return Some(()); }

        // Offset into the read we've completed
        let mut loff = 0u64;

        while buf.len() > 0 {
            // Get the guest physical address for this page
            let gpaddr = match addr {
                Address::PhysicalLinear { addr } => addr.wrapping_add(loff),
                Address::PhysicalSegOff { seg, off } => {
                    self.seg_base(seg).wrapping_add(off).wrapping_add(loff)
                }
                Address::Virtual { seg, off, mode, cr3 } => {
                    let linear = self.seg_base(seg).wrapping_add(off)
                        .wrapping_add(loff);
                    let (page, off, _) = match mode {
                        PagingMode::Bits32 => {
                            translate_32_no_pae(cr3, VirtAddr(linear),
                                |paddr| self.read_phys(paddr))?
                        }
                        PagingMode::Bits32Pae => {
                            translate_32_pae(cr3, VirtAddr(linear),
                                |paddr| self.read_phys(paddr))?
                        }
                        PagingMode::Bits64 => {
                            translate_64_4_level(cr3, VirtAddr(linear),
                                |paddr| self.read_phys(paddr))?
                        }
                    };
                    page.0.wrapping_add(off)
                }
                Address::Linear { addr, mode, cr3 } => {
                    let addr = addr.wrapping_add(loff);
                    let (page, off, _) = match mode {
                        PagingMode::Bits32 => {
                            translate_32_no_pae(cr3, VirtAddr(addr),
                                |paddr| self.read_phys(paddr))?
                        }
                        PagingMode::Bits32Pae => {
                            print!("Pae {:#x} {:#x}\n", cr3, addr);
                            translate_32_pae(cr3, VirtAddr(addr),
                                |paddr| self.read_phys(paddr))?
                        }
                        PagingMode::Bits64 => {
                            translate_64_4_level(cr3, VirtAddr(addr),
                                |paddr| self.read_phys(paddr))?
                        }
                    };
                    page.0.wrapping_add(off)
                }
            };

            // Get the host physical address for this page
            let paddr = self.backing.translate(
                PhysAddr(gpaddr), true, false, false, &mut self.pml)?;

            // Compute the remaining number of bytes on the page
            let page_remain = 0x1000 - (paddr.0 & 0xfff);

            // Compute the number of bytes to copy
            let to_copy = core::cmp::min(page_remain as usize, buf.len());

            // Read the memory from the backing page into the user's buffer
            let psl = unsafe { mm::slice_phys(paddr, to_copy as u64) };
            buf[..to_copy].copy_from_slice(psl);

            // Advance the buffers
            loff += to_copy as u64;
            buf   = &mut buf[to_copy..];
        }

        Some(())
    }
    
    /// Writes memory using to the `addr` provided
    pub fn write_addr(&mut self, addr: Address, mut buf: &[u8])
            -> Option<()> {
        // Nothing to do in the 0 byte case
        if buf.len() == 0 { return Some(()); }

        // Offset into the read we've completed
        let mut loff = 0u64;

        while buf.len() > 0 {
            // Get the guest physical address for this page
            let gpaddr = match addr {
                Address::PhysicalLinear { addr } => addr.wrapping_add(loff),
                Address::PhysicalSegOff { seg, off } => {
                    self.seg_base(seg).wrapping_add(off).wrapping_add(loff)
                }
                Address::Virtual { seg, off, mode, cr3 } => {
                    let linear = self.seg_base(seg).wrapping_add(off)
                        .wrapping_add(loff);
                    let (page, off, _) = match mode {
                        PagingMode::Bits32 => {
                            translate_32_no_pae(cr3, VirtAddr(linear),
                                |paddr| self.read_phys(paddr))?
                        }
                        PagingMode::Bits32Pae => {
                            translate_32_pae(cr3, VirtAddr(linear),
                                |paddr| self.read_phys(paddr))?
                        }
                        PagingMode::Bits64 => {
                            translate_64_4_level(cr3, VirtAddr(linear),
                                |paddr| self.read_phys(paddr))?
                        }
                    };
                    page.0.wrapping_add(off)
                }
                Address::Linear { addr, mode, cr3 } => {
                    let addr = addr.wrapping_add(loff);
                    let (page, off, _) = match mode {
                        PagingMode::Bits32 => {
                            translate_32_no_pae(cr3, VirtAddr(addr),
                                |paddr| self.read_phys(paddr))?
                        }
                        PagingMode::Bits32Pae => {
                            translate_32_pae(cr3, VirtAddr(addr),
                                |paddr| self.read_phys(paddr))?
                        }
                        PagingMode::Bits64 => {
                            translate_64_4_level(cr3, VirtAddr(addr),
                                |paddr| self.read_phys(paddr))?
                        }
                    };
                    page.0.wrapping_add(off)
                }
            };

            // Get the host physical address for this page
            let paddr = self.backing.translate(PhysAddr(gpaddr), false, true,
                false, &mut self.pml)?;

            // Compute the remaining number of bytes on the page
            let page_remain = 0x1000 - (paddr.0 & 0xfff);

            // Compute the number of bytes to copy
            let to_copy = core::cmp::min(page_remain as usize, buf.len());

            // Read the memory from the backing page into the user's buffer
            let psl = unsafe { mm::slice_phys_mut(paddr, to_copy as u64) };
            psl.copy_from_slice(&buf[..to_copy]);

            // Advance the buffers
            loff += to_copy as u64;
            buf   = &buf[to_copy..];
        }

        Some(())
    }

    /// Gets the current paging mode of the system
    pub fn paging_mode(&mut self) -> Option<PagingMode> {
        let cr0  = self.reg(Register::Cr0);
        let cr4  = self.reg(Register::Cr4);
        let efer = self.reg(Register::Efer);

        if cr0 & (1 << 31) == 0 {
            // Paging disabled
            None
        } else {
            // Paging enabled
            if efer & (1 << 8) == 0 {
                // EFER.LME not set (32-bit mode)
                if cr4 & (1 << 5) == 0 {
                    // CR4.PAE clear
                    Some(PagingMode::Bits32)
                } else {
                    // CR4.PAE set
                    Some(PagingMode::Bits32Pae)
                }
            } else {
                // EFER.LME set (64-bit mode)
                if cr4 & (1 << 5) == 0 {
                    // CR4.PAE clear, invalid state
                    None
                } else {
                    // CR4.PAE set
                    Some(PagingMode::Bits64)
                }
            }
        }
    }
    
    /// Reads the contents at `vaddr` into a `T` which implements `Primitive`
    /// using the current active page table
    pub fn read_virt<T: Primitive>(&mut self, vaddr: VirtAddr) -> Option<T> {
        let cr3 = self.reg(Register::Cr3);
        self.read_virt_cr3(vaddr, cr3)
    }
    
    /// Reads the contents at `vaddr` into a `T` which implements `Primitive`
    /// using the page table in `cr3`
    pub fn read_virt_cr3<T: Primitive>(&mut self, vaddr: VirtAddr, cr3: u64)
            -> Option<T> {
        let mut ret = T::default();
        self.read_virt_cr3_into(vaddr, ret.cast_mut(), cr3)?;
        Some(ret)
    }
    
    /// Read the contents of the guest virtual memory at `vaddr` into the
    /// `buf` provided using the current page table
    ///
    /// Returns `None` if the request cannot be fully satisfied. It is possible
    /// that some reading did occur, but is partial.
    pub fn read_virt_into(&mut self, vaddr: VirtAddr,
                          buf: &mut [u8]) -> Option<()> {
        let cr3 = self.reg(Register::Cr3);
        self.read_virt_cr3_into(vaddr, buf, cr3)
    }
    
    /// Read the contents of the guest virtual memory at `vaddr` into the
    /// `buf` provided using page table `cr3`
    ///
    /// Returns `None` if the request cannot be fully satisfied. It is possible
    /// that some reading did occur, but is partial.
    pub fn read_virt_cr3_into(&mut self, vaddr: VirtAddr,
                              buf: &mut [u8], cr3: u64) -> Option<()> {
        let mode = self.paging_mode()?;
        self.read_addr(Address::Linear {
            addr: vaddr.0,
            mode: mode,
            cr3:  cr3,
        }, buf)
    }
    
    /// Writes the `val` into `vaddr` in the current active `cr3`
    pub fn write_virt<T: Primitive>(&mut self, vaddr: VirtAddr, val: T)
            -> Option<()> {
        let cr3 = self.reg(Register::Cr3);
        self.write_virt_cr3_from(vaddr, val.cast(), cr3)
    }
    
    /// Writes the `val` into `vaddr` using `cr3` as the page table
    pub fn write_virt_cr3<T: Primitive>(&mut self, vaddr: VirtAddr, val: T,
                                        cr3: u64) -> Option<()> {
        self.write_virt_cr3_from(vaddr, val.cast(), cr3)
    }
    
    /// Write the contents of `buf` into `vaddr` in the current active `cr3`
    pub fn write_virt_from(&mut self, vaddr: VirtAddr,
                           buf: &[u8]) -> Option<()> {
        let cr3 = self.reg(Register::Cr3);
        self.write_virt_cr3_from(vaddr, buf, cr3)
    }

    /// Write the contents of `buf` to the guest virtual memory at `vaddr`
    /// using page table `cr3`
    ///
    /// Returns `None` if the request cannot be fully satisfied. It is possible
    /// that some reading did occur, but is partial.
    pub fn write_virt_cr3_from(&mut self, vaddr: VirtAddr,
                               buf: &[u8], cr3: u64) -> Option<()> {
        let mode = self.paging_mode()?;
        self.write_addr(Address::Linear {
            addr: vaddr.0,
            mode: mode,
            cr3:  cr3,
        }, buf)
    }

    /// Reads the contents at `gpaddr` into a `T` which implements `Primitive`
    pub fn read_phys<T: Primitive>(&mut self, gpaddr: PhysAddr) -> Option<T> {
        let mut ret = T::default();
        self.read_phys_into(gpaddr, ret.cast_mut())?;
        Some(ret)
    }

    /// Read the contents of the guest physical memory at `gpaddr` into the
    /// `buf` provided
    ///
    /// Returns `None` if the request cannot be fully satisfied. It is possible
    /// that some reading did occur, but is partial.
    pub fn read_phys_into(&mut self, mut gpaddr: PhysAddr, mut buf: &mut [u8])
            -> Option<()> {
        // Nothing to do in the 0 byte case
        if buf.len() == 0 { return Some(()); }
        
        // Starting physical address (invalid paddr, but page aligned)
        let mut paddr = PhysAddr(!0xfff);

        while buf.len() > 0 {
            if (paddr.0 & 0xfff) == 0 {
                // Crossed into a new page, translate
                paddr = self.backing.translate(gpaddr, true, false, false,
                                               &mut self.pml)?;
            }

            // Compute the remaining number of bytes on the page
            let page_remain = 0x1000 - (paddr.0 & 0xfff);

            // Compute the number of bytes to copy
            let to_copy = core::cmp::min(page_remain as usize, buf.len());

            // Read the memory from the backing page into the user's buffer
            let psl = unsafe { mm::slice_phys(paddr, to_copy as u64) };
            buf[..to_copy].copy_from_slice(psl);

            // Advance the buffer pointers
            paddr  = PhysAddr(paddr.0 + to_copy as u64);
            gpaddr = PhysAddr(gpaddr.0 + to_copy as u64);
            buf    = &mut buf[to_copy..];
        }

        Some(())
    }
    
    /// Writes the contents of `T` to the `gpaddr`
    pub fn write_phys<T: Primitive>(&mut self, gpaddr: PhysAddr, val: T)
            -> Option<()> {
        self.write_phys_from(gpaddr, val.cast())
    }

    /// Write the contents of `buf` into the guest physical memory at `gpaddr`
    /// at the guest
    ///
    /// Returns `None` if the request cannot be fully satisfied. It is possible
    /// that some writing did occur, but is partial.
    pub fn write_phys_from(&mut self, mut gpaddr: PhysAddr, mut buf: &[u8])
            -> Option<()>{
        // Nothing to do in the 0 byte case
        if buf.len() == 0 { return Some(()); }
        
        // Starting physical address (invalid paddr, but page aligned)
        let mut paddr = PhysAddr(!0xfff);

        while buf.len() > 0 {
            if (paddr.0 & 0xfff) == 0 {
                // Crossed into a new page, translate
                paddr = self.backing.translate(gpaddr, false, true, false,
                                               &mut self.pml)?;
            }

            // Compute the remaining number of bytes on the page
            let page_remain = 0x1000 - (paddr.0 & 0xfff);

            // Compute the number of bytes to copy
            let to_copy = core::cmp::min(page_remain as usize, buf.len());

            // Get mutable access to the underlying page and copy the memory
            // from the buffer into it
            let psl = unsafe { mm::slice_phys_mut(paddr, to_copy as u64) };
            psl.copy_from_slice(&buf[..to_copy]);

            // Advance the buffer pointers
            paddr  = PhysAddr(paddr.0 + to_copy as u64);
            gpaddr = PhysAddr(gpaddr.0 + to_copy as u64);
            buf    = &buf[to_copy..];
        }

        Some(())
    }
}

type InjectCallback<'a> = fn(&mut Worker<'a>, &mut dyn Any);

type VmExitFilter<'a> = fn(&mut Worker<'a>, &VmExit) -> bool;

/// A session for multiple workers to fuzz a shared job
pub struct FuzzSession<'a> {
    /// Master VM state
    master_vm: Arc<Backing<'a>>,

    /// Timeout for each fuzz case
    timeout: Option<u64>,

    /// Callback to invoke before every fuzz case, for the fuzzer to inject
    /// information into the VM
    inject: Option<InjectCallback<'a>>,

    /// Callback to invoke when VM exits are hit to allow a user to handle VM
    /// exits to re-enter the VM
    vmexit_filter: Option<VmExitFilter<'a>>,
    
    /// All observed coverage information
    coverage: Aht<CoverageRecord<'a>, (), 1048576>,

    /// Coverage which has yet to be reported to the server
    pending_coverage: LockCell<Vec<CoverageRecord<'a>>, LockInterrupts>,
    
    /// Inputs which have yet to be reported to the server
    pending_inputs: LockCell<Vec<InputRecord<'a>>, LockInterrupts>,

    /// Table mapping input hashes to inputs
    input_dedup: Aht<u128, Arc<Vec<u8>>, 1048576>,

    /// Inputs which caused coverage
    inputs: AtomicVec<Arc<Vec<u8>>, 65536>,

    /// Unique crashes, currently only keyed by the RIP
    crashes: Aht<(u64, CrashType), (), 4096>,

    /// Global statistics for the fuzz cases
    stats: LockCell<Statistics, LockInterrupts>,

    /// Address to use when communicating with the server
    server_addr: String,

    /// Number of workers
    workers: AtomicU64,

    /// "Unique" session identifier
    id: u64,
}

impl<'a> FuzzSession<'a> {
    /// Create a new empty fuzz session
    pub fn from_falkdump<S, F>(server: &str, name: S, init_master: F) -> Self
            where F: FnOnce(&mut Worker),
                  S: AsRef<str> {
        macro_rules! consume {
            ($ptr:expr, $ty:ty) => {{
                let ret = <$ty>::from_le_bytes(
                    $ptr[..size_of::<$ty>()].try_into().unwrap());
                $ptr = &$ptr[size_of::<$ty>()..];
                ret
            }}
        }

        // Convert the generic name into a reference to a string
        let name: &str = name.as_ref();

        // Network map the memory file contents as read-only
        let memory = Arc::new(NetMapping::new(server, name, true)
            .expect("Failed to netmap falkdump"));

        print!("Netmapped {}, {} bytes\n", name, memory.len());

        // Check the signature
        assert!(&memory[..8] == b"FALKDUMP", "Invalid signature for falkdump");

        // Get a pointer to the file contents
        let mut ptr = &memory[8..];

        // Get the number of regions
        let regions = consume!(ptr, u64);

        // Parse out the physical region information
        let mut phys_ranges = BTreeMap::new();
        for _ in 0..regions {
            let start  = consume!(ptr, u64);
            let end    = consume!(ptr, u64);
            let offset = consume!(ptr, u64);

            assert!(end > start && end & 0xfff == 0xfff && start & 0xfff == 0);

            // Log the region
            phys_ranges.insert(start, (offset as usize, end));
        }
 
        // Get the number of processors in the snapshot
        let num_cpus: usize = consume!(ptr, u64).try_into().unwrap();
        print!("Snapshot has {} CPUs\n", num_cpus);
        
        // Create a new master VM from the information provided
        let netbacking = Arc::new(NetBacking {
            memory: memory.clone(),
            phys_ranges
        });
        let mut master = Worker::new(num_cpus, Some(netbacking.clone()));

        for regs in master.backing.vm.guest_regs.guest_regs.iter_mut() {
            // Get the size of the region region in bytes
            let regs_size: usize = consume!(ptr, u64).try_into().unwrap();
            let mut tptr = &ptr[..regs_size];
            ptr = &ptr[regs_size..];

            // Parse the registers from the register state
            let _version = consume!(tptr, u32);
            let _size    = consume!(tptr, u32);
            regs.set_reg(Register::Rax, consume!(tptr, u64));
            regs.set_reg(Register::Rbx, consume!(tptr, u64));
            regs.set_reg(Register::Rcx, consume!(tptr, u64));
            regs.set_reg(Register::Rdx, consume!(tptr, u64));
            regs.set_reg(Register::Rsi, consume!(tptr, u64));
            regs.set_reg(Register::Rdi, consume!(tptr, u64));
            regs.set_reg(Register::Rsp, consume!(tptr, u64));
            regs.set_reg(Register::Rbp, consume!(tptr, u64));
            regs.set_reg(Register::R8 , consume!(tptr, u64));
            regs.set_reg(Register::R9 , consume!(tptr, u64));
            regs.set_reg(Register::R10, consume!(tptr, u64));
            regs.set_reg(Register::R11, consume!(tptr, u64));
            regs.set_reg(Register::R12, consume!(tptr, u64));
            regs.set_reg(Register::R13, consume!(tptr, u64));
            regs.set_reg(Register::R14, consume!(tptr, u64));
            regs.set_reg(Register::R15, consume!(tptr, u64));
            regs.set_reg(Register::Rip, consume!(tptr, u64));
            regs.set_reg(Register::Rflags, consume!(tptr, u64));

            regs.set_reg(Register::Cs,      consume!(tptr, u32) as u64);
            regs.set_reg(Register::CsLimit, consume!(tptr, u32) as u64);
            regs.set_reg(Register::CsAccessRights,
                              (consume!(tptr, u32) as u64) >> 8);
            let _ = consume!(tptr, u32);
            regs.set_reg(Register::CsBase, consume!(tptr, u64));
            
            regs.set_reg(Register::Ds,      consume!(tptr, u32) as u64);
            regs.set_reg(Register::DsLimit, consume!(tptr, u32) as u64);
            regs.set_reg(Register::DsAccessRights,
                              (consume!(tptr, u32) as u64) >> 8);
            let _ = consume!(tptr, u32);
            regs.set_reg(Register::DsBase, consume!(tptr, u64));
            
            regs.set_reg(Register::Es,      consume!(tptr, u32) as u64);
            regs.set_reg(Register::EsLimit, consume!(tptr, u32) as u64);
            regs.set_reg(Register::EsAccessRights,
                              (consume!(tptr, u32) as u64) >> 8);
            let _ = consume!(tptr, u32);
            regs.set_reg(Register::EsBase, consume!(tptr, u64));
            
            regs.set_reg(Register::Fs,      consume!(tptr, u32) as u64);
            regs.set_reg(Register::FsLimit, consume!(tptr, u32) as u64);
            regs.set_reg(Register::FsAccessRights,
                              (consume!(tptr, u32) as u64) >> 8);
            let _ = consume!(tptr, u32);
            regs.set_reg(Register::FsBase, consume!(tptr, u64));
            
            regs.set_reg(Register::Gs,      consume!(tptr, u32) as u64);
            regs.set_reg(Register::GsLimit, consume!(tptr, u32) as u64);
            regs.set_reg(Register::GsAccessRights,
                              (consume!(tptr, u32) as u64) >> 8);
            let _ = consume!(tptr, u32);
            regs.set_reg(Register::GsBase, consume!(tptr, u64));
            
            regs.set_reg(Register::Ss,      consume!(tptr, u32) as u64);
            regs.set_reg(Register::SsLimit, consume!(tptr, u32) as u64);
            regs.set_reg(Register::SsAccessRights,
                              (consume!(tptr, u32) as u64) >> 8);
            let _ = consume!(tptr, u32);
            regs.set_reg(Register::SsBase, consume!(tptr, u64));
            
            regs.set_reg(Register::Ldtr,      consume!(tptr, u32) as u64);
            regs.set_reg(Register::LdtrLimit, consume!(tptr, u32) as u64);
            regs.set_reg(Register::LdtrAccessRights,
                              (consume!(tptr, u32) as u64) >> 8);
            let _ = consume!(tptr, u32);
            regs.set_reg(Register::LdtrBase, consume!(tptr, u64));
            
            regs.set_reg(Register::Tr,      consume!(tptr, u32) as u64);
            regs.set_reg(Register::TrLimit, consume!(tptr, u32) as u64);
            regs.set_reg(Register::TrAccessRights,
                              (consume!(tptr, u32) as u64) >> 8);
            let _ = consume!(tptr, u32);
            regs.set_reg(Register::TrBase, consume!(tptr, u64));
            
            let _ = consume!(tptr, u32);
            regs.set_reg(Register::GdtrLimit, consume!(tptr, u32) as u64);
            let _ = consume!(tptr, u32);
            let _ = consume!(tptr, u32);
            regs.set_reg(Register::GdtrBase, consume!(tptr, u64));
            
            let _ = consume!(tptr, u32);
            regs.set_reg(Register::IdtrLimit, consume!(tptr, u32) as u64);
            let _ = consume!(tptr, u32);
            let _ = consume!(tptr, u32);
            regs.set_reg(Register::IdtrBase, consume!(tptr, u64));
            
            regs.set_reg(Register::Cr0, consume!(tptr, u64));
            let _ = consume!(tptr, u64);
            regs.set_reg(Register::Cr2, consume!(tptr, u64));
            regs.set_reg(Register::Cr3, consume!(tptr, u64));
            regs.set_reg(Register::Cr4, consume!(tptr, u64) | (1 << 13));
            
            regs.set_reg(Register::KernelGsBase, consume!(tptr, u64));
            
            regs.set_reg(Register::Cr8, consume!(tptr, u64));
            
            regs.set_reg(Register::CStar, consume!(tptr, u64));
            regs.set_reg(Register::LStar, consume!(tptr, u64));
            regs.set_reg(Register::FMask, consume!(tptr, u64));
            regs.set_reg(Register::Star,  consume!(tptr, u64));

            regs.set_reg(Register::SysenterCs,  consume!(tptr, u64));
            regs.set_reg(Register::SysenterEsp, consume!(tptr, u64));
            regs.set_reg(Register::SysenterEip, consume!(tptr, u64));
            
            regs.set_reg(Register::Efer, consume!(tptr, u64));

            let _ = consume!(tptr, u64);
            let _ = consume!(tptr, u64);
            let _ = consume!(tptr, u64);
            let _ = consume!(tptr, u64);
            let _ = consume!(tptr, u64);
            let _ = consume!(tptr, u64);
            let _ = consume!(tptr, u64);
            regs.set_reg(Register::Dr7, consume!(tptr, u64));

            master.backing.vm.guest_regs.tsc = consume!(tptr, u64);
            let _ = consume!(tptr, u64);
            let _ = consume!(tptr, u64);
            let _ = consume!(tptr, u64);

            unsafe {
                assert!(tptr.len() == 512);

                regs.set_fxsave(
                    core::ptr::read_unaligned(
                        tptr[..512].as_ptr() as *const FxSave));
            }
            
            let efer = regs.reg(Register::Efer);
            if efer & (1 << 8) != 0 {
                // Long mode, QEMU gives some non-zero limits, zero them out
                regs.set_reg(Register::EsLimit, 0);
                regs.set_reg(Register::CsLimit, 0);
                regs.set_reg(Register::SsLimit, 0);
                regs.set_reg(Register::DsLimit, 0);
                regs.set_reg(Register::FsLimit, 0);
                regs.set_reg(Register::GsLimit, 0);
            }

            /// Perform some filtering of the access rights as QEMU and VT-x
            /// have slightly different expectations for these bits
            macro_rules! filter_ars {
                ($ar:expr, $lim:expr) => {
                    // Mark any non-present segment as inactive
                    if regs.reg($ar) & (1 << 7) == 0 {
                        regs.set_reg($ar, 0x10000);
                    }

                    // If any bit in the bottom 12 bits of the limit is zero,
                    // then G must be zero
                    if regs.reg($lim) & 0xfff != 0xfff {
                        let oldr = regs.reg($ar);
                        regs.set_reg($ar, oldr & !(1 << 15));
                    }
                }
            }

            filter_ars!(Register::EsAccessRights, Register::EsLimit);
            filter_ars!(Register::CsAccessRights, Register::CsLimit);
            filter_ars!(Register::SsAccessRights, Register::SsLimit);
            filter_ars!(Register::DsAccessRights, Register::DsLimit);
            filter_ars!(Register::FsAccessRights, Register::FsLimit);
            filter_ars!(Register::GsAccessRights, Register::GsLimit);
            filter_ars!(Register::LdtrAccessRights, Register::LdtrLimit);
            filter_ars!(Register::TrAccessRights, Register::TrLimit);
        }
        
        // Init the master VM
        init_master(&mut master);

        // Rip out only the backing from the master
        let master = Arc::new(master.backing);

        FuzzSession {
            master_vm:        master,
            coverage:         Aht::new(),
            pending_coverage: LockCell::new(Vec::new()),
            pending_inputs:   LockCell::new(Vec::new()),
            stats:            LockCell::new(Statistics::default()),
            timeout:          None,
            inject:           None,
            vmexit_filter:    None,
            input_dedup:      Aht::new(),
            crashes:          Aht::new(),
            inputs:           AtomicVec::new(),
            workers:          AtomicU64::new(0),
            id:               cpu::rdtsc(),
            server_addr:      server.into(),
        }
    }

    /// Set the timeout for the VMs in microseconds
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the injection callback routine. This will be invoked every time
    /// the VM is reset and a new fuzz case is about to begin.
    pub fn inject(mut self, inject: InjectCallback<'a>) -> Self {
        self.inject = Some(inject);
        self
    }
    
    /// Set the VM exit filter for the workers. This will be invoked on an
    /// unhandled VM exit and gives an opportunity for the fuzzer to handle
    /// a VM exit to allow re-entry into the VM
    pub fn vmexit_filter(mut self, vmexit_filter: VmExitFilter<'a>)
            -> Self {
        self.vmexit_filter = Some(vmexit_filter);
        self
    }

    /// Get a new worker for this fuzz session
    pub fn worker(session: Arc<Self>) -> Worker<'a> {
        // Get a new worker ID
        let worker_id = session.workers.fetch_add(1, Ordering::SeqCst);

        // Fork the worker from the master
        let mut worker =
            Worker::fork(session.master_vm.vm.cpus(), session.clone(),
                session.master_vm.clone(), worker_id);
       
        if ENABLE_APIC {
            // Map in a read-only APIC
            worker.map_zeroed_readonly_page(PhysAddr(0xfee00000));
        }

        // Connect to the server and associate this connection with the
        // worker
        let netdev = NetDevice::get()
            .expect("Failed to get network device for creating worker");
        worker.server = Some(
            BufferedIo::new(NetDevice::tcp_connect(netdev, &session.server_addr)
            .expect("Failed to connect to server")));
        
        // Log into the server with a new worker
        session.login(worker.server.as_mut().unwrap());

        worker
    }

    /// Update statistics to the server
    pub fn report_statistics(&self, server: &mut BufferedIo<TcpConnection>) {
        {
            // Report new inputs to the server
            let mut pending_inputs = self.pending_inputs.lock();
            if pending_inputs.len() > 0 {
                ServerMessage::Inputs(
                    Cow::Borrowed(pending_inputs.as_slice())
                ).serialize(server).unwrap();
                pending_inputs.clear();
            }
        }
        
        {
            // Report new coverage to the server
            let mut pending_coverage = self.pending_coverage.lock();
            if pending_coverage.len() > 0 {
                ServerMessage::Coverage(
                    Cow::Borrowed(pending_coverage.as_slice())
                ).serialize(server).unwrap();
                pending_coverage.clear();
            }
        }

        {
            let stats = self.stats.lock();
            ServerMessage::ReportStatistics {
                fuzz_cases:    stats.fuzz_cases,
                total_cycles:  stats.total_cycles,
                vm_cycles:     stats.vm_cycles,
                reset_cycles:  stats.reset_cycles,
                inject_cycles: stats.inject_cycles,
                vm_exits:      stats.vm_exits,
                allocs: crate::mm::GLOBAL_ALLOCATOR
                    .num_allocs.load(Ordering::Relaxed),
                frees: crate::mm::GLOBAL_ALLOCATOR
                    .num_frees.load(Ordering::Relaxed),
                phys_free: crate::mm::GLOBAL_ALLOCATOR
                    .free_physical.load(Ordering::Relaxed),
                phys_total: core!().boot_args
                    .total_physical_memory.load(Ordering::Relaxed),
            }.serialize(server).unwrap();
        }

        // Flush anything we sent to the server
        server.flush().unwrap();

        // Now, the server will respond to our stats with some things to do,
        // this is where we handle syncing from the server which may be
        // reporting new inputs and coverage that other machines have found
        loop {
            let msg = ServerMessage::deserialize(server).unwrap();
            match msg {
                ServerMessage::Coverage(records) => {
                    for record in records.iter() {
                        self.report_coverage(None, record);
                    }
                }
                ServerMessage::Inputs(inputs) => {
                    for input in inputs.iter() {
                        // Insert the input into the dedup table
                        let record = self.input_dedup.entry_or_insert(
                                &input.hash, input.hash as usize,
                                || Box::new(input.input.clone().into_owned()));
                        if record.inserted() {
                            let entry = record.entry();

                            // Input was new, also save it to the input list
                            self.inputs.push(Box::new(entry.clone()));

                            // Mark these inputs as something we should report
                            // to the server, so it knows we received and
                            // processed them
                            let mut pending_inputs = self.pending_inputs
                                .lock();
                            pending_inputs.push(InputRecord {
                                hash:  input.hash,
                                input: Cow::Owned(entry.clone()),
                            });
                        }
                    }
                }
                ServerMessage::SyncComplete => {
                    // Server has released us
                    break;
                }
                _ => panic!("Unexpected server message during sync"),
            }
        }
    }

    /// Log in with the server
    pub fn login(&self, server: &mut BufferedIo<TcpConnection>) {
        ServerMessage::Login(self.id, core!().id).serialize(server).unwrap();
        server.flush().unwrap();
    }

    /// Report coverage
    pub fn report_coverage(&self, input: Option<(&[u8], &FalkHasher)>,
                           cr: &CoverageRecord) -> bool {
        if self.coverage.entry_or_insert(cr, cr.offset as usize,
                                         || Box::new(())).inserted() {
            // Save the input which caused this new unique coverage
            if let Some((input, hasher)) = input {
                // Hash the input
                let hash = hasher.hash(input);

                // Check if this input already is in our database
                let record = self.input_dedup.entry_or_insert(
                        &hash, hash as usize,
                        || Box::new(Arc::new(input.to_vec())));

                if record.inserted() {
                    // Oooh, this is a new input, save it and queue it to send
                    // to server
                    
                    // Get the entry we just inserted
                    let entry = record.entry();

                    // Save the input to the input vector, so we can
                    // easily randomly access it
                    self.inputs.push(Box::new(entry.clone()));

                    let mut pending_inputs = self.pending_inputs.lock();
                    pending_inputs.push(InputRecord {
                        hash:  hash,
                        input: Cow::Owned(entry.clone()),
                    });
                }
            }

            // Coverage was new, queue it to be reported to the server
            self.pending_coverage.lock().push(CoverageRecord {
                module: cr.module.as_ref().map(|x| Cow::Owned((**x).clone())),
                offset: cr.offset,
            });

            true
        } else {
            false
        }
    }
}

