//! Fuzzable snapshotted application backed by an Intel VT-x VM

use core::cell::Cell;
use core::mem::size_of;
use core::sync::atomic::{AtomicU64, Ordering};
use core::alloc::Layout;
use core::convert::TryInto;
use alloc::vec::Vec;
use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::borrow::Cow;
use alloc::collections::{BTreeMap};

use crate::mm;
use crate::time;
use crate::net::{NetDevice, UdpBind, UdpAddress};
use crate::vtx::{Vm, FxSave, RegisterState, VmExit};
use crate::vtx::Exception;
use crate::net::netmapping::NetMapping;
use crate::core_locals::LockInterrupts;

use aht::Aht;
use falktp::{CoverageRecord, ServerMessage};
use noodle::*;
use lockcell::LockCell;
use atomicvec::AtomicVec;
use page_table::{PhysAddr, VirtAddr, PhysMem, PageType, Mapping};
use page_table::{PAGE_PRESENT, PAGE_WRITE, PAGE_USER};

/// Trait to allow conversion of slices of bytes to primitives and back
/// generically
pub trait Primitive: Sized {
    fn cast(buf: &[u8]) -> Self;
}

macro_rules! primitive {
    ($ty:ty) => {
        impl Primitive for $ty {
            fn cast(buf: &[u8]) -> Self {
                <$ty>::from_ne_bytes(buf.try_into().unwrap())
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

/// Number of microseconds to wait before syncing worker statistics into the
/// `FuzzTarget`
///
/// This is used to reduce the frequency which workers sync with the master,
/// to cut down on the lock contention
const STATISTIC_SYNC_INTERVAL: u64 = 100_000;

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
#[derive(Default)]
pub struct Statistics {
    /// Number of fuzz cases performed on the target
    fuzz_cases: u64,

    /// Frequencies of various VM exit reasons
    vmexits: BTreeMap<VmExit, u64>,
}

impl Statistics {
    /// Sync the statistics in `self` into `master`, resetting `self`'s
    /// statistics back to 0 such that the syncing cycle can repeat.
    fn sync_into(&mut self, master: &mut Statistics) {
        // Merge number of fuzz cases
        master.fuzz_cases += self.fuzz_cases;

        // Merge vmexit reasons
        for (reason, freq) in self.vmexits.iter() {
            *master.vmexits.entry(*reason).or_insert(0) += freq;
        }

        // Reset our statistics
        self.fuzz_cases = 0;
        self.vmexits.clear();
    }
}

/// Network backed VM memory information
struct NetBacking<'a> {
    /// Mapping of valid pages to their offsets in the `memory` buffer
    virt_to_offset: BTreeMap<VirtAddr, usize>,

    /// Raw memory backing the snasphot
    memory: NetMapping<'a>,
}

pub struct Worker<'a> {
    /// Master worker that we are forked from
    master: Option<Arc<Worker<'a>>>,

    /// Network mapped memory for the VM
    network_mem: Option<Arc<NetBacking<'a>>>,

    /// The fuzz session this worker belongs to
    session: Option<Arc<FuzzSession<'a>>>,

    /// Raw virtual machine that this worker uses
    pub vm: Vm,
    
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

    /// List of all modules
    /// Maps from base address to module, to end of module (inclusive) and the
    /// module name
    module_list: BTreeMap<u64, (u64, String)>,
}

impl<'a> Worker<'a> {
    /// Create a new empty VM from network backed memory
    fn from_net(memory: Arc<NetBacking<'a>>) -> Self {
        Worker {
            master:      None,
            network_mem: Some(memory),
            vm:          Vm::new_user(),
            rng:         Rng::new(),
            stats:       Statistics::default(),
            sync:        0,
            session:     None,
            worker_id:   !0,
            module_list: BTreeMap::new(),
            fuzz_input:  None,
        }
    }
    
    /// Create a new VM forked from a master
    fn fork(session: Arc<FuzzSession<'a>>, master: Arc<Self>, worker_id: u64)
            -> Self {
        // Create a new VM with the masters guest registers as the current
        // register state
        let mut vm = Vm::new_user();
        vm.guest_regs = master.vm.guest_regs;

        // Create the new VM referencing the master
        Worker {
            master:      Some(master),
            network_mem: None,
            vm:          vm,
            rng:         Rng::new(),
            stats:       Statistics::default(),
            sync:        0,
            session:     Some(session),
            worker_id:   worker_id,
            module_list: BTreeMap::new(),
            fuzz_input:  Some(Vec::new()),
        }
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

    /// Perform a single fuzz case to completion
    pub fn fuzz_case(&mut self) -> VmExit {
        // Get access to the session
        let session = self.session.as_ref().unwrap().clone();

        // Get access to the master
        let master = self.master.as_ref().expect("Cannot fuzz without master");

        // Load the original snapshot registers
        self.vm.guest_regs = master.vm.guest_regs;
       
        // Reset memory to its original state
        unsafe {
            self.vm.page_table.for_each_dirty_page(
                    &mut mm::PhysicalMemory, |addr, page| {
                let orig_page = master.get_page(addr)
                    .expect("Dirtied page without master!?");

                // Get mutable access to the underlying page
                let psl = mm::slice_phys_mut(page, 4096);

                // Copy the original page into the modified copy of the page
                llvm_asm!(r#"
                  
                    mov rcx, 4096 / 8
                    rep movsq

                "# ::
                "{rdi}"(psl.as_ptr()),
                "{rsi}"(orig_page.0) :
                "memory", "rcx", "rdi", "rsi", "cc" : 
                "intel", "volatile");
            });
        }

        // Invoke the injection callback
        if let Some(inject) = session.inject {
            inject(self);
        }

        // Counter of number of single steps we should perform
        let mut single_step = 0;

        // Compute the timeout
        let timeout = session.timeout.map(|x| time::future(x));

        let vmexit = 'vm_loop: loop {
            if cpu::rdtsc() >= timeout.unwrap_or(!0) {
                break 'vm_loop VmExit::Timeout;
            }

            // Check if single stepping is requested
            if single_step > 0 {
                // Enable single stepping
                self.vm.guest_regs.rfl |= 1 << 8;

                // Decrement number of single steps requested
                single_step -= 1;
            } else {
                // Disable single stepping
                self.vm.guest_regs.rfl &= !(1 << 8);
            }

            // Set the pre-emption timer for randomly breaking into the VM
            // to record coverage information
            self.vm.preemption_timer = Some(3); //(self.rng.rand() & 0x3f) as u32);

            // Run the VM until a VM exit
            let mut vmexit = self.vm.run();

            match vmexit {
                VmExit::Exception(
                        Exception::PageFault { addr, write, .. }) => {
                    if self.translate(addr, write).is_some() {
                        continue 'vm_loop;
                    }
                }
                VmExit::Exception(Exception::DebugException) => {
                    let modoff = self.resolve_module(self.vm.guest_regs.rip);
                    if session.report_coverage(&CoverageRecord {
                        module: modoff.0.map(|x| Cow::Borrowed(x)),
                        offset: modoff.1,
                    }) {
                        single_step = 1000;
                        if let Some(input) = &self.fuzz_input {
                            if session.input_dedup.entry_or_insert(
                                    input, 0, || Box::new(())).inserted() {
                                print!("Saving input {:02x?}\n", input);
                                session.inputs.push(Box::new(input.clone()));
                            }
                        }
                    }
                    continue 'vm_loop;
                }
                VmExit::PreemptionTimer => {
                    let modoff = self.resolve_module(self.vm.guest_regs.rip);
                    if session.report_coverage(&CoverageRecord {
                        module: modoff.0.map(|x| Cow::Borrowed(x)),
                        offset: modoff.1,
                    }) {
                        single_step = 1000;
                        if let Some(input) = &self.fuzz_input {
                            if session.input_dedup.entry_or_insert(
                                    input, 0, || Box::new(())).inserted() {
                                print!("Saving input {:02x?}\n", input);
                                session.inputs.push(Box::new(input.clone()));
                            }
                        }
                    }
                    continue 'vm_loop;
                }
                VmExit::ExternalInterrupt => {
                    // Host interrupt happened, ignore it
                    continue 'vm_loop;
                }
                _ => {},
            }

            // Convert a potential `InvalidOpcode` which could be a syscall
            // into a syscall vmexit. This helps for tracking statistics and
            // vmexit handling for the `vmexit_filter`
            if vmexit == VmExit::Exception(Exception::InvalidOpcode) {
                // Check if the reason for the invalid opcode was a syscall
                let mut inst_bytes = [0u8; 2];
                if self.read_into(VirtAddr(self.vm.guest_regs.rip),
                        &mut inst_bytes).is_some() &&
                        inst_bytes == [0x0f, 0x05] {
                    vmexit = VmExit::Syscall(self.vm.guest_regs.rax as u32);
                }
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

        // Update number of fuzz cases
        self.stats.fuzz_cases += 1;

        // Update VM exit reason statistics
        *self.stats.vmexits.entry(vmexit).or_insert(0) += 1;

        // Sync the local statistics into the master on an interval
        if cpu::rdtsc() >= self.sync {
            self.stats.sync_into(&mut session.stats.lock());
            if self.worker_id == 0 {
                // Report to the server
                session.report_statistics();
            }

            // Set the next sync time
            self.sync = time::future(STATISTIC_SYNC_INTERVAL);
        }

        vmexit
    }

    /// Attempt to resolve the `addr` into a module + offset based on the
    /// current `module_list`
    pub fn resolve_module(&mut self, addr: u64) -> (Option<&str>, u64) {
        if let Some((base, (end, name))) =
                self.module_list.range(..=addr).next_back() {
            if addr <= *end {
                (Some(&name), addr - base)
            } else {
                (None, addr)
            }
        } else {
            (None, addr)
        }
    }

    /// Assuming the current process is a Windows 64-bit userland process,
    /// extract the module list from it
    pub fn get_module_list_win64(&mut self) -> Option<()> {
        // Create a new module list
        let mut module_list = BTreeMap::new();

        // Get the base of the TEB
        let gs_base = self.vm.guest_regs.gs_base;

        // Get the address of the `_PEB`
        let peb = self.read::<u64>(VirtAddr(gs_base + 0x60))?;

        // Get the address of the `_PEB_LDR_DATA`
        let peb_ldr_data = self.read::<u64>(VirtAddr(peb + 0x18))?;

        // Get the in load order module list links
        let mut mod_flink = self.read::<u64>(VirtAddr(peb_ldr_data + 0x10))?;
        let mod_blink = self.read::<u64>(VirtAddr(peb_ldr_data + 0x18))?;

        // Traverse the linked list
        while mod_flink != 0 {
            let base = self.read::<u64>(VirtAddr(mod_flink + 0x30))?;
            let size = self.read::<u32>(VirtAddr(mod_flink + 0x40))?;
            if size <= 0 {
                return None;
            }

            // Get the length of the module name unicode string
            let name_len = self.read::<u16>(VirtAddr(mod_flink + 0x58))?;
            let name_ptr = self.read::<u64>(VirtAddr(mod_flink + 0x60))?;
            if name_ptr == 0 || name_len <= 0 || (name_len % 2) != 0 {
                return None;
            }

            let mut name = vec![0u16; name_len as usize / 2];
            for (ii, wc) in name.iter_mut().enumerate() {
                *wc = self.read::<u16>(VirtAddr(
                    name_ptr.checked_add((ii as u64).checked_mul(2)?)?))?;
            }

            // Convert the module name into a UTF-8 Rust string
            let name_utf8 = String::from_utf16(&name).ok()?;

            // Save the module information into the module list
            module_list.insert(base,
                (base.checked_add(size as u64 - 1)?, name_utf8));

            // Go to the next link in the table
            if mod_flink == mod_blink { break; }
            mod_flink = self.read::<u64>(VirtAddr(mod_flink))?;
        }

        // Establish the new module list
        self.module_list = module_list;

        Some(())
    }

    /// Reads the contents at `vaddr` into a `T` which implements `Primitive`
    pub fn read<T: Primitive>(&mut self, vaddr: VirtAddr) -> Option<T> {
        let mut buf = [0u8; 16];
        let ptr = &mut buf[..size_of::<T>()];
        self.read_into(vaddr, ptr)?;
        Some(T::cast(ptr))
    }

    /// Read the contents of the virtual memory at `vaddr` in the guest into
    /// the `buf` provided
    ///
    /// Returns `None` if the request cannot be fully satisfied. It is possible
    /// that some reading did occur, but is partial.
    pub fn read_into(&mut self, mut vaddr: VirtAddr, mut buf: &mut [u8])
            -> Option<()> {
        // Nothing to do in the 0 byte case
        if buf.len() == 0 { return Some(()); }
        
        // Starting physical address (invalid paddr, but page aligned)
        let mut paddr = PhysAddr(!0xfff);

        while buf.len() > 0 {
            if (paddr.0 & 0xfff) == 0 {
                // Crossed into a new page, translate
                paddr = self.translate(vaddr, false)?;
            }

            // Compute the remaining number of bytes on the page
            let page_remain = 0x1000 - (paddr.0 & 0xfff);

            // Compute the number of bytes to copy
            let to_copy = core::cmp::min(page_remain as usize, buf.len());

            // Get mutable access to the underlying page and copy the memory
            // from the buffer into it
            let psl = unsafe { mm::slice_phys_mut(paddr, to_copy as u64) };
            buf[..to_copy].copy_from_slice(psl);

            // Advance the buffer pointers
            paddr = PhysAddr(paddr.0 + to_copy as u64);
            vaddr = VirtAddr(vaddr.0 + to_copy as u64);
            buf   = &mut buf[to_copy..];
        }

        Some(())
    }

    /// Write the contents of `buf` into the virtual memory at `vaddr` for
    /// the guest
    ///
    /// Returns `None` if the request cannot be fully satisfied. It is possible
    /// that some writing did occur, but is partial.
    pub fn write_from(&mut self, mut vaddr: VirtAddr, mut buf: &[u8])
            -> Option<()>{
        // Nothing to do in the 0 byte case
        if buf.len() == 0 { return Some(()); }
        
        // Starting physical address (invalid paddr, but page aligned)
        let mut paddr = PhysAddr(!0xfff);

        while buf.len() > 0 {
            if (paddr.0 & 0xfff) == 0 {
                // Crossed into a new page, translate
                paddr = self.translate(vaddr, true)?;
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
            paddr = PhysAddr(paddr.0 + to_copy as u64);
            vaddr = VirtAddr(vaddr.0 + to_copy as u64);
            buf   = &buf[to_copy..];
        }

        Some(())
    }

    /// Attempts to get a slice to the page backing `vaddr` in host addressable
    /// memory
    fn get_page(&self, vaddr: VirtAddr) -> Option<VirtAddr> {
        // Validate alignment
        assert!(vaddr.0 & 0xfff == 0,
                "get_page() requires an aligned virtual address");

        // Get access to physical memory
        let mut pmem = mm::PhysicalMemory;

        // Attempt to translate the page, it is possible it has not yet been
        // mapped and we need to page it in from the network mapped storage in
        // the `FuzzTarget`
        let translation = self.vm.page_table.translate(&mut pmem, vaddr);
        if let Some(Mapping { page: Some(orig_page), .. }) = translation {
            Some(VirtAddr(unsafe {
                mm::slice_phys_mut(orig_page.0, 4096).as_ptr() as u64
            }))
        } else {
            if let Some(master) = &self.master {
                master.get_page(vaddr)
            } else if let Some(netmem) = &self.network_mem {
                let offset = *netmem.virt_to_offset.get(&vaddr)?;
                Some(VirtAddr(netmem.memory[offset..].as_ptr() as u64))
            } else {
                // Nobody can provide the memory for us, it's not present
                None
            }
        }
    }

    /// Translate a virtual address for the guest into a physical address on
    /// the host. If `write` is set, the translation will occur for a write
    /// access, and thus the copy-on-write will be performed on the page if
    /// needed to satisfy the write.
    ///
    /// If the virtual address is not valid for the guest, this will return
    /// `None`.
    ///
    /// The translation will only be valid for the page the `vaddr` resides in.
    /// The returned physical address will have the offset from the virtual
    /// address applied. Such that a request for virtual address `0x13371337`
    /// would return a physical address ending in `0x337`
    fn translate(&mut self, vaddr: VirtAddr, write: bool) -> Option<PhysAddr> {
        // Get access to physical memory
        let mut pmem = mm::PhysicalMemory;
        
        // Align the virtual address
        let align_vaddr = VirtAddr(vaddr.0 & !0xfff);

        // Attempt to translate the page, it is possible it has not yet been
        // mapped and we need to page it in from the network mapped storage in
        // the `FuzzTarget`
        let translation = self.vm.page_table.translate_dirty(
            &mut pmem, align_vaddr, write);
        
        // First, determine if we need to perform a CoW or make a mapping for
        // an unmapped page
        if let Some(Mapping {
                pte: Some(pte), page: Some(orig_page), .. }) = translation {
            // Page is mapped, it is possible it needs to be promoted to
            // writable
            let page_writable =
                (unsafe { mm::read_phys::<u64>(pte) } & PAGE_WRITE) != 0;

            // If the page is writable, and this is is a write, OR if the
            // operation is not a write, then the existing allocation can
            // satisfy the translation request.
            if (write && page_writable) || !write {
                return Some(PhysAddr((orig_page.0).0 + (vaddr.0 & 0xfff)));
            }
        }

        // At this stage, we either must perform a CoW or map an unmapped page

        // Get the original contents of the page
        let orig_page_vaddr = if let Some(master) = &self.master {
            // Get the page from the master
            master.get_page(align_vaddr)?
        } else if let Some(netmem) = &self.network_mem {
            // Get the offset into the network backing which holds the page
            // for the provided virtual address
            let offset = *netmem.virt_to_offset.get(&align_vaddr)?;
            VirtAddr(netmem.memory[offset..].as_ptr() as u64)
        } else {
            // Page is not present, and cannot be filled from the master or
            // network memory
            return None;
        };

        // Look up the physical page backing for the mapping

        // Touch the page to make sure it's present
        unsafe { core::ptr::read_volatile(orig_page_vaddr.0 as *const u8); }
        
        let orig_page = {
            // Get access to the host page table
            let mut page_table = core!().boot_args.page_table.lock();
            let page_table = page_table.as_mut().unwrap();

            // Translate the mapping virtual address into a physical
            // address
            //
            // This will always succeed as we touched the memory above
            let (page, offset) =
                page_table.translate(&mut pmem, orig_page_vaddr)
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
                Layout::from_size_align(4096, 4096).unwrap());

            // Get mutable access to the underlying page
            let psl = unsafe { mm::slice_phys_mut(page, 4096) };

            // Copy in the bytes to initialize the page from the network
            // mapped memory
            psl.copy_from_slice(&ro_page);

            // Promote the page via CoW
            unsafe {
                mm::write_phys(pte, page.0 | PAGE_USER | PAGE_WRITE |
                               PAGE_PRESENT);
            }

            page
        } else {
            // Page was not mapped
            if write {
                // Page needs to be CoW-ed from the network mapped file

                // Allocate a new page
                let page = pmem.alloc_phys(
                    Layout::from_size_align(4096, 4096).unwrap());

                // Get mutable access to the underlying page
                let psl = unsafe { mm::slice_phys_mut(page, 4096) };

                // Copy in the bytes to initialize the page from the network
                // mapped memory
                psl.copy_from_slice(&ro_page);

                unsafe {
                    // Map in the page as RW
                    self.vm.page_table.map_raw(&mut pmem, align_vaddr,
                        PageType::Page4K,
                        page.0 | PAGE_USER | PAGE_WRITE | PAGE_PRESENT)
                        .unwrap();
                }

                // Return the physical address of the new page
                page
            } else {
                // Page is only being accessed for read. Alias the guest's
                // virtual memory directly into the network mapped page as
                // read-only
                
                unsafe {
                    // Map in the page as read-only into the guest page table
                    self.vm.page_table.map_raw(&mut pmem, align_vaddr,
                        PageType::Page4K,
                        orig_page.0 | PAGE_USER | PAGE_PRESENT).unwrap();
                }

                // Return the physical address of the backing page
                orig_page
            }
        };
        
        // Return the physical address of the requested virtual address
        Some(PhysAddr(page.0 + (vaddr.0 & 0xfff)))
    }
}

type InjectCallback<'a> = fn(&mut Worker<'a>);

type VmExitFilter<'a> = fn(&mut Worker<'a>, &VmExit) -> bool;

/// A session for multiple workers to fuzz a shared job
pub struct FuzzSession<'a> {
    /// Master VM state
    master_vm: Arc<Worker<'a>>,

    /// Timeout for each fuzz case
    timeout: Option<u64>,

    /// Callback to invoke before every fuzz case, for the fuzzer to inject
    /// information into the VM
    inject: Option<InjectCallback<'a>>,

    /// Callback to invoke when VM exits are hit to allow a user to handle VM
    /// exits to re-enter the VM
    vmexit_filter: Option<VmExitFilter<'a>>,
    
    /// All observed coverage information
    coverage: Aht<CoverageRecord<'a>, (), 65536>,

    /// Hash table of inputs
    input_dedup: Aht<Vec<u8>, (), 65536>,

    /// Inputs which caused coverage
    inputs: AtomicVec<Vec<u8>, 4096>,

    /// Global statistics for the fuzz cases
    stats: LockCell<Statistics, LockInterrupts>,

    /// Open connection to the server
    server: UdpBind,

    /// Address to use when communicating with the server
    server_addr: UdpAddress,

    /// Number of workers
    workers: AtomicU64,

    /// "Unique" session identifier
    id: u64,
}

impl<'a> FuzzSession<'a> {
    /// Create a new empty fuzz session
    pub fn new<S>(server: &str, name: S) -> Self
            where S: AsRef<str> {
        // Convert the generic name into a reference to a string
        let name: &str = name.as_ref();

        // Network map the memory file contents as read-only
        let memory = NetMapping::new(server, &format!("{}.memory", name), true)
            .expect("Failed to netmap memory file for snapshotted app");

        // Network map the info file contents as read-only
        let info = NetMapping::new(server, &format!("{}.info", name), true)
            .expect("Failed to netmap info file for snapshotted app");

        // Create a new register state
        let mut regs = RegisterState::default();

        // Get access to the snapshot info
        let mut ptr = &info[..];

        /// Consume a `$ty` from the snapshot info and update the pointer
        macro_rules! consume {
            ($ty:ty) => {{
                let val: $ty = <$ty>::from_le_bytes(
                    ptr[..size_of::<$ty>()].try_into().unwrap());
                ptr = &ptr[size_of::<$ty>()..];
                val
            }}
        }

        // Parse out the register fields from the snapshot info
        regs.gs_base = consume!(u64);
        regs.rfl = consume!(u64);
        regs.r15 = consume!(u64);
        regs.r14 = consume!(u64);
        regs.r13 = consume!(u64);
        regs.r12 = consume!(u64);
        regs.r11 = consume!(u64);
        regs.r10 = consume!(u64);
        regs.r9  = consume!(u64);
        regs.r8  = consume!(u64);
        regs.rdi = consume!(u64);
        regs.rsi = consume!(u64);
        regs.rbp = consume!(u64);
        regs.rdx = consume!(u64);
        regs.rcx = consume!(u64);
        regs.rbx = consume!(u64);
        regs.rax = consume!(u64);
        regs.rsp = consume!(u64);

        // Parse the `FxSave` out of the info
        unsafe {
            regs.fxsave = core::ptr::read_unaligned(
                ptr[..512].as_ptr() as *const FxSave);
            ptr = &ptr[512..];
        }

        // Construct the virtual to memory offset table
        let mut virt_to_offset = BTreeMap::new();

        // File contains a dynamic amount of MEMORY_BASIC_INFORMATION
        // structures until the end of the file
        assert!(ptr.len() % 48 == 0, "Invalid shape for info file");
        let mut offset = 0;
        for chunk in ptr.chunks(48) {
            // Parse out the section base and size
            let base = u64::from_le_bytes(
                chunk[0x00..0x08].try_into().unwrap());
            let size = u64::from_le_bytes(
                chunk[0x18..0x20].try_into().unwrap());

            // Make sure the size is non-zero and the base and the size are
            // both 4 KiB aligned
            assert!(size > 0 && base & 0xfff == 0 && size & 0xfff == 0);

            // Create the virtual to offset mappings
            for page in (base..=(base.checked_add(size - 1).unwrap()))
                    .step_by(4096) {
                // Create a mapping from each page in the virtual address
                // space of the dumped process, into the offset into the
                // memory backing for the snapshot.
                virt_to_offset.insert(VirtAddr(page), offset);
                offset += 4096;
            }
        }

        // Make sure all of the memory has been accounted for in the snapshot
        assert!(offset == memory.len());

        // Create a new master VM from the information provided
        let mut master =
            Worker::from_net(Arc::new(NetBacking {
                virt_to_offset,
                memory
            }));
        master.vm.guest_regs = regs;
        
        // Get access to a network device
        let netdev = NetDevice::get().expect("Failed to get network device");

        // Bind to a random UDP port on this network device
        let udp = NetDevice::bind_udp(netdev.clone())
            .expect("Failed to bind to UDP for network");

        // Resolve the target
        let server_address = UdpAddress::resolve(
            &netdev, udp.port(), server)
            .expect("Couldn't resolve target address");

        FuzzSession {
            master_vm:     Arc::new(master),
            coverage:      Aht::new(),
            stats:         LockCell::new(Statistics::default()),
            timeout:       None,
            inject:        None,
            vmexit_filter: None,
            input_dedup:   Aht::new(),
            inputs:        AtomicVec::new(),
            server:        udp,
            server_addr:   server_address,
            workers:       AtomicU64::new(0),
            id:            cpu::rdtsc(),
        }
    }

    /// Invoke a closure with access to the initial memory and register states
    /// of the snapshot such that they can be mutated to create the basis for
    /// all fuzz cases.
    pub fn init_master_vm<F>(mut self, callback: F) -> Self
            where F: FnOnce(&mut Worker) {
        callback(Arc::get_mut(&mut self.master_vm).unwrap());
        self
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
    pub fn vmexit_filter(mut self, vmexit_filter: VmExitFilter<'a>) -> Self {
        self.vmexit_filter = Some(vmexit_filter);
        self
    }

    /// Get a new worker for this fuzz session
    pub fn worker(session: Arc<Self>) -> Worker<'a> {
        // Log into the server with a new worker
        session.login();

        // Get a new worker ID
        let worker_id = session.workers.fetch_add(1, Ordering::SeqCst);

        // Fork the worker from the master
        Worker::fork(session.clone(), session.master_vm.clone(), worker_id)
    }

    /// Update statistics to the server
    pub fn report_statistics(&self) {
        // Attempt to log into the server
        let mut packet = self.server.device().allocate_packet();
        {
            let mut pkt = packet.create_udp(&self.server_addr);
            ServerMessage::ReportStatistics {
                fuzz_cases: self.stats.lock().fuzz_cases
            }.serialize(&mut pkt).unwrap();
        }
        self.server.device().send(packet, true);
    }

    /// Log in with the server
    pub fn login(&self) {
        loop {
            // Attempt to log into the server
            let mut packet = self.server.device().allocate_packet();
            {
                let mut pkt = packet.create_udp(&self.server_addr);
                ServerMessage::Login(self.id, core!().id)
                    .serialize(&mut pkt).unwrap();
            }
            self.server.device().send(packet, true);

            // Wait for the acknowledge from the server
            if self.server.recv_timeout(50_000, |_, udp| {
                // Deserialize the message
                let mut ptr = &udp.payload[..];
                let msg = ServerMessage::deserialize(&mut ptr)
                    .expect("Failed to deserialize File ID response");
                
                // Check if we got an ack
                match msg {
                    ServerMessage::LoginAck(sid, core) => {
                        if sid == self.id && core == core!().id {
                            Some(())
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }).is_some() { break; }
        }
    }

    /// Report coverage
    pub fn report_coverage(&self, cr: &CoverageRecord) -> bool {
        if self.coverage.entry_or_insert(cr, cr.offset as usize,
                                         || Box::new(())).inserted() {
            // Coverage was new, report it to the server

            loop {
                // Report the coverage
                let mut packet = self.server.device().allocate_packet();
                {
                    let mut pkt = packet.create_udp(&self.server_addr);
                    ServerMessage::ReportCoverage(Cow::Borrowed(cr))
                        .serialize(&mut pkt).unwrap();
                }
                self.server.device().send(packet, true);

                // Wait for the acknowledge from the server
                if self.server.recv_timeout(100, |_, udp| {
                    // Deserialize the message
                    let mut ptr = &udp.payload[..];
                    let msg = ServerMessage::deserialize(&mut ptr)
                        .expect("Failed to deserialize File ID response");
                    
                    // Check if we got an ack
                    match msg {
                        ServerMessage::ReportCoverageAck(x) => {
                            // Check if the ack is acknowledging the coverage
                            // we reported
                            if &*x == cr {
                                // Ack matches, break out of the recv
                                Some(())
                            } else {
                                // Nope
                                None
                            }
                        }
                        _ => None,
                    }
                }).is_some() { break; }
            }

            true
        } else {
            false
        }
    }
}


