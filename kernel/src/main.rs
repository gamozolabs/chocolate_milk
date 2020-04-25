//! A kernel written all in Rust

#![feature(panic_info_message, alloc_error_handler, llvm_asm, global_asm)]
#![feature(const_in_array_repeat_expressions)]

#![no_std]
#![no_main]

extern crate core_reqs;

#[allow(unused_imports)]
#[macro_use] extern crate alloc;

#[allow(unused_imports)]
#[macro_use] extern crate noodle;

#[macro_use] pub mod core_locals;
#[macro_use] pub mod print;
pub mod panic;
pub mod mm;
pub mod interrupts;
pub mod apic;
pub mod acpi;
pub mod intrinsics;
pub mod pci;
pub mod net;
pub mod time;
pub mod vtx;

use page_table::PhysAddr;

/// Release the early boot stack such that other cores can use it by marking
/// it as available
fn release_early_stack() {
    unsafe { mm::write_phys(PhysAddr(0x7e00), 1u8); }
}

/// Entry point of the kernel!
#[no_mangle]
pub extern fn entry(boot_args: PhysAddr, core_id: u32) -> ! {
    // Release the early boot stack, now that we have our own stack
    release_early_stack();

    // Initialize the core locals, this must happen first.
    core_locals::init(boot_args, core_id);
     
    // Calibrate the TSC so we can use `time` routines
    if core_id == 0 { unsafe { time::calibrate(); } }
    
    // Initialize interrupts
    interrupts::init();

    // Initialize the APIC
    unsafe { apic::init(); }
    
    if core!().id == 0 {
        // One-time initialization for the whole kernel

        // Initialize PCI devices
        unsafe { pci::init() }

        // Bring up all APICs on the system and also initialize NUMA
        // information with the memory manager through the use of the ACPI
        // information.
        unsafe { acpi::init() }
    }

    // Enable the APIC timer
    unsafe { core!().apic().lock().as_mut().unwrap().enable_timer(); }

    // Now we're ready for interrupts!
    unsafe { core!().enable_interrupts(); }

    // Let ACPI know that we've booted, it'll be happy to know we're here!
    // This will also serialize until all cores have come up. Once all cores
    // are online this will release all of the cores. This ensures that no
    // kernel task ends up hogging locks which are needed during bootloader
    // stack creation on other cores. This makes sure that by the time cores
    // get free reign of execution, we've intialized all cores to a state where
    // NMIs and soft reboots work.
    acpi::core_checkin();

    /*
    if core!().id == acpi::num_cores() - 1 {
        print!("[{:16.8}] We made it! All cores online! {}\n",
               time::uptime(), core!().id + 1);
    }*/

    //if core!().id == 0 {
        test_vm();
    //}

    cpu::halt();
}

fn test_vm() {
    use core::alloc::Layout;
    use core::sync::atomic::{AtomicU64, Ordering};
    use alloc::sync::Arc;
    use vtx::{Vm, VmExit, Exception};
    use page_table::{VirtAddr, PhysMem, PageType, Mapping};
    use page_table::{PAGE_PRESENT, PAGE_WRITE, PAGE_USER};
    use lockcell::LockCell;
    use net::netmapping::NetMapping;
    use core_locals::LockInterrupts;

    /// Network mapped file to execute from
    static MAPPING: LockCell<Option<Arc<NetMapping>>, LockInterrupts> =
        LockCell::new(None);

    /// Base for this test VM
    const VM_BASE: VirtAddr = VirtAddr(0x13370000);

    /// Number of fuzz cases
    static FUZZ_CASES: AtomicU64 = AtomicU64::new(0);
    
    static DIRTY_COST: [AtomicU64; 1024] = [AtomicU64::new(0); 1024];
    static NUM_TESTS:  [AtomicU64; 1024] = [AtomicU64::new(0); 1024];
    
    let mapping = {
        let mut ms = MAPPING.lock();
        if let Some(mapping) = &*ms {
            mapping.clone()
        } else {
            // Network map the memory contents as read-only
            let mapping = Arc::new(NetMapping::new(
                "192.168.101.1:1911", "test.bin", true)
                .expect("Failed to netmap file"));
            let ret = mapping.clone();
            *ms = Some(mapping);
            ret
        }
    };
    
    // Compute the end of the mapped space
    let mapping_end = VirtAddr(VM_BASE.0 + (mapping.len() as u64 - 1));

    let it = cpu::rdtsc();
    
    // Create a new virtual machine
    let mut vm = Vm::new_user();
    vm.guest_regs.rip = VM_BASE.0;

    // Save off the original register state
    let orig_regs = vm.guest_regs.clone();

    // Time to print the next status message
    let mut next_print = time::future(1_000_000);

    let mut start = None;

    let mut to_dirty = 0;
    let mut next_dirty = time::future(1_000_000);

    loop {
        // Reset the register state
        vm.guest_regs = orig_regs;

        let mut dirtied = 0;
        unsafe {
            // Reset memory
            vm.page_table.for_each_dirty_page(&mut mm::PhysicalMemory, |addr, page| {
                // Compute the offset into the mapped file
                let offset = ((addr.0 & !0xfff) - VM_BASE.0) as usize;

                // Get mutable access to the underlying page
                let psl = mm::slice_phys_mut(page, 4096);

                llvm_asm!(r#"
                  
                    mov rcx, 4096 / 8
                    rep movsq

                "# ::
                "{rdi}"(psl.as_ptr()),
                "{rsi}"(mapping.get_unchecked(offset..).as_ptr()) :
                "memory", "rcx", "rdi", "rsi", "cc" : 
                "intel", "volatile");

                dirtied += 1;
            });
        }

        if let Some(start) = start {
            DIRTY_COST[dirtied].fetch_add(cpu::rdtsc() - start, Ordering::Relaxed);
            NUM_TESTS[dirtied].fetch_add(1, Ordering::Relaxed);
        }

        // Print status messages on an interval
        if core!().id == 0 && cpu::rdtsc() >= next_print {
            let fuzz_case = FUZZ_CASES.load(Ordering::Relaxed);

            print!("Fuzz case {:12} | {:12.1} fcps\n", fuzz_case,
                   fuzz_case as f64 / time::elapsed(it));

            for bucket in 0..=200 {
                let cycles_per = DIRTY_COST[bucket].load(Ordering::Relaxed) as f64 /
                    NUM_TESTS[bucket].load(Ordering::Relaxed) as f64;

                let fcps = time::tsc_mhz() as f64 * 1_000_000. / cycles_per;
                let fcps = fcps * acpi::num_cores() as f64;
                print!("{:5} {:16.4}\n", bucket, fcps);
                /*print!("Stats for dirty pages {:5} | {:12.1} fcps\n",
                       bucket, fcps);*/
            }
            print!("-------------------------------------\n");

            next_print = time::future(1_000_000);
        }

        start = Some(cpu::rdtsc());
        
        if cpu::rdtsc() >= next_dirty {
            to_dirty += 1;
            next_dirty = time::future(1_000_000);
        }
        vm.guest_regs.rcx = to_dirty;

        'vm_loop: loop {
            let vmexit = vm.run();
            if matches!(vmexit, VmExit::ExternalInterrupt) {
                continue 'vm_loop;
            }
            
            print!("[{:16.8}] {:x?}\n", time::uptime(), vmexit);

            if let VmExit::Exception(Exception::PageFault { addr, write, .. }) =
                    vmexit {
                // Compute the offset into the mapped file
                let offset = ((addr.0 & !0xfff) - VM_BASE.0) as usize;
                
                // If the page fault was inbounds of our mapping
                if !write && addr.0 >= VM_BASE.0 && addr.0 <= mapping_end.0 {
                    unsafe {
                        // Touch the mapping to make sure it is downloaded and
                        // mapped
                        core::ptr::read_volatile(&mapping[offset]);
                    }
                        
                    // Get access to physical memory
                    let mut pmem = mm::PhysicalMemory;

                    // Look up the physical page backing for the mapping
                    let page = {
                        // Get access to the host page table
                        let mut page_table =
                            core!().boot_args.page_table.lock();
                        let page_table = page_table.as_mut().unwrap();

                        // Translate the mapping virtual address into a
                        // physical address
                        page_table.translate(&mut pmem,
                            VirtAddr(mapping[offset..].as_ptr() as u64))
                            .map(|x| x.page).flatten()
                            .expect("Whoa, mapping page not mapped?!").0
                    };
                    
                    unsafe {
                        // Map in the page
                        vm.page_table.map_raw(&mut pmem,
                            VirtAddr(addr.0 & !0xfff),
                            PageType::Page4K,
                            page.0 | PAGE_USER | PAGE_PRESENT).unwrap();
                    }
                    
                    continue 'vm_loop;
                }

                // If the page fault was inbounds of our mapping
                if write && addr.0 >= VM_BASE.0 && addr.0 <= mapping_end.0 {
                    // Map in the page
                    let mut pmem = mm::PhysicalMemory;

                    // Allocate a new page and zero it out
                    let page = pmem.alloc_phys_zeroed(
                        Layout::from_size_align(4096, 4096).unwrap());

                    unsafe {
                        // Compute the offset into the mapped file
                        let offset = ((addr.0 & !0xfff) - VM_BASE.0) as usize;

                        // Get mutable access to the underlying page
                        let psl = mm::slice_phys_mut(page, 4096);

                        // Compute the number of bytes to copy
                        let to_copy =
                            core::cmp::min(4096, mapping.len() - offset);

                        // Copy in the bytes to initialize the page
                        psl[..to_copy].copy_from_slice(
                            &mapping[offset..offset + to_copy]);
                        
                        // Attempt to translate the page, it may already be
                        // mapped read-only
                        let translation = vm.page_table.translate(&mut pmem,
                            VirtAddr(addr.0 & !0xfff));

                        if let Some(Mapping {
                                    pte: Some(pte), page: Some(page), ..
                                }) = translation {
                            // If this page is already mapped, we are doing
                            // CoW and need to promote it to it's own page
                            mm::write_phys(pte, (page.0).0 | PAGE_USER |
                                           PAGE_WRITE | PAGE_PRESENT);
                        } else {
                            // Map in the page
                            vm.page_table.map_raw(&mut pmem,
                                VirtAddr(addr.0 & !0xfff),
                                PageType::Page4K,
                                page.0 |
                                PAGE_USER | PAGE_WRITE | PAGE_PRESENT)
                                .unwrap();
                        }
                    }

                    continue 'vm_loop;
                }
                
                break 'vm_loop;
            } else {
                break 'vm_loop;
            }
        }

        FUZZ_CASES.fetch_add(1, Ordering::Relaxed);
    }
}

