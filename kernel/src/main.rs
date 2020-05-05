//! A kernel written all in Rust

#![feature(panic_info_message, alloc_error_handler, llvm_asm, global_asm)]
#![feature(const_in_array_repeat_expressions, const_generics)]
#![allow(incomplete_features)]

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
pub mod snapshotted_app;
pub mod test_fuzzer;
pub mod ept;
pub mod paging;

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

    // ====================================================================
    // Put your whatever code here, typically I just branch to a module
    // which has a "main" or something and call `mod::main()`
    // ====================================================================
    
    if core!().id == 0 {
        use net::{NetDevice, UdpBind, UdpAddress};
        use falktp::DatagramTransceiver;
        use crate::noodle::Writer;

        /// A session of lossless UDP transactions. Allows sending and
        /// receiving data in a stable and windows way over UDP. Totally not
        /// just too lazy to implement TCP.
        struct LosslessUdp {
            /// A UDP binding which we send from
            udp: UdpBind,

            /// The address of what we are talking to
            address: UdpAddress,
        }

        impl LosslessUdp {
            /// Create a new lossless UDP session to `server`. There is no
            /// protocol negotiation here, it's just expected that both
            /// parties are complying.
            ///
            /// This is not zero-cost, as we have to resolve the target address
            /// over ARP.
            fn new(server: &str) -> Option<Self> {
                // Get access to a network device
                let netdev = NetDevice::get()?;

                // Bind to a random UDP port on this network device
                let udp = NetDevice::bind_udp(netdev.clone())?;

                // Resolve the target
                let address =
                    UdpAddress::resolve(&netdev, udp.port(), server)?;

                Some(LosslessUdp {
                    udp,
                    address,
                })
            }
        }

        impl DatagramTransceiver for LosslessUdp {
            fn send(&mut self, data: &[u8], flush: bool) {
                let mut packet = self.udp.device().allocate_packet();
                {
                    let mut pkt = packet.create_udp(&self.address);
                    pkt.write(data);
                }
                self.udp.device().send(packet, flush);
            }

            fn recv<T, F: FnMut(&[u8]) -> Option<T>>(&mut self, mut func: F)
                    -> Option<T> {
                self.udp.recv_timeout(50_000, |_, udp| {
                    Some(func(udp.payload))
                })?
            }
        }

        let mut ludp = LosslessUdp::new("192.168.100.1:1911").unwrap();
        ludp.send_message(&[b'A'; 129]);
    }

    //test_fuzzer::fuzz();

    cpu::halt();
}

