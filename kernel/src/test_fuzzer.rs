use alloc::sync::Arc;

use crate::core_locals::LockInterrupts;
use crate::snapshotted_app::{Worker, FuzzSession};

use lockcell::LockCell;
use page_table::VirtAddr;

pub fn fuzz() {
    //if core!().id != 0 { cpu::halt(); }

    static SESSION:
        LockCell<Option<Arc<FuzzSession>>, LockInterrupts> =
        LockCell::new(None);

    // Create the master sessionshot, and fork from it for all cores
    let session = {
        let mut session = SESSION.lock();
        if session.is_none() {
            *session = Some(
                Arc::new(FuzzSession::new("192.168.101.1:1911",
                    "falkdump_pid_00000000000000007500_tid_00000000000000007560")
                .init_master_vm(|worker| {
                    worker.vm.guest_regs.rip = 0x00007FF62C3D6E10;
                    worker.write_from(
                        VirtAddr(worker.vm.guest_regs.rip as u64),
                        b"\x48\x89\x54\x24\x10\x48\x89\x4c\x24\x08\
                          \x48\x83\x7c\x24\x10\x05").unwrap();
                    
                    worker.write_from(
                        VirtAddr(worker.vm.guest_regs.rip as u64 +
                                 0x6ea7 - 0x6e10),
                        b"\xcc").unwrap();
                })
                .timeout(100_000)
                .inject(inject))
            );
        }
        session.as_ref().unwrap().clone()
    };

    let mut worker = FuzzSession::worker(session);
    
    // Parse the module lists for the target
    worker.get_module_list_win64().expect("Failed to get module list");

    loop {
        worker.fuzz_case();
    }
}

fn inject(worker: &mut Worker) {
    // rcx points to the input buffer
    // rdx is the length of the input buffer
    
    // Create an empty input
    let mut input = worker.fuzz_input.take().unwrap();
    input.clear();

    if let (0, Some(old)) = (worker.rng.rand() % 2, worker.rand_input()) {
        // Use an existing input from the corpus
        input.extend_from_slice(old);
    } else {
        // Pick a random input size
        let input_size = worker.rng.rand() % (128 + 1);
        input.resize(input_size, 0u8);
    }
    
    // Set the input size
    worker.vm.guest_regs.rdx = input.len() as u64;

    // Corrupt the input
    if input.len() > 0 {
        let il = input.len();
        for _ in 0..worker.rng.rand() % 6 {
            input[worker.rng.rand() % il] = worker.rng.rand() as u8;
        }
    }

    // Inject the input
    worker.write_from(VirtAddr(worker.vm.guest_regs.rcx),
                      input.as_slice()).unwrap();

    // Save the input back with the worker
    worker.fuzz_input = Some(input);
}

