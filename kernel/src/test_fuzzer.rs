use alloc::sync::Arc;

//use crate::vtx::Register;
use crate::core_locals::LockInterrupts;
use crate::snapshotted_app::{Worker, FuzzSession};

use lockcell::LockCell;

pub fn fuzz() {
    if core!().id != 0 { cpu::halt(); }

    static SESSION:
        LockCell<Option<Arc<FuzzSession<()>>>, LockInterrupts> =
        LockCell::new(None);

    // Create the master sessionshot, and fork from it for all cores
    let session = {
        let mut session = SESSION.lock();
        if session.is_none() {
            *session = Some(
                Arc::new(FuzzSession::from_falkdump(
                        "192.168.101.1:1911", "out.falkdump")
                .init_master_vm(|_worker| {})
                //.timeout(100_000)
                .inject(inject))
            );
        }
        session.as_ref().unwrap().clone()
    };

    let mut worker = FuzzSession::worker(session);
    
    // Parse the module lists for the target
    worker.get_module_list_win64().expect("Failed to get module list");

    loop {
        let _vmexit = worker.fuzz_case();
        /*
        print!("PC is at {:#x} {:#x}\n", worker.vm.reg(Register::Rip),
            worker.vm.reg(Register::Rax));
        print!("{:#x?}\n", _vmexit);

        crate::time::sleep(1_000_000);*/
    }
}

fn inject(_worker: &mut Worker<()>) {
}

