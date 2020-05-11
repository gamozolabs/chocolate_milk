use alloc::sync::Arc;
use alloc::boxed::Box;

//use crate::vtx::Register;
use crate::core_locals::LockInterrupts;
use crate::fuzz_session::{Worker, FuzzSession};

use lockcell::LockCell;

pub fn fuzz() {
    if core!().id != 0 { cpu::halt(); }

    static SESSION:
        LockCell<Option<Arc<FuzzSession>>, LockInterrupts> =
        LockCell::new(None);

    // Create the master sessionshot, and fork from it for all cores
    let session = {
        let mut session = SESSION.lock();
        if session.is_none() {
            *session = Some(
                Arc::new(FuzzSession::from_falkdump(
                        "192.168.101.1:1911", "out.falkdump", |_worker| {
                    //_worker.set_reg(crate::vtx::Register::Rsp, 0x13371337);
                    _worker.set_reg(crate::vtx::Register::Cr3, 0x3713371337);
                })
                //.timeout(100_000)
                .inject(inject))
            );
        }
        session.as_ref().unwrap().clone()
    };

    let mut worker = FuzzSession::worker(session);
    
    // Set that this is a Windows guest
    worker.enlighten(Some(Box::new(crate::fuzz_session::windows::Enlightenment::default())));

    loop {
        let _vmexit = worker.fuzz_case();
        /*print!("{:#x?}\n", _vmexit);
        crate::time::sleep(1_000_000);*/
    }
}

fn inject(worker: &mut Worker) {
    let mut input = worker.fuzz_input.borrow_mut();
    input.clear();
    input.push(worker.rng.rand() as u8);
    input.push(worker.rng.rand() as u8);
}

