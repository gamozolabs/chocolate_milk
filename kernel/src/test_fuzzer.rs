use core::any::Any;
use alloc::sync::Arc;
use alloc::boxed::Box;

use crate::core_locals::LockInterrupts;
use crate::fuzz_session::{Worker, FuzzSession};

use lockcell::LockCell;

pub fn fuzz() {
    if core!().id != 0 { cpu::halt(); }
    //if core!().id >= 24 { cpu::halt(); }

    static SESSION:
        LockCell<Option<Arc<FuzzSession>>, LockInterrupts> =
        LockCell::new(None);

    // Create the master snapshot, and fork from it for all cores
    let session = {
        let mut session = SESSION.lock();
        if session.is_none() {
            print!("LETS FUZZ!\n");
            *session = Some(
                Arc::new(FuzzSession::from_falkdump(
                        "192.168.101.1:1911", "test.falkdump", |_worker| {
                    // Mutate the master at this point
                })
                .timeout(1_000_000)
                .inject(inject))
            );
        }
        session.as_ref().unwrap().clone()
    };

    let mut worker = FuzzSession::worker(session);
    
    // Set that this is a Windows guest
    worker.enlighten(Some(Box::new(
                crate::fuzz_session::windows::Enlightenment::default())));

    loop {
        let _vmexit = worker.fuzz_case(&mut ());
    }
}

fn inject(_worker: &mut Worker, _context: &mut dyn Any) {
}

