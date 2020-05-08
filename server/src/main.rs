//! Implementation of the falktp transfer protocol

#[allow(unused)]
#[macro_use] extern crate noodle;

use std::io::{self, Write};
use std::fs::File;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, Duration};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, TcpStream, TcpListener};
use std::collections::{BTreeSet, HashMap};
use std::collections::hash_map::DefaultHasher;

use noodle::*;
use falktp::{CoverageRecord, ServerMessage};

/// If `true` prints some extra spew
const VERBOSE: bool = false;

/// A fuzzing session. This represents a unique `FuzzSession` on a server and
/// may span multiple cores and IPs (in the case of multiple NICs)
struct Session<'a> {
    /// Session ID, a "unique" identifier passed by the client
    id: u64,

    /// Unique core IDs of the workers on this session
    workers: BTreeSet<u32>,

    /// Time of the first packet receieved from this client
    first_packet: Instant,

    /// Time of the last packet reciept from this client
    last_packet: Instant,

    /// Number of fuzz cases performed on this client
    fuzz_cases: u64,
    
    /// Number of cycles spent resetting the VM
    reset_cycles: u64,

    /// Total cycles spent fuzzing
    total_cycles: u64,

    /// Number of cycles spent inside the VM
    vm_cycles: u64,

    /// Set of coverage for this client
    coverage: BTreeSet<CoverageRecord<'a>>,
}

/// A client (a unique IP address), which may be part of a set of IP addresses
/// on a single machine which are collaborating
struct Client<'a> {
    /// A session we belong to
    session: Arc<RwLock<Session<'a>>>,

    /// The session identifier of the session we belong to
    session_id: u64,
}

fn stats(context: Arc<Context>) {
    /// Time to wait between prints
    const PRINT_DELAY: Duration = Duration::from_millis(1000);

    let mut last_cases = 0;

    loop {
        std::thread::sleep(PRINT_DELAY);

        // Total number of fuzz cases and workers
        let mut total_cases    = 0u64;
        let mut total_workers  = 0usize;
        let mut total_sessions = 0u64;

        let sessions = context.sessions.read().unwrap();
        for (_, session) in sessions.iter() {
            let session = session.read().unwrap();

            // Compute the duration of time since the last report
            let tsl = Instant::now() - session.last_packet;
            let unresponsive = tsl > Duration::from_secs(5);

            let uptime = (Instant::now() - session.first_packet).as_secs_f64();

            let reset_pct =
                session.reset_cycles as f64 / session.total_cycles as f64;
            let vm_pct =
                session.vm_cycles as f64 / session.total_cycles as f64;

            print!("\x1b[34;1m    workers {:3} | cov {:8} | \
                        cases {:14} [{:12.2} / s] | vm {:8.4} | \
                        reset {:8.4} | {:016x} {}\x1b[0m\n",
                   session.workers.len(),
                   session.coverage.len(),
                   session.fuzz_cases,
                   session.fuzz_cases as f64 / uptime,
                   vm_pct,
                   reset_pct,
                   session.id,
                   if unresponsive { "???" } else { "" });

            if !unresponsive {
                total_cases    += session.fuzz_cases;
                total_workers  += session.workers.len();
                total_sessions += 1;
            }
        }

        let cases_delta = total_cases.saturating_sub(last_cases);
        let coverage = context.coverage.read().unwrap().len();
        print!("\x1b[32;1mTOTALS: workers {:5} ({:3}) | cases {:14} \
                [{:12.2} / s] | \
                cov {:8}\x1b[0m\n\n",
               total_workers, total_sessions,
               total_cases,
               cases_delta as f64 / PRINT_DELAY.as_secs_f64(),
               coverage);

        // Update last cases
        last_cases = total_cases;
    }
}

fn handle_client(stream: TcpStream,
                 context: Arc<Context>) -> io::Result<()> {
    // Disable Nagle's algoritm
    stream.set_nodelay(true)?;

    // Get the IP of the peer
    let src_ip = stream.peer_addr()?.ip();

    // Convert the stream to a buffered I/O stream
    let mut stream = BufferedIo::new(stream);

    // Get the current directory
    let cur_dir = std::fs::canonicalize("files")?;

    loop {
        // Deserialize the message
        let msg = ServerMessage::deserialize(&mut stream)
            .expect("Failed to deserialize ServerMessage");

        // Insert the client record if one does not exist
        let mut client = {
            let clients = context.clients.read().unwrap();
            clients.get(&src_ip).map(|x| x.clone())
        };

        if let Some(ref client) = client {
            client.session.write().unwrap().last_packet = Instant::now();
        }

        match msg {
            ServerMessage::ReportStatistics { fuzz_cases, total_cycles,
                    vm_cycles, reset_cycles } => {
                if let Some(client) = client {
                    let mut session = client.session.write().unwrap();
                    session.fuzz_cases   = fuzz_cases;
                    session.total_cycles = total_cycles;
                    session.vm_cycles    = vm_cycles;
                    session.reset_cycles = reset_cycles;
                }
            }
            ServerMessage::Login(session_id, core_id) => {
                // If there is no existing client or the session ID has changed
                // create a new client
                if let Some(ref cl) = client {
                    // A client has logged in a second time, it's possible it
                    // has rebooted and has a new session, if it does, remove
                    // the old session and create a new session
                    if cl.session_id != session_id {
                        // Delete the old session from the session list
                        context.sessions.write().unwrap().remove(
                            &cl.session_id);

                        // Delete the client from the client list
                        {
                            let mut clients = context.clients.write().unwrap();
                            clients.remove(&src_ip);
                        }

                        // Set the client to none, such that we create a new
                        // session and client context
                        client = None;
                    }
                }
                
                if client.is_none() {
                    // New client, potentially new session
                    let mut sessions = context.sessions.write().unwrap();
                    let session = sessions.entry(session_id)
                            .or_insert_with(|| {
                        Arc::new(RwLock::new(Session {
                            id:           session_id,
                            workers:      BTreeSet::new(),
                            first_packet: Instant::now(),
                            last_packet:  Instant::now(),
                            fuzz_cases:   0,
                            total_cycles: 0,
                            reset_cycles: 0,
                            vm_cycles:    0,
                            coverage:     BTreeSet::new(),
                        }))
                    });

                    client = {
                        // Update the client to reference this session
                        let mut clients = context.clients.write().unwrap();
                        clients.insert(src_ip, Arc::new(Client {
                            session:    session.clone(),
                            session_id: session_id,
                        }));
                        clients.get_mut(&src_ip).map(|x| x.clone())
                    };
                }

                // Client is always valid at this point
                let client = client.unwrap();

                // Insert our core ID into the session
                let mut session = client.session.write().unwrap();
                session.workers.insert(core_id);
            }
            ServerMessage::Coverage(records) => {
                let mut coverage = context.coverage.write().unwrap();
                let mut coverage_file = context.coverage_file.lock().unwrap();

                // Go through each coverage record that was reported
                for record in records.iter() {
                    // Update the global coverage database
                    if !coverage.contains(&record) {
                        if let Some(module) = &record.module {
                            write!(coverage_file, "{}+", module)?;
                        }
                        write!(coverage_file, "{:#x}\n", record.offset)?;
                        coverage.insert(record.clone());
                    }

                    // Update the per-client coverage records
                    if let Some(ref mut client) = client {
                        let mut session = client.session.write().unwrap();
                        if !session.coverage.contains(&record) {
                            session.coverage.insert(record.clone());
                        }
                    }
                }
            }
            ServerMessage::GetFileId(filename) => {
                // Normalize the filename
                if let Ok(filename) =
                        std::fs::canonicalize(Path::new("files")
                                              .join(&*filename)) {
                    // Jail the filename to the current directory
                    if !filename.starts_with(&cur_dir) {
                        continue;
                    }

                    // Compute the file ID by hashing the file path
                    let mut hasher = DefaultHasher::new();
                    filename.to_str().unwrap().hash(&mut hasher);
                    let file_id = hasher.finish();

                    // Get the modified time of the file
                    let modified = filename.metadata().unwrap()
                        .modified().unwrap();

                    // Get access to the file database
                    let mut file_db = context.file_db.write().unwrap();

                    // Insert into the file database if needed
                    let file = file_db.entry(file_id)
                        .or_insert_with(|| {
                            print!("Loading {:?}\n", filename);
                            (modified, std::fs::read(&filename).unwrap())
                        });

                    // Check if we should reload the file since it has been
                    // modified
                    if file.0 < modified {
                        print!("Reloading {:?}\n", filename);
                        *file = (modified, std::fs::read(&filename).unwrap());
                    }

                    // Send the ID response
                    ServerMessage::FileId {
                        id:   file_id,
                        size: file.1.len(),
                    }.serialize(&mut stream).unwrap();
                    stream.flush().unwrap();
                }
            },
            ServerMessage::ReadPage { id, offset } => {
                if VERBOSE {
                    print!("Read page {:016x} offset {}\n",
                           id, offset);
                }

                // Get access to the file database
                let file_db = context.file_db.read().unwrap();

                // Attempt to get access to the file contents at the requested
                // location
                let sliced = file_db.get(&id).and_then(|(_, x)| {
                    x.get(offset..offset + 4096)
                });

                if let Some(sliced) = sliced {
                    let mut tmp = [0u8; 4096];
                    tmp.copy_from_slice(sliced);

                    ServerMessage::ReadPageResponse(tmp)
                        .serialize(&mut stream).unwrap();
                    stream.flush().unwrap();
                }
            },
            _ => panic!("Unhandled packet\n"),
        }
    }
}

struct Context<'a> {
    file_db:       RwLock<HashMap<u64, (SystemTime, Vec<u8>)>>,
    coverage:      RwLock<BTreeSet<CoverageRecord<'a>>>,
    clients:       RwLock<HashMap<IpAddr, Arc<Client<'a>>>>,
    sessions:      RwLock<HashMap<u64, Arc<RwLock<Session<'a>>>>>,
    coverage_file: Mutex<File>,
}

fn main() -> io::Result<()> {
    let context = Arc::new(Context {
        file_db:       Default::default(),
        coverage:      Default::default(),
        clients:       Default::default(),
        sessions:      Default::default(),
        coverage_file: Mutex::new(File::create("coverage.txt")?),
    });

    // Bind to all network devices on TCP port 1911
    let listener = TcpListener::bind("0.0.0.0:1911")?;

    {
        let context = context.clone();
        std::thread::spawn(move || stats(context));
    }

    let mut threads = Vec::new();
    for stream in listener.incoming() {
        let context = context.clone();
        threads.push(std::thread::spawn(move || {
            handle_client(stream?, context)
        }));
    }

    for thread in threads {
        thread.join().unwrap()?;
    }

    Ok(())
}

