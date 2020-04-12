//! Main Rust entry point for the chocolate milk bootloader

#![feature(panic_info_message, rustc_private, alloc_error_handler)]
#![no_std]
#![no_main]

extern crate compiler_builtins;
extern crate core_reqs;
extern crate alloc;

#[macro_use] mod print;
mod realmode;
mod mm;
mod panic;
mod pxe;
mod intrins;

use serial::SerialPort;
use boot_args::BootArgs;
use pe_parser::PeParser;
use lockcell::LockCell;
use page_table::{VirtAddr, PageType, PageTable};

pub static BOOT_ARGS: BootArgs = BootArgs {
    free_memory: LockCell::new(None),
    serial:      LockCell::new(None),
};

#[no_mangle]
extern fn entry() -> ! {
    {
        // Get access to the serial driver
        let mut serial = BOOT_ARGS.serial.lock();

        if serial.is_none() {
            // Driver has not yet been set up, initialize the ports
            *serial = Some(unsafe { SerialPort::new() });
        }
    }

    mm::init();

    let (entry_point, stack, cr3): (u64, u64, u32) = {
        // Download the kernel
        let kernel = pxe::download("chocolate_milk.kern")
            .expect("Failed to download chocolate_milk.kern over TFTP");

        // Parse the PE from the kernel
        let pe = PeParser::parse(&kernel).expect("Failed to parse PE");

        // Get exclusive access to physical memory
        let mut pmem = BOOT_ARGS.free_memory.lock();
        let pmem = pmem.as_mut()
            .expect("Whoa, physical memory not initialized yet");
        let mut pmem = mm::PhysicalMemory(pmem);

        // Create a new page table
        let mut table = PageTable::new(&mut pmem)
            .expect("Failed to create page table");

        // Create a 4 GiB identity map
        for paddr in (0..(4 * 1024 * 1024 * 1024)).step_by(4096) {
            unsafe {
                table.map_raw(VirtAddr(paddr), PageType::Page4K,
                    paddr | 3, true, false, false).unwrap();
            }
        }

        // Load all the sections from the PE into the new page table
        pe.sections(|vaddr, vsize, raw| {
            // Create a new virtual mapping for the PE range and initialize it
            // to the raw bytes from the PE file, otherwise to zero for all
            // bytes that were not initialized in the file.
            unsafe {
                table.map_init(VirtAddr(vaddr), PageType::Page4K,
                    vsize as u64, true, true, true,
                    Some(|off| {
                        raw.get(off as usize).copied().unwrap_or(0)
                    }));
            }

            print!("Created map at {:#018x} for {:#018x} bytes\n",
                   vaddr, vsize);

            Some(())
        }).unwrap();

        // Map in a stack
        unsafe {
            table.map(VirtAddr(0xb00_0000_0000), PageType::Page4K, 8192,
                true, true, false).unwrap();
        }

        print!("Entry point is {:#x}\n", pe.entry_point);

        (pe.entry_point, 0xb00_0000_0000 + 8192, table.table().0 as u32)
    };

    extern {
        fn enter64(entry_point: u64, stack: u64, param: u64, cr3: u32) -> !;
    }

    unsafe {
        enter64(entry_point, stack, &BOOT_ARGS as *const BootArgs as u64, cr3);
    }
}

