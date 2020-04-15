use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Get access to the serial port
    let mut serial = crate::BOOT_ARGS.serial.lock();

    if let Some(serial) = serial.as_mut() {
        // Write out the panic message if there is an active serial driver
        serial.write(b"PANIC in bootloader\n");
    }

    cpu::halt();
}

