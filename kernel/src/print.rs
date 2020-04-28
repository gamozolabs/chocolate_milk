//! `print!()` macro support

/// Dummy type to implement `core::fmt::Write` for `print!` macros
pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, st: &str) -> core::fmt::Result {
        // Get access to the serial port
        let mut lock = core!().boot_args.serial.lock();

        // Write the message to the serial port!
        if let Some(serial) = &mut *lock {
            serial.write(st.as_bytes());
        }

        Ok(())
    }
}

/// Serial port formatted printing
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        // Lock the print arguments so cores don't interleave their print
        // statements
        let _lock = core!().boot_args.print_lock.lock();

        let _ = core::fmt::Write::write_fmt(
            &mut $crate::print::SerialWriter, format_args!($($arg)*));
    }}
}

