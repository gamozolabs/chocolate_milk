//! print macro support

/// Dummy type to implement `core::fmt::Write` for `print!` macros
pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, st: &str) -> core::fmt::Result {
        // Attempt to get access to the lock. If we can do a blocking request,
        // then we will, otherwise we will attempt a lock, in which case we
        // might end up missing console output during an exceptional condition.
        let lock = if core!().in_exception() {
            core!().boot_args.serial.try_lock()
        } else {
            Some(core!().boot_args.serial.lock())
        };

        // Write the message to the serial port!
        if let Some(mut serial) = lock {
            if let Some(serial) = serial.as_mut() {
                serial.write(st.as_bytes());
            }
        }

        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        // Print lock is not critical, it's only used to prevent overlapping
        // writes. Thus, if we're in an exception (and thus, we got pre-empted
        // potentially during having the lock held), we will only attempt to
        // get the lock.
        let _lock = if core!().in_exception() {
            core!().boot_args.print_lock.try_lock()
        } else {
            Some(core!().boot_args.print_lock.lock())
        };

        let _ = core::fmt::Write::write_fmt(
            &mut $crate::print::SerialWriter, format_args!($($arg)*));
    }}
}

