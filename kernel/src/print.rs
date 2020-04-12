//! print macro support

/// Dummy type to implement `core::fmt::Write` for `print!` macros
pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, st: &str) -> core::fmt::Result {
        if let Some(serial) = core!().boot_args.serial.lock().as_mut() {
            serial.write(st.as_bytes());
        }

        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        let _lock = core!().boot_args.print_lock.lock();
        let _ = core::fmt::Write::write_fmt(
            &mut $crate::print::SerialWriter, format_args!($($arg)*));
    }}
}

