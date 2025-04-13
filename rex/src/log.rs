use core::fmt::{self, Write};

use crate::bindings::uapi::linux::errno::E2BIG;
use crate::ffi;
use crate::per_cpu::this_cpu_ptr_mut;

/// An abstraction over the in-kernel per-cpu log buffer
/// This struct implements [`Write`], and therefore can be used for formatting
pub(crate) struct LogBuf {
    buf: &'static mut [u8],
    off: usize,
}

impl LogBuf {
    /// Construct a new `LogBuf` from the kernel log buffer on the current CPU
    pub(crate) fn new() -> Self {
        let buf = unsafe {
            &mut *this_cpu_ptr_mut(&raw mut ffi::rex_log_buf).as_mut_slice()
        };
        Self { buf, off: 0 }
    }

    /// Reset the offset of the buffer, i.e. discarding all contents not yet
    /// sent to the kernel
    #[inline(always)]
    pub(crate) fn reset(&mut self) {
        self.off = 0;
    }
}

impl Write for LogBuf {
    /// Writes a string slice into the kernel buffer on this CPU
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let input_len = s.len();
        let available = self.buf.len() - self.off - 1;

        // Make sure we have enough space
        if input_len > available {
            return Err(fmt::Error);
        }

        // Copy and null-terminated the buf
        let end = self.off + input_len;
        self.buf[self.off..end].copy_from_slice(s.as_bytes());
        self.buf[end] = 0;

        // Update the write offset
        self.off = end;

        Ok(())
    }
}

/// Prints a message defined by `args` to the TraceFS file
/// `/sys/kernel/debug/tracing/trace`.
pub fn rex_trace_printk(args: fmt::Arguments<'_>) -> crate::Result {
    // Format and write message to the per-cpu buf, then print it out
    write!(&mut LogBuf::new(), "{}", args).map_err(|_| -(E2BIG as i32))?;
    unsafe {
        ffi::rex_trace_printk();
    }

    Ok(0)
}

/// `println`-style convenience macro for [`rex_trace_printk`].
/// Different from `println`, this macro produces the value of [`crate::Result`]
/// from [`rex_trace_printk`]
#[macro_export]
macro_rules! rex_printk {
    ($($arg:tt)*) => {{
        $crate::rex_trace_printk(format_args!($($arg)*))
    }};
}
