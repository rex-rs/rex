use core::ffi::{c_int, c_uchar};

use crate::ffi;

// WARN must add "\0" at the end of &str, c_str is different from rust str
#[allow(improper_ctypes_definitions)]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn printk(fmt: &str, mut ap: ...) -> c_int {
    unsafe { ffi::vprintk(fmt.as_ptr() as *const c_uchar, ap.as_va_list()) }
}
