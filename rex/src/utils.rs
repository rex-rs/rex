use core::ffi::{c_int, c_uchar};
use core::mem;

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct u16be(pub(crate) u16);

impl From<u16be> for u16 {
    // Required method
    fn from(value: u16be) -> Self {
        u16::from_be(value.0)
    }
}

/// A specialized Result for typical int return value in the kernel
///
/// To be used as the return type for functions that may fail.
///
/// Ref: linux/rust/kernel/error.rs
pub type Result = core::result::Result<c_int, c_int>;

/// Converts an integer as returned by a C kernel function to an error if it's
/// negative, and `Ok(val)` otherwise.
///
/// Ref: linux/rust/kernel/error.rs
// genetic specialization to Macro
#[macro_export]
macro_rules! to_result {
    ($retval:expr) => {{
        let val = $retval;
        if val < 0 {
            Err(val as i32)
        } else {
            Ok(val as i32)
        }
    }};
}
pub(crate) use to_result;

// User can get the customized struct like memcached from the data_slice
// TODO: add a bound checking for this function, add size check
#[inline(always)]
pub unsafe fn convert_slice_to_struct<T: NoRef>(slice: &[c_uchar]) -> &T {
    assert!(
        slice.len() >= mem::size_of::<T>(),
        "size mismatch in convert_slice_to_struct"
    );

    unsafe { &*(slice.as_ptr() as *const T) }
}

#[inline(always)]
pub unsafe fn convert_slice_to_struct_mut<T: NoRef>(
    slice: &mut [c_uchar],
) -> &mut T {
    assert!(
        slice.len() >= mem::size_of::<T>(),
        "size mismatch in convert_slice_to_struct_mut"
    );

    unsafe { &mut *(slice.as_mut_ptr() as *mut T) }
}

/// A marker trait that prevents derivation on types that contain references or
/// raw pointers. This avoids accidental dereference of invalid pointers in
/// foreign objects obtained from the kernel (e.g. via `bpf_map_lookup_elem` or
/// `bpf_probe_read_kernel`).
///
/// Though dererferencing raw pointers are not possible in Rex programs as it
/// requires `unsafe`, we still need to consider the case where a core library
/// type wraps the unsafe deref operation under a safe interface (an example is
/// `core::slice::Iter`).
pub unsafe auto trait NoRef {}
impl<T: ?Sized> !NoRef for &T {}
impl<T: ?Sized> !NoRef for &mut T {}
impl<T: ?Sized> !NoRef for *const T {}
impl<T: ?Sized> !NoRef for *mut T {}

/// Design decision: programs that can stream data through a
/// RexPerfEventArray will implement this trait
pub trait StreamableProgram {
    pub fn output_event<T>(
        &self,
        map: &'static RexPerfEventArray<T>,
        data: &T,
        idx: u64,
    );
}
