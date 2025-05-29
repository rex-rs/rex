use core::ffi::{c_int, c_uchar};
use core::mem;
use core::ops::{Deref, DerefMut, Drop};

use crate::bindings::uapi::linux::bpf::{BPF_F_CURRENT_CPU, BPF_F_INDEX_MASK};
use crate::map::RexPerfEventArray;
use crate::prog_type::rex_prog;

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

/// An enum used internally by `Aligned` and `AlignedMut`, the encapsulated
/// value is either a reference to the data if the aligned requirement is
/// satisfied, or a copied value of the data if it is not aligned and a
/// reference cannot be taken directly.
enum AlignedInner<RefT, ValT> {
    Ref(RefT),
    Val(ValT),
}

/// An abstraction over a `&T` for both aligned and unaligned accesses. This
/// struct can be constructed with [`convert_slice_to_struct`] from an
/// underlying data slice. The underlying data is either a direct `&'a T` by
/// reborrowing the slice or a copied value of `T` from the slice, depending on
/// whether the slice pointer is properly aligned for `T`.
///
/// The abstraction provided by this struct is a shared reference, for an
/// abstraction over mutable references, use [`AlignedMut`].
pub struct Aligned<'a, T> {
    inner: AlignedInner<&'a T, T>,
}

impl<'a, T> Aligned<'a, T> {
    /// Constructs an `Aligned<'a, T>` from an aligned reference.
    #[inline(always)]
    pub(crate) const fn from_ref(aligned_ref: &'a T) -> Self {
        Self {
            inner: AlignedInner::Ref(aligned_ref),
        }
    }

    /// Constructs an `Aligned<'a, T>` from a copied value of `T` to handle
    /// unaligned cases.
    #[inline(always)]
    pub(crate) const fn from_val(copied_val: T) -> Self {
        Self {
            inner: AlignedInner::Val(copied_val),
        }
    }
}

/// Allows users of `Aligned<'_, T>` to transparently access the value behind
/// the reference abstraction.
impl<T> Deref for Aligned<'_, T> {
    type Target = T;

    /// If the underlying data is a `&T`, it is directly returned;
    /// otherwise a shared reference to the copied value of `T` is taken and
    /// returned.
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        match &self.inner {
            AlignedInner::Ref(aligned_ref) => aligned_ref,
            AlignedInner::Val(ref unaligned_val) => unaligned_val,
        }
    }
}

/// An abstraction over a `&mut T` for both aligned and unaligned accesses. This
/// struct can be constructed with [`convert_slice_to_struct_mut`] from an
/// underlying data slice. The underlying data is either a direct `&'a mut T` by
/// reborrowing the slice or a copied value of `T` from the slice, depending on
/// whether the slice pointer is properly aligned for `T`. In the unaligned
/// case, the mutable reference to slice is also stored in this struct.
///
/// The abstraction provided by this struct is a mutable reference, for an
/// abstraction over shared references, use [`Aligned`].
pub struct AlignedMut<'a, T: Copy> {
    inner: AlignedInner<&'a mut T, (T, &'a mut [c_uchar])>,
}

impl<'a, T: Copy> AlignedMut<'a, T> {
    /// Constructs an `AlignedMut<'a, T>` from an aligned reference.
    #[inline(always)]
    pub(crate) const fn from_ref(aligned_ref: &'a mut T) -> Self {
        Self {
            inner: AlignedInner::Ref(aligned_ref),
        }
    }

    /// Constructs an `AlignedMut<'a, T>` from a copied value of `T` and the
    /// original mutable reference to slice to handle unaligned cases.
    #[inline(always)]
    pub(crate) const fn from_val(
        copied_val: T,
        slice: &'a mut [c_uchar],
    ) -> Self {
        Self {
            inner: AlignedInner::Val((copied_val, slice)),
        }
    }
}

/// Allows users of `AlignedMut<'_, T>` to transparently access the value behind
/// the reference abstraction.
impl<T: Copy> Deref for AlignedMut<'_, T> {
    type Target = T;

    /// If the underlying data is a `&mut T`, the coerced `&T` is returned;
    /// otherwise a shared reference to the copied value of `T` is taken and
    /// returned.
    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        match &self.inner {
            AlignedInner::Ref(aligned_ref) => aligned_ref,
            AlignedInner::Val(ref unaligned_val) => &unaligned_val.0,
        }
    }
}

/// Allows users of `AlignedMut<'_, T>` to transparently access and mutate the
/// value behind the reference abstraction.
impl<T: Copy> DerefMut for AlignedMut<'_, T> {
    /// If the underlying data is a `&mut T`, it is directly returned;
    /// otherwise a mutable reference to the copied value of `T` is taken and
    /// returned.
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        match &mut self.inner {
            AlignedInner::Ref(aligned_ref) => aligned_ref,
            AlignedInner::Val(ref mut unaligned_val) => &mut unaligned_val.0,
        }
    }
}

/// Drop handler to support automatic writeback to the original data slice
impl<T: Copy> Drop for AlignedMut<'_, T> {
    #[inline(always)]
    fn drop(&mut self) {
        if let AlignedInner::Val(ref mut unaligned_val) = self.inner {
            unsafe {
                (unaligned_val.1.as_mut_ptr() as *mut T)
                    .write_unaligned(unaligned_val.0);
            }
        }
    }
}

/// Converts the bytes in `slice` into a `&T` abstracted by [`Aligned<'_, T>`].
/// This is only performed on the first `core::mem::size_of::<T>()` bytes.
/// If the slice is not long enough, this function panics.
///
/// If `slice.as_ptr()` is properly aligned for `T`, the pointer is reborrowed
/// into a `&T` and stored in the returned `Aligned<'_, T>`.
/// If the pointer does not satisfy the alignment requirement of `T`, this
/// function copies the value via `core::ptr::read_unaligned` and stores it in
/// the returned `Aligned<'_, T>`.
///
/// The [operation][read_unaligned_doc] performed in the unaligned case implies
/// that `T` has to be [`Copy`].
///
/// [read_unaligned_doc]: https://doc.rust-lang.org/core/ptr/fn.read_unaligned.html
#[inline]
pub fn convert_slice_to_struct<T>(slice: &[c_uchar]) -> Aligned<'_, T>
where
    T: Copy + NoRef,
{
    assert!(
        slice.len() >= mem::size_of::<T>(),
        "size mismatch in convert_slice_to_struct"
    );

    let ptr = slice.as_ptr() as *const T;

    if ptr.is_aligned() {
        unsafe { Aligned::from_ref(&*ptr) }
    } else {
        unsafe { Aligned::from_val(ptr.read_unaligned()) }
    }
}

/// Converts the bytes in `slice` into a `&mut T` abstracted by
/// [`AlignedMut<'_, T>`].
/// This is only performed on the first `core::mem::size_of::<T>()` bytes.
/// If the slice is not long enough, this function panics.
///
/// If `slice.as_mut_ptr()` is properly aligned for `T`, the pointer is
/// reborrowed into a `&mut T` and stored in the returned `AlignedMut<'_, T>`.
/// If the pointer does not satisfy the alignment requirement of `T`, this
/// function copies the value via `core::ptr::read_unaligned` and stores it in
/// the returned `AlignedMut<'_, T>`.
///
/// The [operation][read_unaligned_doc] performed in the unaligned case implies
/// that `T` has to be [`Copy`].
///
/// [read_unaligned_doc]: https://doc.rust-lang.org/core/ptr/fn.read_unaligned.html
#[inline]
pub fn convert_slice_to_struct_mut<T>(
    slice: &mut [c_uchar],
) -> AlignedMut<'_, T>
where
    T: Copy + NoRef,
{
    assert!(
        slice.len() >= mem::size_of::<T>(),
        "size mismatch in convert_slice_to_struct_mut"
    );

    let ptr = slice.as_mut_ptr() as *mut T;

    if ptr.is_aligned() {
        unsafe { AlignedMut::from_ref(&mut *ptr) }
    } else {
        unsafe { AlignedMut::from_val(ptr.read_unaligned(), slice) }
    }
}

/// Read a numeric field that is stored **big-endian** inside a header already
/// sitting in `payload_slice` at offset `hdr_base`.
///
/// Example:
/// ```
/// let iphdr_base = size_of::<ethhdr>();
/// let proto_be = read_field!(skb.data_slice, iphdr_base, iphdr, protocol, u8);
/// match u8::from_be(proto_be) as u32 {
///     IPPROTO_TCP => handle_tcp(),
///     IPPROTO_UDP => handle_udp(),
///     _  => {}
/// }
/// ```
#[macro_export]
macro_rules! read_field {
    ($slice:expr,     // payload slice
     $hdr_base:expr,  // where this header starts inside the buffer
     $hdr:path,       // concrete header type, for `offset_of!`
     $field:ident,    // field we want
     $ty:ty           // Rust type of that field (u8, u16, …)
    ) => {{
        let start = $hdr_base + core::mem::offset_of!($hdr, $field);
        *$crate::utils::convert_slice_to_struct::<$ty>(
            &$slice[start..start + size_of::<$ty>()],
        )
    }};
}

// For implementers, see tp_impl.rs for how to implement
// this trait
/// Programs that can stream data through a
/// RexPerfEventArray will implement this trait
pub trait PerfEventStreamer: rex_prog {
    type Context;
    fn output_event<T: Copy + NoRef>(
        &self,
        ctx: &Self::Context,
        map: &'static RexPerfEventArray<T>,
        data: &T,
        cpu: PerfEventMaskedCPU,
    ) -> Result;
}

/// Newtype for a cpu for perf event output to ensure
/// type safety since the cpu must be masked with
/// BPF_F_INDEX_MASK
#[derive(Debug, Copy, Clone)]
pub struct PerfEventMaskedCPU {
    pub(crate) masked_cpu: u64,
}

impl PerfEventMaskedCPU {
    pub fn current_cpu() -> Self {
        PerfEventMaskedCPU {
            masked_cpu: BPF_F_CURRENT_CPU,
        }
    }

    pub fn any_cpu(cpu: u64) -> Self {
        PerfEventMaskedCPU {
            masked_cpu: cpu & BPF_F_INDEX_MASK,
        }
    }
}
