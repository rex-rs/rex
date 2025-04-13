use crate::ffi;
use crate::linux::bpf::bpf_map_type;
use crate::linux::errno::EINVAL;
use crate::map::*;
use crate::per_cpu::{cpu_number, this_cpu_read};
use crate::random32::bpf_user_rnd_u32;
use crate::utils::{to_result, NoRef, Result};
use core::mem::MaybeUninit;
// use crate::timekeeping::*;

use core::intrinsics::unlikely;

macro_rules! termination_check {
    ($func:expr) => {{
        // Declare and initialize the termination flag pointer
        let termination_flag: *mut u8;
        unsafe {
            termination_flag = crate::per_cpu::this_cpu_ptr_mut(
                &raw mut crate::ffi::rex_termination_state,
            );

            // Set the termination flag
            *termination_flag = 1;
        }

        // Call the provided function
        let res = $func;

        // Check the termination flag and handle timeout
        unsafe {
            if core::intrinsics::unlikely(*termination_flag == 2) {
                crate::panic::__rex_handle_timeout();
            } else {
                // Reset the termination flag upon exiting
                *termination_flag = 0;
            }
        }

        // Return the result of the function call
        res
    }};
}

pub(crate) fn bpf_get_smp_processor_id() -> i32 {
    unsafe { this_cpu_read(cpu_number()) }
}

pub(crate) fn bpf_map_lookup_elem<'a, const MT: bpf_map_type, K, V>(
    map: &'static RexMapHandle<MT, K, V>,
    key: &'a K,
) -> Option<&'a mut V>
where
    V: Copy + NoRef,
{
    let map_kptr = unsafe { core::ptr::read_volatile(&map.kptr) };
    if unlikely(map_kptr.is_null()) {
        return None;
    }

    let value = termination_check!(unsafe {
        ffi::bpf_map_lookup_elem(map_kptr, key as *const K as *const ())
            as *mut V
    });

    if value.is_null() {
        None
    } else {
        Some(unsafe { &mut *value })
    }
}

pub(crate) fn bpf_map_update_elem<const MT: bpf_map_type, K, V>(
    map: &'static RexMapHandle<MT, K, V>,
    key: &K,
    value: &V,
    flags: u64,
) -> Result
where
    V: Copy + NoRef,
{
    let map_kptr = unsafe { core::ptr::read_volatile(&map.kptr) };
    if unlikely(map_kptr.is_null()) {
        return Err(EINVAL as i32);
    }

    termination_check!(unsafe {
        to_result!(ffi::bpf_map_update_elem(
            map_kptr,
            key as *const K as *const (),
            value as *const V as *const (),
            flags
        ) as i32)
    })
}

pub(crate) fn bpf_map_delete_elem<const MT: bpf_map_type, K, V>(
    map: &'static RexMapHandle<MT, K, V>,
    key: &K,
) -> Result
where
    V: Copy + NoRef,
{
    let map_kptr = unsafe { core::ptr::read_volatile(&map.kptr) };
    if unlikely(map_kptr.is_null()) {
        return Err(EINVAL as i32);
    }

    termination_check!(unsafe {
        to_result!(ffi::bpf_map_delete_elem(
            map_kptr,
            key as *const K as *const ()
        ) as i32)
    })
}

pub(crate) fn bpf_map_push_elem<const MT: bpf_map_type, K, V>(
    map: &'static RexMapHandle<MT, K, V>,
    value: &V,
    flags: u64,
) -> Result
where
    V: Copy + NoRef,
{
    let map_kptr = unsafe { core::ptr::read_volatile(&map.kptr) };
    if unlikely(map_kptr.is_null()) {
        return Err(EINVAL as i32);
    }

    termination_check!(unsafe {
        to_result!(ffi::bpf_map_push_elem(
            map_kptr,
            value as *const V as *const (),
            flags
        ) as i32)
    })
}

pub(crate) fn bpf_map_pop_elem<const MT: bpf_map_type, K, V>(
    map: &'static RexMapHandle<MT, K, V>,
) -> Option<V>
where
    V: Copy + NoRef,
{
    let map_kptr = unsafe { core::ptr::read_volatile(&map.kptr) };
    if unlikely(map_kptr.is_null()) {
        return None;
    }

    let mut value: MaybeUninit<V> = MaybeUninit::uninit();

    let res = termination_check!(unsafe {
        to_result!(ffi::bpf_map_pop_elem(
            map_kptr,
            value.as_mut_ptr() as *mut ()
        ) as i32)
    });
    res.map(|_| unsafe { value.assume_init() }).ok()
}

pub(crate) fn bpf_map_peek_elem<const MT: bpf_map_type, K, V>(
    map: &'static RexMapHandle<MT, K, V>,
) -> Option<V>
where
    V: Copy + NoRef,
{
    let map_kptr = unsafe { core::ptr::read_volatile(&map.kptr) };
    if unlikely(map_kptr.is_null()) {
        return None;
    }

    let mut value: MaybeUninit<V> = MaybeUninit::uninit();

    let res = termination_check!(unsafe {
        to_result!(ffi::bpf_map_peek_elem(
            map_kptr,
            value.as_mut_ptr() as *mut ()
        ) as i32)
    });

    res.map(|_| unsafe { value.assume_init() }).ok()
}

// pub(crate) fn bpf_for_each_map_elem<const MT: bpf_map_type, K, V, C>(
//     map: &'static RexMapHandle<MT, K, V>,
//     callback_fn: extern "C" fn(*const (), *const K, *const V, *const C) ->
// i64,     callback_ctx: &C,
//     flags: u64,
// ) -> Result {
//     let map_kptr = unsafe { core::ptr::read_volatile(&map.kptr) };
//     if unlikely(map_kptr.is_null()) {
//         return Err(EINVAL as i32);
//     }

//     unsafe {
//         to_result!(ffi::bpf_for_each_map_elem(map_kptr, callback_fn as
// *const (), callback_ctx as *const C as *const (), flags) as i32)     }
// }

// Design decision: Make the destination a generic type so that probe read
// kernel can directly fill in variables of certain type. This also achieves
// size checking, since T is known at compile time for monomorphization
pub(crate) fn bpf_probe_read_kernel<T>(
    dst: &mut T,
    unsafe_ptr: *const (),
) -> Result
where
    T: Copy + NoRef,
{
    termination_check!(unsafe {
        to_result!(ffi::bpf_probe_read_kernel(
            dst as *mut T as *mut (),
            core::mem::size_of::<T>() as u32,
            unsafe_ptr,
        ))
    })
}

pub(crate) fn bpf_jiffies64() -> u64 {
    unsafe { core::ptr::read_volatile(&ffi::jiffies) }
}

/// Assumes `CONFIG_USE_PERCPU_NUMA_NODE_ID`
pub(crate) fn bpf_get_numa_node_id() -> i32 {
    unsafe { this_cpu_read(&raw const ffi::numa_node) }
}

// This two functions call the original helper directly, so that confirm the
// return value is correct
/*
pub(crate) fn bpf_ktime_get_ns_origin() -> u64 {
    unsafe { ffi::ktime_get_mono_fast_ns() }
}

pub(crate) fn bpf_ktime_get_boot_ns_origin() -> u64 {
    unsafe { ffi::ktime_get_boot_fast_ns() }
}
*/

pub(crate) fn bpf_ktime_get_ns() -> u64 {
    termination_check!(unsafe { ffi::bpf_ktime_get_ns() })
}

pub(crate) fn bpf_ktime_get_boot_ns() -> u64 {
    termination_check!(unsafe { ffi::bpf_ktime_get_boot_ns() })
}

pub(crate) fn bpf_ktime_get_coarse_ns() -> u64 {
    termination_check!(unsafe { ffi::bpf_ktime_get_coarse_ns() })
}

/*
pub(crate) fn bpf_ktime_get_ns() -> u64 {
    ktime_get_mono_fast_ns()
}

pub(crate) fn bpf_ktime_get_boot_ns() -> u64 {
    ktime_get_boot_fast_ns()
}

pub(crate) fn bpf_ktime_get_coarse_ns() -> u64 {
    ktime_get_coarse() as u64
}
*/

pub(crate) fn bpf_get_prandom_u32() -> u32 {
    termination_check!(bpf_user_rnd_u32())
}

// In document it says that data is a pointer to an array of 64-bit values.
pub(crate) fn bpf_snprintf<const N: usize, const M: usize>(
    str: &mut [u8; N],
    fmt: &str,
    data: &[u64; M],
) -> Result {
    termination_check!(unsafe {
        to_result!(ffi::bpf_snprintf(
            str.as_mut_ptr(),
            N as u32,
            fmt.as_ptr(),
            data.as_ptr(),
            M as u32,
        ) as i32)
    })
}

// TODO: fix ring buf helpers for Electrode, need to limit type with trait NoRef
// pub(crate) fn bpf_ringbuf_reserve<T>(
//     map: &'static RexRingBuf,
//     size: u64,
// ) -> *mut T {
//     let map_kptr = unsafe { core::ptr::read_volatile(&map.kptr) };
//     if unlikely(map_kptr.is_null()) {
//         return core::ptr::null_mut();
//     }
//
//     let data = termination_check!(unsafe {
//         ffi::bpf_ringbuf_reserve(map_kptr, mem::size_of::<T>() as u64, 0)
//     });
//
//     data as *mut T
// }
//
// pub(crate) fn bpf_ringbuf_submit<T>(data: &mut T, flags: u64) {
//     compile_error!("Not finished");
//     termination_check!(unsafe {
//         ffi::bpf_ringbuf_submit(data as *mut T as *mut (), flags)
//     })
// }

// pub(crate) fn bpf_ringbuf_discard<T>(data: &mut T, flags: u64) {
//     compile_error!("Not finished");
//     termination_check!(unsafe {
//         ffi::bpf_ringbuf_discard(data as *mut T as *mut (), flags)
//     })
// }

// pub(crate) fn bpf_ringbuf_query(
//     map: &'static RexRingBuf,
//     flags: u64,
// ) -> Option<u64> {
//     let map_kptr = unsafe { core::ptr::read_volatile(&map.kptr) };
//     if unlikely(map_kptr.is_null()) {
//         return None;
//     }
//     Some(termination_check!(unsafe {
//         ffi::bpf_ringbuf_query(map_kptr, flags)
//     }))
// }

macro_rules! base_helper_defs {
    () => {
        #[inline(always)]
        pub fn bpf_get_smp_processor_id(&self) -> i32 {
            crate::base_helper::bpf_get_smp_processor_id()
        }

        // Self should already have impl<'a>
        #[inline(always)]
        pub fn bpf_map_lookup_elem<'b, const MT: bpf_map_type, K, V>(
            &self,
            map: &'static crate::map::RexMapHandle<MT, K, V>,
            key: &'b K,
        ) -> Option<&'b mut V>
        where
            V: Copy + crate::utils::NoRef,
        {
            crate::base_helper::bpf_map_lookup_elem(map, key)
        }

        #[inline(always)]
        pub fn bpf_map_update_elem<const MT: bpf_map_type, K, V>(
            &self,
            map: &'static crate::map::RexMapHandle<MT, K, V>,
            key: &K,
            value: &V,
            flags: u64,
        ) -> crate::Result
        where
            V: Copy + crate::utils::NoRef,
        {
            crate::base_helper::bpf_map_update_elem(map, key, value, flags)
        }

        #[inline(always)]
        pub fn bpf_map_delete_elem<const MT: bpf_map_type, K, V>(
            &self,
            map: &'static crate::map::RexMapHandle<MT, K, V>,
            key: &K,
        ) -> crate::Result
        where
            V: Copy + crate::utils::NoRef,
        {
            crate::base_helper::bpf_map_delete_elem(map, key)
        }

        #[inline(always)]
        pub fn bpf_map_push_elem<const MT: bpf_map_type, K, V>(
            &self,
            map: &'static crate::map::RexMapHandle<MT, K, V>,
            value: &V,
            flags: u64,
        ) -> crate::Result
        where
            V: Copy + crate::utils::NoRef,
        {
            crate::base_helper::bpf_map_push_elem(map, value, flags)
        }

        #[inline(always)]
        pub fn bpf_map_pop_elem<const MT: bpf_map_type, K, V>(
            &self,
            map: &'static crate::map::RexMapHandle<MT, K, V>,
        ) -> Option<V>
        where
            V: Copy + crate::utils::NoRef,
        {
            crate::base_helper::bpf_map_pop_elem(map)
        }

        #[inline(always)]
        pub fn bpf_map_peek_elem<const MT: bpf_map_type, K, V>(
            &self,
            map: &'static crate::map::RexMapHandle<MT, K, V>,
        ) -> Option<V>
        where
            V: Copy + crate::utils::NoRef,
        {
            crate::base_helper::bpf_map_peek_elem(map)
        }

        #[inline(always)]
        pub fn bpf_probe_read_kernel<T>(
            &self,
            dst: &mut T,
            unsafe_ptr: *const (),
        ) -> crate::Result
        where
            T: Copy + crate::utils::NoRef,
        {
            crate::base_helper::bpf_probe_read_kernel(dst, unsafe_ptr)
        }

        #[inline(always)]
        pub fn bpf_jiffies64(&self) -> u64 {
            crate::base_helper::bpf_jiffies64()
        }

        #[inline(always)]
        pub fn bpf_get_numa_node_id(&self) -> i32 {
            crate::base_helper::bpf_get_numa_node_id()
        }

        /*
        #[inline(always)]
        pub fn bpf_ktime_get_ns_origin(&self) -> u64 {
            crate::base_helper::bpf_ktime_get_ns_origin()
        }

        #[inline(always)]
        pub fn bpf_ktime_get_boot_ns_origin(&self) -> u64 {
            crate::base_helper::bpf_ktime_get_boot_ns_origin()
        }
        */

        #[inline(always)]
        pub fn bpf_ktime_get_ns(&self) -> u64 {
            crate::base_helper::bpf_ktime_get_ns()
        }

        #[inline(always)]
        pub fn bpf_ktime_get_boot_ns(&self) -> u64 {
            crate::base_helper::bpf_ktime_get_boot_ns()
        }

        #[inline(always)]
        pub fn bpf_ktime_get_coarse_ns(&self) -> u64 {
            crate::base_helper::bpf_ktime_get_coarse_ns()
        }

        #[inline(always)]
        pub fn bpf_get_prandom_u32(&self) -> u32 {
            crate::base_helper::bpf_get_prandom_u32()
        }

        #[inline(always)]
        pub fn bpf_snprintf<const N: usize, const M: usize>(
            &self,
            buf: &mut [u8; N],
            fmt: &str,
            data: &[u64; M],
        ) -> crate::Result {
            crate::base_helper::bpf_snprintf(buf, fmt, data)
        }

        // #[inline(always)]
        // pub fn bpf_ringbuf_reserve<T>(
        //     &self,
        //     map: &'static RexRingBuf,
        //     size: u64,
        //     flags: u64,
        // ) -> *mut T {
        //     crate::base_helper::bpf_ringbuf_reserve(map, flags)
        // }
        //
        // #[inline(always)]
        // pub fn bpf_ringbuf_submit<T>(&self, data: &mut T, flags: u64) {
        //     crate::base_helper::bpf_ringbuf_submit(data, flags)
        // }
    };
}

pub(crate) use base_helper_defs;
pub(crate) use termination_check;
