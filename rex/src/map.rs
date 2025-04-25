use core::intrinsics::unlikely;
use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
use core::{mem, ptr, slice};

use crate::base_helper::{
    bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_peek_elem,
    bpf_map_pop_elem, bpf_map_push_elem, bpf_map_update_elem,
    termination_check,
};
use crate::ffi;
use crate::linux::bpf::{
    bpf_map_type, BPF_ANY, BPF_EXIST, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH,
    BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    BPF_MAP_TYPE_QUEUE, BPF_MAP_TYPE_RINGBUF, BPF_MAP_TYPE_STACK,
    BPF_MAP_TYPE_STACK_TRACE, BPF_NOEXIST, BPF_RB_AVAIL_DATA, BPF_RB_CONS_POS,
    BPF_RB_PROD_POS, BPF_RB_RING_SIZE,
};
use crate::linux::errno::EINVAL;
use crate::utils::{
    to_result, NoRef, PerfEventMaskedCPU, Result, StreamableProgram,
};

/// Rex equivalent to be used for map APIs in place of the `struct bpf_map`.
/// The key and the value type are encoded as generics types `K` and `V`.
/// The map type is encoded as a const-generic using the `bpf_map_type` enum.
#[repr(C)]
pub struct RexMapHandle<const MT: bpf_map_type, K, V>
where
    V: Copy + NoRef,
{
    // Map metadata
    map_type: u32,
    key_size: u32,
    val_size: u32,
    max_size: u32,
    map_flag: u32,

    // Actual kernel side map pointer
    pub(crate) kptr: *mut (),

    // Zero-sized marker
    key_type: PhantomData<K>,
    val_type: PhantomData<V>,
}

impl<const MT: bpf_map_type, K, V> RexMapHandle<MT, K, V>
where
    V: Copy + NoRef,
{
    pub const fn new(ms: u32, mf: u32) -> RexMapHandle<MT, K, V> {
        Self {
            map_type: MT,
            key_size: mem::size_of::<K>() as u32,
            val_size: mem::size_of::<V>() as u32,
            max_size: ms,
            map_flag: mf,
            kptr: ptr::null_mut(),
            key_type: PhantomData,
            val_type: PhantomData,
        }
    }
}

unsafe impl<const MT: bpf_map_type, K, V> Sync for RexMapHandle<MT, K, V> where
    V: Copy + NoRef
{
}

pub type RexStackTrace<K, V> = RexMapHandle<BPF_MAP_TYPE_STACK_TRACE, K, V>;
pub type RexPerCPUArrayMap<V> = RexMapHandle<BPF_MAP_TYPE_PERCPU_ARRAY, u32, V>;
pub type RexPerfEventArray<V> =
    RexMapHandle<BPF_MAP_TYPE_PERF_EVENT_ARRAY, u32, V>;
pub type RexArrayMap<V> = RexMapHandle<BPF_MAP_TYPE_ARRAY, u32, V>;
pub type RexHashMap<K, V> = RexMapHandle<BPF_MAP_TYPE_HASH, K, V>;
pub type RexStack<V> = RexMapHandle<BPF_MAP_TYPE_STACK, (), V>;
pub type RexQueue<V> = RexMapHandle<BPF_MAP_TYPE_QUEUE, (), V>;
pub type RexRingBuf = RexMapHandle<BPF_MAP_TYPE_RINGBUF, (), ()>;

impl<'a, K, V> RexHashMap<K, V>
where
    V: Copy + NoRef,
{
    pub fn insert(&'static self, key: &K, value: &V) -> Result {
        bpf_map_update_elem(self, key, value, BPF_ANY as u64)
    }

    pub fn insert_new(&'static self, key: &K, value: &V) -> Result {
        bpf_map_update_elem(self, key, value, BPF_NOEXIST as u64)
    }

    pub fn update(&'static self, key: &K, value: &V) -> Result {
        bpf_map_update_elem(self, key, value, BPF_EXIST as u64)
    }

    pub fn get_mut(&'static self, key: &'a K) -> Option<&'a mut V> {
        bpf_map_lookup_elem(self, key)
    }

    pub fn delete(&'static self, key: &K) -> Result {
        bpf_map_delete_elem(self, key)
    }
}

impl<'a, V> RexArrayMap<V>
where
    V: Copy + NoRef,
{
    pub fn insert(&'static self, key: &u32, value: &V) -> Result {
        bpf_map_update_elem(self, key, value, BPF_ANY as u64)
    }

    pub fn get_mut(&'static self, key: &'a u32) -> Option<&'a mut V> {
        bpf_map_lookup_elem(self, key)
    }

    pub fn delete(&'static self, key: &u32) -> Result {
        bpf_map_delete_elem(self, key)
    }
}

impl<'a, V> RexPerfEventArray<V>
where
    V: Copy + NoRef,
{
    pub fn output<P: StreamableProgram>(
        &'static self,
        program: &P,
        ctx: &P::Context,
        data: &V,
        cpu: PerfEventMaskedCPU,
    ) -> Result {
        program.output_event(ctx, self, data, cpu)
    }
}

impl<V> RexStack<V>
where
    V: Copy + NoRef,
{
    pub fn push(&'static self, value: &V) -> Result {
        bpf_map_push_elem(self, value, BPF_ANY as u64)
    }

    pub fn force_push(&'static self, value: &V) -> Result {
        bpf_map_push_elem(self, value, BPF_EXIST as u64)
    }

    pub fn pop(&'static self) -> Option<V> {
        bpf_map_pop_elem(self)
    }

    pub fn peek(&'static self) -> Option<V> {
        bpf_map_peek_elem(self)
    }
}

impl<V> RexQueue<V>
where
    V: Copy + NoRef,
{
    pub fn push(&'static self, value: &V) -> Result {
        bpf_map_push_elem(self, value, BPF_ANY as u64)
    }

    pub fn force_push(&'static self, value: &V) -> Result {
        bpf_map_push_elem(self, value, BPF_EXIST as u64)
    }

    pub fn pop(&'static self) -> Option<V> {
        bpf_map_pop_elem(self)
    }

    pub fn peek(&'static self) -> Option<V> {
        bpf_map_peek_elem(self)
    }
}

impl RexRingBuf {
    /// Reserves `size` bytes of payload in the ring buffer.
    ///
    /// If the operation succeeds, A [`RexRingBufEntry`] representing the
    /// payload is returned, otherwise (e.g., there is not enough memory
    /// available), `None` is returned.
    pub fn reserve<'a>(
        &'static self,
        size: usize,
    ) -> Option<RexRingBufEntry<'a>> {
        let map_kptr = unsafe { core::ptr::read_volatile(&self.kptr) };
        if unlikely(map_kptr.is_null()) {
            return None;
        }

        let data = termination_check!(unsafe {
            ffi::bpf_ringbuf_reserve(map_kptr, size as u64, 0)
        });

        if data.is_null() {
            None
        } else {
            let data =
                unsafe { slice::from_raw_parts_mut(data as *mut u8, size) };
            Some(RexRingBufEntry { data })
        }
    }

    /// Copies bytes from the `data` slice into the ring buffer.
    ///
    /// If [`crate::linux::bpf::BPF_RB_NO_WAKEUP`] is specified in `flags`,
    /// no notification of new data availability is sent.
    /// If [`crate::linux::bpf::BPF_RB_FORCE_WAKEUP`] is specified in `flags`,
    /// notification of new data availability is sent unconditionally.
    /// If `0` is specified in `flags`, an adaptive notification of new data
    /// availability is sent.
    ///
    /// Returns a [`crate::Result`] on whether the operation is successful
    pub fn output(&'static self, data: &[u8], flags: u64) -> crate::Result {
        let map_kptr = unsafe { core::ptr::read_volatile(&self.kptr) };
        if unlikely(map_kptr.is_null()) {
            return Err(EINVAL as i32);
        }

        termination_check!(unsafe {
            to_result!(ffi::bpf_ringbuf_output(
                map_kptr,
                data.as_ptr() as *const (),
                data.len() as u64,
                flags
            ))
        })
    }

    /// Queries the amount of data not yet consumed.
    ///
    /// Returns `None` is `self` is not a valid ring buffer.
    pub fn available_bytes(&'static self) -> Option<u64> {
        let map_kptr = unsafe { core::ptr::read_volatile(&self.kptr) };
        if unlikely(map_kptr.is_null()) {
            return None;
        }

        termination_check!(unsafe {
            Some(ffi::bpf_ringbuf_query(map_kptr, BPF_RB_AVAIL_DATA as u64))
        })
    }

    /// Queries the size of ring buffer.
    ///
    /// Returns `None` is `self` is not a valid ring buffer.
    pub fn size(&'static self) -> Option<u64> {
        let map_kptr = unsafe { core::ptr::read_volatile(&self.kptr) };
        if unlikely(map_kptr.is_null()) {
            return None;
        }

        termination_check!(unsafe {
            Some(ffi::bpf_ringbuf_query(map_kptr, BPF_RB_RING_SIZE as u64))
        })
    }

    /// Queries the consumer position, which may wrap around.
    ///
    /// Returns `None` is `self` is not a valid ring buffer.
    pub fn consumer_position(&'static self) -> Option<u64> {
        let map_kptr = unsafe { core::ptr::read_volatile(&self.kptr) };
        if unlikely(map_kptr.is_null()) {
            return None;
        }

        termination_check!(unsafe {
            Some(ffi::bpf_ringbuf_query(map_kptr, BPF_RB_CONS_POS as u64))
        })
    }

    /// Queries the Producer(s) position which may wrap around.
    ///
    /// Returns `None` is `self` is not a valid ring buffer.
    pub fn producer_position(&'static self) -> Option<u64> {
        let map_kptr = unsafe { core::ptr::read_volatile(&self.kptr) };
        if unlikely(map_kptr.is_null()) {
            return None;
        }

        termination_check!(unsafe {
            Some(ffi::bpf_ringbuf_query(map_kptr, BPF_RB_PROD_POS as u64))
        })
    }
}

pub struct RexRingBufEntry<'a> {
    data: &'a mut [u8],
}

impl RexRingBufEntry<'_> {
    /// Consumes the reserved payload and submits it to the ring buffer.
    ///
    /// If [`crate::linux::bpf::BPF_RB_NO_WAKEUP`] is specified in `flags`,
    /// no notification of new data availability is sent.
    /// If [`crate::linux::bpf::BPF_RB_FORCE_WAKEUP`] is specified in `flags`,
    /// notification of new data availability is sent unconditionally.
    /// If `0` is specified in `flags`, an adaptive notification of new data
    /// availability is sent.
    ///
    /// This method always succeeds.
    pub fn submit(self, flags: u64) {
        termination_check!(unsafe {
            ffi::bpf_ringbuf_submit(self.data.as_mut_ptr() as *mut (), flags)
        });
        // Avoid calling ringbuf_discard twice
        mem::forget(self);
    }

    /// Consumes the reserved payload and discards it.
    ///
    /// If [`crate::linux::bpf::BPF_RB_NO_WAKEUP`] is specified in `flags`,
    /// no notification of new data availability is sent.
    /// If [`crate::linux::bpf::BPF_RB_FORCE_WAKEUP`] is specified in `flags`,
    /// notification of new data availability is sent unconditionally.
    /// If `0` is specified in `flags`, an adaptive notification of new data
    /// availability is sent.
    ///
    /// This method always succeeds.
    pub fn discard(self, flags: u64) {
        termination_check!(unsafe {
            ffi::bpf_ringbuf_discard(self.data.as_mut_ptr() as *mut (), flags)
        });
        // Avoid calling ringbuf_discard twice
        mem::forget(self);
    }
}

impl Deref for RexRingBufEntry<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl DerefMut for RexRingBufEntry<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

impl core::ops::Drop for RexRingBufEntry<'_> {
    /// Discard reserved payload when dropped
    fn drop(&mut self) {
        termination_check!(unsafe {
            ffi::bpf_ringbuf_discard(self.data.as_mut_ptr() as *mut (), 0)
        });
    }
}
