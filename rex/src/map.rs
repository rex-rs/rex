use crate::utils::{NoRef, Result};
use crate::{
    base_helper::{
        bpf_map_delete_elem,
        bpf_map_lookup_elem,
        bpf_map_peek_elem,
        bpf_map_pop_elem,
        bpf_map_push_elem,
        bpf_map_update_elem,
        // bpf_ringbuf_discard, bpf_ringbuf_query, bpf_ringbuf_reserve,
        // bpf_ringbuf_submit,
    },
    linux::bpf::{
        bpf_map_type, BPF_ANY, BPF_EXIST, BPF_MAP_TYPE_ARRAY,
        BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_QUEUE,
        BPF_MAP_TYPE_STACK, BPF_MAP_TYPE_STACK_TRACE, BPF_NOEXIST,
    },
};
use core::{marker::PhantomData, mem, ptr};

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
pub type RexArrayMap<V> = RexMapHandle<BPF_MAP_TYPE_ARRAY, u32, V>;
pub type RexHashMap<K, V> = RexMapHandle<BPF_MAP_TYPE_HASH, K, V>;
pub type RexStack<V> = RexMapHandle<BPF_MAP_TYPE_STACK, (), V>;
pub type RexQueue<V> = RexMapHandle<BPF_MAP_TYPE_QUEUE, (), V>;

#[repr(C)]
pub struct RexRingBuf {
    map_type: u32,
    key_size: u32,
    val_size: u32,
    max_size: u32,
    map_flag: u32,
    pub(crate) kptr: *mut (),
}

unsafe impl Sync for RexRingBuf {}

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

// impl RexRingBuf {
//     pub const fn new(ms: u32, mf: u32) -> RexRingBuf {
//         RexRingBuf {
//             map_type: BPF_MAP_TYPE_RINGBUF,
//             key_size: 0,
//             val_size: 0,
//             max_size: ms,
//             map_flag: mf,
//             kptr: ptr::null_mut(),
//         }
//     }
//
//     pub fn reserve<'a, T>(
//         &'static self,
//         submit_by_default: bool,
//         value: T,
//     ) -> Option<RexRingBufEntry<'a, T>> {
//         let data: *mut T = bpf_ringbuf_reserve::<T>(self, 0);
//         if data.is_null() {
//             None
//         } else {
//             unsafe { data.write(value) };
//             Some(RexRingBufEntry {
//                 data: unsafe { &mut *data },
//                 submit_by_default,
//                 has_used: false,
//             })
//         }
//     }
//
//     pub fn available_bytes(&'static self) -> Option<u64> {
//         bpf_ringbuf_query(self, BPF_RB_AVAIL_DATA as u64)
//     }
//
//     pub fn size(&'static self) -> Option<u64> {
//         bpf_ringbuf_query(self, BPF_RB_RING_SIZE as u64)
//     }
//
//     pub fn consumer_position(&'static self) -> Option<u64> {
//         bpf_ringbuf_query(self, BPF_RB_CONS_POS as u64)
//     }
//
//     pub fn producer_position(&'static self) -> Option<u64> {
//         bpf_ringbuf_query(self, BPF_RB_PROD_POS as u64)
//     }
// }

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

// pub struct RexRingBufEntry<'a, T> {
//     data: &'a mut T,
//     submit_by_default: bool,
//     has_used: bool,
// }
//
// impl<T> RexRingBufEntry<'_, T> {
//     pub fn submit(mut self) {
//         self.has_used = true;
//         bpf_ringbuf_submit(self.data, 0)
//     }
//
//     pub fn discard(mut self) {
//         self.has_used = true;
//         bpf_ringbuf_discard(self.data, 0)
//     }
//
//     pub fn write(&mut self, value: T) {
//         *self.data = value
//     }
// }
//
// impl<T> core::ops::Drop for RexRingBufEntry<'_, T> {
//     fn drop(&mut self) {
//         if !self.has_used {
//             if self.submit_by_default {
//                 bpf_ringbuf_submit(self.data, 0);
//             } else {
//                 bpf_ringbuf_discard(self.data, 0);
//             }
//         }
//     }
// }
