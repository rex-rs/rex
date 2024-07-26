use crate::utils::{to_result, Result};
use crate::{
    base_helper::{
        bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_peek_elem,
        bpf_map_pop_elem, bpf_map_push_elem, bpf_map_update_elem,
        bpf_ringbuf_discard, bpf_ringbuf_reserve, bpf_ringbuf_submit,
        bpf_ringbuf_query
    },
    linux::bpf::{
        bpf_map_type, BPF_ANY, BPF_EXIST, BPF_MAP_TYPE_ARRAY,
        BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_QUEUE, BPF_MAP_TYPE_RINGBUF,
        BPF_MAP_TYPE_STACK, BPF_MAP_TYPE_STACK_TRACE, BPF_NOEXIST,
        BPF_RB_AVAIL_DATA, BPF_RB_CONS_POS, BPF_RB_PROD_POS, BPF_RB_RING_SIZE,
        BPF_MAP_TYPE_PERCPU_ARRAY
    },
};
use core::{marker::PhantomData, mem, ptr};

#[repr(C)]
pub struct RexMapHandle<const MT: bpf_map_type, K, V> {
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

impl<const MT: bpf_map_type, K, V> RexMapHandle<MT, K, V> {
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

unsafe impl<const MT: bpf_map_type, K, V> Sync for RexMapHandle<MT, K, V> {}

//pub type IUArrayMap<V> = IUMap<BPF_MAP_TYPE_ARRAY, u32, V>;
//pub type IUHashMap<K, V> = IUMap<BPF_MAP_TYPE_HASH, K, V>;
//pub type IURingBuf = IUMap<BPF_MAP_TYPE_RINGBUF, (), ()>;
pub type RexStackTrace<K, V> = RexMapHandle<BPF_MAP_TYPE_STACK_TRACE, K, V>;
pub type RexPerCPUArrayMap<V> = RexMapHandle<BPF_MAP_TYPE_PERCPU_ARRAY, u32, V>;

#[repr(C)]
pub struct RexArray<V> {
    map: RexMapHandle<BPF_MAP_TYPE_ARRAY, u32, V>,
}

#[repr(C)]
pub struct RexHashMap<K, V> {
    map: RexMapHandle<BPF_MAP_TYPE_HASH, K, V>,
}

#[repr(C)]
pub struct RexRingBuf {
    map_type: u32,
    max_size: u32,
    map_flag: u32,
    pub(crate) kptr: *mut (),
}

unsafe impl Sync for RexRingBuf {}

#[repr(C)]
pub struct RexStack<V> {
    map: RexMapHandle<BPF_MAP_TYPE_STACK, (), V>,
}

#[repr(C)]
pub struct RexQueue<V> {
    map: RexMapHandle<BPF_MAP_TYPE_QUEUE, (), V>,
}

impl<'a, K, V> RexHashMap<K, V> {
    pub const fn new(ms: u32, mf: u32) -> RexHashMap<K, V> {
        RexHashMap {
            map: RexMapHandle::new(ms, mf),
        }
    }

    pub fn insert(&'static self, key: &K, value: &V) -> Result {
        bpf_map_update_elem(&self.map, key, value, BPF_ANY as u64)
    }

    pub fn insert_new(&'static self, key: &K, value: &V) -> Result {
        bpf_map_update_elem(&self.map, key, value, BPF_NOEXIST as u64)
    }

    pub fn update(&'static self, key: &K, value: &V) -> Result {
        bpf_map_update_elem(&self.map, key, value, BPF_EXIST as u64)
    }

    pub fn get_mut(&'static self, key: &'a K) -> Option<&'a mut V> {
        bpf_map_lookup_elem(&self.map, key)
    }

    pub fn delete(&'static self, key: &K) -> Result {
        bpf_map_delete_elem(&self.map, key)
    }
}

impl<'a, V> RexArray<V> {
    pub const fn new(ms: u32, mf: u32) -> RexArray<V> {
        RexArray {
            map: RexMapHandle::new(ms, mf),
        }
    }

    pub fn insert(&'static self, key: &u32, value: &V) -> Result {
        bpf_map_update_elem(&self.map, key, value, BPF_ANY as u64)
    }

    pub fn get_mut(&'static self, key: &'a u32) -> Option<&'a mut V> {
        bpf_map_lookup_elem(&self.map, key)
    }

    pub fn delete(&'static self, key: &u32) -> Result {
        bpf_map_delete_elem(&self.map, key)
    }
}

impl RexRingBuf {
    pub const fn new(ms: u32, mf: u32) -> RexRingBuf {
        RexRingBuf { map_type: BPF_MAP_TYPE_RINGBUF, max_size: ms, map_flag: mf, kptr: ptr::null_mut() }
    }

    pub fn reserve<T>(
        &'static self,
        submit_by_default: bool,
        value: T
    ) -> Option<RexRingBufEntry<T>> {
        let data: *mut T = bpf_ringbuf_reserve::<T>(&self, 0);
        if data.is_null() {
            None
        } else {
            unsafe { data.write(value); };
            Some(RexRingBufEntry { data: unsafe {
                 { &mut *data }
            }, submit_by_default, has_used: false })
        }
    }

    pub fn available_bytes(&'static self) -> Option<u64> {
        bpf_ringbuf_query(&self, BPF_RB_AVAIL_DATA as u64)
    }

    pub fn size(&'static self) -> Option<u64> {
        bpf_ringbuf_query(&self, BPF_RB_RING_SIZE as u64)
    }

    pub fn consumer_position(&'static self) -> Option<u64> {
        bpf_ringbuf_query(&self, BPF_RB_CONS_POS as u64)
    }

    pub fn producer_position(&'static self) -> Option<u64> {
        bpf_ringbuf_query(&self, BPF_RB_PROD_POS as u64)
    }
}

impl<V> RexStack<V> {
    pub const fn new(ms: u32, mf: u32) -> RexStack<V> {
        RexStack {
            map: RexMapHandle::new(ms, mf),
        }
    }

    pub fn push(&'static self, value: &V) -> Result {
        bpf_map_push_elem(&self.map, value, BPF_ANY as u64)
    }

    pub fn force_push(&'static self, value: &V) -> Result {
        bpf_map_push_elem(&self.map, value, BPF_EXIST as u64)
    }

    pub fn pop(&'static self) -> Option<V> {
        bpf_map_pop_elem(&self.map)
    }

    pub fn peek(&'static self) -> Option<V> {
        bpf_map_peek_elem(&self.map)
    }
}

impl<V> RexQueue<V> {
    pub const fn new(ms: u32, mf: u32) -> RexQueue<V> {
        RexQueue {
            map: RexMapHandle::new(ms, mf),
        }
    }

    pub fn push(&'static self, value: &V) -> Result {
        bpf_map_push_elem(&self.map, value, BPF_ANY as u64)
    }

    pub fn force_push(&'static self, value: &V) -> Result {
        bpf_map_push_elem(&self.map, value, BPF_EXIST as u64)
    }

    pub fn pop(&'static self) -> Option<V> {
        bpf_map_pop_elem(&self.map)
    }

    pub fn peek(&'static self) -> Option<V> {
        bpf_map_peek_elem(&self.map)
    }
}

pub struct RexRingBufEntry<'a, T> {
    data: &'a mut T,
    submit_by_default: bool,
    has_used: bool,
}

impl<'a, T> RexRingBufEntry<'a, T> {
    pub fn submit(mut self) {
        self.has_used = true;
        bpf_ringbuf_submit(self.data, 0)
    }

    pub fn discard(mut self) {
        self.has_used = true;
        bpf_ringbuf_discard(self.data, 0)
    }

    pub fn write(&mut self, value: T) {
        *self.data = value
    }
}

impl<'a, T> core::ops::Drop for RexRingBufEntry<'a, T> {
    fn drop(&mut self) {
        if !self.has_used {
            if self.submit_by_default {
                bpf_ringbuf_submit(self.data, 0);
            } else {
                bpf_ringbuf_discard(self.data, 0);
            }
        }
    }
}
