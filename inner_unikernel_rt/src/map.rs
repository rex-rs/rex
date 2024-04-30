use crate::{base_helper::{bpf_map_delete_elem, bpf_map_lookup_elem, bpf_map_peek_elem, bpf_map_pop_elem, bpf_map_push_elem, bpf_map_update_elem, bpf_ringbuf_discard, bpf_ringbuf_reserve, bpf_ringbuf_submit}, linux::bpf::{
    bpf_map_type, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_RINGBUF,
    BPF_MAP_TYPE_STACK_TRACE,
}};
use crate::utils::{to_result, Result};
use core::{marker::PhantomData, mem, ptr};

#[repr(C)]
pub(crate) struct IUMapHandle<const MT: bpf_map_type, K, V> {
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

impl<const MT: bpf_map_type, K, V> IUMapHandle<MT, K, V> {
    pub const fn new(ms: u32, mf: u32) -> IUMapHandle<MT, K, V> {
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

unsafe impl<const MT: bpf_map_type, K, V> Sync for IUMapHandle<MT, K, V> {}

#[macro_export]
macro_rules! MAP_DEF {
    ($n:ident, $k:ty, $v:ty, $mt:expr, $ms:expr, $mf:expr) => {
        #[no_mangle]
        #[link_section = ".maps"]
        pub(crate) static $n: IUMap<$mt, $k, $v> = IUMap::new($ms, $mf);
    };
}

pub type IUArrayMap<V> = IUMapHandle<BPF_MAP_TYPE_ARRAY, u32, V>;
pub type IUHashMap<K, V> = IUMapHandle<BPF_MAP_TYPE_HASH, K, V>;
pub type IURingBuf = IUMapHandle<BPF_MAP_TYPE_RINGBUF, (), ()>;
pub type IUStackMap<K, V> = IUMapHandle<BPF_MAP_TYPE_STACK_TRACE, K, V>;

impl<K, V> IUHashMap<K, V> {
    pub fn insert(&mut self, key: &K, value: &V) -> Result {
        bpf_map_update_elem(self, key, value, 0)
    }
    pub fn get(&self, key: &K) -> Option<&V> {
        bpf_map_lookup_elem(self, key).map(|&mut v| &v)
    }
    pub fn get_mut(&self, key: &K) -> Option<&mut V> {
        bpf_map_lookup_elem(self, key)
    }
    pub fn delete(&mut self, key: &K) -> Result {
        bpf_map_delete_elem(self, key)
    }
}

impl<V> core::ops::Index<u32> for IUArrayMap<V> {
    type Output = V;
    fn index(&self, index: u32) -> &Self::Output {
        bpf_map_lookup_elem(self, &index).unwrap()
    }
}

impl<V> core::ops::IndexMut<u32> for IUArrayMap<V> {
    fn index_mut(&mut self, index: u32) -> &mut Self::Output {
        bpf_map_lookup_elem(self, &index).unwrap()
    }
}

impl IURingBuf {
    pub fn reserve(&mut self, size: u64) -> Option<IURingBufEntry> {
        bpf_ringbuf_reserve(self, size, 0).map(|data| IURingBufEntry { data, has_used: false })
    }
}

impl<K, V> IUStackMap<K, V> {
    pub fn push(&mut self, value: &V) -> Result {
        bpf_map_push_elem(self, value, 0)
    }
    pub fn pop(&mut self, value: &V) -> Result {
        bpf_map_pop_elem(self, value)
    }
    pub fn peek(&self, value: &V) -> Result {
        bpf_map_peek_elem(self, value)
    }
}

pub struct IURingBufEntry<'a> {
    data: &'a mut [u8],
    has_used: bool
}

impl<'a> IURingBufEntry<'a> {
    pub fn submit(mut self) {
        self.has_used = true;
        bpf_ringbuf_submit(self.data, 0)
    }
    pub fn discard(mut self) {
        self.has_used = true;
        bpf_ringbuf_discard(self.data, 0)
    }
}

impl<'a> core::ops::Drop for IURingBufEntry<'a> {
    fn drop(&mut self) {
        if !self.has_used {
            bpf_ringbuf_discard(self.data, 0);
        }
    }
}