use crate::linux::bpf::bpf_perf_event_value;
use crate::map::IUMap;
use crate::perf_event_kern::bpf_perf_event_data_kern;
use crate::rt::{__bpf_get_stackid_pe, __bpf_perf_prog_read_value, bpf_perf_event_data};
use crate::stub;

pub fn bpf_get_current_pid_tgid() -> u64 {
    let ptr = stub::STUB_BPF_GET_CURRENT_PID_TGID as *const ();
    let code: extern "C" fn() -> u64 = unsafe { core::mem::transmute(ptr) };
    code()
}

pub fn bpf_get_current_comm<T>(buf: &T, size_of_buf: usize) -> i64 {
    let ptr = stub::STUB_BPF_GET_CURRENT_COMM as *const ();
    let code: extern "C" fn(&T, u32) -> i64 = unsafe { core::mem::transmute(ptr) };
    code(buf, size_of_buf as u32)
}

// TODO hard to generalize
//pub fn bpf_get_stackid_pe<T>(ctx: &bpf_perf_event_data, map: &T, flags: u64) -> i64 {
//    __bpf_get_stackid_pe(ctx, map, flags)
//}
pub use crate::rt::__bpf_get_stackid_pe as bpf_get_stackid_pe;

pub fn bpf_get_smp_processor_id() -> u32 {
    let ptr = stub::STUB_BPF_GET_SMP_PROCESSOR_ID as *const ();
    let code: extern "C" fn() -> u32 = unsafe { core::mem::transmute(ptr) };
    code()
}

//pub fn bpf_perf_prog_read_value(
//    ctx: &bpf_perf_event_data,
//    buf: &bpf_perf_event_value,
//    buf_size: usize,
//) -> i64 {
//    __bpf_perf_prog_read_value(ctx, buf, buf_size)
//}
pub use crate::rt::__bpf_perf_prog_read_value as bpf_perf_prog_read_value;

#[macro_export]
macro_rules! bpf_trace_printk {
    ($s:expr) => {
        {
            // Add the missing null terminator
            let mut fmt_arr: [u8; $s.len() + 1] = [0; $s.len() + 1];
            for (i, c) in $s.chars().enumerate() {
                fmt_arr[i] = c as u8
            }
            fmt_arr[$s.len()] = 0;
            let fmt_str = fmt_arr.as_ptr();

            let ptr = stub::STUB_BPF_TRACE_PRINTK as *const ();
            let code: extern "C" fn(*const u8, u32) -> i64 =
                unsafe { core::mem::transmute(ptr) };

            code(fmt_str, ($s.len() + 1) as u32)
        }
    };

    ($s:expr,$($t:ty : $a:expr),*) => {
        {
            // Add the missing null terminator
            let mut fmt_arr: [u8; $s.len() + 1] = [0; $s.len() + 1];
            for (i, c) in $s.chars().enumerate() {
                fmt_arr[i] = c as u8
            }
            fmt_arr[$s.len()] = 0;
            let fmt_str = fmt_arr.as_ptr();

            let ptr = stub::STUB_BPF_TRACE_PRINTK as *const ();
            let code: extern "C" fn(*const u8, u32, $($t),*) -> i64 =
                unsafe { core::mem::transmute(ptr) };

            code(fmt_str, ($s.len() + 1) as u32, $($a),*)
        }
    };
}

pub fn bpf_map_lookup_elem<K, V>(map: &IUMap<K, V>, key: K) -> Option<V>
where
    V: Copy,
{
    let f_ptr = stub::STUB_BPF_MAP_LOOKUP_ELEM as *const ();
    let helper: extern "C" fn(&IUMap<K, V>, *const K) -> *mut V =
        unsafe { core::mem::transmute(f_ptr) };

    let value = helper(map, &key) as *mut V;

    if value.is_null() {
        None
    } else {
        Some(unsafe { *value })
    }
}

pub fn bpf_map_update_elem<K, V>(map: &IUMap<K, V>, key: K, value: V, flags: u64) -> i64 {
    let f_ptr = stub::STUB_BPF_MAP_UPDATE_ELEM as *const ();
    let helper: extern "C" fn(&IUMap<K, V>, *const K, *const V, u64) -> i64 =
        unsafe { core::mem::transmute(f_ptr) };

    helper(map, &key, &value, flags)
}
