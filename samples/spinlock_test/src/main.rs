#![no_std]
#![no_main]

extern crate rex;

use rex::linux::bpf::bpf_spin_lock;
use rex::map::RexArrayMap;
use rex::spinlock::rex_spinlock_guard;
use rex::tracepoint::*;
use rex::{Result, rex_map, rex_tracepoint};

#[repr(C)]
#[derive(Clone, Copy)]
struct MapEntry {
    data: u64,
    lock: bpf_spin_lock,
}

#[rex_map]
static MAP_ARRAY: RexArrayMap<MapEntry> = RexArrayMap::new(256, 0);

fn test1(obj: &tracepoint) {
    if let Some(entry) = obj.bpf_map_lookup_elem(&MAP_ARRAY, &0) {
        // entry.lock locked in rex_spinlock_guard::new
        let _guard = rex_spinlock_guard::new(&mut entry.lock);
        entry.data = 1;
        // entry.lock is automatically released when _guard goes out of scope
    }
}

fn test2(obj: &tracepoint) {
    if let Some(entry) = obj.bpf_map_lookup_elem(&MAP_ARRAY, &0) {
        // entry.lock locked in rex_spinlock_guard::new
        let _guard = rex_spinlock_guard::new(&mut entry.lock);
        entry.data = 1;
        panic!("test\n");
        // entry.lock is automatically released by cleanup mechanism
    }
}

#[rex_tracepoint]
fn rex_prog1(obj: &tracepoint, _: &'static SyscallsEnterDupCtx) -> Result {
    test1(obj);
    test2(obj);
    Ok(0)
}
