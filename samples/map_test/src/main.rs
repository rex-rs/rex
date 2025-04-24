#![no_std]
#![no_main]

extern crate rex;

use rex::linux::bpf::BPF_ANY;
use rex::map::*;
use rex::tracepoint::*;
use rex::{Result, rex_map, rex_printk, rex_tracepoint};

#[rex_map]
static MAP_HASH: RexHashMap<u32, i64> = RexHashMap::new(1024, 0);

#[rex_map]
static MAP_ARRAY: RexArrayMap<u64> = RexArrayMap::new(256, 0);

fn map_test1(obj: &tracepoint) -> Result {
    let key: u32 = 0;

    rex_printk!("Map Testing 1 Start with key {}\n", key)?;

    match obj.bpf_map_lookup_elem(&MAP_HASH, &key) {
        None => {
            rex_printk!("Not found.\n")?;
        }
        Some(val) => {
            rex_printk!("Found Val={}.\n", *val)?;
        }
    }

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    rex_printk!("Rust program triggered from PID {}\n", pid)?;

    obj.bpf_map_update_elem(&MAP_HASH, &key, &(pid as i64), BPF_ANY as u64)?;
    rex_printk!("Map Updated\n")?;

    match obj.bpf_map_lookup_elem(&MAP_HASH, &key) {
        None => {
            rex_printk!("Not found.\n")?;
        }
        Some(val) => {
            rex_printk!("Found Val={}.\n", *val)?;
        }
    }

    obj.bpf_map_delete_elem(&MAP_HASH, &key)?;
    rex_printk!("Map delete key\n")?;

    match obj.bpf_map_lookup_elem(&MAP_HASH, &key) {
        None => {
            rex_printk!("Not found.\n")?;
        }
        Some(val) => {
            rex_printk!("Found Val={}.\n", *val)?;
        }
    }

    Ok(0)
}

fn map_test2(obj: &tracepoint) -> Result {
    rex_printk!("Array Map Testing Start\n")?;
    let key = 0;

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    rex_printk!("Rust program triggered from PID {}\n", pid)?;

    // Add a new element
    obj.bpf_map_update_elem(&MAP_ARRAY, &key, &(pid as u64), BPF_ANY as u64)?;
    rex_printk!("Map Updated\n")?;

    match obj.bpf_map_lookup_elem(&MAP_ARRAY, &key) {
        None => {
            rex_printk!("Not found.\n")?;
        }
        Some(val) => {
            rex_printk!("Found Val={}.\n", *val)?;
        }
    }
    // let ret = obj.bpf_map_push_elem(MAP_ARRAY, pid as u64, BPF_EXIST.into());
    // rex_printk!(obj, "Map push ret={}\n", ret)?;

    Ok(0)
}

#[rex_tracepoint]
fn rex_prog1(obj: &tracepoint, _: &'static SyscallsEnterDupCtx) -> Result {
    map_test1(obj)
        .or_else(|e| rex_printk!("map_test1 failed with {}.\n", e))?;
    map_test2(obj).or_else(|e| rex_printk!("map_test2 failed with {}.\n", e))
}
