#![no_std]
#![no_main]

extern crate rex;

use rex::map::*;
use rex::rex_tracepoint;
use rex::tracepoint::*;
use rex::{Result, rex_map, rex_printk};

#[rex_map]
static MAP_HASH: RexHashMap<u32, i64> = RexHashMap::new(1024, 0);

#[rex_map]
static ARRAY: RexArrayMap<i64> = RexArrayMap::new(256, 0);

#[rex_map]
static STACK: RexStack<i64> = RexStack::new(256, 0);

#[rex_map]
static QUEUE: RexQueue<i64> = RexQueue::new(256, 0);

// #[rex_map]
// static RINGBUF: IURingBuf = IURingBuf::new(4096, 0);

fn map_test_hash(obj: &tracepoint) -> Result {
    let key: u32 = 0;

    rex_printk!("Map Testing Hash Start with key {}\n", key)?;

    match MAP_HASH.get_mut(&key) {
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

    MAP_HASH.insert(&key, &(pid as i64))?;
    rex_printk!("Map Updated\n")?;

    match MAP_HASH.get_mut(&key) {
        None => {
            rex_printk!("Not found.\n")?;
        }
        Some(val) => {
            rex_printk!("Found Val={}.\n", *val)?;
        }
    }

    MAP_HASH.delete(&key)?;
    rex_printk!("Map delete key\n")?;

    match MAP_HASH.get_mut(&key) {
        None => {
            rex_printk!("Not found.\n")?;
        }
        Some(val) => {
            rex_printk!("Found Val={}.\n", *val)?;
        }
    }

    Ok(0)
}

fn map_test_array(obj: &tracepoint) -> Result {
    let key: u32 = 0;

    rex_printk!("Map Testing Array Start with key {}\n", key)?;

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    rex_printk!("Rust program triggered from PID {}\n", pid)?;

    ARRAY.insert(&key, &(pid as i64))?;
    rex_printk!("Map Updated\n")?;

    match ARRAY.get_mut(&key) {
        None => {
            rex_printk!("Not found.\n")?;
        }
        Some(val) => {
            rex_printk!("Found Val={}.\n", *val)?;
        }
    }

    Ok(0)
}

fn map_test_stack(obj: &tracepoint) -> Result {
    rex_printk!("Map Testing Stack Start\n")?;

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    rex_printk!("Rust program triggered from PID {}\n", pid)?;

    STACK.push(&(pid as i64))?;
    rex_printk!("Pushed {} onto stack\n", pid)?;

    STACK.push(&((pid + 1) as i64))?;
    rex_printk!("Pushed {} onto stack\n", pid + 1)?;

    match STACK.peek() {
        None => rex_printk!("Not found.\n")?,
        Some(top) => rex_printk!("Top of stack: {}.\n", top)?,
    };

    STACK.pop();
    rex_printk!("Popped top of stack\n")?;

    match STACK.peek() {
        None => rex_printk!("Not found.\n")?,
        Some(next_top) => rex_printk!("Next top of stack: {}.\n", next_top)?,
    };

    Ok(0)
}

fn map_test_queue(obj: &tracepoint) -> Result {
    rex_printk!("Map Testing Queue Start\n")?;

    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    rex_printk!("Rust program triggered from PID {}\n", pid)?;

    QUEUE.push(&(pid as i64))?;
    rex_printk!("Pushed {} into queue\n", pid)?;

    QUEUE.push(&((pid + 1) as i64))?;
    rex_printk!("Pushed {} into queue\n", pid + 1)?;

    match QUEUE.peek() {
        None => rex_printk!("Not found.\n")?,
        Some(front) => rex_printk!("Front of queue: {}.\n", front)?,
    };

    QUEUE.pop();
    rex_printk!("Popped front of queue\n")?;

    match QUEUE.peek() {
        None => rex_printk!("Not found.\n")?,
        Some(next_front) => {
            rex_printk!("Next front of queue: {}.\n", next_front)?
        }
    };
    Ok(0)
}

/*
fn map_test_ringbuf(obj: &tracepoint) -> Result {
    rex_printk!("Map Testing Ring Buffer Start\n")?;
    let pid = if let Some(task) = obj.bpf_get_current_task() {
        task.get_pid()
    } else {
        -1
    };
    rex_printk!("Rust program triggered from PID {}\n", pid)?;

    rex_printk!("Available bytes in ringbuf: {}\n", RINGBUF.available_bytes().unwrap())?;

    let entry = match RINGBUF.reserve::<i64>(true, pid as i64) {
        None => {
            rex_printk!("Unable to reserve ringbuf.\n")?;
            return Err(0);
        }
        Some(entry) => entry,
    };

    entry.submit();

    rex_printk!("Available bytes in ringbuf: {}\n", RINGBUF.available_bytes().unwrap())?;

    Ok(0)
}
*/

#[rex_tracepoint]
fn rex_prog1(obj: &tracepoint, _: &'static SyscallsEnterDupCtx) -> Result {
    map_test_hash(obj)
        .or_else(|e| rex_printk!("map_test failed with {}.\n", e))?;
    map_test_array(obj)
        .or_else(|e| rex_printk!("map_test failed with {}.\n", e))?;
    map_test_stack(obj)
        .or_else(|e| rex_printk!("map_test failed with {}.\n", e))?;
    // map_test_ringbuf(obj).or_else(|e| {
    //     rex_printk!("map_test2 failed with {}.\n", e)
    // })?;
    map_test_queue(obj)
        .or_else(|e| rex_printk!("map_test failed with {}.\n", e))
}
