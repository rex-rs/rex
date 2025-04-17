#![no_std]
#![no_main]

extern crate rex;

use rex::linux::bpf::BPF_ANY;
use rex::map::RexHashMap;
use rex::tracepoint::{tp_ctx, tp_type, tracepoint};
use rex::{Result, rex_map, rex_printk, rex_tracepoint};

#[rex_map]
static SYSCALL_COUNTS: RexHashMap<u32, u64> = RexHashMap::new(512, 0);

#[rex_map]
static SYSCALL_ERRORS: RexHashMap<u32, u64> = RexHashMap::new(512, 0);

#[rex_map]
static SYSCALL_START: RexHashMap<u64, u64> = RexHashMap::new(1024, 0);

#[rex_map]
static SYSCALL_LATENCY: RexHashMap<u32, u64> = RexHashMap::new(512, 0);

#[rex_tracepoint(name = "raw_syscalls/sys_enter", tp_type = "RawSyscallsEnter")]
fn trace_syscall_enter(obj: &tracepoint, ctx: tp_ctx) -> Result {
    let syscall_id = match ctx {
        tp_ctx::RawSyscallsEnter(args) => args.id as u32,
        _ => return Ok(0), // should not reach here
    };

    match obj.bpf_map_lookup_elem(&SYSCALL_COUNTS, &syscall_id) {
        Some(count) => {
            *count += 1;
        }
        None => {
            obj.bpf_map_update_elem(
                &SYSCALL_COUNTS,
                &syscall_id,
                &1,
                BPF_ANY as u64,
            )?;
        }
    }

    if let Some(task) = obj.bpf_get_current_task() {
        let pid_tgid =
            ((task.get_tgid() as u64) << 32) | (task.get_pid() as u64);
        let key = (syscall_id as u64) | (pid_tgid << 32);
        let start_time = obj.bpf_ktime_get_ns();
        obj.bpf_map_update_elem(
            &SYSCALL_START,
            &key,
            &start_time,
            BPF_ANY as u64,
        )?;
    }

    Ok(0)
}

#[rex_tracepoint(name = "raw_syscalls/sys_exit", tp_type = "RawSyscallsExit")]
fn trace_syscall_exit(obj: &tracepoint, ctx: tp_ctx) -> Result {
    let (syscall_id, ret) = match ctx {
        tp_ctx::RawSyscallsExit(args) => (args.id as u32, args.ret),
        _ => return Ok(0), // should not reach here
    };

    if ret < 0 {
        match obj.bpf_map_lookup_elem(&SYSCALL_ERRORS, &syscall_id) {
            Some(count) => {
                *count += 1;
            }
            None => {
                obj.bpf_map_update_elem(
                    &SYSCALL_ERRORS,
                    &syscall_id,
                    &1,
                    BPF_ANY as u64,
                )?;
            }
        }
    }

    if let Some(task) = obj.bpf_get_current_task() {
        let pid_tgid =
            ((task.get_tgid() as u64) << 32) | (task.get_pid() as u64);
        let key = (syscall_id as u64) | (pid_tgid << 32);

        if let Some(start_time) = obj.bpf_map_lookup_elem(&SYSCALL_START, &key)
        {
            let now = obj.bpf_ktime_get_ns();
            let delta = now - *start_time;

            match obj.bpf_map_lookup_elem(&SYSCALL_LATENCY, &syscall_id) {
                Some(total) => {
                    *total += delta;
                }
                None => {
                    obj.bpf_map_update_elem(
                        &SYSCALL_LATENCY,
                        &syscall_id,
                        &delta,
                        BPF_ANY as u64,
                    )?;
                }
            }

            obj.bpf_map_delete_elem(&SYSCALL_START, &key)?;
        }
    }

    Ok(0)
}
