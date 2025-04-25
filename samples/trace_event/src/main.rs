#![no_std]
#![no_main]

extern crate rex;

use rex::linux::bpf::*;
use rex::linux::perf_event::PERF_MAX_STACK_DEPTH;
use rex::map::*;
use rex::perf_event::*;
use rex::utils::copy_cstr_to_array;
use rex::{Result, rex_map, rex_perf_event, rex_printk};

pub const TASK_COMM_LEN: usize = 16;

// What if user does not use repr(C)?
#[repr(C)]
#[derive(Copy, Clone)]
pub struct KeyT {
    pub comm: [u8; TASK_COMM_LEN],
    pub kernstack: u32,
    pub userstack: u32,
}

#[rex_map]
static counts: RexHashMap<KeyT, u64> = RexHashMap::new(10000, 0);

#[rex_map]
static stackmap: RexStackTrace<u32, [u64; PERF_MAX_STACK_DEPTH as usize]> =
    RexStackTrace::new(10000, 0);

pub const KERN_STACKID_FLAGS: u64 = BPF_F_FAST_STACK_CMP as u64;
pub const USER_STACKID_FLAGS: u64 =
    (BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK) as u64;

#[rex_perf_event]
fn rex_prog1(obj: &perf_event, ctx: &bpf_perf_event_data) -> Result {
    let cpu = obj.bpf_get_smp_processor_id();
    let mut value_buf: bpf_perf_event_value = bpf_perf_event_value {
        counter: 0,
        enabled: 0,
        running: 0,
    };
    let mut key: KeyT = KeyT {
        comm: [0; TASK_COMM_LEN],
        kernstack: 0,
        userstack: 0,
    };
    if ctx.sample_period() < 10000 {
        return Ok(0);
    }

    obj.bpf_get_current_task()
        .map(|t| {
            let prog_name = t.get_comm().unwrap_or_default();
            copy_cstr_to_array(prog_name, &mut key.comm);
            0u64
        })
        .ok_or(0i32)?;

    key.kernstack = obj
        .bpf_get_stackid_pe(ctx, &stackmap, KERN_STACKID_FLAGS)
        .or_else(|_| {
        rex_printk!(
            "CPU-{} period {} ip {:x}",
            cpu,
            ctx.sample_period(),
            ctx.regs().rip()
        )
    })? as u32;

    key.userstack = obj
        .bpf_get_stackid_pe(ctx, &stackmap, USER_STACKID_FLAGS)
        .or_else(|_| {
        rex_printk!(
            "CPU-{} period {} ip {:x}",
            cpu,
            ctx.sample_period(),
            ctx.regs().rip()
        )
    })? as u32;

    obj.bpf_perf_prog_read_value(ctx, &mut value_buf)
        .map_or_else(
            |err| rex_printk!("Get Time Failed, ErrCode: {}", err),
            |_| {
                rex_printk!(
                    "Time Enabled: {}, Time Running: {}",
                    value_buf.enabled,
                    value_buf.running
                )
            },
        )?;

    if ctx.addr() != 0 {
        rex_printk!("Address recorded on event: {:x}", ctx.addr())?;
    }

    match obj.bpf_map_lookup_elem(&counts, &key) {
        None => {
            obj.bpf_map_update_elem(&counts, &key, &1, BPF_NOEXIST as u64)?;
        }
        Some(val) => {
            *val += 1;
        }
    }
    Ok(0)
}
