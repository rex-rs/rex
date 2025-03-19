#![no_std]
#![no_main]

extern crate rex;

use rex::Result;
use rex::bpf_printk;
use rex::{rex_tracepoint, rex_map, rex_uprobe};
use rex::tracepoint::*;
use rex::kprobe::kprobe;
use rex::map::{RexArrayMap, RexHashMap, RexPerfEventArray};
use rex::pt_regs::PtRegs;
use core::ffi::CStr;

#[repr(C)]
#[derive(Clone, Copy)]
struct Config {
    pub values: [u8, 25],
}

#[repr(C)]
#[derive(Clone, Copy, core::Default)]
struct SyscallData {
    id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Tracing {
    status: u32,
};

#[rex_map]
static CONFIG_MAP: RexArrayMap<Config> = RexArrayMap::new(1, 0);

#[rex_map]
static EVENTS: RexPerfEventArray<SyscallData> = RexPerfEventArray::new(64, 0);

#[rex_map]
static TRACING_STATUS: RexHashMap<u32, Tracing> = RexHashMap::new(1, 0);

#[rex_uprobe]
fn enter_function(obj: &kprobe, ctx: &mut PtRegs) -> Result {
    let tc = Tracing { status: 0 };
    let key = 0;
    TRACING_STATUS.insert(&key, &tc);
    bpf_printk!(obj, c"Enter function.\n");
}

#[rex_uprobe]
fn exit_function(obj: &kprobe, ctx: &mut PtRegs) -> Result {
    let tc = Tracing { status: 1 };
    let key = 0;
    TRACING_STATUS.insert(&key, &tc);
    bpf_printk!(obj, c"Exit function.\n");
}

#[rex_tracepoint(name = "syscalls/sys_enter_dup", tp_type = "Void")]
fn rex_prog1(obj: &tracepoint, _: tp_ctx) -> Result {
    let mut data = SyscallData::new();
    let key_config = 0;
    let key_trace = 0;

    let Some(tc) = TRACING_STATUS.get_mut(&key_trace) else {
        bpf_printk!(obj, c"Error getting tracing status.\n");
        return Err(1);
    }

    if tc.status == 1 {
        bpf_printk!(obj, c"Tracing is not active.\n");
        return Err(1);
    }

    let Some(task) = obj.bpf_get_current_task() else {
        bpf_printk!(obj, c"Unable to get current task.\n");
        return Err(1);
    }

    let Ok(command) = task.get_comm() else {
        bpf_printk!(obj, c"Unable to read current program name.\n");
        return Err(1);
    }

    let Some(input_command_raw) = CONFIG_MAP.get_mut(&key_config) else {
        bpf_printk!(obj, c"Unable to get config.\n");
        return Err(1);
    }

    let Ok(input_command) = CStr::from_bytes_until_nul(input_command_raw.values) else {
        bpf_printk!(obj, c"Unable to read input command.\n");
        return Err(1);
    }

    if command != input_command {
        return Err(1);
    }

    Ok(0)
}
