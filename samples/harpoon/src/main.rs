#![no_std]
#![no_main]

extern crate rex;

use rex::Result;
use rex::rex_printk;
use rex::{rex_tracepoint, rex_map, rex_uprobe};
use rex::tracepoint::*;
use rex::kprobe::kprobe;
use rex::map::{RexArrayMap, RexHashMap, RexPerfEventArray};
use rex::pt_regs::PtRegs;
use rex::utils::PerfEventMaskedCPU;
use core::ffi::CStr;

#[repr(C)]
#[derive(Clone, Copy)]
struct Config {
    pub values: [u8, 25],
}

#[repr(C)]
#[derive(Clone, Copy, core::Default)]
struct SyscallData {
    id: i64,
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
    rex_printk!("Enter function.\n");
}

#[rex_uprobe]
fn exit_function(obj: &kprobe, ctx: &mut PtRegs) -> Result {
    let tc = Tracing { status: 1 };
    let key = 0;
    TRACING_STATUS.insert(&key, &tc);
    rex_printk!("Exit function.\n");
}

#[rex_tracepoint(name = "raw_syscalls/sys_enter", tp_type = "RawSyscallsEnter")]
fn rex_prog1(obj: &tracepoint, ctx: tp_ctx) -> Result {
    let mut data = SyscallData::new();
    let key_config = 0;
    let key_trace = 0;

    let Some(tc) = TRACING_STATUS.get_mut(&key_trace) else {
        rex_printk!("Error getting tracing status.\n");
        return Err(1);
    }

    if tc.status == 1 {
        rex_printk!("Tracing is not active.\n");
        return Err(1);
    }

    let Some(task) = obj.bpf_get_current_task() else {
        rex_printk!("Unable to get current task.\n");
        return Err(1);
    }

    let Ok(command) = task.get_comm() else {
        rex_printk!("Unable to read current program name.\n");
        return Err(1);
    }

    let Some(input_command_raw) = CONFIG_MAP.get_mut(&key_config) else {
        rex_printk!("Unable to get config.\n");
        return Err(1);
    }

    let Ok(input_command) = CStr::from_bytes_until_nul(input_command_raw.values) else {
        rex_printk!("Unable to read input command.\n");
        return Err(1);
    }

    if command != input_command {
        return Err(1);
    }

    let id = match ctx {
        RawSyscallsEnter(args) => args.id,
        _ => 0,
    };

    data.id = id;

    EVENTS.output(obj, ctx, data, PerfEventMaskedCPU::current_cpu());

    rex_printk!("Sending syscall id {}.\n", id);

    Ok(0)
}
