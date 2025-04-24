#![no_std]
#![no_main]

extern crate rex;

use rex::tracepoint::*;
use rex::{Result, rex_printk, rex_tracepoint};

#[rex_tracepoint]
fn rex_prog1(obj: &tracepoint, _: &'static SyscallsEnterDupCtx) -> Result {
    let option_task = obj.bpf_get_current_task();
    if let Some(task) = option_task {
        let cpu = obj.bpf_get_smp_processor_id();
        let pid = task.get_pid();
        rex_printk!("Rust triggered from PID {} on CPU {}.\n", pid, cpu)?;
    }
    Ok(0)
}
