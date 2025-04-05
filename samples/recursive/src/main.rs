#![no_std]
#![no_main]
extern crate rex;

use rex::rex_kprobe;
use rex::rex_printk;
// use rex::tracepoint::*;
use core::hint::black_box;
use rex::Result;
use rex::kprobe::*;
use rex::map::RexArrayMap;
use rex::pt_regs::PtRegs;
use rex::rex_map;

#[rex_map]
static data_map: RexArrayMap<u32> = RexArrayMap::new(2, 0);

#[rex_kprobe(function = "kprobe_target_func")]
fn rex_recursive(obj: &kprobe, ctx: &mut PtRegs) -> Result {
    // let curr_pid: i32 = if let Some(task_struct) = obj.bpf_get_current_task()
    // {     task_struct.get_pid()
    // } else {
    //     return Err(0);
    // };

    // let stored_pid: u32 = if let Some(val) =
    // obj.bpf_map_lookup_elem(&data_map, &0) {     *val
    // } else {
    //     return Err(0);
    // };

    let n = ctx.rdi() as u32;
    // let n: u32 = if let Some(val) = obj.bpf_map_lookup_elem(&data_map, &1) {
    //     *val
    // } else {
    //     return Err(0);
    // };

    // rex_printk!("Received n: {}", n)?;
    let start_time: u64 = obj.bpf_ktime_get_ns();
    calculate_tail_fib(n);
    let end_time: u64 = obj.bpf_ktime_get_ns();
    // rex_printk!("Result: {}", result)?;

    rex_printk!("Time: {}", end_time - start_time)?;

    Ok(0)
}

#[inline(never)]
fn calculate_tail_fib(n: u32) {
    if n == 0 {
        return;
    }

    black_box(calculate_tail_fib(n - 1))
}
