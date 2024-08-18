#![no_std]
#![no_main]
extern crate rex;

use core::sync::atomic::{AtomicU64, Ordering};
use rex::pt_regs::PtRegs;
use rex::{bpf_printk, Result};
use rex::{kprobe::*, rex_kprobe};

static ATOM: AtomicU64 = AtomicU64::new(42);

#[rex_kprobe(function = "kprobe_target_func")]
fn rex_prog1(obj: &kprobe, _ctx: &mut PtRegs) -> Result {
    let random = obj.bpf_get_prandom_u32() as u64;
    ATOM.store(random, Ordering::Relaxed);

    let start = obj.bpf_ktime_get_ns();
    let val = ATOM.load(Ordering::Relaxed);
    let end = obj.bpf_ktime_get_ns();

    bpf_printk!(obj, "Time elapsed: %llu %llu", end - start, val);

    Ok(0)
}
