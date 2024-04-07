#![no_std]
#![no_main]

extern crate inner_unikernel_rt;

use core::sync::atomic::{AtomicU64, Ordering};
use inner_unikernel_rt::kprobe::*;
use inner_unikernel_rt::{bpf_printk, entry_link, Result};

static ATOM: AtomicU64 = AtomicU64::new(42);

#[inline(always)]
fn iu_prog1_fn(obj: &kprobe, _ctx: &mut pt_regs) -> Result {
    let random = obj.bpf_get_prandom_u32() as u64;
    ATOM.store(random, Ordering::Relaxed);

    let start = obj.bpf_ktime_get_ns();
    let val = ATOM.load(Ordering::Relaxed);
    let end = obj.bpf_ktime_get_ns();

    bpf_printk!(obj, "Time elapsed: %llu %llu", end - start, val);

    Ok(0)
}
#[entry_link(inner_unikernel/kprobe/kprobe_target_func)]
static PROG: kprobe = kprobe::new(iu_prog1_fn, "iu_prog1");
