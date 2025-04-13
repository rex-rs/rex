#![no_std]
#![no_main]

extern crate rex;

use rex::kprobe::*;
use rex::linux::bpf::*;
use rex::map::*;
use rex::pt_regs::PtRegs;
use rex::{Result, rex_kprobe, rex_map, rex_printk};

#[rex_map]
static MAP_HASH: RexHashMap<u32, u64> = RexHashMap::new(5000, 0);

#[rex_map]
static MAP_ARRAY: RexArrayMap<u64> = RexArrayMap::new(5000, 0);

#[rex_kprobe(function = "kprobe_target_func")]
fn rex_prog1(obj: &kprobe, _ctx: &mut PtRegs) -> Result {
    let zero = 2500u32;

    let random = obj.bpf_get_prandom_u32() as u64;
    obj.bpf_map_update_elem(&MAP_HASH, &zero, &random, BPF_ANY as u64)?;

    let start = obj.bpf_ktime_get_ns();
    obj.bpf_map_lookup_elem(&MAP_HASH, &zero);
    let end = obj.bpf_ktime_get_ns();

    rex_printk!("Time elapsed: {}", end - start)?;

    // let random = obj.bpf_get_prandom_u32() as u64;
    // obj.bpf_map_update_elem(&MAP_ARRAY, &zero, &random, BPF_ANY as u64)?;
    //
    // let start = obj.bpf_ktime_get_ns();
    // obj.bpf_map_lookup_elem(&MAP_ARRAY, &zero);
    // let end = obj.bpf_ktime_get_ns();
    //
    // rex_printk!("Time elapsed: {}", end - start)?;

    Ok(0)
}
