#![no_std]
#![no_main]

extern crate rex;

use rex::kprobe::*;
use rex::pt_regs::PtRegs;
use rex::{Result, rex_kprobe};

#[rex_kprobe(function = "kprobe_target_func")]
fn rex_prog1(_obj: &kprobe, _ctx: &mut PtRegs) -> Result {
    Ok(0)
}
