#![no_std]
#![no_main]

use rex::kprobe::kprobe;
use rex::map::RexHashMap;
use rex::pt_regs::PtRegs;
use rex::{Result, rex_kprobe, rex_map};

#[allow(non_upper_case_globals)]
#[rex_map]
static pid_to_errno: RexHashMap<i32, u64> = RexHashMap::new(1, 0);

#[rex_kprobe]
pub fn err_injector(obj: &kprobe, ctx: &mut PtRegs) -> Result {
    obj.bpf_get_current_task()
        .map(|t| t.get_pid())
        .and_then(|p| obj.bpf_map_lookup_elem(&pid_to_errno, &p).cloned())
        .map(|e| obj.bpf_override_return(ctx, e))
        .ok_or(0)
}
