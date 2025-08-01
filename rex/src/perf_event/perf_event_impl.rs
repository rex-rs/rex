use core::intrinsics::unlikely;

use crate::base_helper::termination_check;
use crate::bindings::linux::kernel::bpf_perf_event_data_kern;
use crate::bindings::uapi::linux::bpf::{bpf_map_type, bpf_perf_event_value};
use crate::ffi;
use crate::linux::errno::EINVAL;
use crate::map::*;
use crate::prog_type::rex_prog;
use crate::pt_regs::PtRegs;
use crate::task_struct::TaskStruct;
use crate::utils::{to_result, NoRef, Result};

#[repr(transparent)]
pub struct bpf_perf_event_data {
    kdata: bpf_perf_event_data_kern,
}

impl bpf_perf_event_data {
    #[inline(always)]
    pub fn regs(&self) -> &PtRegs {
        unsafe { &*(self.kdata.regs as *const PtRegs) }
    }

    #[inline(always)]
    pub fn sample_period(&self) -> u64 {
        unsafe { (*self.kdata.data).period }
    }

    #[inline(always)]
    pub fn addr(&self) -> u64 {
        unsafe { (*self.kdata.data).addr }
    }
}

/// prog_fn should have &Self as its first argument
#[repr(C)]
pub struct perf_event {
    prog: fn(&Self, &bpf_perf_event_data) -> Result,
}

impl perf_event {
    crate::base_helper::base_helper_defs!();

    pub const unsafe fn new(
        f: fn(&perf_event, &bpf_perf_event_data) -> Result,
    ) -> perf_event {
        Self { prog: f }
    }

    fn convert_ctx(&self, ctx: *mut ()) -> &'static bpf_perf_event_data {
        unsafe { &*(ctx as *mut bpf_perf_event_data) }
    }

    pub fn bpf_perf_prog_read_value(
        &self,
        ctx: &bpf_perf_event_data,
        buf: &mut bpf_perf_event_value,
    ) -> Result {
        let size = core::mem::size_of::<bpf_perf_event_value>() as u32;
        let ctx_kptr = ctx as *const bpf_perf_event_data
            as *const bpf_perf_event_data_kern;

        termination_check!(unsafe {
            to_result!(ffi::bpf_perf_prog_read_value(ctx_kptr, buf, size))
        })
    }

    pub fn bpf_get_stackid_pe<K, V>(
        &self,
        ctx: &bpf_perf_event_data,
        map: &'static RexStackTrace<K, V>,
        flags: u64,
    ) -> Result
    where
        V: Copy + NoRef,
    {
        let map_kptr = unsafe { core::ptr::read_volatile(&map.kptr) };
        if unlikely(map_kptr.is_null()) {
            return Err(EINVAL as i32);
        }

        let ctx_kptr = ctx as *const bpf_perf_event_data
            as *const bpf_perf_event_data_kern;

        termination_check!(unsafe {
            to_result!(ffi::bpf_get_stackid_pe(ctx_kptr, map_kptr, flags))
        })
    }

    pub fn bpf_get_current_task(&self) -> Option<TaskStruct> {
        TaskStruct::get_current_task()
    }
}

impl rex_prog for perf_event {
    fn prog_run(&self, ctx: *mut ()) -> u32 {
        let newctx = self.convert_ctx(ctx);
        ((self.prog)(self, newctx)).unwrap_or_else(|e| e) as u32
    }
}
