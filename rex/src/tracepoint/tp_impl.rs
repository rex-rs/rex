use core::marker::PhantomData;

use super::{
    RawSyscallsEnterCtx, RawSyscallsExitCtx, SyscallsEnterDupCtx,
    SyscallsEnterOpenCtx, SyscallsEnterOpenatCtx, SyscallsExitOpenCtx,
    SyscallsExitOpenatCtx,
};
use crate::base_helper::termination_check;
use crate::bindings::uapi::linux::bpf::bpf_map_type;
use crate::map::RexPerfEventArray;
use crate::task_struct::TaskStruct;
use crate::utils::sealed::PerfEventStreamerBase;
use crate::utils::{to_result, NoRef, PerfEventMaskedCPU, PerfEventStreamer};
use crate::{ffi, Result};

pub trait TracepointContext {}
impl TracepointContext for SyscallsEnterOpenCtx {}
impl TracepointContext for SyscallsEnterOpenatCtx {}
impl TracepointContext for SyscallsExitOpenCtx {}
impl TracepointContext for SyscallsExitOpenatCtx {}
impl TracepointContext for SyscallsEnterDupCtx {}
impl TracepointContext for RawSyscallsEnterCtx {}
impl TracepointContext for RawSyscallsExitCtx {}

#[repr(C)]
pub struct tracepoint<C: TracepointContext + 'static> {
    _placeholder: PhantomData<C>,
}

impl<C: TracepointContext + 'static> tracepoint<C> {
    crate::base_helper::base_helper_defs!();

    pub const unsafe fn new() -> tracepoint<C> {
        Self {
            _placeholder: PhantomData,
        }
    }

    pub unsafe fn convert_ctx(&self, ctx: *mut ()) -> &'static C {
        unsafe { &*(ctx as *mut C) }
    }

    pub fn bpf_get_current_task(&self) -> Option<TaskStruct> {
        TaskStruct::get_current_task()
    }
}

impl<C: TracepointContext + 'static> PerfEventStreamerBase for tracepoint<C> {}

impl<C: TracepointContext + 'static> PerfEventStreamer for tracepoint<C> {
    type Context = C;

    fn output_event<T: Copy + NoRef>(
        &self,
        ctx: &Self::Context,
        map: &'static RexPerfEventArray<T>,
        data: &T,
        cpu: PerfEventMaskedCPU,
    ) -> Result {
        let map_kptr = unsafe { core::ptr::read_volatile(&map.kptr) };
        let ctx_ptr = ctx as *const C as *const ();
        termination_check!(unsafe {
            to_result!(ffi::bpf_perf_event_output_tp(
                ctx_ptr,
                map_kptr,
                cpu.masked_cpu,
                data as *const T as *const (),
                core::mem::size_of::<T>() as u64
            ))
        })
    }
}
