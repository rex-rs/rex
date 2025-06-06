use super::{
    RawSyscallsEnterCtx, RawSyscallsExitCtx, SyscallsEnterDupCtx,
    SyscallsEnterOpenCtx, SyscallsEnterOpenatCtx, SyscallsExitOpenCtx,
    SyscallsExitOpenatCtx,
};
use crate::base_helper::termination_check;
use crate::bindings::uapi::linux::bpf::{
    bpf_map_type, BPF_PROG_TYPE_TRACEPOINT,
};
use crate::map::RexPerfEventArray;
use crate::prog_type::rex_prog;
use crate::task_struct::TaskStruct;
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

/// First 3 fields should always be rtti, prog_fn, and name
///
/// rtti should be u64, therefore after compiling the
/// packed struct type rustc generates for LLVM does
/// not additional padding after rtti
///
/// prog_fn should have &Self as its first argument
///
/// name is a &'static str
#[repr(C)]
pub struct tracepoint<C: TracepointContext + 'static> {
    rtti: u64,
    prog: fn(&Self, &'static C) -> Result,
    name: &'static str,
}

impl<C: TracepointContext + 'static> tracepoint<C> {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        f: fn(&tracepoint<C>, &'static C) -> Result,
        nm: &'static str,
    ) -> tracepoint<C> {
        Self {
            rtti: BPF_PROG_TYPE_TRACEPOINT as u64,
            prog: f,
            name: nm,
        }
    }

    fn convert_ctx(&self, ctx: *mut ()) -> &'static C {
        unsafe { &*(ctx as *mut C) }
    }

    pub fn bpf_get_current_task(&self) -> Option<TaskStruct> {
        TaskStruct::get_current_task()
    }
}

impl<C: TracepointContext + 'static> rex_prog for tracepoint<C> {
    fn prog_run(&self, ctx: *mut ()) -> u32 {
        let newctx = self.convert_ctx(ctx);
        ((self.prog)(self, newctx)).unwrap_or_else(|e| e) as u32
    }
}

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
