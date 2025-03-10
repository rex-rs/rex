use crate::bindings::uapi::linux::bpf::{
    bpf_map_type, BPF_PROG_TYPE_TRACEPOINT,
};
use crate::map::*;
use crate::prog_type::rex_prog;
use crate::task_struct::TaskStruct;
use crate::Result;

use super::binding::*;

pub enum tp_type {
    Void,
    SyscallsEnterOpen,
    SyscallsExitOpen,
}
pub enum tp_ctx {
    Void,
    SyscallsEnterOpen(&'static SyscallsEnterOpenArgs),
    SyscallsExitOpen(&'static SyscallsExitOpenArgs),
}

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
pub struct tracepoint {
    rtti: u64,
    prog: fn(&Self, tp_ctx) -> Result,
    name: &'static str,
    tp_type: tp_type,
}

impl tracepoint {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        f: fn(&tracepoint, tp_ctx) -> Result,
        nm: &'static str,
        tp_ty: tp_type,
    ) -> tracepoint {
        Self {
            rtti: BPF_PROG_TYPE_TRACEPOINT as u64,
            prog: f,
            name: nm,
            tp_type: tp_ty,
        }
    }

    fn convert_ctx(&self, ctx: *mut ()) -> tp_ctx {
        match self.tp_type {
            tp_type::Void => tp_ctx::Void,
            tp_type::SyscallsEnterOpen => tp_ctx::SyscallsEnterOpen(unsafe {
                &*(ctx as *mut SyscallsEnterOpenArgs)
            }),
            tp_type::SyscallsExitOpen => tp_ctx::SyscallsExitOpen(unsafe {
                &*(ctx as *mut SyscallsExitOpenArgs)
            }),
        }
    }

    pub fn bpf_get_current_task(&self) -> Option<TaskStruct> {
        TaskStruct::get_current_task()
    }
}

impl rex_prog for tracepoint {
    fn prog_run(&self, ctx: *mut ()) -> u32 {
        let newctx = self.convert_ctx(ctx);
        ((self.prog)(self, newctx)).unwrap_or_else(|e| e) as u32
    }
}
