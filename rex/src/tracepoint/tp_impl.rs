use crate::bindings::uapi::linux::bpf::{
    bpf_map_type, BPF_PROG_TYPE_TRACEPOINT,
};
use crate::prog_type::rex_prog;
use crate::task_struct::TaskStruct;
use crate::Result;

use super::binding::*;


pub enum tp_type {
    Void,
    SyscallsEnterOpen,
    SyscallsExitOpen,
    RawSyscallsEnter,
    RawSyscallsExit,
}
pub enum tp_ctx {
    Void,
    SyscallsEnterOpen(&'static SyscallsEnterOpenArgs),
    SyscallsExitOpen(&'static SyscallsExitOpenArgs),
    RawSyscallsEnter(&'static RawSyscallEnterArgs),
    RawSyscallsExit(&'static RawSyscallExitArgs),
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
    prog: fn(&Self, *mut ()) -> Result,
    name: &'static str,
}

// unlike other programs, we don't perform context conversion here
// as it is handled by the [#rex_tracepoint] macro
impl tracepoint {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        f: fn(&tracepoint, *mut ()) -> Result,
        nm: &'static str,
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
            tp_type::RawSyscallsEnter => tp_ctx::RawSyscallsEnter(unsafe {
                &*(ctx as *mut RawSyscallEnterArgs)
            }),
            tp_type::RawSyscallsExit => tp_ctx::RawSyscallsExit(unsafe {
                &*(ctx as *mut RawSyscallExitArgs)
            }),
        }
    }

    pub fn bpf_get_current_task(&self) -> Option<TaskStruct> {
        TaskStruct::get_current_task()
    }
}

impl rex_prog for tracepoint {
    fn prog_run(&self, ctx: *mut ()) -> u32 {
        ((self.prog)(self, ctx)).unwrap_or_else(|e| e) as u32
    }
}
