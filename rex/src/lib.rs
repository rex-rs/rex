#![no_std]
#![feature(
    array_ptr_get,
    auto_traits,
    c_variadic,
    core_intrinsics,
    negative_impls
)]
#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    internal_features
)]

pub mod kprobe;
pub mod map;
pub mod perf_event;
pub mod prog_type;
pub mod pt_regs;
pub mod sched_cls;
pub mod spinlock;
pub mod task_struct;
pub mod tracepoint;
pub mod utils;
pub mod xdp;

mod base_helper;
mod bindings;
mod debug;
mod panic;
mod per_cpu;
mod random32;
mod stub;

extern crate paste;

use crate::prog_type::rex_prog;
use core::panic::PanicInfo;
pub use rex_macros::*;

use paste::paste;

#[cfg(not(CONFIG_KALLSYMS_ALL = "y"))]
compile_error!("CONFIG_KALLSYMS_ALL is required for rex");

macro_rules! define_prog_entry {
    ($prog_ty:ident) => {
        paste! {
            #[unsafe(no_mangle)]
            #[inline(always)]
            fn [<__rex_entry_ $prog_ty>](
                prog: &$prog_ty::$prog_ty,
                ctx: *mut (),
            ) -> u32 {
                prog.prog_run(ctx)
            }
        }
    };
}

define_prog_entry!(tracepoint);
define_prog_entry!(kprobe);
define_prog_entry!(perf_event);
define_prog_entry!(xdp);
define_prog_entry!(sched_cls);

pub use bindings::uapi::*;
pub use utils::Result;
