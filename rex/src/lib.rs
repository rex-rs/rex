#![no_std]
#![feature(
    array_ptr_get,
    auto_traits,
    c_variadic,
    core_intrinsics,
    negative_impls
)]
#![allow(non_camel_case_types, internal_features)]

pub mod kprobe;
pub mod map;
pub mod perf_event;
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
mod ffi;
mod log;
mod panic;
mod per_cpu;
mod random32;

extern crate paste;

pub use rex_macros::*;

#[cfg(not(CONFIG_KALLSYMS_ALL = "y"))]
compile_error!("CONFIG_KALLSYMS_ALL is required for rex");

pub use bindings::uapi::*;
pub use log::rex_trace_printk;
pub use utils::Result;
