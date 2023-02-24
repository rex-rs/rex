#![no_std]
#![feature(const_mut_refs)]

pub mod kprobe;
pub mod map;
pub mod perf_event;
pub mod prog_type;
pub mod tracepoint;

mod base_helper;
mod bindings;
mod stub;

use crate::prog_type::iu_prog;
use core::panic::PanicInfo;

#[no_mangle]
fn __iu_entry_tracepoint(prog: &tracepoint::tracepoint, ctx: *const ()) -> u32 {
    prog.prog_run(ctx)
}

#[no_mangle]
fn __iu_entry_kprobe(prog: &kprobe::kprobe, ctx: *const ()) -> u32 {
    prog.prog_run(ctx)
}

#[no_mangle]
fn __iu_entry_perf_event(prog: &perf_event::perf_event, ctx: *const ()) -> u32 {
    prog.prog_run(ctx)
}

// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub use bindings::uapi::*;
