mod cli;
mod stats;
mod syscall_names;

use anyhow::{Context, Result};
use cli::Args;
use libc::{c_char, c_int, c_void};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::flag as signal_flag;
use std::ffi::CString;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime};

#[allow(non_camel_case_types)]
type bpf_object = libc::c_void;
#[allow(non_camel_case_types)]
type bpf_link = libc::c_void;

extern "C" {
    fn load_rex_program(file_path: *const c_char) -> *mut bpf_object;
    fn attach_program(
        obj: *mut bpf_object,
        prog_name: *const c_char,
        link: *mut *mut bpf_link,
    ) -> c_int;
    fn get_map_fd(obj: *mut bpf_object, map_name: *const c_char) -> c_int;
    fn lookup_map_value(
        map_fd: c_int,
        key: *const c_void,
        value: *mut c_void,
        value_size: size_t,
    ) -> c_int;
    fn get_next_map_key(
        map_fd: c_int,
        key: *const c_void,
        next_key: *mut c_void,
    ) -> c_int;
    fn detach_programs(links: *mut *mut bpf_link, count: c_int);
}

static EXITING: AtomicBool = AtomicBool::new(false);

struct RexState {
    obj: *mut bpf_object,
    links: Vec<*mut bpf_link>,
}

impl Drop for RexState {
    fn drop(&mut self) {
        for &link in &self.links {
            if !link.is_null() {
                unsafe { destroy_link(link) };
            }
        }
    }
}

fn main() -> Result<()> {
    // parse command line arguments
    let args = cli::parse_args();

    // set up signal handlers
    for sig in TERM_SIGNALS {
        signal_flag::register(*sig, &EXITING)
            .context("Failed to register signal handler")?;
    }

    // load the BPF program
    let state = load_bpf(&args.bpf_path.to_string_lossy())?;

    println!("Tracing syscalls... Hit Ctrl-C to end.");

    // main loop
    let start_time = SystemTime::now();
    while !EXITING.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(args.interval));

        if args.clear_screen {
            print!("\x1B[2J\x1B[1;1H"); // ANSI Code to clear the screen
        }

        stats::print_stats(&state, &args, start_time)
            .context("Failed to print statistics")?;
    }

    println!("\nDetaching programs...");
    // use RexBpfState's drop function to detach programs

    Ok(())
}

fn load_bpf(bpf_path: &str) -> Result<RexState> {
    let c_path = CString::new(bpf_path)
        .context("Failed to convert BPF path to CString")?;
    let obj = unsafe { load_rex_program(c_path.as_ptr()) };
    if obj.is_null() {
        return Err(anyhow::anyhow!("Failed to load BPF program"));
    }

    let mut state = RexState {
        obj,
        links: vec![ptr::null_mut(); 2],
    };

    let c_enter = CString::new("trace_syscall_enter")
        .context("Failed to convert function name to CString")?;

    let ret = unsafe {
        attach_program(
            state.obj,
            c_enter.as_ptr(),
            state.links.as_mut_ptr().add(1),
        )
    };

    if ret != 0 {
        return Err(anyhow::anyhow!("Failed to attach enter program"));
    }
    Ok(state)
}
