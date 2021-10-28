
#![no_std]
#![no_main]

use core::panic::PanicInfo;
pub mod interface;
    
fn bpf_test_call() {
    let ptr = interface::STUB_BPF_TEST_CALL as *const ();
    let code: extern "C" fn() = unsafe { core::mem::transmute(ptr) };
    (code)();
}

macro_rules! bpf_trace_printk {
    ($s:literal,$($a:expr),*;$($t:ty),*) => {
        let ptr = interface::STUB_BPF_TRACE_PRINTK as *const ();
        let code: extern "C" fn(&str, $($t),*) = unsafe { core::mem::transmute(ptr) };
        code($s, $($a),*);
    }
}


#[no_mangle]
pub extern "C" fn _start() -> () {
    bpf_test_call();
    bpf_trace_printk!("BPF triggered from PID %d.\n", 29, 10; u32, u32);
}

/// This function is called on panic.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}


