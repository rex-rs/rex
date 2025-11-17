use core::ffi::{self as core_ffi, CStr};
use core::ops::Deref;

use crate::base_helper::termination_check;
use crate::bindings::linux::kernel::task_struct;
use crate::ffi;
use crate::panic::CleanupEntries;
use crate::per_cpu::this_cpu_read;
use crate::pt_regs::PtRegs;

// Bindgen has problem generating these constants
const TOP_OF_KERNEL_STACK_PADDING: u64 = 0;
const PAGE_SHIFT: u64 = 12;
const PAGE_SIZE: u64 = 1u64 << PAGE_SHIFT;
const THREAD_SIZE_ORDER: u64 = 2; // assume no kasan
const THREAD_SIZE: u64 = PAGE_SIZE << THREAD_SIZE_ORDER;

pub struct TaskStruct {
    // struct task_struct * should always live longer than program execution
    // given the RCU read lock
    task: &'static task_struct,
    kptr: *mut task_struct,
}

impl TaskStruct {
    pub(crate) fn get_current_task() -> Option<Self> {
        let current: *mut task_struct =
            unsafe { this_cpu_read(&raw const ffi::current_task) };

        if current.is_null() {
            None
        } else {
            Some(TaskStruct {
                task: unsafe { &*current },
                kptr: current,
            })
        }
    }

    #[inline(always)]
    pub fn get_pid(&self) -> i32 {
        self.task.pid
    }

    #[inline(always)]
    pub fn get_tgid(&self) -> i32 {
        self.task.tgid
    }

    #[inline(always)]
    pub fn get_utime(&self) -> u64 {
        self.task.utime
    }

    // Design decision: the equivalent BPF helper writes the program name to
    // a user-provided buffer, here we can take advantage of Rust's ownership by
    // just providing a &CStr instead
    pub fn get_comm(&self) -> Result<&CStr, core_ffi::FromBytesUntilNulError> {
        // casting from c_char to u8 is sound, see:
        // https://doc.rust-lang.org/src/core/ffi/c_str.rs.html#264
        let comm_bytes =
            unsafe { &*(&self.task.comm[..] as *const _ as *const [u8]) };
        CStr::from_bytes_until_nul(comm_bytes)
    }

    pub fn get_pt_regs(&self) -> &'static PtRegs {
        // X86 specific
        // stack_top is actually bottom of the kernel stack, it refers to the
        // highest address of the stack pages
        let stack_top =
            self.task.stack as u64 + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
        let reg_addr = stack_top - core::mem::size_of::<PtRegs>() as u64;
        // The pt_regs should always be on the top of the stack
        unsafe { &*(reg_addr as *const PtRegs) }
    }
}

pub struct OwnedTaskStruct {
    inner: TaskStruct,
    cleanup_idx: usize,
}

impl OwnedTaskStruct {
    pub fn from_pid(pid: i32) -> Option<Self> {
        termination_check!({
            let task = unsafe { ffi::bpf_task_from_pid(pid) };

            if task.is_null() {
                None
            } else {
                let cleanup_idx = CleanupEntries::register_cleanup(
                    Self::panic_cleanup,
                    task as *mut (),
                );

                Some(Self {
                    inner: TaskStruct {
                        task: unsafe { &*task },
                        kptr: task,
                    },
                    cleanup_idx,
                })
            }
        })
    }

    pub(crate) unsafe fn panic_cleanup(task: *mut ()) {
        unsafe {
            ffi::bpf_task_release(task as *mut task_struct);
        }
    }
}

impl Deref for OwnedTaskStruct {
    type Target = TaskStruct;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Drop for OwnedTaskStruct {
    fn drop(&mut self) {
        termination_check!({
            unsafe {
                CleanupEntries::deregister_cleanup(self.cleanup_idx);
                ffi::bpf_task_release(self.inner.kptr);
            }
        })
    }
}
