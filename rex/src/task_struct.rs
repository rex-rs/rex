use core::ffi::{self as core_ffi, CStr};

use crate::bindings::linux::kernel::task_struct;
use crate::ffi;
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
    pub(crate) kptr: &'static task_struct,
}

impl TaskStruct {
    #[inline(always)]
    pub(crate) const fn new(kp: &'static task_struct) -> Self {
        Self { kptr: kp }
    }

    pub(crate) fn get_current_task() -> Option<Self> {
        let current: *mut task_struct =
            unsafe { this_cpu_read(&raw const ffi::current_task) };

        if current.is_null() {
            None
        } else {
            Some(TaskStruct::new(unsafe { &*current }))
        }
    }

    #[inline(always)]
    pub fn get_pid(&self) -> i32 {
        self.kptr.pid
    }

    #[inline(always)]
    pub fn get_tgid(&self) -> i32 {
        self.kptr.tgid
    }

    // Design decision: the equivalent BPF helper writes the program name to
    // a user-provided buffer, here we can take advantage of Rust's ownership by
    // just providing a &CStr instead
    pub fn get_comm(&self) -> Result<&CStr, core_ffi::FromBytesUntilNulError> {
        // casting from c_char to u8 is sound, see:
        // https://doc.rust-lang.org/src/core/ffi/c_str.rs.html#264
        let comm_bytes =
            unsafe { &*(&self.kptr.comm[..] as *const _ as *const [u8]) };
        CStr::from_bytes_until_nul(comm_bytes)
    }

    pub fn get_pt_regs(&self) -> &'static PtRegs {
        // X86 specific
        // stack_top is actually bottom of the kernel stack, it refers to the
        // highest address of the stack pages
        let stack_top =
            self.kptr.stack as u64 + THREAD_SIZE - TOP_OF_KERNEL_STACK_PADDING;
        let reg_addr = stack_top - core::mem::size_of::<PtRegs>() as u64;
        // The pt_regs should always be on the top of the stack
        unsafe { &*(reg_addr as *const PtRegs) }
    }

    /// Look up a task by its PID using bpf_task_from_pid kfunc.
    ///
    /// This function creates a new TaskStruct with proper reference counting.
    /// The returned TaskStruct will automatically release the reference when dropped.
    ///
    /// # Arguments
    /// * `pid` - The process ID to look up
    ///
    /// # Returns
    /// Returns `Some(TaskStruct)` if the task is found, `None` otherwise.
    ///
    /// # Safety
    /// This function is safe to call, but the returned TaskStruct must be used
    /// within the BPF program's execution context.
    pub fn from_pid(pid: i32) -> Option<TaskStructOwned> {
        let task_ptr = unsafe { ffi::bpf_task_from_pid(pid) };

        if task_ptr.is_null() {
            None
        } else {
            // bpf_task_from_pid already returns a reference-counted pointer
            Some(TaskStructOwned::new(task_ptr))
        }
    }

    /// Acquire a reference to the current TaskStruct.
    ///
    /// This creates a reference-counted version of the current task that can be
    /// stored and used beyond the immediate context.
    ///
    /// # Returns
    /// Returns `Some(TaskStructOwned)` if successful, `None` if the current task
    /// cannot be acquired.
    pub fn acquire_current() -> Option<TaskStructOwned> {
        if let Some(current_task) = Self::get_current_task() {
            let acquired_ptr = unsafe {
                ffi::bpf_task_acquire(current_task.kptr as *const _ as *mut _)
            };

            if acquired_ptr.is_null() {
                None
            } else {
                Some(TaskStructOwned::new(acquired_ptr))
            }
        } else {
            None
        }
    }
}

/// A reference-counted wrapper around TaskStruct that automatically manages
/// the task_struct reference lifetime using bpf_task_acquire/bpf_task_release.
///
/// This struct ensures that the task_struct reference is properly released
/// when the TaskStructOwned is dropped, preventing reference leaks.
pub struct TaskStructOwned {
    task_ptr: *mut task_struct,
}

impl TaskStructOwned {
    /// Create a new TaskStructOwned from a raw task_struct pointer.
    ///
    /// # Safety
    /// The caller must ensure that the pointer is valid and already has a reference
    /// that will be managed by this TaskStructOwned instance.
    pub(crate) fn new(task_ptr: *mut task_struct) -> Self {
        Self { task_ptr }
    }

    /// Get a TaskStruct view of this owned task.
    ///
    /// This allows access to all the TaskStruct methods while maintaining
    /// the reference counting guarantees.
    pub fn as_task_struct(&self) -> TaskStruct {
        TaskStruct::new(unsafe { &*self.task_ptr })
    }

    /// Get the PID of this task.
    #[inline(always)]
    pub fn get_pid(&self) -> i32 {
        self.as_task_struct().get_pid()
    }

    /// Get the TGID (thread group ID) of this task.
    #[inline(always)]
    pub fn get_tgid(&self) -> i32 {
        self.as_task_struct().get_tgid()
    }

    /// Get the command name of this task.
    pub fn get_comm(&self) -> Result<&CStr, core_ffi::FromBytesUntilNulError> {
        self.as_task_struct().get_comm()
    }

    /// Get the pt_regs for this task.
    pub fn get_pt_regs(&self) -> &'static PtRegs {
        self.as_task_struct().get_pt_regs()
    }

    /// Clone this TaskStructOwned by acquiring an additional reference.
    ///
    /// This allows multiple TaskStructOwned instances to refer to the same task,
    /// each with their own reference that will be released independently.
    pub fn clone_ref(&self) -> Option<TaskStructOwned> {
        let acquired_ptr = unsafe { ffi::bpf_task_acquire(self.task_ptr) };

        if acquired_ptr.is_null() {
            None
        } else {
            Some(TaskStructOwned::new(acquired_ptr))
        }
    }
}

impl Drop for TaskStructOwned {
    /// Automatically release the task_struct reference when TaskStructOwned is dropped.
    fn drop(&mut self) {
        unsafe {
            ffi::bpf_task_release(self.task_ptr);
        }
    }
}

// TaskStructOwned is Send since task_struct operations are atomic
unsafe impl Send for TaskStructOwned {}

// TaskStructOwned is not Sync since multiple threads shouldn't access the same
// task_struct pointer simultaneously without additional synchronization
impl !Sync for TaskStructOwned {}
