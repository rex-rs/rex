//! Implementation of various routines/frameworks related to EH/termination

use core::fmt::Write;
use core::panic::PanicInfo;

use crate::ffi;
use crate::log::LogBuf;
use crate::per_cpu::this_cpu_ptr_mut;

/// Needs to match the kernel side per-cpu definition
pub(crate) const ENTRIES_SIZE: usize = 64;

pub(crate) type CleanupFn = unsafe fn(*mut ()) -> ();

/// Aggregate to hold cleanup information of a specific object. The information
/// is used during panics to ensure proper cleanup of allocated kernel
/// resources. The `valid` field is used to mark whether this given entry holds
/// valid information. The cleanup will happen in the form of
/// `cleanup_fn(cleanup_arg)`
///
/// `#[repr(C)]` is needed because this struct is used from the kernel side.
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub(crate) struct CleanupEntry {
    pub(crate) valid: u64,
    pub(crate) cleanup_fn: Option<CleanupFn>,
    pub(crate) cleanup_arg: *mut (),
}

impl CleanupEntry {
    /// Create a new entry with valid function and argument
    #[inline]
    pub(crate) fn new(cleanup_fn: CleanupFn, cleanup_arg: *mut ()) -> Self {
        Self {
            valid: 1,
            cleanup_fn: Some(cleanup_fn),
            cleanup_arg,
        }
    }

    /// Run cleanup function
    #[inline]
    pub(crate) unsafe fn cleanup(&self) {
        if self.valid != 0 {
            if let Some(cleanup_fn) = self.cleanup_fn {
                unsafe {
                    (cleanup_fn)(self.cleanup_arg);
                }
            }
        }
    }
}

impl Default for CleanupEntry {
    /// Create a default entry without valid function and argument
    #[inline]
    fn default() -> Self {
        Self {
            valid: 0,
            cleanup_fn: None,
            cleanup_arg: core::ptr::null_mut(),
        }
    }
}

/// Represents an array of `CleanupEntry` on a given CPU. The backing storage
/// is defined as a per-cpu array in the kernel.
pub(crate) struct CleanupEntries<'a> {
    entries: &'a mut [CleanupEntry],
}

impl<'a> CleanupEntries<'a> {
    /// Retrieve the array of `CleanupEntry` on the current CPU.
    #[inline]
    fn this_cpu_cleanup_entries() -> CleanupEntries<'a> {
        let entries: &mut [CleanupEntry];
        unsafe {
            entries = &mut *this_cpu_ptr_mut(&raw mut ffi::rex_cleanup_entries)
                .as_mut_slice();
        }
        Self { entries }
    }

    /// Finds the next empty entry in the array
    ///
    /// Triggers a panic when the array is full. This is allowed because
    /// `CleanupEntries::register_cleanup` is its only caller and is only
    /// called by object constructors
    #[inline]
    fn find_next_emtpy_entry(&mut self) -> (usize, &mut CleanupEntry) {
        for (idx, entry) in self.entries.iter_mut().enumerate() {
            if entry.valid == 0 {
                return (idx, entry);
            }
        }
        panic!("Object count exceeded\n");
    }

    /// This function is (and must only be) called by object constructors
    ///
    /// Panic is allowed here
    pub(crate) fn register_cleanup(
        cleanup_fn: CleanupFn,
        cleanup_arg: *mut (),
    ) -> usize {
        let mut entries = Self::this_cpu_cleanup_entries();
        let (idx, entry) = entries.find_next_emtpy_entry();
        *entry = CleanupEntry::new(cleanup_fn, cleanup_arg);
        idx
    }

    /// This function is called by the object drop handler. It invalidates the
    /// entry corresponding to the object.
    pub(crate) fn deregister_cleanup(idx: usize) {
        let entries = Self::this_cpu_cleanup_entries();
        entries.entries[idx].valid = 0;
    }

    /// This function is called on panic to cleanup everything on the current
    /// CPU. It **must** not cause another panic
    pub(crate) unsafe fn cleanup_all() {
        let entries = Self::this_cpu_cleanup_entries();
        for entry in entries.entries.iter_mut() {
            unsafe {
                entry.cleanup();
            }
            entry.valid = 0;
        }
    }
}

// The best way to deal with this is probably insert it directly in LLVM IR as
// an inline asm block
// For now, use inline(always) to hint the compiler for inlining if LTO is on
#[unsafe(no_mangle)]
#[inline(always)]
unsafe fn __rex_check_stack() {
    // The program can only use the top 4 pages of the stack, therefore subtract
    // 0x4000
    unsafe {
        core::arch::asm!(
            "mov {1:r}, gs:[{0:r}]",
            "sub {1:r}, 0x4000",
            "cmp rsp, {1:r}",
            "ja 2f",
            "call __rex_handle_stack_overflow",
            "2:",
            in(reg) &ffi::rex_stack_ptr as *const u64 as u64,
            lateout(reg) _,
        );
    }
}

#[unsafe(no_mangle)]
pub(crate) unsafe fn __rex_handle_timeout() -> ! {
    panic!("Timeout in Rex program");
}

#[unsafe(no_mangle)]
unsafe fn __rex_handle_stack_overflow() -> ! {
    panic!("Stack overflow in Rex program");
}

// This function is called on panic.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Set the termination flag
    unsafe {
        let termination_flag: *mut u8 = crate::per_cpu::this_cpu_ptr_mut(
            &raw mut crate::ffi::rex_termination_state,
        );
        *termination_flag = 1;
    };

    unsafe { CleanupEntries::cleanup_all() };

    let mut buf = LogBuf::new();
    if write!(&mut buf, "{}", info).is_err() {
        buf.reset();
        // This string always fits in the buffer, so we ignore the Result
        write!(&mut buf, "unknown rust panic").ok();
    }

    unsafe { ffi::rex_landingpad() }
}
