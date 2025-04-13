use crate::base_helper::termination_check;
pub use crate::bindings::uapi::linux::bpf::bpf_spin_lock;
use crate::ffi;
use crate::panic::CleanupEntries;

/// An RAII implementation of a "scoped lock" of a bpf spinlock. When this
/// structure is dropped (falls out of scope), the lock will be unlocked.
///
/// Ref: <https://doc.rust-lang.org/src/std/sync/mutex.rs.html#206-209>
#[must_use = "if unused the spinlock will immediately unlock"]
#[clippy::has_significant_drop]
pub struct rex_spinlock_guard<'a> {
    lock: &'a mut bpf_spin_lock,
    cleanup_idx: usize,
}

impl<'a> rex_spinlock_guard<'a> {
    /// Constructor function that locks the spinlock
    pub fn new(lock: &'a mut bpf_spin_lock) -> Self {
        termination_check!({
            // Put it before lock so if it panics we will not be holding the
            // lock without a valid cleanup entry for it
            let cleanup_idx = CleanupEntries::register_cleanup(
                Self::panic_cleanup,
                lock as *mut bpf_spin_lock as *mut (),
            );

            // Lock
            unsafe { ffi::bpf_spin_lock(lock) };

            Self { lock, cleanup_idx }
        })
    }

    /// Function that unlocks the spinlock, used by cleanup list and drop
    pub(crate) unsafe fn panic_cleanup(lock: *mut ()) {
        unsafe {
            ffi::bpf_spin_unlock(lock as *mut bpf_spin_lock);
        }
    }
}

impl Drop for rex_spinlock_guard<'_> {
    /// Unlock the spinlock when the guard is out-of-scope
    fn drop(&mut self) {
        termination_check!({
            // Put it before unlock so if it panics we will not unlock twice
            // (once here in the drop handler, the other in the
            // panic handler triggered by this function)
            CleanupEntries::deregister_cleanup(self.cleanup_idx);

            // Unlock
            unsafe { ffi::bpf_spin_unlock(self.lock) };
        })
    }
}

/// Unimplement Send and Sync
/// Ref: <https://doc.rust-lang.org/nomicon/send-and-sync.html>
impl !Send for rex_spinlock_guard<'_> {}
impl !Sync for rex_spinlock_guard<'_> {}
