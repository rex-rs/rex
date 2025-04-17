use crate::bindings::linux::kernel::task_struct;
use crate::ffi;

pub(crate) trait PerCPURead {
    unsafe fn this_cpu_read(addr: *const Self) -> Self;
}

// rustc does not auto-detect subregs for us
macro_rules! reg_template {
    (u64) => {
        ":r"
    };
    (i64) => {
        ":r"
    };
    (u32) => {
        ":e"
    };
    (i32) => {
        ":e"
    };
    (u16) => {
        ":x"
    };
    (i16) => {
        ":x"
    };
}

macro_rules! impl_pcpu_read_integral {
    ($t:tt $($ts:tt)*) => {
        impl PerCPURead for $t {
            #[inline(always)]
            unsafe fn this_cpu_read(addr: *const Self) -> Self {
                let mut var: Self;
                unsafe {
                    core::arch::asm!(
                        concat!("mov {0", reg_template!($t), "}, gs:[{1:r}]"),
                        lateout(reg) var,
                        in(reg) addr,
                        options(readonly, nostack),
                    );
                }
                var
            }
        }
        impl_pcpu_read_integral!($($ts)*);
    };
    () => {};
}

macro_rules! impl_pcpu_read_byte {
    ($t:tt $($ts:tt)*) => {
        impl PerCPURead for $t {
            #[inline(always)]
            unsafe fn this_cpu_read(addr: *const Self) -> Self {
                let mut var: Self;
                unsafe {
                    core::arch::asm!(
                        concat!("mov {0}, gs:[{1:r}]"),
                        lateout(reg_byte) var,
                        in(reg) addr,
                        options(readonly, nostack),
                    );
                }
                var
            }
        }
        impl_pcpu_read_byte!($($ts)*);
    };
    () => {};
}

macro_rules! impl_pcpu_read_ptr {
    ($t:tt $($ts:tt)*) => {
        impl<T> PerCPURead for *$t T {
            #[inline(always)]
            unsafe fn this_cpu_read(addr: *const Self) -> Self {
                let mut var: Self;
                unsafe {
                    core::arch::asm!(
                        concat!("mov {0:r}, gs:[{1:r}]"),
                        lateout(reg) var,
                        in(reg) addr,
                        options(readonly, nostack),
                    );
                }
                var
            }
        }
        impl_pcpu_read_ptr!($($ts)*);
    };
    () => {};
}

impl_pcpu_read_integral!(u64 i64 u32 i32 u16 i16);
impl_pcpu_read_byte!(u8 i8);
// Mut: we have the CPU and assume no nesting
impl_pcpu_read_ptr!(const mut);

/// For values of per-cpu variables
#[inline(always)]
pub(crate) unsafe fn this_cpu_read<T: PerCPURead>(pcp_addr: *const T) -> T {
    unsafe { T::this_cpu_read(pcp_addr) }
}

/// For addresses of per-cpu variables
/// This is more expensive (in terms of # of insns)
#[allow(dead_code)]
#[inline(always)]
pub unsafe fn this_cpu_ptr<T>(pcp_addr: *const T) -> *const T {
    unsafe {
        pcp_addr.byte_add(this_cpu_read(&raw const ffi::this_cpu_off) as usize)
    }
}

#[inline(always)]
pub unsafe fn this_cpu_ptr_mut<T>(pcp_addr: *mut T) -> *mut T {
    unsafe {
        pcp_addr.byte_add(this_cpu_read(&raw const ffi::this_cpu_off) as usize)
    }
}

#[inline(always)]
pub(crate) fn current_task() -> *const *const task_struct {
    unsafe {
        &raw const ffi::pcpu_hot.__bindgen_anon_1.__bindgen_anon_1.current_task
            as *const *const task_struct
    }
}

#[inline(always)]
pub(crate) fn cpu_number() -> *const i32 {
    unsafe {
        &raw const ffi::pcpu_hot.__bindgen_anon_1.__bindgen_anon_1.cpu_number
    }
}
