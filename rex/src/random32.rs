use crate::ffi;

// fn get_cpu_var()
#[inline(always)]
pub(crate) fn bpf_user_rnd_u32() -> u32 {
    // directly use get_random_u32
    unsafe { ffi::get_random_u32() }
}
