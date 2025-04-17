#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SyscallsEnterOpenCtx {
    unused: u64,
    pub syscall_nr: i64,
    pub filename_ptr: i64,
    pub flags: i64,
    pub mode: i64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SyscallsEnterOpenatCtx {
    unused: u64,
    pub syscall_nr: i64,
    pub dfd: i64,
    pub filename_ptr: i64,
    pub flags: i64,
    pub mode: i64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SyscallsExitOpenCtx {
    unused: u64,
    pub syscall_nr: i64,
    pub ret: i64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]

pub struct RawSyscallEnterArgs {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,

    pub id: i64,
    pub args: [u64; 6],

pub struct SyscallsExitOpenatCtx {
    unused: u64,
    pub syscall_nr: i64,
    pub ret: i64,

}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RawSyscallExitArgs {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub id: i64,
    pub ret: i64,
pub struct SyscallsEnterDupCtx {
    unused: u64,
    pub syscall_nr: i64,
    pub fildes: u64,
}
