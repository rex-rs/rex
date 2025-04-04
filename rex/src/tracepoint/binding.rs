#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SyscallsEnterOpenArgs {
    pub unused: u64,
    pub syscall_nr: i64,
    pub filename_ptr: i64,
    pub flags: i64,
    pub mode: i64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SyscallsExitOpenArgs {
    pub unused: u64,
    pub syscall_nr: i64,
    pub ret: i64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RawSyscallsEnterArgs {
    pub unused: u64,
    pub id: i64,
    pub args: [u64; 6],
}
