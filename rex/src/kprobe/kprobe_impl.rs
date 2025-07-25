use crate::bindings::uapi::linux::bpf::bpf_map_type;
use crate::prog_type::rex_prog;
use crate::pt_regs::PtRegs;
use crate::task_struct::TaskStruct;
use crate::{ffi, Result};

/// prog_fn should have &Self as its first argument
#[repr(C)]
pub struct kprobe {
    prog: fn(&Self, &mut PtRegs) -> Result,
}

impl kprobe {
    crate::base_helper::base_helper_defs!();

    pub const unsafe fn new(f: fn(&kprobe, &mut PtRegs) -> Result) -> kprobe {
        Self { prog: f }
    }

    // Now returns a mutable ref, but since every reg is private the user prog
    // cannot change reg contents. The user should not be able to directly
    // assign this reference a new value either, given that they will not able
    // to create another instance of pt_regs (private fields, no pub ctor)
    fn convert_ctx(&self, ctx: *mut ()) -> &'static mut PtRegs {
        // ctx has actual type *mut crate::bindings::linux::kernel::pt_regs
        // therefore it is safe to just interpret it as a *mut pt_regs
        // since the later is #[repr(transparent)] over the former
        unsafe { &mut *(ctx as *mut PtRegs) }
    }

    #[cfg(CONFIG_BPF_KPROBE_OVERRIDE = "y")]
    pub fn bpf_override_return(&self, regs: &mut PtRegs, rc: u64) -> i32 {
        regs.regs.ax = rc;
        regs.regs.ip = ffi::just_return_func as *const () as u64;
        0
    }

    pub fn bpf_get_current_task(&self) -> Option<TaskStruct> {
        TaskStruct::get_current_task()
    }
}

impl rex_prog for kprobe {
    fn prog_run(&self, ctx: *mut ()) -> u32 {
        let newctx = self.convert_ctx(ctx);
        ((self.prog)(self, newctx)).unwrap_or_else(|e| e) as u32
    }
}
