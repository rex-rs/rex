use paste::paste;

use crate::bindings::linux::kernel::pt_regs;

/// Transparently wraps around the kernel-internal `struct pt_regs` and make the
/// fields read-only to prevent user-defined code from modifying the registers
#[repr(transparent)]
pub struct PtRegs {
    pub(crate) regs: pt_regs,
}

macro_rules! decl_reg_accessors_1 {
    ($t:ident $($ts:ident)*) => {
        #[inline(always)]
        pub fn $t(&self) -> u64 {
            self.regs.$t
        }
        decl_reg_accessors_1!($($ts)*);
    };
    () => {};
}

macro_rules! decl_reg_accessors_2 {
    ($t:ident $($ts:ident)*) => {
        paste! {
            #[inline(always)]
            pub fn [<r $t>](&self) -> u64 {
                self.regs.$t
            }
        }
        decl_reg_accessors_2!($($ts)*);
    };
    () => {};
}

macro_rules! decl_reg_accessors {
    ($t1:ident $($ts1:ident)*, $t2:ident $($ts2:ident)*) => {
        // regs that does not require special handling
        decl_reg_accessors_1!($t1 $($ts1)*);
        // regs that does not have the 'r' prefix in kernel pt_regs
        decl_reg_accessors_2!($t2 $($ts2)*);
    }
}

impl PtRegs {
    decl_reg_accessors!(r15 r14 r13 r12 r11 r10 r9 r8,
                        bp bx ax cx dx si di ip sp);

    // orig_rax cs eflags ss cannot be batch-processed by macros
    #[inline(always)]
    pub fn orig_rax(&self) -> u64 {
        self.regs.orig_ax
    }

    #[inline(always)]
    pub fn cs(&self) -> u64 {
        unsafe { self.regs.__bindgen_anon_1.cs as u64 }
    }

    #[inline(always)]
    pub fn eflags(&self) -> u64 {
        self.regs.flags
    }

    #[inline(always)]
    pub fn ss(&self) -> u64 {
        unsafe { self.regs.__bindgen_anon_2.ss as u64 }
    }
}
