use crate::stub;

use crate::base_helper::termination_check;
use crate::bindings::linux::kernel::iphdr__bindgen_ty_1__bindgen_ty_1;
pub use crate::bindings::linux::kernel::{
    ethhdr, iphdr, tcphdr, udphdr, xdp_buff,
};
use crate::bindings::uapi::linux::bpf::bpf_map_type;
use crate::debug::printk;
use crate::map::*;
use crate::prog_type::rex_prog;
use crate::utils::*;
use core::ffi::{c_uchar, c_uint, c_void};
use core::{mem, mem::size_of, slice};

// expose the following constants to the user
pub use crate::bindings::uapi::linux::bpf::{
    BPF_PROG_TYPE_XDP, XDP_ABORTED, XDP_DROP, XDP_PASS, XDP_REDIRECT, XDP_TX,
};
pub use crate::bindings::uapi::linux::r#in::{IPPROTO_TCP, IPPROTO_UDP};

impl iphdr {
    #[inline(always)]
    pub fn saddr(&mut self) -> &mut u32 {
        unsafe { &mut self.__bindgen_anon_1.__bindgen_anon_1.saddr }
    }

    pub fn daddr(&mut self) -> &mut u32 {
        unsafe { &mut self.__bindgen_anon_1.__bindgen_anon_1.daddr }
    }
}

#[inline(always)]
pub fn compute_ip_checksum(ip_header: &mut iphdr) -> u16 {
    let mut sum: u32 = 0;
    let mut checksum: u16 = 0;
    ip_header.check = 0;

    let count = size_of::<iphdr>() >> 1;

    let u16_slice = unsafe {
        core::slice::from_raw_parts(ip_header as *const _ as *const u16, count)
    };

    for &word in u16_slice {
        sum += word as u32;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    !sum as u16
}

pub struct xdp_md<'a> {
    pub data_slice: &'a mut [c_uchar],
    kptr: &'static mut xdp_buff,
}

// Define accessors of program-accessible fields
impl xdp_md<'_> {
    #[inline(always)]
    pub fn data_length(&self) -> usize {
        self.data_slice.len()
    }

    #[inline(always)]
    pub fn data_meta(&self) -> usize {
        self.kptr.data_meta as usize
    }

    #[inline(always)]
    pub fn ingress_ifindex(&self) -> u32 {
        unsafe { (*(*self.kptr.rxq).dev).ifindex as u32 }
    }

    #[inline(always)]
    pub fn rx_qeueu_index(&self) -> u32 {
        unsafe { (*self.kptr.rxq).queue_index }
    }

    #[inline(always)]
    pub fn egress_ifindex(&self) -> u32 {
        // TODO: https://elixir.bootlin.com/linux/v5.15.123/source/net/core/filter.c#L8271
        // egress_ifindex is valid only for BPF_XDP_DEVMAP option
        0
    }
}

/// First 3 fields should always be rtti, prog_fn, and name
///
/// rtti should be u64, therefore after compiling the
/// packed struct type rustc generates for LLVM does
/// not additional padding after rtti
///
/// prog_fn should have &Self as its first argument
///
/// name is a &'static str
#[repr(C)]
pub struct xdp {
    rtti: u64,
    prog: fn(&Self, &mut xdp_md) -> Result,
    name: &'static str,
}

impl xdp {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        f: fn(&xdp, &mut xdp_md) -> Result,
        nm: &'static str,
    ) -> xdp {
        Self {
            rtti: BPF_PROG_TYPE_XDP as u64,
            prog: f,
            name: nm,
        }
    }

    // Now returns a mutable ref, but since every reg is private the user prog
    // cannot change reg contents. The user should not be able to directly
    // assign this reference a new value either, given that they will not able
    // to create another instance of pt_regs (private fields, no pub ctor)
    #[inline(always)]
    fn convert_ctx(&self, ctx: *mut ()) -> xdp_md {
        let kptr = unsafe { &mut *(ctx as *mut xdp_buff) };

        // NOTE: not support jumobo frame yet with non-linear xdp_buff
        let data_length = kptr.data_end as usize - kptr.data as usize;

        let data_slice = unsafe {
            slice::from_raw_parts_mut(kptr.data as *mut c_uchar, data_length)
        };

        xdp_md { data_slice, kptr }
    }

    #[inline(always)]
    pub fn tcp_header<'b>(
        &self,
        ctx: &'b mut xdp_md,
    ) -> AlignedMut<'b, tcphdr> {
        // NOTE: this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let end = mem::size_of::<tcphdr>() + begin;

        unsafe {
            convert_slice_to_struct_mut::<tcphdr>(
                &mut ctx.data_slice[begin..end],
            )
        }
    }

    #[inline(always)]
    pub fn udp_header<'b>(
        &self,
        ctx: &'b mut xdp_md,
    ) -> AlignedMut<'b, udphdr> {
        // NOTE: this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let end = mem::size_of::<udphdr>() + begin;

        unsafe {
            convert_slice_to_struct_mut::<udphdr>(
                &mut ctx.data_slice[begin..end],
            )
        }
    }

    #[inline(always)]
    pub fn ip_header<'b>(&self, ctx: &'b mut xdp_md) -> AlignedMut<'b, iphdr> {
        // NOTE: this assumes packet has ethhdr
        let begin = mem::size_of::<ethhdr>();
        let end = mem::size_of::<iphdr>() + begin;

        unsafe {
            convert_slice_to_struct_mut::<iphdr>(
                &mut ctx.data_slice[begin..end],
            )
        }
    }

    #[inline(always)]
    pub fn eth_header<'b>(
        &self,
        ctx: &'b mut xdp_md,
    ) -> AlignedMut<'b, ethhdr> {
        unsafe {
            convert_slice_to_struct_mut::<ethhdr>(
                &mut ctx.data_slice[0..mem::size_of::<ethhdr>()],
            )
        }
    }

    // FIX: update based on xdp_md to convert to xdp_buff
    // pub fn bpf_xdp_adjust_head(&self, xdp: &mut xdp_buff, offset: i32) -> i32
    // {     unsafe { stub::bpf_xdp_adjust_head(xdp, offset) }
    // }

    // WARN: this function is unsafe
    #[inline(always)]
    pub fn bpf_xdp_adjust_tail(&self, ctx: &mut xdp_md, offset: i32) -> Result {
        let ret = termination_check!(unsafe {
            stub::bpf_xdp_adjust_tail(ctx.kptr, offset)
        });
        if ret != 0 {
            return Err(ret);
        }

        // Update xdp_md fields
        let data_length = ctx.kptr.data_end as usize - ctx.kptr.data as usize;

        ctx.data_slice = unsafe {
            slice::from_raw_parts_mut(
                ctx.kptr.data as *mut c_uchar,
                data_length,
            )
        };

        Ok(0)
    }
}
impl rex_prog for xdp {
    fn prog_run(&self, ctx: *mut ()) -> u32 {
        let mut newctx = self.convert_ctx(ctx);
        // Return XDP_PASS if Err, i.e. discard event
        ((self.prog)(self, &mut newctx)).unwrap_or_else(|e| e) as u32
    }
}
