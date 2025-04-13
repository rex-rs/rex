use crate::ffi;

use crate::bindings::linux::kernel::{
    ethhdr, iphdr, sk_buff, sock, tcphdr, udphdr,
};
use crate::bindings::uapi::linux::bpf::bpf_map_type;
pub use crate::bindings::uapi::linux::bpf::BPF_PROG_TYPE_SCHED_CLS;
pub use crate::bindings::uapi::linux::pkt_cls::{
    TC_ACT_OK, TC_ACT_REDIRECT, TC_ACT_SHOT,
};
use crate::prog_type::rex_prog;
use crate::utils::*;

use crate::base_helper::termination_check;
use core::ffi::{c_char, c_uchar};
use core::{mem, slice};

pub struct __sk_buff<'a> {
    pub data_slice: &'a mut [c_uchar],
    kptr: &'static mut sk_buff,
}

// Define accessors of program-accessible fields
// TODO: may need to append more based on __sk_buff
impl<'a> __sk_buff<'a> {
    #[inline(always)]
    pub fn len(&self) -> u32 {
        self.kptr.len
    }

    #[inline(always)]
    pub fn data_len(&self) -> u32 {
        self.kptr.data_len
    }

    #[inline(always)]
    pub fn protocol(&self) -> u16be {
        u16be(unsafe {
            (self.kptr.__bindgen_anon_4.__bindgen_anon_1)
                .as_ref()
                .protocol
        })
    }

    #[inline(always)]
    pub fn priority(&self) -> u32 {
        unsafe {
            (self.kptr.__bindgen_anon_4.__bindgen_anon_1)
                .as_ref()
                .priority
        }
    }

    #[inline(always)]
    // TODO: may need to update based on __sk_buff
    pub fn ingress_ifindex(&self) -> u32 {
        0
    }

    #[inline(always)]
    pub fn ifindex(&self) -> u32 {
        unsafe {
            (*self
                .kptr
                .__bindgen_anon_1
                .__bindgen_anon_1
                .__bindgen_anon_1
                .dev)
                .ifindex as u32
        }
    }

    #[inline(always)]
    pub fn hash(&self) -> u32 {
        unsafe { (self.kptr.__bindgen_anon_4.__bindgen_anon_1).as_ref().hash }
    }

    #[inline(always)]
    // TODO: may need to update based on __sk_buff
    pub fn mark(&self) -> u32 {
        0
    }

    #[inline(always)]
    // TODO: may need to update based on __sk_buff
    pub fn pkt_type(&self) -> u32 {
        0
    }

    #[inline(always)]
    // TODO: may need to update based on __sk_buff
    pub fn queue_mapping(&self) -> u16 {
        self.kptr.queue_mapping
    }

    #[inline(always)]
    // TODO: may need to update based on __sk_buff
    pub fn vlan_present(&self) -> u32 {
        0
    }

    #[inline(always)]
    // TODO: may need to update based on __sk_buff
    pub fn vlan_tci(&self) -> u16 {
        unsafe {
            self.kptr
                .__bindgen_anon_4
                .__bindgen_anon_1
                .as_ref()
                .__bindgen_anon_2
                .__bindgen_anon_1
                .vlan_tci
        }
    }

    #[inline(always)]
    pub fn vlan_proto(&self) -> u16be {
        u16be(unsafe {
            self.kptr
                .__bindgen_anon_4
                .__bindgen_anon_1
                .as_ref()
                .__bindgen_anon_2
                .__bindgen_anon_1
                .vlan_proto
        })
    }

    #[inline(always)]
    pub fn cb(&self) -> [c_char; 20] {
        let mut cb = [0; 20];
        cb[0..20].clone_from_slice(&self.kptr.cb[0..20]);
        cb
    }

    #[inline(always)]
    // TODO: may need to update based on __sk_buff
    pub fn tc_classid(&self) -> u32 {
        0
    }

    #[inline(always)]
    pub fn tc_index(&self) -> u16 {
        unsafe {
            (self.kptr.__bindgen_anon_4.__bindgen_anon_1)
                .as_ref()
                .tc_index
        }
    }

    #[inline(always)]
    // TODO: may need to update based on __sk_buff
    pub fn napi_id(&self) -> u32 {
        0
    }

    #[inline(always)]
    // TODO: may need to update based on __sk_buff
    pub fn data_meta(&self) -> u32 {
        0
    }

    #[inline(always)]
    pub fn sk(&self) -> &'a sock {
        unsafe { &*self.kptr.sk }
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
pub struct sched_cls {
    rtti: u64,
    prog: fn(&Self, &mut __sk_buff) -> Result,
    name: &'static str,
}

impl sched_cls {
    crate::base_helper::base_helper_defs!();

    pub const fn new(
        // TODO update based on signature
        f: fn(&sched_cls, &mut __sk_buff) -> Result,
        nm: &'static str,
    ) -> sched_cls {
        Self {
            rtti: BPF_PROG_TYPE_SCHED_CLS as u64,
            prog: f,
            name: nm,
        }
    }

    // NOTE: copied from xdp impl, may change in the future
    #[inline(always)]
    pub fn eth_header<'b>(
        &self,
        skb: &'b mut __sk_buff,
    ) -> AlignedMut<'b, ethhdr> {
        convert_slice_to_struct_mut::<ethhdr>(
            &mut skb.data_slice[0..mem::size_of::<ethhdr>()],
        )
    }

    #[inline(always)]
    pub fn udp_header<'b>(
        &self,
        skb: &'b mut __sk_buff,
    ) -> AlignedMut<'b, udphdr> {
        // NOTE: this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let end = mem::size_of::<udphdr>() + begin;

        convert_slice_to_struct_mut::<udphdr>(&mut skb.data_slice[begin..end])
    }

    #[inline(always)]
    pub fn tcp_header<'b>(
        &self,
        skb: &'b mut __sk_buff,
    ) -> AlignedMut<'b, tcphdr> {
        // NOTE: this assumes packet has ethhdr and iphdr
        let begin = mem::size_of::<ethhdr>() + mem::size_of::<iphdr>();
        let end = mem::size_of::<tcphdr>() + begin;

        convert_slice_to_struct_mut::<tcphdr>(&mut skb.data_slice[begin..end])
    }

    #[inline(always)]
    pub fn ip_header<'b>(
        &self,
        skb: &'b mut __sk_buff,
    ) -> AlignedMut<'b, iphdr> {
        // NOTE: this assumes packet has ethhdr
        let begin = mem::size_of::<ethhdr>();
        let end = mem::size_of::<iphdr>() + begin;

        convert_slice_to_struct_mut::<iphdr>(&mut skb.data_slice[begin..end])
    }

    #[inline(always)]
    pub fn bpf_clone_redirect(
        &self,
        skb: &mut __sk_buff,
        ifindex: u32,
        flags: u64,
    ) -> Result {
        let ret = termination_check!(unsafe {
            ffi::bpf_clone_redirect(skb.kptr, ifindex, flags)
        });

        if ret != 0 {
            return Err(ret);
        }

        // WARN: bpf_clone_redirect does not update skb.kptr?
        skb.data_slice = unsafe {
            slice::from_raw_parts_mut(
                skb.kptr.data as *mut c_uchar,
                skb.len() as usize,
            )
        };

        Ok(0)
    }

    // Now returns a mutable ref, but since every reg is private the user prog
    // cannot change reg contents. The user should not be able to directly
    // assign this reference a new value either, given that they will not able
    // to create another instance of pt_regs (private fields, no pub ctor)
    #[inline(always)]
    fn convert_ctx(&self, ctx: *mut ()) -> __sk_buff {
        let kptr = unsafe { &mut *(ctx as *mut sk_buff) };

        // NOTE: not support jumobo frame yet with non-linear sk_buff
        let data_length = (kptr.len - kptr.data_len) as usize;

        let data_slice = unsafe {
            slice::from_raw_parts_mut(kptr.data as *mut c_uchar, data_length)
        };

        __sk_buff { data_slice, kptr }
    }
}

impl rex_prog for sched_cls {
    fn prog_run(&self, ctx: *mut ()) -> u32 {
        let mut newctx = self.convert_ctx(ctx);
        // return TC_ACT_OK if error
        ((self.prog)(self, &mut newctx)).unwrap_or_else(|e| e) as u32
    }
}
