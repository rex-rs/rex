#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

extern crate rex;

use rex::bpf_printk;
use rex::sched_cls::*;
use rex::utils::*;
use rex::xdp::*;
use rex::{rex_tc, rex_xdp};

#[rex_xdp]
fn xdp_rx_filter(obj: &xdp, ctx: &mut xdp_md) -> Result {
    let mut ip_header = obj.ip_header(ctx);

    bpf_printk!(
        obj,
        c"IP saddr %pi4\n",
        ip_header.saddr() as *const u32 as u64
    );
    bpf_printk!(
        obj,
        c"IP daddr %pi4\n",
        ip_header.daddr() as *const u32 as u64
    );

    match u8::from_be(ip_header.protocol) as u32 {
        IPPROTO_TCP => {
            bpf_printk!(obj, c"TCP packet!")
        }
        IPPROTO_UDP => {
            bpf_printk!(obj, c"UDP packet!");
        }
        _ => {}
    };

    Ok(XDP_PASS as i32)
}

#[rex_tc]
fn xdp_tx_filter(obj: &sched_cls, skb: &mut __sk_buff) -> Result {
    let mut ip_header = obj.ip_header(skb);

    bpf_printk!(
        obj,
        c"IP saddr %pi4\n",
        ip_header.saddr() as *const u32 as u64
    );
    bpf_printk!(
        obj,
        c"IP daddr %pi4\n",
        ip_header.daddr() as *const u32 as u64
    );
    if u8::from_be(ip_header.protocol) as u32 == IPPROTO_UDP {
        bpf_printk!(obj, c"UDP packet!");
    }

    Ok(TC_ACT_OK as i32)
}
