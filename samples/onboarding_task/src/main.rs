#![no_std]
#![no_main]

extern crate rex;

use rex::bpf_printk;
use rex::rex_xdp;
use rex::utils::*;
use rex::xdp::*;

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
