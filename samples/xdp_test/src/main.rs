#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

extern crate rex;

use core::net::Ipv4Addr;

use rex::sched_cls::*;
use rex::utils::*;
use rex::xdp::*;
use rex::{rex_printk, rex_tc, rex_xdp};

#[rex_xdp]
fn xdp_rx_filter(obj: &xdp, ctx: &mut xdp_md) -> Result {
    let mut ip_header = obj.ip_header(ctx);

    rex_printk!("IP saddr {}\n", Ipv4Addr::from_bits(*ip_header.saddr()))?;
    rex_printk!("IP daddr {}\n", Ipv4Addr::from_bits(*ip_header.daddr()))?;

    match u8::from_be(ip_header.protocol) as u32 {
        IPPROTO_TCP => {
            rex_printk!("TCP packet!")?;
        }
        IPPROTO_UDP => {
            rex_printk!("UDP packet!")?;
        }
        _ => {}
    };

    Ok(XDP_PASS as i32)
}

#[rex_tc]
fn xdp_tx_filter(obj: &sched_cls, skb: &mut __sk_buff) -> Result {
    let mut ip_header = obj.ip_header(skb);

    rex_printk!("IP saddr {}\n", Ipv4Addr::from_bits(*ip_header.saddr()))?;
    rex_printk!("IP daddr {}\n", Ipv4Addr::from_bits(*ip_header.daddr()))?;
    if u8::from_be(ip_header.protocol) as u32 == IPPROTO_UDP {
        return rex_printk!("UDP packet!");
    }

    Ok(TC_ACT_OK as i32)
}
