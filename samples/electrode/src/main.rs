#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

extern crate rex;

use core::mem::{size_of, swap};

use rex::bpf_printk;

use rex::rex_tc;
use rex::rex_xdp;
use rex::sched_cls::*;

use rex::utils::*;
use rex::xdp::*;

pub mod common;
pub mod maps;

use common::*;
use maps::*;

macro_rules! swap_field {
    ($field1:expr, $field2:expr, $size:ident) => {
        for i in 0..$size {
            swap(&mut $field1[i], &mut $field2[i])
        }
    };
}

// NOTE: function calls are not allowed while holding a lock....
// Cause Paxos is in fact a serialized protocol, we limit our to one-core, then
// no lock is needed.

#[rex_xdp]
fn fast_paxos_main(obj: &xdp, ctx: &mut xdp_md) -> Result {
    let header_len =
        size_of::<ethhdr>() + size_of::<iphdr>() + size_of::<udphdr>();
    let ip_header = obj.ip_header(ctx);

    match u8::from_be(ip_header.protocol) as u32 {
        IPPROTO_TCP => {
            // NOTE: currently we only take care of UDP memcached
        }
        IPPROTO_UDP => {
            let port = u16::from_be(obj.udp_header(ctx).dest);
            let payload = &mut ctx.data_slice[header_len..];

            // port check, our process bound to 12345.
            // don't have magic bits...
            if port != 12345 || payload.len() < MAGIC_LEN + size_of::<u64>() {
                return Ok(XDP_PASS as i32);
            }

            // NOTE: currently, we don't support reassembly.
            if payload[0] != 0x18 ||
                payload[1] != 0x03 ||
                payload[2] != 0x05 ||
                payload[3] != 0x20
            {
                return Ok(XDP_PASS as i32);
            }

            // check the message type
            return handle_udp_fast_paxos(obj, ctx);
        }
        _ => {}
    };

    Ok(XDP_PASS as i32)
}

#[rex_tc]
fn fast_broad_cast_main(obj: &sched_cls, skb: &mut __sk_buff) -> Result {
    let mut header_len =
        size_of::<iphdr>() + size_of::<eth_header>() + size_of::<udphdr>();

    // check if the packet is long enough
    if skb.data_slice.len() <= header_len {
        return Ok(TC_ACT_OK as i32);
    }

    let ip_header = obj.ip_header(skb);
    match u8::from_be(ip_header.protocol) as u32 {
        IPPROTO_UDP => {
            // only port 12345 is allowed
            let udp_header = obj.udp_header(skb);
            let port = u16::from_be(udp_header.dest);
            if port != 12345 {
                return Ok(TC_ACT_OK as i32);
            }

            // check for the magic bits
            header_len += MAGIC_LEN + size_of::<u64>();

            if skb.data_slice.len() < header_len {
                bpf_printk!(obj, "data_slice.len() < header_len\n");
                return Ok(TC_ACT_OK as i32);
            }
            let payload = &skb.data_slice;

            if payload[0] != 0x18 ||
                payload[1] != 0x03 ||
                payload[2] != 0x05 ||
                payload[3] != 0x20
            {
                return Ok(TC_ACT_OK as i32);
            }

            return handle_udp_fast_broad_cast(obj, skb);
        }
        _ => {}
    }

    Ok(TC_ACT_OK as i32)
}

#[inline(always)]
fn handle_udp_fast_broad_cast(obj: &sched_cls, skb: &mut __sk_buff) -> Result {
    let header_len = size_of::<ethhdr>() +
        size_of::<iphdr>() +
        size_of::<udphdr>() +
        MAGIC_LEN;
    let payload = &skb.data_slice[header_len..];

    let (type_len_bytes, payload) = payload.split_at(size_of::<u64>());
    let type_str_len = header_len + size_of::<u64>();
    let type_len = u64::from_ne_bytes(type_len_bytes.try_into().unwrap());
    let len = payload.len();

    if type_len >= MTU || len < type_len as usize || len < 5 {
        bpf_printk!(obj, "too small type_len: {}\n", type_len);
        return Ok(TC_ACT_SHOT as i32);
    }

    bpf_printk!(obj, "handle_udp_fast_broad_cast\n");

    // update payload index
    let payload = &payload[type_len as usize..];
    if payload.len() < FAST_PAXOS_DATA_LEN {
        return Ok(TC_ACT_SHOT as i32);
    }

    let msg_view = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
    let is_broadcast = msg_view & BROADCAST_SIGN_BIT;
    let msg_view = msg_view ^ BROADCAST_SIGN_BIT;

    let msg_last_op = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
    let message_type = compute_message_type(payload);

    if message_type == FastProgXdp::FAST_PROG_XDP_HANDLE_PREPARE {
        let idx = msg_last_op & (QUORUM_BITSET_ENTRY - 1);
        let entry = obj
            .bpf_map_lookup_elem(&map_quorum, &idx)
            .ok_or_else(|| 0i32)?;
        if entry.view != msg_view || entry.opnum != msg_last_op {
            entry.view = msg_view;
            entry.opnum = msg_last_op;
            entry.bitset = 0;
        }
    }

    if is_broadcast == 0 {
        return Ok(TC_ACT_OK as i32);
    };

    let zero = 0u32;
    let ctr_state = obj
        .bpf_map_lookup_elem(&map_ctr_state, &zero)
        .ok_or_else(|| 0i32)?;

    let mut id = 0u8;
    let mut nxt;

    {
        let type_str = &mut skb.data_slice[type_str_len..];
        if type_str.starts_with(b"sp") {
            if ctr_state.leader_idx == 0 {
                id = 1;
            }
            nxt = id + 1;
            if ctr_state.leader_idx == nxt as u32 {
                nxt += 1;
            }

            type_str[0] = nxt;
            type_str[1] = b'M';
            if nxt < CLUSTER_SIZE {
                obj.bpf_clone_redirect(skb, skb.ifindex(), 0).unwrap();
            }
        } else {
            id = type_str[0];
            nxt = id + 1;
            if ctr_state.leader_idx == nxt as u32 {
                nxt += 1;
            }
            type_str[0] = nxt;

            if nxt < CLUSTER_SIZE {
                obj.bpf_clone_redirect(skb, skb.ifindex(), 0).unwrap();
            }
        }
    }

    // our version bpf_clone_redirect will update the data reference.
    let type_str = &mut skb.data_slice[type_str_len..];
    type_str[0] = b's';
    type_str[1] = b'p';

    let key = id as u32;
    let replica_info = obj
        .bpf_map_lookup_elem(&MAP_CONFIGURE, &key)
        .ok_or_else(|| TC_ACT_SHOT as i32)?;

    let udp_header = obj.udp_header(skb);
    udp_header.dest = replica_info.port;
    udp_header.check = 0;

    let ip_header = obj.ip_header(skb);
    ip_header.daddr = replica_info.addr;
    ip_header.check = compute_ip_checksum(ip_header);

    let eth_header = obj.eth_header(skb);
    for i in 0..ETH_ALEN {
        eth_header.h_dest[i] = replica_info.eth[i];
    }

    Ok(TC_ACT_OK as i32)
}

#[inline(always)]
fn handle_udp_fast_paxos(obj: &xdp, ctx: &mut xdp_md) -> Result {
    let header_len =
        size_of::<ethhdr>() + size_of::<iphdr>() + size_of::<udphdr>();
    let payload = &mut ctx.data_slice[header_len + MAGIC_LEN..];

    let type_len_bytes = &payload[..size_of::<u64>()];
    let type_len = u64::from_ne_bytes(type_len_bytes.try_into().unwrap());
    bpf_printk!(obj, "type_len: %u\n", type_len);

    // Check the conditions
    let len = payload.len();
    if type_len >= MTU || len < type_len as usize {
        bpf_printk!(obj, "too big type_len: %u\n", type_len);
        return Ok(XDP_PASS as i32);
    }
    let payload_index = header_len + MAGIC_LEN + size_of::<u64>();
    let payload = &mut ctx.data_slice[payload_index..];

    // PrepareMessage in `vr`.
    if len > PREPARE_TYPE_LEN && payload[19..27].starts_with(b"PrepareM") {
        let payload_index = payload_index + PREPARE_TYPE_LEN;
        return handle_prepare(obj, ctx, payload_index);
    }

    // PrepareOK message in `vr`.
    if len > PREPAREOK_TYPE_LEN && payload[19..27].starts_with(b"PrepareO") {
        return handle_prepare_ok(obj, ctx, payload_index);
    }

    if len > MYPREPAREOK_TYPE_LEN && payload[13..17].starts_with(b"MyPr") {
        return handle_prepare_ok(obj, ctx, payload_index);
    }

    return Ok(XDP_PASS as i32);
}

#[inline(always)]
fn compute_message_type(payload: &[u8]) -> FastProgXdp {
    let len = payload.len();

    // if not a valid message, return FAILED
    if len < 13 || !payload[10..12].starts_with(b"vr") {
        return FastProgXdp::FAILED;
    }

    // check the message type
    if len > PREPARE_TYPE_LEN && payload[19..27].starts_with(b"PrepareM") {
        return FastProgXdp::FAST_PROG_XDP_HANDLE_PREPARE;
    } else if len > REQUEST_TYPE_LEN && payload[19..27].starts_with(b"RequestM")
    {
        return FastProgXdp::FAST_PROG_XDP_HANDLE_REQUEST;
    } else if len > PREPAREOK_TYPE_LEN &&
        payload[19..27].starts_with(b"PrepareO")
    {
        return FastProgXdp::FAST_PROG_XDP_HANDLE_PREPAREOK;
    } else if len > MYPREPAREOK_TYPE_LEN && payload[13..17].starts_with(b"MyPr")
    {
        return FastProgXdp::FAST_PROG_XDP_HANDLE_PREPAREOK;
    }

    FastProgXdp::FAILED
}

// This function is ignored in the original implementation.
// #[inline(always)]
// fn handle_request(_obj: &xdp, _ctx: &mut xdp_md) -> Result {
//     Ok(XDP_PASS as i32)
// }

#[inline(always)]
fn handle_prepare(obj: &xdp, ctx: &mut xdp_md, payload_index: usize) -> Result {
    // payload_index = header_len + MAGIC_LEN + size_of::<u64>() +
    // PREPARE_TYPE_LEN point to extra data
    let payload = &mut ctx.data_slice[payload_index..];

    // check the message len
    if payload.len() < FAST_PAXOS_DATA_LEN {
        return Ok(XDP_PASS as i32);
    }

    // NOTE: may update to struct later
    let msg_view = u32::from_ne_bytes(payload[0..4].try_into().unwrap()) as u64;
    let msg_last_op =
        u32::from_ne_bytes(payload[4..8].try_into().unwrap()) as u64;
    let msg_batch_start =
        u32::from_ne_bytes(payload[8..12].try_into().unwrap()) as u64;

    let zero = 0u32;
    let ctr_state = obj
        .bpf_map_lookup_elem(&map_ctr_state, &zero)
        .ok_or_else(|| 0i32)?;

    bpf_printk!(obj, "handle_prepare\n");
    // rare case, not handled properly now.
    if ctr_state.state != ReplicaStatus::STATUS_NORMAL {
        return Ok(XDP_DROP as i32);
    }

    if msg_view < ctr_state.view {
        return Ok(XDP_DROP as i32);
    }

    if msg_view > ctr_state.view {
        return Ok(XDP_PASS as i32);
    }

    // Resend the prepareOK message
    if msg_last_op <= ctr_state.last_op {
        return prepare_fast_reply(obj, ctx, payload_index);
    }

    // rare case, to user-space.
    if msg_batch_start > ctr_state.last_op + 1 {
        return Ok(XDP_PASS as i32);
    }

    ctr_state.last_op = msg_last_op;
    write_buffer(obj, ctx, payload_index)
}

#[inline(always)]
fn write_buffer(obj: &xdp, ctx: &mut xdp_md, payload_index: usize) -> Result {
    // payload_index = header_len + MAGIC_LEN + size_of::<u64>() +
    // PREPARE_TYPE_LEN check the end of the payload
    if ctx.data_slice.len() < payload_index + FAST_PAXOS_DATA_LEN {
        return Ok(XDP_PASS as i32);
    }

    bpf_printk!(obj, "write buffer\n");

    let payload = &mut ctx.data_slice[payload_index + FAST_PAXOS_DATA_LEN..];

    if payload.len() < MAX_DATA_LEN {
        return Ok(XDP_PASS as i32);
    }

    // buffer not enough, offload to user-space.
    // It's easy to avoid cause VR sends `CommitMessage` make followers keep up
    // with the leader.
    let pt = obj
        .bpf_ringbuf_reserve(&map_prepare_buffer, MAX_DATA_LEN as u64, 0)
        .ok_or_else(|| 0i32)?;

    for i in 0..MAX_DATA_LEN {
        pt[i] = payload[i];
        obj.bpf_ringbuf_submit(pt, 0); // guarantee to succeed.
    }

    prepare_fast_reply(obj, ctx, payload_index)
}

#[inline(always)]
fn prepare_fast_reply(
    obj: &xdp,
    ctx: &mut xdp_md,
    payload_index: usize,
) -> Result {
    let mut payload = &mut ctx.data_slice[payload_index..];

    if payload.len() <= FAST_PAXOS_DATA_LEN + size_of::<u64>() {
        return Ok(XDP_PASS as i32);
    }

    bpf_printk!(obj, "prepare_fast_reply\n");

    // read our state
    // may update to function parameter later
    let zero = 0u32;
    let ctr_state = obj
        .bpf_map_lookup_elem(&map_ctr_state, &zero)
        .ok_or_else(|| 0i32)?;

    // struct paxos_configure *leaderInfo =
    // bpf_map_lookup_elem(&map_configure, &ctr_state->leaderIdx);
    let leader_info = obj
        .bpf_map_lookup_elem(&MAP_CONFIGURE, &ctr_state.leader_idx)
        .ok_or_else(|| 0i32)?;

    // Write NONFRAG_MAGIC to the start of the payload
    // FIX: need to check to_ne_bytes or to_be_bytes
    payload[0..4].copy_from_slice(&NONFRAG_MAGIC.to_ne_bytes());
    payload = &mut payload[4..];
    // Write MYPREPAREOK_TYPE_LEN to the new start of the payload
    payload[0..8].copy_from_slice(&MYPREPAREOK_TYPE_LEN.to_ne_bytes());
    payload = &mut payload[8..];

    // change "specpaxos.vr.proto.PrepareMessage" to "specpaxos.vr.MyPrepareOK"
    let replacement: &[u8] = b"MyPrepareOK";
    for (i, &byte) in replacement.iter().enumerate() {
        payload[13 + i] = byte;
    }
    // Move the slice start by MYPREPAREOK_TYPE_LEN
    payload = &mut payload[MYPREPAREOK_TYPE_LEN..];

    // Write the view number, last_op and my_idx to the payload
    payload[0..4].copy_from_slice(&ctr_state.view.to_ne_bytes());
    payload[4..8].copy_from_slice(&payload_index.to_ne_bytes());
    payload[8..12].copy_from_slice(&ctr_state.my_idx.to_ne_bytes());
    // Move the slice start by FAST_PAXOS_DATA_LEN
    payload = &mut payload[FAST_PAXOS_DATA_LEN..];

    if payload.len() < (size_of::<u64>() * 3 + size_of::<u32>()) {
        return Ok(XDP_PASS as i32);
    }

    let size = (size_of::<u64>() * 2 + size_of::<u32>()) as u64;
    // write the len in the protocal, last_op and my_idx to the payload
    payload[0..8].copy_from_slice(&size.to_ne_bytes());
    payload[8..16].copy_from_slice(&ctr_state.view.to_ne_bytes());
    payload[16..24].copy_from_slice(&payload_index.to_ne_bytes());
    // Write ctr_state.my_idx
    payload[24..28].copy_from_slice(&ctr_state.my_idx.to_ne_bytes());
    // move the slice start by size_of::<u64>() * 3 + size_of::<u32>()
    let size = (size_of::<u64>() * 3 + size_of::<u32>()) as u64;
    payload = &mut payload[size as usize..];

    let useless_len = payload.len() as u16;
    let new_len = ctx.data_length() as u16 - useless_len;

    let eth_header = obj.eth_header(ctx);
    swap_field!(eth_header.h_dest, eth_header.h_source, ETH_ALEN);

    // update the port
    let udp_header = obj.udp_header(ctx);
    udp_header.source = udp_header.dest;
    udp_header.dest = leader_info.port;
    udp_header.check = 0;
    udp_header.len = new_len.to_be();

    let ip_header = obj.ip_header(ctx);
    ip_header.tot_len = (new_len + size_of::<iphdr>() as u16).to_be();
    ip_header.saddr = ip_header.daddr;
    ip_header.daddr = leader_info.addr;
    ip_header.check = compute_ip_checksum(ip_header);

    // FIX: need to consider the positive offset
    // but the original code check the length before adjust the tail
    if obj
        .bpf_xdp_adjust_tail(ctx, new_len as i32 - ctx.data_length() as i32)
        .is_err()
    {
        bpf_printk!(obj, "adjust tail failed\n");
        return Ok(XDP_DROP as i32);
    }

    return Ok(XDP_TX as i32);
}

#[inline(always)]
fn handle_prepare_ok(
    obj: &xdp,
    ctx: &mut xdp_md,
    payload_index: usize,
) -> Result {
    // payload_index = header_len + MAGIC_LEN + size_of::<u64>()
    let payload = &mut ctx.data_slice[payload_index..];
    let len = payload.len();

    if len <= FAST_PAXOS_DATA_LEN {
        return Ok(XDP_DROP as i32);
    }

    bpf_printk!(obj, "handle prepareOK\n");

    let msg_view = u32::from_ne_bytes(payload[0..4].try_into().unwrap());
    let msg_opnum = u32::from_ne_bytes(payload[4..8].try_into().unwrap());
    let msg_replica_idx =
        u32::from_ne_bytes(payload[8..12].try_into().unwrap());
    let idx = msg_opnum & (QUORUM_BITSET_ENTRY - 1);

    let entry = obj
        .bpf_map_lookup_elem(&map_quorum, &idx)
        .ok_or_else(|| 0i32)?;

    if entry.view != msg_view || entry.opnum != msg_opnum {
        return Ok(XDP_PASS as i32);
    }

    entry.bitset |= 1 << msg_replica_idx;

    if entry.bitset.count_ones() != QUORUM_SIZE - 1 {
        return Ok(XDP_DROP as i32);
    }

    // *context = (void *)payload + typeLen - data;
    if obj
        .bpf_xdp_adjust_tail(ctx, -(payload_index as i32))
        .is_err()
    {
        bpf_printk!(obj, "adjust tail failed\n");
        return Ok(XDP_DROP as i32);
    }

    return Ok(XDP_PASS as i32);
}
