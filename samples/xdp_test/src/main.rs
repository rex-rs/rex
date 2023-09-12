#![no_std]
#![no_main]
#![allow(non_camel_case_types)]

extern crate inner_unikernel_rt;

use core::ffi::c_void;
use core::mem::size_of;
use core::num::Wrapping;
use inner_unikernel_rt::bpf_printk;
use inner_unikernel_rt::entry_link;
use inner_unikernel_rt::linux::bpf::{
    BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_PERCPU_ARRAY,
};
use inner_unikernel_rt::map::IUMap;
use inner_unikernel_rt::sched_cls::*;
use inner_unikernel_rt::utils::*;
use inner_unikernel_rt::xdp::*;
use inner_unikernel_rt::FieldTransmute;
use inner_unikernel_rt::MAP_DEF;

const BMC_MAX_PACKET_LENGTH: usize = 1500;
const BMC_CACHE_ENTRY_COUNT: u32 = 250000;
const BMC_MAX_KEY_LENGTH: usize = 230;
const BMC_MAX_VAL_LENGTH: usize = 1000;
const BMC_MAX_ADDITIONAL_PAYLOAD_BYTES: usize = 53;
const BMC_MAX_CACHE_DATA_SIZE: usize =
    BMC_MAX_KEY_LENGTH + BMC_MAX_VAL_LENGTH + BMC_MAX_ADDITIONAL_PAYLOAD_BYTES;
const BMC_MAX_KEY_IN_MULTIGET: u32 = 30;
const BMC_MAX_KEY_IN_PACKET: u32 = BMC_MAX_KEY_IN_MULTIGET;

const FNV_OFFSET_BASIS_32: Wrapping<u32> = Wrapping(2166136261);
const FNV_PRIME_32: u32 = 16777619;
const ETH_ALEN: usize = 6;

#[derive(FieldTransmute)]
#[repr(C, packed)]
pub struct memcached_udp_header {
    request_id: u16,
    seq_num: u16,
    num_dgram: u16,
    unused: u16,
}

#[derive(FieldTransmute)]
#[repr(C, packed)]
pub struct eth_header {
    pub h_dest: [u8; ETH_ALEN],
    pub h_source: [u8; ETH_ALEN],
    pub h_proto: u16,
}

#[repr(C)]
pub struct bmc_cache_entry {
    // struct bpf_spin_lock lock;
    pub len: u32,
    pub valid: u8,
    pub hash: u32,
    pub data: [u8; BMC_MAX_PACKET_LENGTH],
}

#[repr(C)]
struct memcached_key {
    hash: Wrapping<u32>,
    data: [u8; BMC_MAX_KEY_LENGTH],
    len: u32,
}

struct parsing_context {
    key_count: u32,
    current_key: u32,
    read_pkt_offset: u8,
    write_pkt_offset: u8,
}

MAP_DEF!(map_hash, u32, i64, BPF_MAP_TYPE_HASH, 1024, 0);
MAP_DEF!(map_array, u32, u64, BPF_MAP_TYPE_ARRAY, 256, 0);
MAP_DEF!(
    map_kcache,
    u32,
    bmc_cache_entry,
    BPF_MAP_TYPE_ARRAY,
    BMC_CACHE_ENTRY_COUNT,
    0
);
MAP_DEF!(
    map_keys,
    u32,
    memcached_key,
    BPF_MAP_TYPE_PERCPU_ARRAY,
    BMC_MAX_KEY_IN_PACKET,
    0
);

fn hash_key(obj: &xdp, ctx: &xdp_md, pctx: &mut parsing_context, payload: &[u8]) -> u32 {
    let mut key = match obj.bpf_map_lookup_elem(&map_keys, pctx.key_count) {
        None => return XDP_PASS,
        Some(k) => k,
    };

    key.hash = FNV_OFFSET_BASIS_32;

    let (mut off, mut done_parsing, mut key_len) = (0usize, 0u32, 0u8);

    while off < BMC_MAX_KEY_LENGTH + 1 && pctx.read_pkt_offset as usize + off + 1 <= ctx.data_length
    {
        if (payload[off] == b'\r') {
            done_parsing = 1;
            break;
        } else if (payload[off] == b' ') {
            break;
        } else if (payload[off] != b' ') {
            key.hash ^= payload[off] as u32;
            key.hash *= FNV_PRIME_32;
            key_len += 1;
        }
        off += 1;
    }

    // no key found
    if (key_len == 0 || key_len as usize > BMC_MAX_KEY_LENGTH) {
        return XDP_PASS;
    }

    // get the cache entry
    let cache_idx: u32 = key.hash.0 % BMC_CACHE_ENTRY_COUNT;
    let entry = match obj.bpf_map_lookup_elem(&map_kcache, cache_idx) {
        // should never happen
        None => return XDP_PASS,
        Some(e) => e,
    };
    // TODO: should have lock here bpf_spin_lock(&entry->lock);

    // potential cache hit
    if (entry.valid == 1 && entry.hash == key.hash.0) {
        // TODO: bpf_spin_unlock(&entry.lock);
        for i in pctx.read_pkt_offset..key_len {
            // end of packet
            if (i as usize + 1 > ctx.data_length) {
                break;
            }
            key.data[i as usize] = payload[i as usize];
        }
        key.len = key_len as u32;
        pctx.key_count += 1;
    } else {
        // cache miss
        // TODO: bpf_spin_unlock(&entry.lock);
        // TODO: add stats here
        // 		bpf_spin_unlock(&entry->lock);
        // 		struct bmc_stats *stats =
        // 			bpf_map_lookup_elem(&map_stats, &zero);
        // 		if (!stats) {
        // 			return XDP_PASS;
        // 		}
        // 		stats->miss_count++;
    }

    if (done_parsing == 1) {
        if (pctx.key_count > 0) {
            return prepare_packet(obj, ctx, payload);
        }
    } else {
        // process more keys
        off += 1;
        pctx.read_pkt_offset += off as u8;
        hash_key(obj, ctx, pctx, payload);
    }

    XDP_PASS
}

fn prepare_packet(obj: &xdp, ctx: &xdp_md, payload: &[u8]) -> u32 {
    // exchange src and dst ip and mac

    // if (payload >= data_end || old_payload + 1 >= data_end)
    // 	return XDP_PASS;
    //
    // // use old headers as a base; then update addresses and ports to create the new headers
    // memmove(eth, old_data,
    // 	sizeof(*eth) + sizeof(*ip) + sizeof(*udp) +
    // 		sizeof(*memcached_udp_hdr));
    //
    let mut eth_tmp = [0u8; ETH_ALEN];
    let mut ip_tmp: u32;
    let mut port_tmp: u16;
    let mut eth_header = eth_header::new(&ctx.data_slice[0..14]);

    // TODO: use memcpy
    // obj.memcpy(&mut eth_tmp, &eth_header.h_source as c_void, 6);
    // obj.memcpy(&eth_header.h_source, &eth_header.h_dest, 6);
    // obj.memcpy(&eth_header.h_dest, &eth_tmp, 6);
    // __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    // __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    // __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    let ip_header_mut = obj.ip_header_mut(ctx);
    let udp_header_mut = obj.udp_header_mut(ctx);
    ip_tmp = ip_header_mut.saddr;
    ip_header_mut.saddr = ip_header_mut.daddr;
    ip_header_mut.daddr = ip_tmp;

    port_tmp = udp_header_mut.source;
    udp_header_mut.source = udp_header_mut.dest;
    udp_header_mut.dest = port_tmp;

    write_pkt_reply(obj, ctx, payload)
}

fn write_pkt_reply(obj: &xdp, ctx: &xdp_md, payload: &[u8]) -> u32 {
    return XDP_PASS;
}

fn xdp_rx_filter_fn(obj: &xdp, ctx: &xdp_md) -> u32 {
    let header_len = size_of::<ethhdr>()
        + size_of::<iphdr>()
        + size_of::<udphdr>()
        + size_of::<memcached_udp_header>();
    let eth_header = eth_header::new(&ctx.data_slice[0..14]);
    let ip_header = obj.ip_header(ctx);

    match u8::from_be(ip_header.protocol) as u32 {
        IPPROTO_TCP => {
            // NOTE: currently we only take care of UDP memcached
        }
        IPPROTO_UDP => {
            let udp_header = obj.udp_header(ctx);
            let port = u16::from_be(obj.udp_header(ctx).dest);
            let payload = &ctx.data_slice[header_len..];

            // check if using the memcached port
            // check if the payload has enough space for a memcached request
            if (port != 11211 || payload.len() < 4) {
                return XDP_PASS;
            }

            // check if a get command
            if !payload.starts_with(b"get ") {
                return XDP_PASS;
            }

            let mut off = 4;
            // move offset to the start of the first key
            while (off < BMC_MAX_PACKET_LENGTH && off + 1 < payload.len() && payload[off] == b' ') {
                off += 1;
            }
            off += header_len;

            let mut pctx = parsing_context {
                key_count: 0,
                current_key: 0,
                read_pkt_offset: off as u8,
                write_pkt_offset: 0,
            };

            // bpf_printk!(obj, "offset is %d\n", off as u64);
            // hash the key
            match hash_key(obj, ctx, &mut pctx, payload) {
                XDP_PASS => return XDP_PASS,
                _ => (),
            }
        }
        _ => {}
    };

    XDP_PASS
}

#[inline(always)]
fn bmc_update_cache(obj: &sched_cls, skb: &__sk_buff, payload: &[u8], header_len: usize) -> u32 {
    let mut hash = FNV_OFFSET_BASIS_32;

    let mut off = 0usize;
    while (off < BMC_MAX_KEY_LENGTH
        && header_len + off + 1 <= skb.len as usize
        && payload[off] != b' ')
    {
        off += 1;
        hash ^= payload[off] as u32;
        hash *= FNV_PRIME_32;
    }
    let cache_idx: u32 = hash.0 % BMC_CACHE_ENTRY_COUNT;
    let bmc_cache_entry = match obj.bpf_map_lookup_elem(&map_kcache, cache_idx) {
        None => return TC_ACT_OK,
        Some(e) => e,
    };
    bpf_printk!(obj, "key hash function\n");

    //   NOTE:  bpf_spin_lock(&entry->lock);

    // check if the cache is up-to-date
    if (bmc_cache_entry.valid == 1 || bmc_cache_entry.hash == hash.0) {
        let mut diff = 0;
        off = 0;
        while off < BMC_MAX_KEY_LENGTH
            && header_len + off + 1 <= skb.len as usize
            && (payload[off] != b' ' || bmc_cache_entry.data[off] != b' ')
        {
            if (bmc_cache_entry.data[off] != payload[off]) {
                diff = 1;
                break;
            }
            off += 1;
        }

        // cache is up-to-date, no need to update
        if diff == 0 {
            //NOTE: bpf_spin_unlock(&entry->lock);
            bpf_printk!(obj, "cache is up-to-date\n");
            return TC_ACT_OK;
        }
    }

    // cache is not up-to-date, update it

    let (mut count, mut i) = (0usize, 0usize);
    bmc_cache_entry.len = 0;
    while i < BMC_MAX_CACHE_DATA_SIZE && header_len + i + 1 <= skb.len as usize && count < 2 {
        bmc_cache_entry.data[i] = payload[i];
        bmc_cache_entry.len += 1;
        if (payload[i] == b'\n') {
            count += 1;
        }
        i += 1;
    }

    // finished copying
    if count == 2 {
        bpf_printk!(obj, "copying key success\n");
        bmc_cache_entry.valid = 1;
        bmc_cache_entry.hash = hash.0;
        // TODO: bpf_spin_unlock(&entry->lock);
        // TODO: add stats here
    } else {
        // TODO: bpf_spin_unlock(&entry->lock);
    }

    TC_ACT_OK
}
fn xdp_tx_filter_fn(obj: &sched_cls, skb: &__sk_buff) -> u32 {
    let mut ret = TC_ACT_OK;

    let header_len = size_of::<iphdr>()
        + size_of::<eth_header>()
        + size_of::<udphdr>()
        + size_of::<memcached_udp_header>();

    // check if the packet is long enough
    if (skb.len as usize <= header_len) {
        return TC_ACT_OK;
    }

    let eth_header = eth_header::new(&skb.data_slice[0..14]);
    let ip_header = obj.ip_header(skb);

    match u8::from_be(ip_header.protocol) as u32 {
        IPPROTO_UDP => {
            let udp_header = obj.udp_header(skb);
            let src_port = u16::from_be(udp_header.source);
            let payload = &skb.data_slice[header_len..];

            // confirm if using the memcached port
            if (src_port != 11211 && payload.len() < 6) {
                return TC_ACT_OK;
            }

            // check if a VALUE command
            if !payload.starts_with(b"VALUE ") {
                return TC_ACT_OK;
            }

            // update cache map based on the packet
            ret = match bmc_update_cache(obj, skb, &payload[6..], header_len) {
                TC_ACT_OK => return TC_ACT_OK,
                e => e,
            };
        }
        _ => {}
    }

    ret
}
#[entry_link(inner_unikernel/xdp)]
static PROG1: xdp = xdp::new(xdp_rx_filter_fn, "xdp_rx_filter", BPF_PROG_TYPE_XDP as u64);

#[entry_link(inner_unikernel/tc)]
static PROG2: sched_cls = sched_cls::new(
    xdp_tx_filter_fn,
    "xdp_tx_filter",
    BPF_PROG_TYPE_SCHED_CLS as u64,
);
