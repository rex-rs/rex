use rex::linux::bpf::bpf_spin_lock;
use rex::map::*;
use rex::rex_map;

use crate::common::*;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct paxos_quorum {
    pub(crate) view: u32,
    pub(crate) opnum: u32,
    pub(crate) bitset: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct paxos_ctr_state {
    pub(crate) state: ReplicaStatus,
    pub(crate) my_idx: u32,
    pub(crate) leader_idx: u32,
    pub(crate) batch_size: u32,
    pub(crate) view: u64,
    pub(crate) last_op: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct paxos_batch {
    counter: u32,
    lock: bpf_spin_lock,
}

#[rex_map]
pub(crate) static MAP_CONFIGURE: RexArrayMap<PaxosConfigure> =
    RexArrayMap::new(FAST_REPLICA_MAX, 0);

#[rex_map]
pub(crate) static map_ctr_state: RexArrayMap<paxos_ctr_state> =
    RexArrayMap::new(1, 0);

#[rex_map]
pub(crate) static map_msg_last_op: RexArrayMap<u64> = RexArrayMap::new(1, 0);

#[rex_map]
pub(crate) static map_quorum: RexArrayMap<paxos_quorum> =
    RexArrayMap::new(QUORUM_BITSET_ENTRY, 0);

#[rex_map]
pub(crate) static batch_context: RexArrayMap<paxos_batch> =
    RexArrayMap::new(1, 0);

#[rex_map]
pub(crate) static map_prepare_buffer: RexRingBuf = RexRingBuf::new(1 << 20, 0);
#[rex_map]
pub(crate) static map_request_buffer: RexRingBuf = RexRingBuf::new(1 << 20, 0);
