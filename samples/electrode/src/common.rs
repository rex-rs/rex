#![allow(unused)]
//
// Software Name : fast-paxos
// SPDX-FileCopyrightText: Copyright (c) 2022 Orange
// SPDX-License-Identifier: LGPL-2.1-only
//
// This software is distributed under the
// GNU Lesser General Public License v2.1 only.
//
// Author: asd123www <wzz@pku.edu.cn> et al.
// Author: asd123www <ruowenq2@illinois.edu> et al.
//

pub(crate) const ETH_ALEN: usize = 6; // Octets in one ethernet addr
pub(crate) const MTU: u64 = 1500;
pub(crate) const MAX_DATA_LEN: usize = 64;

pub(crate) const CLUSTER_SIZE: u8 = 3;
pub(crate) const FAST_REPLICA_MAX: u32 = 100; // max # of replicas.
pub(crate) const NONFRAG_MAGIC: u32 = 0x20050318;
pub(crate) const FRAG_MAGIC: u32 = 0x20101010;

pub(crate) const MAGIC_LEN: usize = 4;
pub(crate) const REQUEST_TYPE_LEN: usize = 33;
pub(crate) const PREPARE_TYPE_LEN: usize = 33;
pub(crate) const PREPAREOK_TYPE_LEN: usize = 35;
pub(crate) const MYPREPAREOK_TYPE_LEN: usize = 24;

pub(crate) const FAST_PAXOS_DATA_LEN: usize = 12;
pub(crate) const BROADCAST_SIGN_BIT: u32 = 1 << 31;
pub(crate) const QUORUM_SIZE: u32 = (CLUSTER_SIZE as u32 + 1) >> 1;
pub(crate) const QUORUM_BITSET_ENTRY: u32 = 1024; // must be 2^t

#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) enum ReplicaStatus {
    STATUS_NORMAL = 0,
    STATUS_VIEW_CHANGE,
    STATUS_RECOVERING,
}

#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) enum FastProgXdp {
    FAILED = -1,
    FAST_PROG_XDP_HANDLE_PREPARE = 0,
    FAST_PROG_XDP_HANDLE_REQUEST,
    FAST_PROG_XDP_HANDLE_PREPAREOK,
    FAST_PROG_XDP_WRITE_BUFFER,
    FAST_PROG_XDP_PREPARE_REPLY,
    FAST_PROG_XDP_MAX,
}

#[derive(Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) enum FastProgTc {
    FAST_PROG_TC_BROADCAST = 0,
    FAST_PROG_TC_MAX,
}

#[repr(C)]
pub(crate) struct PaxosConfigure {
    pub(crate) addr: u32, // ipv4.
    pub(crate) port: u16,
    pub(crate) eth: [u8; ETH_ALEN],
}
