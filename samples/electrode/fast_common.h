/*
 *  Software Name : fast-paxos
 *  SPDX-FileCopyrightText: Copyright (c) 2022 Orange
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 *  This software is distributed under the
 *  GNU Lesser General Public License v2.1 only.
 *
 *  Author: asd123www <wzz@pku.edu.cn> et al.
 */

#ifndef _FAST_COMMON_H
#define _FAST_COMMON_H

#define ETH_ALEN 6 /* Octets in one ethernet addr	 */

#define CLUSTER_SIZE 3        // need
#define FAST_REPLICA_MAX 100  // max # of replicas.
#define NONFRAG_MAGIC 0x20050318
#define FRAG_MAGIC 0x20101010

#define MAGIC_LEN 4
#define REQUEST_TYPE_LEN 33
#define PREPARE_TYPE_LEN 33
#define PREPAREOK_TYPE_LEN 35
#define MYPREPAREOK_TYPE_LEN 24

#define FAST_PAXOS_DATA_LEN 12
#define BROADCAST_SIGN_BIT (1 << 31)
#define QUORUM_SIZE ((CLUSTER_SIZE + 1) >> 1)
#define QUORUM_BITSET_ENTRY 1024  // must be 2^t

enum ReplicaStatus { STATUS_NORMAL, STATUS_VIEW_CHANGE, STATUS_RECOVERING };

enum {
  FAST_PROG_XDP_HANDLE_PREPARE = 0,
  FAST_PROG_XDP_HANDLE_REQUEST,
  FAST_PROG_XDP_HANDLE_PREPAREOK,
  FAST_PROG_XDP_WRITE_BUFFER,
  FAST_PROG_XDP_PREPARE_REPLY,

  FAST_PROG_XDP_MAX
};

enum {
  FAST_PROG_TC_BROADCAST = 0,

  FAST_PROG_TC_MAX
};

struct paxos_configure {
  __u32 addr;  // ipv4.
  __u16 port;
  char eth[ETH_ALEN];
};

#endif
