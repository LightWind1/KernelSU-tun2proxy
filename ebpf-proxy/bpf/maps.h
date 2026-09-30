/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
#ifndef EP_BPF_MAPS_H
#define EP_BPF_MAPS_H
#include "common.h"
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,65536); __type(key,__u32); __type(value,__u32); } target_uid_map SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,65536); __type(key,__u32); __type(value,__u32); } bypass_uid_map SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1); __type(key,__u32); __type(value,struct ep_policy); } config_map SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_SK_STORAGE); __uint(map_flags,BPF_F_NO_PREALLOC); __type(key,int); __type(value,struct ep_flow_value); } socket_store SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_LRU_HASH); __uint(max_entries,EP_MAX_FLOWS); __type(key,struct ep_flow_key); __type(value,struct ep_flow_value); } flow_map SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries,1024); __uint(map_flags,BPF_F_NO_PREALLOC); __type(key,struct ep_prefix); __type(value,__u32); } bypass_prefix SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,5); __type(key,__u32); __type(value,__u64); } stats_map SEC(".maps");
/* 0 redirect, 1 policy-pass, 2 bypass, 3 metadata-failure, 4 flow-published */
INLINE void count(__u32 key) { __u64 *n=bpf_map_lookup_elem(&stats_map,&key); if(n) __sync_fetch_and_add(n,1); }
#endif
