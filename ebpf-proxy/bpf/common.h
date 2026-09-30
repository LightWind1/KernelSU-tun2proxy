/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
#ifndef EP_BPF_COMMON_H
#define EP_BPF_COMMON_H
#include <linux/bpf.h>
#include "../include/flow.h"
#define SEC(name) __attribute__((section(name), used))
#define INLINE static __attribute__((always_inline)) inline
#define __uint(name, value) int (*name)[value]
#define __type(name, type) type *name
#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *, const void *, const void *, __u64) = (void *)BPF_FUNC_map_update_elem;
static long (*bpf_map_delete_elem)(void *, const void *) = (void *)BPF_FUNC_map_delete_elem;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *)BPF_FUNC_get_current_uid_gid;
static __u64 (*bpf_get_socket_cookie)(void *) = (void *)BPF_FUNC_get_socket_cookie;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static void *(*bpf_sk_storage_get)(void *, void *, void *, __u64) = (void *)BPF_FUNC_sk_storage_get;
static long (*bpf_sock_ops_cb_flags_set)(struct bpf_sock_ops *, int) = (void *)BPF_FUNC_sock_ops_cb_flags_set;
#endif
