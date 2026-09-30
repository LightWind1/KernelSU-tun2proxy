/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
#ifndef EP_FLOW_H
#define EP_FLOW_H
#include <linux/types.h>
#define EP_ABI_VERSION 1
#define EP_MAX_FLOWS 16384
struct ep_flow_key {
    __u32 version;
    __u16 family;
    __u8 protocol;
    __u8 reserved;
    __u32 client[4];
    __u32 listener[4];
    __u16 client_port; /* host endian */
    __u16 listener_port;
    __u32 reserved2;
};
struct ep_flow_value {
    __u32 version;
    __u16 family;
    __u16 port; /* host endian */
    __u32 destination[4]; /* network bytes */
    __u32 uid;
    __u32 tgid;
    __u64 cookie;
    __u64 created_ns;
};
struct ep_policy {
    __u32 version;
    __u32 enabled;
    __u32 all_non_bypass;
    __u32 ipv6;
    __u16 port;
    __u16 reserved;
    __u32 ipv4;
    __u64 heartbeat_ns;
    __u64 lease_ns;
};
struct ep_prefix { __u32 prefixlen; __u32 address[4]; };
#endif
