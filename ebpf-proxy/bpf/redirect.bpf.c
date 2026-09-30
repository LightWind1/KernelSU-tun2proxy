/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
#include "maps.h"

INLINE int redirect(struct bpf_sock_addr *ctx, __u16 family) {
    if(ctx->protocol!=IPPROTO_TCP) return 1;
    __u32 uid=(__u32)bpf_get_current_uid_gid(), zero=0;
    if(bpf_map_lookup_elem(&bypass_uid_map,&uid)){count(2);return 1;}
    struct ep_policy *p=bpf_map_lookup_elem(&config_map,&zero);
    __u64 now=bpf_ktime_get_ns();
    if(!p || p->version!=EP_ABI_VERSION || !p->enabled ||
       now-p->heartbeat_ns>p->lease_ns || (family==AF_INET6&&!p->ipv6)) return 1;
    if(!p->all_non_bypass&&!bpf_map_lookup_elem(&target_uid_map,&uid)){count(1);return 1;}
    struct ep_prefix prefix={.prefixlen=128};
    if(family==AF_INET) {
        /* Map IPv4 CIDRs to ::ffff:a.b.c.d for the shared LPM ABI. */
        prefix.address[2]=__builtin_bswap32(0xffff);
        prefix.address[3]=ctx->user_ip4;
    } else {prefix.address[0]=ctx->user_ip6[0];prefix.address[1]=ctx->user_ip6[1];prefix.address[2]=ctx->user_ip6[2];prefix.address[3]=ctx->user_ip6[3];}
    if(family==AF_INET){if(bpf_map_lookup_elem(&bypass_prefix,&prefix)){count(2);return 1;}}
    else if(bpf_map_lookup_elem(&bypass_prefix6,&prefix)){count(2);return 1;}
    struct ep_flow_value v={.version=EP_ABI_VERSION,.family=family,
        .port=bpf_ntohs((__u16)ctx->user_port),.uid=uid,
        .cookie=bpf_get_socket_cookie(ctx),.created_ns=now};
    if(family==AF_INET) v.destination[0]=ctx->user_ip4;
    else {v.destination[0]=ctx->user_ip6[0];v.destination[1]=ctx->user_ip6[1];v.destination[2]=ctx->user_ip6[2];v.destination[3]=ctx->user_ip6[3];}
    if(!v.cookie||!ctx->sk){count(3);return 1;}
    struct ep_flow_value *stored=bpf_sk_storage_get(&socket_store,ctx->sk,&v,BPF_SK_STORAGE_GET_F_CREATE);
    if(!stored){count(3);return 1;}
    *stored=v;
    if(family==AF_INET) ctx->user_ip4=p->ipv4;
    else {
        ctx->user_ip6[0]=0;ctx->user_ip6[1]=0;ctx->user_ip6[2]=0;
        ctx->user_ip6[3]=__builtin_bswap32(1);
    }
    ctx->user_port=bpf_htons(p->port);
    count(0);return 1;
}
SEC("cgroup/connect4") int ep_connect4(struct bpf_sock_addr *ctx) { return redirect(ctx,AF_INET); }
SEC("cgroup/connect6") int ep_connect6(struct bpf_sock_addr *ctx) { return redirect(ctx,AF_INET6); }

SEC("sockops") int ep_sockops(struct bpf_sock_ops *ctx) {
    if(!ctx->sk || (ctx->family!=AF_INET&&ctx->family!=AF_INET6)) return 1;
    if(ctx->op!=BPF_SOCK_OPS_TCP_CONNECT_CB && ctx->op!=BPF_SOCK_OPS_STATE_CB) return 1;
    struct ep_flow_value *v=bpf_sk_storage_get(&socket_store,ctx->sk,0,0);
    if(!v) return 1;
    struct ep_flow_key key={.version=EP_ABI_VERSION,.family=ctx->family,
        .protocol=IPPROTO_TCP,.client_port=ctx->local_port,
        .listener_port=bpf_ntohl(ctx->remote_port)};
    if(ctx->family==AF_INET){key.client[0]=ctx->local_ip4;key.listener[0]=ctx->remote_ip4;}
    else{key.client[0]=ctx->local_ip6[0];key.client[1]=ctx->local_ip6[1];key.client[2]=ctx->local_ip6[2];key.client[3]=ctx->local_ip6[3];key.listener[0]=ctx->remote_ip6[0];key.listener[1]=ctx->remote_ip6[1];key.listener[2]=ctx->remote_ip6[2];key.listener[3]=ctx->remote_ip6[3];}
    if(ctx->op==BPF_SOCK_OPS_TCP_CONNECT_CB) {
        if(bpf_map_update_elem(&flow_map,&key,v,BPF_ANY)) count(3);
        else count(4);
        bpf_sock_ops_cb_flags_set(ctx,ctx->bpf_sock_ops_cb_flags|BPF_SOCK_OPS_STATE_CB_FLAG);
    } else if(ctx->args[1]==7 /* TCP_CLOSE */) {
        struct ep_flow_value *current=bpf_map_lookup_elem(&flow_map,&key);
        if(current&&current->cookie==v->cookie) bpf_map_delete_elem(&flow_map,&key);
    }
    return 1;
}
char _license[] SEC("license")="Dual MIT/GPL";
