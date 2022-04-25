// SPDX-License-Identifier: GPL-2.0
/* Example of L3 forwarding via XDP and use of bpf FIB lookup helper.
 *
 * Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 */
#define KBUILD_MODNAME "xdp_l3fwd"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>

#define IPV6_FLOWINFO_MASK              cpu_to_be32(0x0FFFFFFF)
#define ENS38_DIP   0xc0a80081                    //192.168.0.129
#define ENS38_DIP_N   0x8100a8c0                    //192.168.0.129
#define ENS38_IFX   3
#define ENS38_DMAC  "\x00\x0c\x29\x3b\xf4\x86"                //00:0c:29:3b:f4:86
#define ENS38_SMAC  "\x00\x0c\x29\x3a\x6c\xc4"            //00:0c:29:3a:6c:c4

#define ENS39_DIP   0xc0a80180   //192.168.1.128
#define ENS39_DIP_N   0x8001a8c0  //192.168.1.128
#define ENS39_IFX   4
#define ENS39_DMAC  "\x00\x0c\x29\x91\x18\xd9" //00:0c:29:91:18:d9
#define ENS39_SMAC  "\x00\x0c\x29\x3a\x6c\xc4" //00:0c:29:3a:6c:c4

//--------------debug print------------------
#define bpf_printk(fmt, ...)                                    \
({                                                              \
	char ____fmt[] = fmt;                                   \
	bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})
//-------------------debug print end---------------

struct bpf_map_def SEC("maps") xdp_l3fwd_ports = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 32,
};

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	u32 check = (__force u32)iph->check;

	check += (__force u32)htons(0x0100);
	iph->check = (__force __sum16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

static __always_inline int xdp_l3fwd_route_out(struct ethhdr *eth,struct iphdr *iph, u32 ifidx, u8* smac, u8* dmac){
	if (!bpf_map_lookup_elem(&xdp_l3fwd_ports, &ifidx))
		return XDP_PASS;

	ip_decrease_ttl(iph);

	__builtin_memcpy(eth->h_dest, dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, smac, ETH_ALEN);
	return bpf_redirect_map(&xdp_l3fwd_ports, ifidx, 0);
}


static __always_inline int xdp_l3fwd_flags(struct xdp_md *ctx, u32 flags)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct bpf_fib_lookup fib_params;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	u16 h_proto;
	u64 nh_off;
	int rc;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));

	h_proto = eth->h_proto;
	if (h_proto == htons(ETH_P_IP)) {
		iph = data + nh_off;

		if (iph + 1 > data_end) //sanity check
			return XDP_DROP;

		if (iph->ttl <= 1)
			return XDP_PASS;

		fib_params.family	= AF_INET;
		fib_params.tos		= iph->tos;
		fib_params.l4_protocol	= iph->protocol;
		fib_params.tot_len	= ntohs(iph->tot_len);
		fib_params.ipv4_src	= iph->saddr;
		fib_params.ipv4_dst	= iph->daddr;
		if (iph->daddr == ENS38_DIP_N ){ //use 'xdpdump -i ens38 -x --rx-capture entry,exit' to dump the packet 
			//bpf_printk("daddr:%lx,ens38 ip=%lx \n", iph->daddr, ENS38_DIP_N);
			return xdp_l3fwd_route_out(eth,iph, ENS38_IFX, ENS38_SMAC, ENS38_DMAC);			
		}	

		if (iph->daddr == ENS39_DIP_N ){ //use xdpdump -i ens39 -x --rx-capture entry,exit to dump the packet 
			//bpf_printk("daddr:%lu, ens39 ip=%lx, redirect to ifx %d\n", iph->daddr, ENS39_DIP_N,ENS39_IFX);		
			return xdp_l3fwd_route_out(eth,iph, ENS39_IFX, ENS39_SMAC, ENS39_DMAC);
		}		

	} else {		
		//bpf_printk("not ip %x,ip should be %x, pass it \n",h_proto,htons(ETH_P_IP) );		
		return XDP_PASS;
	}
	//bpf_printk("daddr:%lx, ens38 ip=%lx, ens39=%lx \n", iph->daddr ,ENS38_DIP_N, ENS39_DIP_N);		
	return XDP_PASS;
}

SEC("xdp_l3fwd")
int xdp_l3fwd_static_prog(struct xdp_md *ctx)
{
	return xdp_l3fwd_flags(ctx, 0);
}

SEC("xdp_l3fwd_direct")
int xdp_l3fwd_direct_prog(struct xdp_md *ctx)
{
	return xdp_l3fwd_flags(ctx, BPF_FIB_LOOKUP_DIRECT);
}

char _license[] SEC("license") = "GPL";
