// SPDX-License-Identifier: GPL-2.0
/* 
 */
#define KBUILD_MODNAME "afp_filter"
#include <stddef.h>
#include <linux/bpf.h>

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/filter.h>


#include <bpf/bpf_helpers.h>

struct flowv4_keys {
//    __u32 src;
    __u32 dst;
/*
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u8 ip_proto:1;
    __u16 vlan0:15;
    __u16 vlan1;
*/    
};

struct pair {
    __u64 packets;
    __u64 bytes;
};

struct bpf_map_def SEC("maps") flow_table_v4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct flowv4_keys),
    .value_size = sizeof(struct pair),
    .max_entries = 32768,
};

unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

//copy from suricrata default bypass_filter.c
/**
 * IPv4 filter
 *
 * \return 0 to drop packet out and -1 to accept it
 */
static __always_inline int ipv4_filter(struct __sk_buff *skb)
{
    __u32 nhoff, verlen;
    struct flowv4_keys tuple;
    struct pair *value;
    __u16 port;
    __u8 ip_proto;

    nhoff = skb->cb[0];
    tuple.dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));
        

#if 0
    if ((tuple.port16[0] == 22) || (tuple.port16[1] == 22))
    {
        __u16 sp = tuple.port16[0];
        //__u16 dp = tuple.port16[1];
        char fmt[] = "Parsed SSH flow: %u %d -> %u\n";
        bpf_trace_printk(fmt, sizeof(fmt), tuple.src, sp, tuple.dst);
    }
#endif
    /* Test if src is in hash */
    value = bpf_map_lookup_elem(&flow_table_v4, &tuple);
    if (value) {
#if 0
        {
            char bfmt[] = "Hit filter flow: dip %lx \n";
            bpf_trace_printk(bfmt, sizeof(bfmt), tuple.dst);
        }
#endif
        value->packets++;
        value->bytes += skb->len;
        return 0;
    }
#if 0
    else{
        char bfmt[] = "Not filter flow: dip %lx \n";
        bpf_trace_printk(bfmt, sizeof(bfmt), tuple.dst);
    }
#endif
    return skb->len;
}

SEC("socket_afp")
int afp_filter_prog(struct __sk_buff *skb)
{
       __u32 nhoff = ETH_HLEN;
    
        __u16 proto = load_half(skb, offsetof(struct ethhdr, h_proto));
        skb->cb[0] = nhoff;
        switch (proto) {
            case ETH_P_IP:
                return ipv4_filter(skb);
            default:
#if 0
                {
                    char fmt[] = "Got proto %u\n";
                    bpf_trace_printk(fmt, sizeof(fmt), h_proto);
                    break;
                }
#else
                break;
#endif
        }
        return -1;

}


char _license[] SEC("license") = "GPL";
