#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"
#include <linux/if_arp.h>

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
        void *pos;
};

/* Unified standard 28-byte Ethernet ARP packet layout */
struct ethernet_arp {
        /* Fixed 8-byte Header Fields */
        __be16 ar_hrd;        /* Format of hardware address (Ethernet = 1) */
        __be16 ar_pro;        /* Format of protocol address (IPv4 = 0x0800) */
        unsigned char ar_hln; /* Length of hardware address (6 for MAC) */
        unsigned char ar_pln; /* Length of protocol address (4 for IPv4) */
        __be16 ar_op;         /* ARP opcode (command: 1=Req, 2=Reply) */

        /* Trailing 20-byte Address Block Payload */
        unsigned char ar_sha[ETH_ALEN]; /* Sender hardware (MAC) address */
        __be32        ar_sip;           /* Sender protocol (IPv4) address */
        unsigned char ar_tha[ETH_ALEN]; /* Target hardware (MAC) address */
        __be32        ar_tip;           /* Target protocol (IPv4) address */
} __attribute__((packed));

/* eBPF Map to store established IP-to-MAC pairings */
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 256);
        __type(key, __be32);           // key = sender IP (4 bytes)
        __type(value, __u8[ETH_ALEN]); // value = sender MAC (6 bytes)
} ip_mac_map SEC(".maps");

/* Parse Ethernet layer */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
        struct ethhdr *eth = nh->pos;
        int hdrsize = sizeof(*eth);

        if (nh->pos + hdrsize > data_end)
                return -1;

        nh->pos += hdrsize;
        *ethhdr = eth;

        return eth->h_proto; /* network-byte-order */
}

SEC("xdp")
int xdp_parser_func(struct xdp_md *ctx)
{
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct ethhdr *eth;

        /* Default action */
        __u32 action = XDP_PASS; 

        struct hdr_cursor nh;
        int nh_type;

        /* Start cursor at packet data baseline */
        nh.pos = data;

        bpf_printk("[DEBUG] Packet entered XDP pipeline\n"); 

        /* 1. Parse Ethernet Header */
        nh_type = parse_ethhdr(&nh, data_end, &eth);
        if (nh_type < 0) {
                bpf_printk("[DEBUG] ERR: Ethernet header parsing failed (Bounds check violation)\n");
                goto out;
        }

        /* 2. Isolate ARP traffic */
        if (nh_type != bpf_htons(ETH_P_ARP))
                goto out;

        bpf_printk("[DEBUG] ARP packet detected!\n");
	__u32 pkt_size = (__u32)(data_end - data);
	bpf_printk("[DEBUG] Packet size: %d bytes (need 42)\n", pkt_size);
        /* 3. Direct Parse of the Unified 28-byte Ethernet ARP block */
        struct ethernet_arp *arp = nh.pos;
        if ((void *)(arp + 1) > data_end) {
                bpf_printk("[DEBUG] ERR: ARP full block bounds check failed\n");
                goto out;
        }
        nh.pos = arp + 1; // Securely advance the cursor past the complete layout

        int ar_op = bpf_ntohs(arp->ar_op);
        bpf_printk("[DEBUG] ARP Header parsed successfully. Opcode: %d (%s)\n", 
                   ar_op, (ar_op == ARPOP_REQUEST) ? "Request" : (ar_op == ARPOP_REPLY) ? "Reply" : "Unknown");

        /* 4. Extract targeted metadata fields */
        __be32 sender_ip = arp->ar_sip;
        __u8 *sender_mac = arp->ar_sha;

        bpf_printk("[DEBUG] Processing claim: IP %pI4 matches MAC %02x:%02x:%02x...\n", 
                   &sender_ip, sender_mac[0], sender_mac[1], sender_mac[2]);

        /* 5. Spoofing Detection Logic Engine */
        __u8 *known_mac = bpf_map_lookup_elem(&ip_mac_map, &sender_ip);

        if (known_mac == NULL) {
                bpf_printk("[DEBUG] Map Miss: First time seeing IP %pI4. Learning binding.\n", &sender_ip);
                
                /* Copy the array to stack memory to safely execute the helper update */
                __u8 mac_buffer[ETH_ALEN];
                __builtin_memcpy(mac_buffer, sender_mac, ETH_ALEN);
                
                bpf_map_update_elem(&ip_mac_map, &sender_ip, &mac_buffer, BPF_ANY);
                action = XDP_PASS;
        } else {
                if (__builtin_memcmp(known_mac, sender_mac, ETH_ALEN) != 0) {
                        bpf_printk("!!! ARP SPOOF ALERT !!!\n");
                        bpf_printk("[ALERT] IP %pI4 is target of conflicting claims!\n", &sender_ip);
                        bpf_printk("[ALERT] Trusted Base MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                   known_mac[0], known_mac[1], known_mac[2], known_mac[3], known_mac[4], known_mac[5]);
                        bpf_printk("[ALERT] Malicious New MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                                   sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);
                        
                        /* Change this to XDP_DROP when you want to actively isolate the attacker */
                        action = XDP_PASS; 
                } else {
                        bpf_printk("[DEBUG] Map Hit: Valid match confirmed for IP %pI4\n", &sender_ip);
                }
        }

        out:
            return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
