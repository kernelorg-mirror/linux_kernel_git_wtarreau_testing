/* slhttp.c: a stateless HTTP server implemented as a network driver
 *
 *   This driver was originally copied from dummy.c - W.Tarreau - 20131207
 *
 * GPL etc...
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/rtnetlink.h>
#include <net/rtnetlink.h>
#include <linux/u64_stats_sync.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define LEN_ETH 14
#define LEN_IP  20

struct pcpu_dstats {
	u64			tx_packets;
	u64			tx_bytes;
	u64			tx_dropped;
	u64			rx_packets;
	u64			rx_bytes;
	struct u64_stats_sync	syncp;
};

enum {
	SLH_ST_REQ = 0,
	SLH_ST_LASTACK = 1,
	SLH_ST_ACK_CL_LAST = 2,
	SLH_ST_ACK_CL_FIN = 3,
	/* other states are not as much important */
};

/* This one has to be increased by 16 for each SYN emitted. It does not
 * require any locking as we only increase it to avoid confuse the client
 * in case we get a late packet.
 * We can have an array of a few isns per source port hash if needed.
 */
static u32 isn;

static struct rtnl_link_stats64 *slhttp_get_stats64(struct net_device *dev,
						   struct rtnl_link_stats64 *stats)
{
	int i;

	for_each_possible_cpu(i) {
		const struct pcpu_dstats *dstats;
		u64 tbytes, tpackets, tdropped;
		u64 rbytes, rpackets;
		unsigned int start;

		dstats = per_cpu_ptr(dev->dstats, i);
		do {
			start = u64_stats_fetch_begin_bh(&dstats->syncp);
			tbytes = dstats->tx_bytes;
			tpackets = dstats->tx_packets;
			tdropped = dstats->tx_dropped;
			rpackets = dstats->rx_packets;
			rbytes = dstats->rx_bytes;
		} while (u64_stats_fetch_retry_bh(&dstats->syncp, start));
		stats->tx_bytes += tbytes;
		stats->tx_packets += tpackets;
		stats->tx_dropped += tdropped;
		stats->rx_bytes += rbytes;
		stats->rx_packets += rpackets;
	}
	return stats;
}

/* insert the ethernet header by copying the MAC addresses and protocol from an
 * incoming skb. The addresses are not reversed because we're working with a
 * no-arp device.
 */
static void insert_eth(struct sk_buff *out, struct sk_buff *in)
{
	/* prepend 14 bytes */
	skb_push(out, LEN_ETH);
	memcpy(out->data, in->data, LEN_ETH);
}

/* Insert an IP header in front of an existing SKB. It is assumed that there is enough
 * room. The IP header checksum is computed.
 */
static void insert_ip(struct sk_buff *out, u16 id, u32 saddr, u32 daddr)
{
	/* prepend 20 bytes */
	skb_push(out, LEN_IP);

	/* build IP header */
	*(u16 *)(out->data +  0)  = htons(0x4510);     /* IP, tos 10 */
	*(u16 *)(out->data +  2)  = htons(out->len);   /* IP+TCP real len */
	*(u16 *)(out->data +  4)  = id;                /* same ID as sender */
	*(u16 *)(out->data +  6)  = htons(0x4000);     /* DF, ofs=0 */
	*(u32 *)(out->data +  8)  = htonl(0x40060000); /* TTL=64, TCP, check=0 */
	*(u32 *)(out->data + 12)  = saddr;
	*(u32 *)(out->data + 16)  = daddr;

	/* compute IP checksum. See also ip_send_check(). */
	*(u16 *)(out->data + 10)  = ip_fast_csum(out->data, 5);
}

/* updates the TCP checksum after the packet is ready to go. It is assumed that
 * the IP header is already OK and at the correct place, and that the partial
 * TCP checksum has already been put into skb->csum. The ip_summed flag on the
 * skb is updated.
 */
static void update_tcp_csum(struct sk_buff *out)
{
	*(u16 *)(out->data + LEN_ETH + LEN_IP + 16) =
		tcp_v4_check(out->len - LEN_IP - LEN_ETH,
			     *(u32 *)(out->data + LEN_ETH + 12), /* saddr */
			     *(u32 *)(out->data + LEN_ETH + 16), /* daddr */
			     out->csum);
	out->ip_summed = CHECKSUM_UNNECESSARY;
	out->csum = 0;
}

/* allocate an SKB for an FIN with enough room for prepending ETH + IP in
 * front. The partial checksum is put into ->csum.
 */
static struct sk_buff *build_rst(struct net_device *dev, u16 spt, u16 dpt, u32 seq)
{
	struct sk_buff *out;

	out = netdev_alloc_skb_ip_align(dev, LEN_ETH + LEN_IP + 20);
	if (!out)
		return out;

	skb_reserve(out, LEN_ETH + LEN_IP);

	/* build TCP header */
	*(u16 *)(out->data +  0)  = spt;
	*(u16 *)(out->data +  2)  = dpt;
	*(u32 *)(out->data +  4)  = seq;
	*(u32 *)(out->data +  8)  = 0;
	*(u32 *)(out->data + 12)  = htonl(0x500405b4); /* doff=20, rst, win=1460 */
	*(u32 *)(out->data + 16)  = 0;                 /* check, urgptr */
	skb_put(out, 20);

	/* compute partial TCP checksum */
	out->csum  = csum_partial(out->data, 20, 0);
	return out;
}

/* allocate an SKB for a FIN with enough room for prepending ETH + IP in
 * front. The partial checksum is put into ->csum.
 */
static struct sk_buff *build_fin(struct net_device *dev, u16 spt, u16 dpt, u32 seq, u32 ack)
{
	struct sk_buff *out;

	out = netdev_alloc_skb_ip_align(dev, LEN_ETH + LEN_IP + 20);
	if (!out)
		return out;

	skb_reserve(out, LEN_ETH + LEN_IP);

	/* build TCP header */
	*(u16 *)(out->data +  0)  = spt;
	*(u16 *)(out->data +  2)  = dpt;
	*(u32 *)(out->data +  4)  = seq;
	*(u32 *)(out->data +  8)  = ack;
	*(u32 *)(out->data + 12)  = htonl(0x501105b4); /* doff=20, fin+ack, win=1460 */
	*(u32 *)(out->data + 16)  = 0;                 /* check, urgptr */
	skb_put(out, 20);

	/* compute partial TCP checksum */
	out->csum  = csum_partial(out->data, 20, 0);
	return out;
}

/* allocate an SKB for a SYN/ACK with enough room for prepending ETH + IP in
 * front. The partial checksum is put into ->csum.
 */
static struct sk_buff *build_syn_ack(struct net_device *dev, u16 spt, u16 dpt, u32 seq, u32 ack)
{
	struct sk_buff *out;

	out = netdev_alloc_skb_ip_align(dev, LEN_ETH + LEN_IP + 24);
	if (!out)
		return out;

	skb_reserve(out, LEN_ETH + LEN_IP);

	/* build TCP header */
	*(u16 *)(out->data +  0)  = spt;
	*(u16 *)(out->data +  2)  = dpt;
	*(u32 *)(out->data +  4)  = seq;
	*(u32 *)(out->data +  8)  = ack;
	*(u32 *)(out->data + 12)  = htonl(0x601205b4); /* doff=24, synack, win=1460 */
	*(u32 *)(out->data + 16)  = 0;                 /* check, urgptr */
	*(u32 *)(out->data + 20)  = htonl(0x020405b4); /* opt: MSS=<1460> */
	skb_put(out, 24);

	/* compute partial TCP checksum */
	out->csum  = csum_partial(out->data, 24, 0);
	return out;
}

/* allocate an SKB for a data ACK with enough room for prepending ETH + IP in
 * front. The partial checksum is put into ->csum.
 */
static struct sk_buff *build_data_ack(struct net_device *dev, u16 spt, u16 dpt, u32 seq, u32 ack, u8 flags, u16 data)
{
	struct sk_buff *out;

	out = netdev_alloc_skb_ip_align(dev, LEN_ETH + LEN_IP + 20 + data);
	if (!out)
		return out;

	skb_reserve(out, LEN_ETH + LEN_IP);

	/* build TCP header */
	*(u16 *)(out->data +  0)  = spt;
	*(u16 *)(out->data +  2)  = dpt;
	*(u32 *)(out->data +  4)  = seq;
	*(u32 *)(out->data +  8)  = ack;
	*(u32 *)(out->data + 12)  = htonl(0x501005b4); /* doff=20, ack, win=1460 */
	*(u32 *)(out->data + 13)  |= flags;
	*(u32 *)(out->data + 16)  = 0;                 /* check, urgptr */
	skb_put(out, 20 + data);

	/* compute partial TCP checksum */
	out->csum  = csum_partial(out->data, out->len, 0);
	return out;
}

static void slhttp_reply_to_skb(struct net_device *dev, struct sk_buff *skb, int *op, int *ob)
{
	struct iphdr *ih;
	struct tcphdr *th;
	u32 ack, st;
	u32 ihl;
	u32 thlen;
	struct sk_buff *pkt1, *pkt2;

	skb->protocol = eth_type_trans(skb, dev);
	if (skb->protocol != htons(ETH_P_IP))
		return;

	/* we're on a no-arp device, recover the ethernet header */
	skb_push(skb, 14);

	if (unlikely(!pskb_may_pull(skb, sizeof(*ih))))
		return;

	ih = ip_hdr(skb);
	ihl = ih->ihl * 4;
	if (ihl < sizeof(*ih))
		return;

	if (ih->protocol != 6)
		return;

	th = tcp_hdr(skb);

	thlen = th->doff * 4;
	if (thlen < sizeof(*th))
		return;

	if (!pskb_may_pull(skb, thlen))
		return;

	/* note that all sources and destinations are swapped since we're
	 * responding to a peer.
	 */
	if (th->syn && !th->ack) {
		/* we got a SYN, we return a SYN-ACK with SEQ%16=0 for state REQ */
		pkt1 = build_syn_ack(dev, th->dest, th->source,
		                     htonl((isn << 4) + SLH_ST_REQ - 1),  /* -1 for the SYN */
		                     htonl(ntohl(th->seq) + 1));
		if (!pkt1)
			return;

		insert_ip(pkt1, ih->id, ih->daddr, ih->saddr);

		insert_eth(pkt1, skb);

		update_tcp_csum(pkt1);
		pkt1->protocol = eth_type_trans(pkt1, dev);

		isn++;

		//skb_dst_force(pkt1);
		/* see dev_forward_skb() instead ? => no, does netif_rx() */
		local_bh_disable();
		netif_receive_skb(pkt1);
		local_bh_enable();
		return;
	}

	ack = th->ack_seq;
	st = ack & 15;
	return;
}

static netdev_tx_t slhttp_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);
	int rxp, rxb;

	rxp = 0; rxb = 0;
	slhttp_reply_to_skb(dev, skb, &rxp, &rxb);

	u64_stats_update_begin(&dstats->syncp);
	dstats->tx_packets++;
	dstats->tx_bytes   += skb->len;
	dstats->rx_packets += rxp;
	dstats->rx_bytes   += rxb;
	u64_stats_update_end(&dstats->syncp);

	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}

static int slhttp_dev_init(struct net_device *dev)
{
	dev->dstats = alloc_percpu(struct pcpu_dstats);
	if (!dev->dstats)
		return -ENOMEM;

	return 0;
}

static void slhttp_dev_uninit(struct net_device *dev)
{
	free_percpu(dev->dstats);
}

static int slhttp_change_carrier(struct net_device *dev, bool new_carrier)
{
	if (new_carrier)
		netif_carrier_on(dev);
	else
		netif_carrier_off(dev);
	return 0;
}

static const struct net_device_ops slhttp_netdev_ops = {
	.ndo_init		= slhttp_dev_init,
	.ndo_uninit		= slhttp_dev_uninit,
	.ndo_start_xmit		= slhttp_xmit,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_get_stats64	= slhttp_get_stats64,
	.ndo_change_carrier	= slhttp_change_carrier,
};

static void slhttp_setup(struct net_device *dev)
{
	ether_setup(dev);

	/* Initialize the device structure. */
	dev->netdev_ops = &slhttp_netdev_ops;
	dev->destructor = free_netdev;

	/* Fill in device structure with ethernet-generic values. */
	dev->tx_queue_len  = 0;
	dev->flags        |= IFF_NOARP;
	dev->flags        &= ~IFF_MULTICAST;
	dev->priv_flags   |= IFF_LIVE_ADDR_CHANGE;
	dev->features     |= NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_TSO;
	dev->features     |= NETIF_F_HW_CSUM | NETIF_F_HIGHDMA | NETIF_F_LLTX;
	eth_hw_addr_random(dev);
}

static struct rtnl_link_ops slhttp_link_ops __read_mostly = {
	.kind		= "slhttp",
	.setup		= slhttp_setup,
};

static int __init slhttp_init_one(void)
{
	struct net_device *dev_slhttp;
	int err;

	dev_slhttp = alloc_netdev(0, "slhttp%d", slhttp_setup);
	if (!dev_slhttp)
		return -ENOMEM;

	dev_slhttp->rtnl_link_ops = &slhttp_link_ops;
	err = register_netdevice(dev_slhttp);
	if (err < 0)
		goto err;
	return 0;

err:
	free_netdev(dev_slhttp);
	return err;
}

static int __init slhttp_init_module(void)
{
	int err = 0;

	rtnl_lock();
	err = __rtnl_link_register(&slhttp_link_ops);
	if (err < 0)
		goto out;

	err = slhttp_init_one();
	if (err < 0)
		__rtnl_link_unregister(&slhttp_link_ops);
out:
	rtnl_unlock();
	return err;
}

static void __exit slhttp_cleanup_module(void)
{
	rtnl_link_unregister(&slhttp_link_ops);
}

module_init(slhttp_init_module);
module_exit(slhttp_cleanup_module);
MODULE_LICENSE("GPL");
MODULE_ALIAS_RTNL_LINK("slhttp");
