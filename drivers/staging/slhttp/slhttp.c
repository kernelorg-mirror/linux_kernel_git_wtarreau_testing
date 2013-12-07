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
#include <linux/ip.h>

struct pcpu_dstats {
	u64			tx_packets;
	u64			tx_bytes;
	u64			tx_dropped;
	u64			rx_packets;
	u64			rx_bytes;
	struct u64_stats_sync	syncp;
};

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

static netdev_tx_t slhttp_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct pcpu_dstats *dstats = this_cpu_ptr(dev->dstats);
	int len, ihl;
	struct iphdr *ih;
	u32 daddr;
	u32 saddr;

	skb->protocol = eth_type_trans(skb, dev);

	len = skb->len;

	if (skb->protocol != htons(ETH_P_IP))
		goto drop;

	if (unlikely(!pskb_may_pull(skb, sizeof(*ih))))
		goto drop;

	ih = ip_hdr(skb);
	ihl = ih->ihl * 4;
	if (ihl < sizeof(*ih))
		goto drop;

	skb_orphan(skb);

	saddr = ih->saddr;
	daddr = ih->daddr;

	ih->saddr = daddr;
	ih->daddr = saddr;

	/* Before queueing this packet to netif_rx(),
	 * make sure dst is refcounted.
	 */
	skb_dst_force(skb);

	local_bh_disable();
	netif_receive_skb(skb);
	local_bh_enable();

	u64_stats_update_begin(&dstats->syncp);
	dstats->tx_packets++;
	dstats->tx_bytes += skb->len;
	dstats->rx_packets++;
	dstats->rx_bytes += skb->len;
	u64_stats_update_end(&dstats->syncp);
	return NETDEV_TX_OK;

 drop:
	u64_stats_update_begin(&dstats->syncp);
	dstats->tx_dropped++;
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
