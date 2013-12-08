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
	SLH_ST_REQ           = 0,
	SLH_ST_LASTACK       = 1,
	/* data states for close mode: up to 8 packets may be sent (1 + 7 extra) */
	SLH_ST_ACK_CL_LAST_7 = 2,
	SLH_ST_ACK_CL_LAST_6 = 3,
	SLH_ST_ACK_CL_LAST_5 = 4,
	SLH_ST_ACK_CL_LAST_4 = 5,
	SLH_ST_ACK_CL_LAST_3 = 6,
	SLH_ST_ACK_CL_LAST_2 = 7,
	SLH_ST_ACK_CL_LAST_1 = 8,
	SLH_ST_ACK_CL_LAST   = 9,  /* last packetd ACKed, send FIN */
	SLH_ST_ACK_CL_FIN    = 10, /* must absolutely equal SLH_ST_ACK_CL_LAST + 1 */
	/* the last states must be the ones for the keep-alive mode, because we
	 * want them to count +1 modulo 16 and automatically loop to 0, so up to
	 * 6 packets may be sent (1 + 5 extra).
	 */
	SLH_ST_ACK_KA_LAST_5 = 11,
	SLH_ST_ACK_KA_LAST_4 = 12,
	SLH_ST_ACK_KA_LAST_3 = 13,
	SLH_ST_ACK_KA_LAST_2 = 14,
	SLH_ST_ACK_KA_LAST_1 = 15,
};

/* flags used to build our return packets */
enum {
	FLG_FIN = 1,
	FLG_SYN = 2,
	FLG_RST = 4,
	FLG_PSH = 8,
	FLG_ACK = 16,
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
 * front. The partial checksum is put into ->csum. skb->tail points to where
 * the data can be copied.
 */
static struct sk_buff *build_data_ack(struct net_device *dev, u16 spt, u16 dpt, u32 seq, u32 ack, u32 flags, u32 data)
{
	struct sk_buff *out;

	out = netdev_alloc_skb_ip_align(dev, LEN_ETH + LEN_IP + 20 + data);
	if (!out)
		return out;

	//printk(KERN_ERR "@%d: skb(%p)=%ld+%ld+%ld=%ld (%d requested)\n",
	//       __LINE__,
	//       out,
	//       out->data - out->head,
	//       skb_tail_pointer(out) - out->data,
	//       skb_end_pointer(out) - skb_tail_pointer(out),
	//       skb_end_pointer(out) - out->head,
	//       LEN_ETH + LEN_IP + 20 + data);

	skb_reserve(out, LEN_ETH + LEN_IP);

	/* build TCP header */
	*(u16 *)(out->data +  0)  = spt;
	*(u16 *)(out->data +  2)  = dpt;
	*(u32 *)(out->data +  4)  = seq;
	*(u32 *)(out->data +  8)  = ack;
	*(u32 *)(out->data + 12)  = htonl(0x501005b4); /* doff=20, ack, win=1460 */
	*(u32 *)(out->data + 13)  |= flags;
	*(u32 *)(out->data + 16)  = 0;                 /* check, urgptr */
	skb_put(out, 20);

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
	u32 datalen;
	const char *dataptr;
	struct sk_buff *pkt1;

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

	/* retrieve the next state requested by the peer */
	dataptr = (u8 *)th + thlen;
	datalen = skb->data + skb->len - (u8 *)dataptr;

	ack = th->ack_seq;
	st = ntohl(ack) & 15;

	//printk(KERN_ERR "seq=%d ack_seq=%d syn=%d ack=%d fin=%d rst=%d st=%d\n",
	//       ntohl(th->seq), ntohl(th->ack_seq), th->syn,
	//       th->ack, th->fin, th->rst, st);

	/* note that all sources and destinations are swapped since we're
	 * responding to a peer.
	 */
	if (th->syn && !th->ack) {
		/* we got a SYN, we return a SYN-ACK with SEQ%16=0 for state REQ */
		pkt1 = build_syn_ack(dev, th->dest, th->source,
		                     htonl((isn << 4) + SLH_ST_REQ - 1),  /* -1 for the SYN */
		                     htonl(ntohl(th->seq) + 1));
		isn++;
	}
	else if (th->rst) {
		/* never reply anything to an RST */
		return;
	}
	else if (!th->ack) {
		/* we want an ACK here */
		goto send_rst;
	}
	else if (st == SLH_ST_REQ) {
		int ka   = 0;  /* 0 = close, 1 = keep-alive */
		int size = 0;  /* requested object size */
		int ver  = 0;  /* 0 = HTTP/1.0, 1 = HTTP/1.1 */
		int budget;    /* how much left in the first packet */
		int sizelen;   /* bytes needed to encode <size> */
		int hdrlen;    /* header len for the first packet */
		int pkt1_size = 0;   /* data in the first packet */
		int nb_data_pkt = 0; /* # of extra packets */
		int final_state;
		int pad = 0;   /* amount of padding to add */
		int fin = 0;   /* send fin */
		const char *parse;
		unsigned char *out;

		if (!datalen) {
			if (th->fin) {
				/* return a FIN and go to the LASTACK state on FIN */
				pkt1 = build_fin(dev, th->dest, th->source,
						 ack, htonl(ntohl(th->seq) + 1));
				goto send_ip;
			}
			/* silently drop the connection ACK and the
			 * keep-alive ACK on end of data transfer.
			 */
			return;
		}

		/* we need enough space for the response */
		if (ntohs(th->window) < 1460)
			return;

		if (datalen < 15 || /* "GET / HTTP/1.0\n", at least supports telnet */
		    *(u32 *)dataptr != ntohl(0x47455420) || dataptr[4] != '/') // "GET /"
			goto send_rst;

		/* parse the request */

		/* first, "/k/something" requests keep-alive */
		parse = dataptr + 5;
		if (*parse == 'k') {
			ka = !th->fin;  /* no keep-alive if FIN present */
			parse += 1 + (parse[1] == '/');
		}

		/* get requested object size */
		while (parse < dataptr + datalen && (unsigned char)(*parse - '0') <= 9) {
			size = (size * 10) + (*parse - '0');
			parse++;
		}

		if (size < 10)
			sizelen = 1;
		else if (size < 100)
			sizelen = 2;
		else if (size < 1000)
			sizelen = 3;
		else if (size < 10000)
			sizelen = 4;
		else
			sizelen = 5;

		/* check HTTP version */
		while (parse < dataptr + datalen && *parse != ' ' && *parse != '\r' && *parse != '\n')
			parse++;

		if (parse + 9 <= dataptr + datalen && memcmp(parse, " HTTP/1.", 8) == 0) {
			ver = parse[8] == '1';
			parse += 9;
		}

		/* Now let's see how we'll build the response. We have to send :
		 *   "HTTP/1.x 200 OK\r\n"        => 17 chars
		 *   "Connection: keep-alive\r\n" => 24 chars when in 1.0 with keep-alive
		 *   "Content-length: x\r\n"      => 19 chars for 0..9, 20 for 10..99,
		 *                                   21 for 100..999, 22 for 1000..9999,
		 *                                   23 for 10000..99999, RST above
		 *   "X-Pad:xxxxx\r\n"            => 8..23 (0..15 spaces) if padding is required
		 *   "\r\n"                       => 2 chars
		 *
		 * Total:
		 *   - 17+24+2+18+sizelen in 1.0 + keep-alive = 61+sizelen
		 *   - 17+2+18+sizelen in 1.1 or 1.0+close    = 37+sizelen
		 *   - plus up to 23 if padding is required =>
		 *        61 + 5 + 23 = 89 in 1.0 + keep-alive
		 *        37 + 5 + 23 = 65 otherwise
		 *
		 * We need to adjust the amount of output data so that the sum
		 * of data emitted modulo 16 equals :
		 *   - 16 - #extra_packets if responding in keep-alive as we
		 *     want to get back to this state after #extra packets ;
		 *   - 0 if doing keep-alive with a single packet (same as above)
		 *   - 0 if we're on the last packet and FIN was present, because
		 *     we're going to emit a FIN which counts as one and will go to
		 *     LASTACK ;
		 *   - CL_LAST if we're emitting the last packet + a FIN so that
		 *     the sum equals ACK_CL_FIN
		 *
		 * The data in the first packet may not be larger than 1370 bytes
		 * so that we still have up to 90 bytes to the headers.
		 */

		budget  = 1460;
		hdrlen  = 0;
		hdrlen += 17;           /* status line */
		hdrlen += 2;            /* CRLF */
		hdrlen += 18 + sizelen; /* content-length */
		if (!ver && ka)         /* connection */
			hdrlen += 24;

		budget -= hdrlen + 23;  /* if X-Pad is needed */

		pkt1_size = size;
		if (pkt1_size > budget) {
			int max_pkt;

			/* need more than one packet. Each other packet will be
			 * 1457 bytes (=1 modulo 16). The first one will carry
			 * the complement.
			 *
			 * This means that there are a number of sizes we cannot
			 * handle, they're all those which add more than budget to
			 * multiples of 1457. We don't care much, we simply truncate
			 * the size so that the first packet can be sent and that we
			 * don't send too many packets.
			 */
			if (ka || th->fin)
				max_pkt = 5; /* 5 data states in the keep-alive chain */
			else
				max_pkt = 7; /* 7 data states in the close chain */

			nb_data_pkt = size / 1457;

			if (nb_data_pkt > max_pkt) {
				nb_data_pkt = max_pkt;
				size = nb_data_pkt * 1457 + budget;
			}

			pkt1_size = size - (nb_data_pkt * 1457);
			if (pkt1_size > budget) {
				pkt1_size = budget;
				size = pkt1_size + nb_data_pkt * 1457;
			}

			//printk(KERN_ERR "@%d: Preparing to send %d bytes, with a first pkt of %d hdr + %d data (budget %d) and %d packets of 1457 (%d max). ka=%d ver=%d sizelen=%d\n", __LINE__,
			//       size, hdrlen, pkt1_size, budget, nb_data_pkt, max_pkt, ka, ver, sizelen);
		}

		/* We don't consider our FIN here. It equals one byte but since
		 * our post-FIN states are exactly the previous one plus 1, we
		 * must ignore it for now. However, we want to go to the LASTACK
		 * state if the client has presented a FIN first, so this is
		 * equivalent to going into ST_REQ without FIN.
		 */
		if (ka || th->fin)
			final_state = SLH_ST_REQ;
		else
			final_state = SLH_ST_ACK_CL_LAST;

		/* remember, each packet counts 1 step */
		pad  = final_state - st - nb_data_pkt;
		pad -= hdrlen + pkt1_size;
		pad  = pad & 15;
		/* pad is the size we need to add using the "X-Pad" header */

		//printk(KERN_ERR "@%d: Preparing to send %d bytes, with a first pkt of %d hdr + %d pad + %d data (budget %d) and %d packets of 1457. ka=%d ver=%d finst=%d, sizelen=%d\n", __LINE__,
		//       size, hdrlen, pad, pkt1_size, budget, nb_data_pkt, ka, ver, final_state, sizelen);

		/* now it's getting tricky. We ack the peer's possible FIN only
		 * if we're in the last packet so that it continues sending it.
		 * We send a FIN if we're on the last packet and we have a FIN
		 * in the request, or if the final state is ACK_CL_LAST because
		 * we're sending the last packet of a close transfer.
		 */
		fin = !nb_data_pkt && (th->fin || final_state == SLH_ST_ACK_CL_LAST);

		pkt1 = build_data_ack(dev, th->dest, th->source,
				      ack,
				      htonl(ntohl(th->seq) + datalen + (nb_data_pkt ? 0 : th->fin)),
				      FLG_PSH + (fin ? FLG_FIN : 0),
				      hdrlen + pkt1_size + 24 /* pad */);
		if (!pkt1)
			return;

		out = skb_tail_pointer(pkt1);
		out += snprintf(out, hdrlen,
		                "HTTP/1.%d 200 OK\r\nContent-length: %d\r\n",
		                ver, size);

		if (!ver && ka) {
			memcpy(out, "Connection: keep-alive\r\n", 24);
			out += 24;
		}

		if (pad) {
			/* we have 8 non-reductible bytes */
			memcpy(out, "X-Pad: 0123456789abcde", 22);
			out[((pad - 8) & 15) + 6] = '\r';
			out[((pad - 8) & 15) + 7] = '\n';
			out += ((pad - 8) & 15) + 8;
		}

		/* final CRLF */
		*out++ = '\r';
		*out++ = '\n';

		/* fill with readable data for small packets, and skip one line for last char */
		if (pkt1_size < 200) {
			int i;
			for (i = 0; i < pkt1_size; i++) {
				if (i == pkt1_size - 1)
					*out++ = '\n';
				else
					*out++ = ".123456789ABCDEF"[i & 15];
			}
		}
		else {
			out += pkt1_size;
		}

		skb_put(pkt1, out - skb_tail_pointer(pkt1));
	}
	else if ((st >= SLH_ST_ACK_CL_LAST_7 && st <= SLH_ST_ACK_CL_LAST_1) ||
		 (st >= SLH_ST_ACK_KA_LAST_5 && st <= SLH_ST_ACK_KA_LAST_1)) {
		int fin;

		/* we need enough space for the response */
		if (ntohs(th->window) < 1460)
			return;

		/* we want to send a FIN if we're sending the last packet in the
		 * CLOSE mode, or if we're sending the last one in the keep-alive
		 * mode and the client has already sent its FIN. It's also the
		 * only case where we're ready to ACK the client's FIN.
		 */
		fin = (st == SLH_ST_ACK_KA_LAST_1 && th->fin) || (st == SLH_ST_ACK_CL_LAST_1);

		pkt1 = build_data_ack(dev, th->dest, th->source,
				      ack, htonl(ntohl(th->seq) + datalen + (fin && th->fin)),
				      FLG_PSH + (fin ? FLG_FIN : 0),
				      1460);
		if (!pkt1)
			return;

		//printk(KERN_ERR "@%d: skb(%p)=%ld+%ld+%ld=%ld\n", __LINE__,
		//       pkt1,
		//       pkt1->data - pkt1->head,
		//       skb_tail_pointer(pkt1) - pkt1->data,
		//       skb_end_pointer(pkt1) - skb_tail_pointer(pkt1),
		//       skb_end_pointer(pkt1) - pkt1->head);

		//memset(skb_tail_pointer(pkt1), 0, 1460);
		//skb_put(pkt1, 16); /* 16 bytes and loop here */
		skb_put(pkt1, 1457); /* 91*16 + 1 => one step forward */
	}
	else if (st == SLH_ST_LASTACK) {
		/* We have already got the client's FIN. Silently drop
		 * the empty ACKs in this state. However we may encounter
		 * late retransmitted FINs, let's re-ACK them. All other
		 * packets are reset.
		 */
		if (th->fin) {
			/* return a FIN and go to the LASTACK state on FIN */
			pkt1 = build_fin(dev, th->dest, th->source,
					 ack, htonl(ntohl(th->seq) + datalen + 1));
			goto send_ip;
		}
		if (datalen)
			goto send_rst; /* forbidden to send data after FIN */
		return;
	}
	else if (st == SLH_ST_ACK_CL_LAST) {
		/* our FIN was not ACKed, let's retransmit it, it will push us
		 * automatically to state ACK_CL_FIN
		 */
		pkt1 = build_data_ack(dev, th->dest, th->source,
				      ack, th->seq, FLG_FIN, 0);
	}
	else if (st == SLH_ST_ACK_CL_FIN) {
		/* our FIN was ACKed. If the client sent its FIN, we must ACK it.
		 * Otherwise it might be the remote stack which is ACKing our
		 * last packet, in which case we have nothing more to say. The
		 * client will happily close with its FIN later or with an RST.
		 * We must not emit any FIN since it was already sent and ACKed.
		 */
		if (!th->fin)
			return;

		pkt1 = build_data_ack(dev, th->dest, th->source,
				      ack, htonl(ntohl(th->seq) + datalen + th->fin),
				      0, 0);
	}
	else {
		/* for now on, we reset everything */
		pkt1 = build_rst(dev, th->dest, th->source, ack);
	}

 send_ip:
	if (!pkt1)
		return;
	insert_ip(pkt1, ih->id, ih->daddr, ih->saddr);
	insert_eth(pkt1, skb);
	update_tcp_csum(pkt1);
	pkt1->protocol = eth_type_trans(pkt1, dev);

	*op += 1;
	*ob += pkt1->len;

	netif_rx(pkt1);
	// This does not work when ab uses 2 packets in keep-alive mode with
	// a single connection: ab -k -c 1 -n 2 http://1.0.0.2:8000/2000,
	// the system hangs in netif_receive_skb().
	//local_bh_disable();
	//netif_receive_skb(pkt1);
	//local_bh_enable();
	return;

 send_rst:
	/* for now on, we reset everything */
	pkt1 = build_rst(dev, th->dest, th->source, ack);
	goto send_ip;
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
