/**
 *		Tempesta FW
 *
 * We split traditional filtering logic to two separate pieces:
 * - packet classification (e.g. should we pass or block a packet);
 * - packet action (e.g. drop the packet or close whole TCP connection).
 * Tempesta classifiers are responsible for the first task while filtering
 * modules are responsible for the second one. Different classifiers can emply
 * different policies to service/block packets (e.g. QoS), so typically
 * filtering actions are called by classifiers.
 *
 * The rules work only on 3 and 4 network layers, since only they are managed
 * by current filtering routines. Blocking on all higher layers are provided
 * by GFSM, so classifier can play role of blocking logic: it makes a decision
 * and GFSM is responsible to pass or block a message. This is the way how
 * application level filters must be implemented.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/tcp.h>

#include "tdb.h"

#include "tempesta_fw.h"
#include "classifier.h"
#include "filter.h"
#include "log.h"

static struct {
	unsigned int db_size;
	const char *db_path;
} filter_cfg __read_mostly;

static struct {
	__be16		ports[DEF_MAX_PORTS];
	unsigned int	count;
} tfw_inports __read_mostly;

static TDB *ip_filter_db;

void
tfw_filter_add_inport(__be16 port)
{
	tfw_inports.ports[tfw_inports.count++] = port;
}

/**
 * Check that the incoming packet should be serviced by Tempesta.
 * @return true if it's our packet, false otherwise.
 */
static bool
tfw_our_packet(struct tcphdr *th)
{
	int i;

	for (i = 0; i < tfw_inports.count; ++i)
		if (th->dest == tfw_inports.ports[i])
			return true;
	return false;
}

/*
 * Make sure we're dealing with an IPv4 packet. While at that, make sure
 * that the full IPv4 header is in the linear part. This is similar to what
 * ip_rcv() does in the Linux network stack (linux/net/ipv4/ip_input.c).
 */
static struct iphdr *
__ipv4_hdr_check(struct sk_buff *skb)
{
	u32 pkt_len;
	struct iphdr *ih;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return NULL;

	ih = ip_hdr(skb);
	if (unlikely((ih->ihl < 5) || (ih->version != 4)))
		return NULL;

	if (!pskb_may_pull(skb, ih->ihl * 4))
		return NULL;

	ih = ip_hdr(skb);
	pkt_len = ntohs(ih->tot_len);
	if (unlikely((pkt_len > skb->len) || (pkt_len < ih->ihl * 4)))
		return NULL;

	return ih;
}

static unsigned int
tfw_ipv4_nf_hook(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	int r;
	const struct iphdr *ih;
	TfwFRule *rule;

	ih = __ipv4_hdr_check(skb);
	if (!ih)
		return NF_DROP;

	/* Drop early: chech the table first. */
	rule = tdb_rec_get(ip_filter_db, ih->saddr);
	if (rule && rule->action == TFW_F_DROP) {
		tdb_rec_put(rule);
		return NF_DROP;
	}
	tdb_rec_put(rule);

	/* Check classifiers for Layer 3. */
	r = tfw_classify_ipv4(skb);
	switch (r) {
	case TFW_PASS:
		return NF_ACCEPT;
	case TFW_POSTPONE:
		return NF_STOLEN;
	}

	return NF_DROP;
}

static u8 *
__ipv6_opt_ptr(struct sk_buff *skb, size_t off)
{
	if (!pskb_may_pull(skb, off + 8)) /* ext headers are 8-byte aligned */
		return NULL;

	return (u8 *)(ipv6_hdr(skb) + 1);
}

static struct ipv6hdr *
__ipv6_hdr_check(struct sk_buff *skb)
{
	u32 len;
	size_t off = 0;
	struct ipv6hdr *ih;
	u8 next, *buf;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		return NULL;

	ih = ipv6_hdr(skb);
	if (unlikely(ih->version != 6))
		return NULL;

	len = ntohs(ih->payload_len);
	if (unlikely(len + sizeof(struct ipv6hdr) > skb->len))
		return NULL;

	/* Check options. */
	next = ih->nexthdr;
	buf = __ipv6_opt_ptr(skb, 0);
	while (next != IPPROTO_TCP) {
		if (!buf)
			return NULL;

		switch(next) {
		case 0 : /* hop-by-hop */
		case 60 : /* destination options */
		case 43 : /* routing */
			next = buf[0];
			len = (buf[1] + 1) * 8;

			off += len;
			buf = __ipv6_opt_ptr(skb, off);

			break;
		case 44 : /* fragment */
			/* TODO we do not support fragmented IPv6 yet. */
		default: /* unknoun or unsupported ext. header, skipping */
			return NULL;
		}
	}

	return ih;
}

static unsigned int
tfw_ipv6_nf_hook(unsigned int hooknum, struct sk_buff *skb,
		const struct net_device *in, const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	int r;
	unsigned long key;
	struct ipv6hdr *ih;
	TfwFRule *rule;

	ih = __ipv6_hdr_check(skb);
	if (!ih)
		return NF_DROP;

	key = ((unsigned long)ih->saddr.s6_addr32[0] << 32)
	      | ((unsigned long)ih->saddr.s6_addr32[1] << 24)
	      | ((unsigned long)ih->saddr.s6_addr32[2] << 8)
	      | ih->saddr.s6_addr32[3];

	/* Drop early: chech the table first. */
	rule = tdb_rec_get(ip_filter_db, key);
	if (rule && rule->action == TFW_F_DROP) {
		tdb_rec_put(rule);
		return NF_DROP;
	}
	tdb_rec_put(rule);

	/* Check classifiers for Layer 3. */
	r = tfw_classify_ipv6(skb);
	switch (r) {
	case TFW_PASS:
		return NF_ACCEPT;
	case TFW_POSTPONE:
		return NF_STOLEN;
	}

	return NF_DROP;
}

static struct nf_hook_ops tfw_nf_ops[] __read_mostly = {
	{
		.hook		= tfw_ipv4_nf_hook,
		.owner		= THIS_MODULE,
		.pf		= PF_INET,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK_DEFRAG + 1,
	},
	{
		.hook		= tfw_ipv6_nf_hook,
		.owner		= THIS_MODULE,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP6_PRI_CONNTRACK_DEFRAG + 1,
	},
};

/**
 * Called from sk_filter() called from tcp_v4_rcv() and tcp_v6_rcv(),
 * i.e. when IP fragments are already assembled and we can process TCP.
 */
static int
tfw_sock_tcp_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct tcphdr *th = tcp_hdr(skb);

	/* Pass the packet if it's not for us. */
	if (!tfw_our_packet(th))
		return 0;

	/* Call L4 layer classification. */
	if (tfw_classify_tcp(th) == TFW_BLOCK)
		return -EPERM;

	return 0;
}

static TempestaOps tempesta_ops = {
	.sock_tcp_rcv = tfw_sock_tcp_rcv,
};

static int
tfw_filter_start(void)
{
	int r;

	ip_filter_db = tdb_open(filter_cfg.db_path, filter_cfg.db_size,
				sizeof(TfwFRule), numa_node_id());
	if (!ip_filter_db)
		return -EINVAL;

	r = nf_register_hooks(tfw_nf_ops, ARRAY_SIZE(tfw_nf_ops));
	if (r) {
		TFW_ERR("can't register netfilter hooks\n");
		tdb_close(ip_filter_db);
		return r;
	}

	tempesta_register_ops(&tempesta_ops);

	return r;
}

static void
tfw_filter_stop(void)
{
	tempesta_unregister_ops(&tempesta_ops);
	nf_unregister_hooks(tfw_nf_ops, ARRAY_SIZE(tfw_nf_ops));

	tdb_close(ip_filter_db);
}

static TfwCfgSpec tfw_filter_cfg_specs[] = {
	{
		"filter_tbl_size",
		"262144",
		tfw_cfg_set_int,
		&filter_cfg.db_size,
		&(TfwCfgSpecInt) {
			.multiple_of = PAGE_SIZE,
			.range = { PAGE_SIZE, (1 << 30) },
		}
	},
	{
		"filter_dir",
		"/opt/tempesta/filter",
		tfw_cfg_set_str,
		&filter_cfg.db_path,
		&(TfwCfgSpecStr) {
			.len_range = { 1, PATH_MAX },
		}
	},
	{}
};

TfwCfgMod tfw_filter_cfg_mod = {
	.name 	= "filter",
	.start	= tfw_filter_start,
	.stop	= tfw_filter_stop,
	.specs	= tfw_filter_cfg_specs,
};
