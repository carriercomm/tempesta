/**
 *		Synchronous Socket API.
 *
 * Generic socket routines.
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

/*
 * TODO:
 * -- Read cache objects by 64KB and use GSO?
 */
#include <linux/module.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/inet_common.h>
#include <net/ip6_route.h>

#include "log.h"
#include "sync_socket.h"

#ifdef TFW_BANNER
#undef TFW_BANNER
#define TFW_BANNER	"[sync_sockets] "
#endif

#ifdef DEBUG
static const char *ss_statename[] = {
	"Unused",	"Established",	"Syn Sent",	"Syn Recv",
	"Fin Wait 1",	"Fin Wait 2",	"Time Wait",	"Close",
	"Close Wait",	"Last ACK",	"Listen",	"Closing"
};
#endif

#define SS_CALL(f, ...)							\
	(((SsProto *)(sk)->sk_user_data)->hooks->f			\
	? ((SsProto *)(sk)->sk_user_data)->hooks->f(__VA_ARGS__)	\
	: 0)

/**
 * Copied from net/netfilter/xt_TEE.c.
 */
static struct net *
ss_pick_net(struct sk_buff *skb)
{
#ifdef CONFIG_NET_NS
	const struct dst_entry *dst;

	if (skb->dev != NULL)
		return dev_net(skb->dev);
	dst = skb_dst(skb);
	if (dst != NULL && dst->dev != NULL)
		return dev_net(dst->dev);
#endif
	return &init_net;
}

/**
 * Reroute a packet to the destination for IPv4 and IPv6.
 */
static bool
ss_skb_route(struct sk_buff *skb, struct tcp_sock *tp)
{
	struct rtable *rt;
	struct inet_sock *isk = &tp->inet_conn.icsk_inet;
#if IS_ENABLED(CONFIG_IPV6)
	struct ipv6_pinfo *np = inet6_sk(&isk->sk);

	if (np) {
		struct flowi6 fl6 = { .daddr = np->daddr };
		struct dst_entry *dst;

		BUG_ON(isk->sk.sk_family != AF_INET6);
		BUG_ON(skb->protocol != htons(ETH_P_IPV6));

		dst = ip6_route_output(ss_pick_net(skb), NULL, &fl6);
		if (dst->error) {
			dst_release(dst);
			return false;
		}

		skb_dst_drop(skb);
		skb_dst_set(skb, dst);
		skb->dev = dst->dev;
	} else
#endif
	{
		struct flowi4 fl4 = { .daddr = isk->inet_daddr };

		BUG_ON(isk->sk.sk_family != AF_INET);

		rt = ip_route_output_key(ss_pick_net(skb), &fl4);
		if (IS_ERR(rt))
			return false;

		skb_dst_drop(skb);
		skb_dst_set(skb, &rt->dst);
		skb->dev = rt->dst.dev;
	}

	return true;
}

/*
 * ------------------------------------------------------------------------
 *  	Server and client connections handling
 * ------------------------------------------------------------------------
 */
/**
 * Directly insert all skbs from @skb_list into @sk TCP write queue regardless
 * write buffer size. This allows directly forward modified packets without
 * copying.
 * See do_tcp_sendpages() and tcp_sendmsg() in linux/net/ipv4/tcp.c.
 *
 * Called in softirq context.
 *
 * TODO use MSG_MORE untill we reach end of message.
 */
void
ss_send(struct sock *sk, const SsSkbList *skb_list)
{
	struct sk_buff *skb;
	struct tcp_skb_cb *tcb;
	struct tcp_sock *tp = tcp_sk(sk);
	int flags = MSG_DONTWAIT; /* we can't sleep */
	int size_goal, mss_now;

	SS_DBG("%s: sk %p, sk->sk_socket %p, state (%s)\n",
		__FUNCTION__, sk, sk->sk_socket, ss_statename[sk->sk_state]);

	bh_lock_sock_nested(sk);

	mss_now = tcp_send_mss(sk, &size_goal, flags);

	BUG_ON(ss_skb_queue_empty(skb_list));
	for (skb = ss_skb_peek(skb_list), tcb = TCP_SKB_CB(skb);
	     skb; skb = ss_skb_next(skb_list, skb))
	{
		skb->ip_summed = CHECKSUM_PARTIAL;
		skb_shinfo(skb)->gso_segs = 0;

		/*
		 * TODO
		 * Mark all data with PUSH to force receiver to consume
		 * the data. Currently we do this in debugging purpose.
		 * We need to do this only for complete messages/skbs.
		 * (Actually tcp_push() already does it for the last skb.)
		 */
		tcp_mark_push(tp, skb);

		SS_DBG("%s:%d entail skb=%p data_len=%u len=%u\n",
		       __FUNCTION__, __LINE__, skb, skb->data_len, skb->len);

		skb_entail(sk, skb);

		tcb->end_seq += skb->len;
		tp->write_seq += skb->len;

		if (!ss_skb_route(skb, tp)) {
			/*
			 * FIXME how to handle the error?
			 * Just free the skb?
			 */
			SS_WARN("cannot route skb\n");
		}
	}

	SS_DBG("%s:%d sk=%p is_queue_empty=%d tcp_send_head(sk)=%p"
	       " sk->sk_state=%d\n", __FUNCTION__, __LINE__,
	       sk, tcp_write_queue_empty(sk), tcp_send_head(sk), sk->sk_state);

	tcp_push(sk, flags, mss_now, TCP_NAGLE_OFF|TCP_NAGLE_PUSH);

	bh_unlock_sock(sk);
}
EXPORT_SYMBOL(ss_send);

static int
ss_tcp_process_proto_skb(struct sock *sk, unsigned char *data, size_t len,
			 struct sk_buff *skb)
{
	int r = SS_CALL(connection_recv, sk, data, len);
	if (r == SS_POSTPONE) {
		SS_CALL(postpone_skb, sk->sk_user_data, skb);
		r = SS_OK;
	}

	return r;
}

/**
 * Process a socket buffer.
 * See standard skb_copy_datagram_iovec() implementation.
 * @return SS_OK, SS_DROP or negative value of error code.
 *
 * In any case returns with @skb passed to application layer.
 * We don't manege the skb any more.
 */
static int
ss_tcp_process_skb(struct sk_buff *skb, struct sock *sk, unsigned int off,
		   int *count)
{
	int i, r = SS_OK;
	int lin_len = skb_headlen(skb);
	struct sk_buff *frag_i;

	/*
	 * We know for sure from the caller that the skb has data.
	 * No matter where exactly the data is placed, but the skb relates
	 * to current message, so put it to the message.
	 */
	r = SS_CALL(put_skb_to_msg, sk->sk_user_data, skb);
	if (r != SS_OK)
		return r;

	/* Process linear data. */
	if (off < lin_len) {
		r = ss_tcp_process_proto_skb(sk, skb->data + off,
					     lin_len - off, skb);
		if (r < 0)
			return r;
		*count += lin_len - off;
		off = 0;
	} else
		off -= lin_len;

	/* Process paged data. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		unsigned int f_sz = skb_frag_size(frag);
		if (f_sz > off) {
			unsigned char *f_addr = skb_frag_address(frag);
			r = ss_tcp_process_proto_skb(sk, f_addr + off,
						     f_sz - off, skb);
			if (r < 0)
				return r;
			*count += f_sz - off;
			off = 0;
		} else
			off -= f_sz;
	}

	/* Process packet fragments. */
	skb_walk_frags(skb, frag_i) {
		if (frag_i->len > off) {
			r = ss_tcp_process_skb(frag_i, sk, off, count);
			if (r < 0)
				return r;
			off = 0;
		} else
			off -= frag_i->len;
	}

	return r;
}

/**
 * inet_release() can sleep (as well as tcp_close()), so we make our own
 * non-sleepable socket closing.
 *
 * This function must be used only for data sockets.
 * Use standard sock_release() for listening sockets.
 *
 * In most cases it's called from softirq and from softirqd which processes data
 * from the socket (RSS and RPS distributes packets in such way).
 * However, it also can be called from process context,
 * e.g. on module unloading.
 *
 * TODO In some cases we need to close socket agresively w/o FIN_WAIT_2 state,
 * e.g. by sending RST. So we need to add second parameter to the function
 * which says how to close the socket.
 * One of the examples is rcl_req_limit() (it should reset connections).
 * See tcp_sk(sk)->linger2 processing in standard tcp_close().
 */
static void
ss_do_close(struct sock *sk)
{
	struct sk_buff *skb;
	int data_was_unread = 0;
	int state;

	SS_DBG("Close socket %p (account=%d)\n", sk, sk_has_account(sk));
	SS_DBG("%s: sk %p, sk->sk_socket %p, state (%s)\n",
		__FUNCTION__, sk, sk->sk_socket, ss_statename[sk->sk_state]);

	if (unlikely(!sk))
		return;

	BUG_ON(sk->sk_state == TCP_LISTEN);
	/* Don't try to close unassigned socket. */
	BUG_ON(!sk->sk_user_data);

	SS_CALL(connection_drop, sk);

	sock_rps_reset_flow(sk);

	/*
	 * Sanity checks.
	 */
	/* We must return immediately, so LINGER option is meaningless. */
	WARN_ON(sock_flag(sk, SOCK_LINGER));
	/* We don't support virtual containers, so TCP_REPAIR is prohibited. */
	WARN_ON(tcp_sk(sk)->repair);
	/* The socket must have atomic allocation mask. */
	WARN_ON(!(sk->sk_allocation & GFP_ATOMIC));

	/*
	 * The below is mostly copy-paste from tcp_close().
	 */
	sk->sk_shutdown = SHUTDOWN_MASK;

	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		u32 len = TCP_SKB_CB(skb)->end_seq - TCP_SKB_CB(skb)->seq -
			  tcp_hdr(skb)->fin;
		data_was_unread += len;
		SS_DBG("free rcv skb %p\n", skb);
		__kfree_skb(skb);
	}

	sk_mem_reclaim(sk);

	if (sk->sk_state == TCP_CLOSE)
		goto adjudge_to_death;

	if (data_was_unread) {
		NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONCLOSE);
		tcp_set_state(sk, TCP_CLOSE);
		tcp_send_active_reset(sk, sk->sk_allocation);
	}
	else if (tcp_close_state(sk)) {
		/* The code below is taken from tcp_send_fin(). */
		struct tcp_sock *tp = tcp_sk(sk);
		int mss_now = tcp_current_mss(sk);

		skb = tcp_write_queue_tail(sk);

		if (tcp_send_head(sk) != NULL) {
			/* Send FIN with data if we have any. */
			TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_FIN;
			TCP_SKB_CB(skb)->end_seq++;
			tp->write_seq++;
		}
		else {
			/* No data to send in the socket, allocate new skb. */
			skb = alloc_skb_fclone(MAX_TCP_HEADER,
					       sk->sk_allocation);
			if (!skb) {
				SS_WARN("can't send FIN due to bad alloc");
			} else {
				skb_reserve(skb, MAX_TCP_HEADER);
				tcp_init_nondata_skb(skb, tp->write_seq,
						     TCPHDR_ACK | TCPHDR_FIN);
				tcp_queue_skb(sk, skb);
			}
		}
		__tcp_push_pending_frames(sk, mss_now, TCP_NAGLE_OFF);
	}

adjudge_to_death:
	state = sk->sk_state;
	sock_hold(sk);
	sock_orphan(sk);

	/*
	 * release_sock(sk) w/o sleeping.
	 *
	 * We're in softirq and there is no other socket users,
	 * so don't acquire sk->sk_lock.
	 */
	if (sk->sk_backlog.tail) {
		skb = sk->sk_backlog.head;
		do {
			sk->sk_backlog.head = sk->sk_backlog.tail = NULL;
			do {
				struct sk_buff *next = skb->next;
				prefetch(next);
				WARN_ON_ONCE(skb_dst_is_noref(skb));
				/*
				 * We're in active closing state,
				 * so there is nobody interesting in receiving
				 * data.
				 */
				SS_DBG("free backlog skb %p\n", skb);
				__kfree_skb(skb);
				skb = next;
			} while (skb != NULL);
		} while ((skb = sk->sk_backlog.head) != NULL);
	}
	sk->sk_backlog.len = 0;
	if (sk->sk_prot->release_cb)
		sk->sk_prot->release_cb(sk);
	sk->sk_lock.owned = 0;

	percpu_counter_inc(sk->sk_prot->orphan_count);

	if (state != TCP_CLOSE && sk->sk_state == TCP_CLOSE)
		return;

	if (sk->sk_state == TCP_FIN_WAIT2) {
		const int tmo = tcp_fin_time(sk);
		if (tmo > TCP_TIMEWAIT_LEN) {
			inet_csk_reset_keepalive_timer(sk,
						tmo - TCP_TIMEWAIT_LEN);
		} else {
			tcp_time_wait(sk, TCP_FIN_WAIT2, tmo);
			return;
		}
	}
	if (sk->sk_state != TCP_CLOSE) {
		sk_mem_reclaim(sk);
		if (tcp_check_oom(sk, 0)) {
			tcp_set_state(sk, TCP_CLOSE);
			tcp_send_active_reset(sk, GFP_ATOMIC);
			NET_INC_STATS_BH(sock_net(sk),
					 LINUX_MIB_TCPABORTONMEMORY);
		}
	}
	if (sk->sk_state == TCP_CLOSE) {
		struct request_sock *req = tcp_sk(sk)->fastopen_rsk;
		if (req != NULL)
			reqsk_fastopen_remove(sk, req, false);
		inet_csk_destroy_sock(sk);
	}
}

void
ss_close(struct sock *sk)
{
	local_bh_disable();
	bh_lock_sock_nested(sk);

	ss_do_close(sk);

	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}
EXPORT_SYMBOL(ss_close);

/**
 * Receive data on TCP socket. Very similar to standard tcp_recvmsg().
 *
 * We can't use standard tcp_read_sock() with our actor callback, because
 * tcp_read_sock() calls __kfree_skb() through sk_eat_skb() which is good
 * for copying data from skb, but we need to manage skb's ourselves.
 *
 * TODO:
 * -- process URG
 */
static void
ss_tcp_process_data(struct sock *sk)
{
	int processed = 0;
	unsigned int off;
	struct sk_buff *skb, *tmp;
	struct tcp_sock *tp = tcp_sk(sk);

	skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
		if (unlikely(before(tp->copied_seq, TCP_SKB_CB(skb)->seq))) {
			SS_WARN("recvmsg bug: TCP sequence gap at seq %X"
				" recvnxt %X\n",
				tp->copied_seq, TCP_SKB_CB(skb)->seq);
			ss_do_close(sk);
			return;
		}

		__skb_unlink(skb, &sk->sk_receive_queue);

		off = tp->copied_seq - TCP_SKB_CB(skb)->seq;
		if (tcp_hdr(skb)->syn)
			off--;
		if (off < skb->len) {
			int count = 0;
			int r = ss_tcp_process_skb(skb, sk, off, &count);
			if (r < 0) {
				SS_WARN("can't process app data on socket %p\n",
					sk);
				/*
				 * Drop connection on internal errors as well as
				 * on banned packets.
				 *
				 * ss_do_close() is responsible for calling
				 * application layer connection closing callback
				 * which will free all the passed and linked
				 * with currently processed message skbs.
				 */
				__kfree_skb(skb);
				ss_do_close(sk);
				goto out; /* connection dropped */
			}
			tp->copied_seq += count;
			processed += count;
		}
		else if (tcp_hdr(skb)->fin) {
			SS_DBG("received FIN, do active close\n");
			++tp->copied_seq;
			ss_do_close(sk);
			__kfree_skb(skb);
		}
		else {
			SS_WARN("recvmsg bug: overlapping TCP segment at %X"
				" seq %X rcvnxt %X len %x\n",
			       tp->copied_seq, TCP_SKB_CB(skb)->seq,
			       tp->rcv_nxt, skb->len);
			__kfree_skb(skb);
		}
	}
out:
	/*
	 * Recalculate the appropriate TCP receive buffer space and
	 * send ACK to the client with new window.
	 */
	tcp_rcv_space_adjust(sk);
	if (processed)
		tcp_cleanup_rbuf(sk, processed);
}

/**
 * Just drain accept queue of listening socket &lsk.
 * See implementation of standard inet_csk_accept().
 */
static void
ss_drain_accept_queue(struct sock *lsk, struct sock *nsk)
{
	struct inet_connection_sock *icsk = inet_csk(lsk);
	struct request_sock_queue *queue = &icsk->icsk_accept_queue;
#if 0
	struct request_sock *prev_r, *req;
#else
	struct request_sock *req;
#endif
	SS_DBG("%s: sk %p, sk->sk_socket %p, state (%s)\n",
		__FUNCTION__, lsk, lsk->sk_socket, ss_statename[lsk->sk_state]);

	/* Currently we process TCP only. */
	BUG_ON(lsk->sk_protocol != IPPROTO_TCP);

	WARN(reqsk_queue_empty(queue),
	     "drain empty accept queue for socket %p", lsk);

#if 0
	/* TODO it works to slowly, need to patch Linux kernel to make it faster. */
	for (prev_r = NULL, req = queue->rskq_accept_head; req;
	     prev_r = req, req = req->dl_next)
	{
		if (req->sk != nsk)
			continue;
		/* We found the socket, remove it. */
		if (prev_r) {
			/* There are some items before @req in the queue. */
			prev_r->dl_next = req->dl_next;
			if (queue->rskq_accept_tail == req)
				/* @req is the last item. */
				queue->rskq_accept_tail = prev_r;
		} else {
			/* @req is the first item in the queue. */
			queue->rskq_accept_head = req->dl_next;
			if (queue->rskq_accept_head == NULL)
				/* The queue contained only this one item. */
				queue->rskq_accept_tail = NULL;
		}
		break;
	}
#else
	/*
	 * FIXME push any request from the queue,
	 * doesn't matter which exactly.
	 */
	req = reqsk_queue_remove(queue);
#endif
	BUG_ON(!req);
	sk_acceptq_removed(lsk);

	/*
	 * @nsk is in ESTABLISHED state, so 3WHS has completed and
	 * we can safely remove the request socket from accept queue of @lsk.
	 */
	__reqsk_free(req);
}

/*
 * ------------------------------------------------------------------------
 *  	Socket callbacks
 * ------------------------------------------------------------------------
 */
static void ss_tcp_state_change(struct sock *sk);

/*
 * Called when a new data received on the socket.
 * Called under bh_lock_sock_nested(sk) (see tcp_v4_rcv()).
 *
 * XXX ./net/ipv4/tcp_* call sk_data_ready() with 0 as the value of @bytes.
 * This seems wrong.
 */
static void
ss_tcp_data_ready(struct sock *sk, int bytes)
{
	SS_DBG("%s: sk %p, sk->sk_socket %p, state (%s)\n",
		__FUNCTION__, sk, sk->sk_socket, ss_statename[sk->sk_state]);

	if (!skb_queue_empty(&sk->sk_error_queue)) {
		/*
		 * Error packet received.
		 * See sock_queue_err_skb() in linux/net/core/skbuff.c.
		 */
		SS_ERR("error data on socket %p\n", sk);
	}
	else if (!skb_queue_empty(&sk->sk_receive_queue)) {
		ss_tcp_process_data(sk);
	}
	else {
		/*
		 * Check for URG data.
		 * TODO shouldn't we do it in th_tcp_process_data()?
		 */
		struct tcp_sock *tp = tcp_sk(sk);
		if (tp->urg_data & TCP_URG_VALID) {
			tp->urg_data = 0;
			SS_DBG("urgent data on socket %p\n", sk);
		}
	}
}

/**
 * Socket failover.
 */
static void
ss_tcp_error(struct sock *sk)
{
	SS_DBG("process error on socket %p\n", sk);
	SS_DBG("%s: sk %p, sk->sk_socket %p, state (%s)\n",
		__FUNCTION__, sk, sk->sk_socket, ss_statename[sk->sk_state]);

	if (sk->sk_destruct)
		sk->sk_destruct(sk);
}

/**
 * Socket state change callback.
 */
static void
ss_tcp_state_change(struct sock *sk)
{
	SS_DBG("%s: sk %p, sk->sk_socket %p, state (%s)\n",
		__FUNCTION__, sk, sk->sk_socket, ss_statename[sk->sk_state]);

	if (sk->sk_state == TCP_ESTABLISHED) {
		/* Process the new TCP connection. */

		SsProto *proto = sk->sk_user_data;
		struct sock *lsk = proto->listener;
		int r;

		/* The callback is called from tcp_rcv_state_process(). */
		r = SS_CALL(connection_new, sk);
		if (r) {
			SS_DBG("New connection hook failed, r=%d\n", r);
			ss_do_close(sk);
			return;
		}
		if (lsk) {
			/*
			 * This is a new socket for an accepted connect
			 * request that the kernel has allocated itself.
			 * Kernel initializes this field to GFP_KERNEL.
			 * Tempesta works with sockets in SoftIRQ context,
			 * so set it to atomic allocation.
			 */
			sk->sk_allocation = GFP_ATOMIC;

			/*
			 * We know which socket is just accepted.
			 * Just drain listening socket accept queue,
			 * and don't care about the returned socket.
			 */
			assert_spin_locked(&lsk->sk_lock.slock);
			ss_drain_accept_queue(lsk, sk);
		}
	} else if ((sk->sk_state == TCP_CLOSE_WAIT)
		 || (sk->sk_state == TCP_FIN_WAIT1)) {
		/*
		 * Connection is being closed.
		 * Either Tempesta sent FIN, or we received FIN.
		 *
		 * FIXME it seems we should to do things below on TCP_CLOSE
		 * instead of TCP_CLOSE_WAIT.
		 */
		SS_DBG("Peer connection closing\n");
		ss_do_close(sk);
	} else if (sk->sk_state == TCP_CLOSE) {
		/*
		 * In current implementation we never get to TCP_CLOSE
		 * in normal course of action. We only get here if we
		 * never entered TCP_ESTABLISHED state.
		 */
		SS_DBG("Connection is finished\n");
		SS_CALL(connection_close, sk);
	}
}

void
ss_proto_init(SsProto *proto, const SsHooks *hooks, int type)
{
	proto->hooks = hooks;
	proto->type = type;

	/* The memory allocated for @proto should be already zero'ed, so don't
	 * initialize this field to NULL, but instead check the invariant. */
	BUG_ON(proto->listener);
}

void
ss_proto_inherit(const SsProto *parent, SsProto *child, int child_type)
{
	*child = *parent;
	child->type |= child_type;
}

/**
 * Make data socket serviced by synchronous sockets.
 */
void
ss_set_callbacks(struct sock *sk)
{
	/* ss_tcp_state_change() dereferences sk->sk_user_data as SsProto, so
	 * the caller should initialize it before setting callbacks. */
	BUG_ON(!sk->sk_user_data);

	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_data_ready = ss_tcp_data_ready;
	sk->sk_state_change = ss_tcp_state_change;
	sk->sk_error_report = ss_tcp_error;
	write_unlock_bh(&sk->sk_callback_lock);
}
EXPORT_SYMBOL(ss_set_callbacks);

/**
 * Store listening socket as parent for all accepted connections,
 * and initialize first callbacks.
 */
void
ss_set_listen(struct sock *sk)
{
	((SsProto *)sk->sk_user_data)->listener = sk;

	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_state_change = ss_tcp_state_change;
	write_unlock_bh(&sk->sk_callback_lock);
}
EXPORT_SYMBOL(ss_set_listen);

/*
 * Tempesta works with Linux internal sockets (struct sock), and it
 * does not need full BSD sockets (struct socket), nor does it need
 * file/inode operations on these sockets. Both take memory and system
 * resources. Here is a set of socket interface functions that accept
 * "struct sock" instead of "struct socket". With these we avoid taking
 * unnecessary system memory and resources.
 *
 * Some of these functions cover lots of cases that are not applicable
 * to Tempesta's use. As speed is important, shorter and faster variants
 * of those are implemented by removing unnecessary parts of code.
 *
 * Where there's little to gain by implementing a shorter variant,
 * an original kernel protocol interface function is called.
 * As a BSD socket (struct socket) is not allocated and populated,
 * a socket placeholder is used in these functions. A placeholder
 * is initialized with just enough data to satisfy an underlying
 * kernel function that still wants "struct socket" as an argument.
 */
/*
 * Create a new socket for IPv4 or IPv6 protocol. The original functions
 * are inet_create() and inet6_create(). They are nearly identical and
 * only minor details are different. All of them are covered here.
 *
 * NOTE: This code assumes that both IPv4 and IPv6 are compiled in as
 * part of the Linux kernel, and not as separate loadable kernel modules.
 */
static int
ss_inet_create(struct net *net, int family,
	       int type, int protocol, struct sock **nsk)
{
	int err, pfinet;
	struct sock *sk;
	struct inet_sock *inet;
	struct proto *answer_prot;

	/* TCP only is supported for now. */
	BUG_ON(type != SOCK_STREAM || protocol != IPPROTO_TCP);

	/*
	 * Get socket properties.
	 * See inet_protosw and tcpv6_protosw definitions.
	 */
	if (family == AF_INET) {
		pfinet = PF_INET;
		answer_prot = &tcp_prot;
	} else {
		pfinet = PF_INET6;
		answer_prot = &tcpv6_prot;
	}
	WARN_ON(answer_prot->slab == NULL);

	if (unlikely(!inet_ehash_secret))
		build_ehash_secret();

	err = -ENOBUFS;
	if ((sk = sk_alloc(net, pfinet, GFP_ATOMIC, answer_prot)) == NULL)
		goto out;

	err = 0;
	sk->sk_no_check = 0;

	inet = inet_sk(sk);
	inet->is_icsk = 1;
	inet->nodefrag = 0;
	inet->inet_id = 0;

	if (ipv4_config.no_pmtu_disc)
		inet->pmtudisc = IP_PMTUDISC_DONT;
	else
		inet->pmtudisc = IP_PMTUDISC_WANT;

	sock_init_data(NULL, sk);
	sk->sk_type = type;
	sk->sk_allocation = GFP_ATOMIC;

	sk->sk_destruct = inet_sock_destruct;
	sk->sk_protocol = protocol;
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	if (family == AF_INET6) {
		/* The next two lines are inet6_sk_generic(sk) */
		const int offset = sk->sk_prot->obj_size
				   - sizeof(struct ipv6_pinfo);
		struct ipv6_pinfo *np = (struct ipv6_pinfo *)
					(((u8 *)sk) + offset);
		np->hop_limit = -1;
		np->mcast_hops = IPV6_DEFAULT_MCASTHOPS;
		np->mc_loop = 1;
		np->pmtudisc = IPV6_PMTUDISC_WANT;
		np->ipv6only = net->ipv6.sysctl.bindv6only;
		inet->pinet6 = np;
	}

	inet->uc_ttl = -1;
	inet->mc_loop = 1;
	inet->mc_ttl = 1;
	inet->mc_all = 1;
	inet->mc_index = 0;
	inet->mc_list = NULL;
	inet->rcv_tos = 0;

	sk_refcnt_debug_inc(sk);

	if (sk->sk_prot->init)
		if ((err = sk->sk_prot->init(sk)) != 0) {
			sk_common_release(sk);
			goto out;
		}

	*nsk = sk;
out:
	return err;
}

int
ss_sock_create(int family, int type, int protocol, struct sock **res)
{
	int ret;
	struct sock *sk;
	const struct net_proto_family *pf;

	rcu_read_lock();
	if ((pf = get_proto_family(family)) == NULL)
		goto out_rcu_unlock;
	if (!try_module_get(pf->owner))
		goto out_rcu_unlock;
	rcu_read_unlock();

	ret = ss_inet_create(&init_net, family, type, protocol, &sk);
	module_put(pf->owner);
	if (ret < 0)
		goto out_module_put;

	*res = sk;
	return 0;

out_module_put:
	module_put(pf->owner);
out_ret_error:
	return ret;
out_rcu_unlock:
	ret = -EAFNOSUPPORT;
	rcu_read_unlock();
	goto out_ret_error;
}
EXPORT_SYMBOL(ss_sock_create);

/*
 * The original functions are inet_release() and inet6_release().
 * NOTE: Rework this function if/when Tempesta needs multicast support.
 */
void
ss_release(struct sock *sk)
{
	BUG_ON(sock_flag(sk, SOCK_LINGER));

	sock_rps_reset_flow(sk);
	sk->sk_prot->close(sk, 0);
}
EXPORT_SYMBOL(ss_release);

/*
 * The original function is inet_stream_connect() that is common
 * to IPv4 and IPv6.
 */
int
ss_connect(struct sock *sk, struct sockaddr *uaddr, int uaddr_len, int flags)
{
	int err;

	BUG_ON((sk->sk_family != AF_INET) && (sk->sk_family != AF_INET6));
	BUG_ON((uaddr->sa_family != AF_INET) && (uaddr->sa_family != AF_INET6));

	lock_sock(sk);
	if (uaddr_len < sizeof(uaddr->sa_family))
		return -EINVAL;
	err = -EISCONN;
	if (sk->sk_state != TCP_CLOSE)
		goto out;
	if ((err = sk->sk_prot->connect(sk, uaddr, uaddr_len)) != 0)
		goto out;
	err = 0;
out:
	release_sock(sk);
	return err;
}
EXPORT_SYMBOL(ss_connect);

/*
 * The original functions are inet_bind() and inet6_bind().
 * These two can be made a bit shorter should that become necessary.
 */
int
ss_bind(struct sock *sk, struct sockaddr *uaddr, int uaddr_len)
{
	struct socket sock = {
		.sk = sk,
		.type = sk->sk_type
	};
	BUG_ON((sk->sk_family != AF_INET) && (sk->sk_family != AF_INET6));
	BUG_ON(sk->sk_type != SOCK_STREAM);
	if (sk->sk_family == AF_INET)
		return inet_bind(&sock, uaddr, uaddr_len);
	else
		return inet6_bind(&sock, uaddr, uaddr_len);
}
EXPORT_SYMBOL(ss_bind);

/*
 * The original function is inet_listen() that is common to IPv4 and IPv6.
 * There isn't much to make shorter there, so just invoke it directly.
 */
int
ss_listen(struct sock *sk, int backlog)
{
	struct socket sock = {
		.sk = sk,
		.type = sk->sk_type,
		.state = SS_UNCONNECTED
	};
	BUG_ON(sk->sk_type != SOCK_STREAM);
	return inet_listen(&sock, backlog);
}
EXPORT_SYMBOL(ss_listen);

/*
 * The original functions are inet_getname() and inet6_getname().
 * There isn't much to make shorter there, so just invoke them directly.
 */
int
ss_getpeername(struct sock *sk, struct sockaddr *uaddr, int *uaddr_len)
{
	struct socket sock = { .sk = sk };

	BUG_ON((sk->sk_family != AF_INET) && (sk->sk_family != AF_INET6));
	if (sk->sk_family == AF_INET)
		return inet_getname(&sock, uaddr, uaddr_len, 1);
	else
		return inet6_getname(&sock, uaddr, uaddr_len, 1);
}
EXPORT_SYMBOL(ss_getpeername);
