/**
 *		Synchronous Socket API.
 *
 * Generic socket routines.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
#include <linux/highmem.h>
#include <linux/module.h>
#include <net/tcp.h>
#include <net/inet_common.h>

#include "log.h"
#include "sync_socket.h"

MODULE_AUTHOR("NatSys Lab. (http://natsys-lab.com)");
MODULE_DESCRIPTION("Linux Kernel Synchronous Sockets");
MODULE_VERSION("0.4.3");
MODULE_LICENSE("GPL");

static const char *ss_statename[]={
	"Unused","Established","Syn Sent","Syn Recv",
	"Fin Wait 1","Fin Wait 2","Time Wait", "Close",
	"Close Wait","Last ACK","Listen","Closing"
};

static SsHooks *ss_hooks __read_mostly;

#define SS_CALL(f, ...)		(ss_hooks->f ? ss_hooks->f(__VA_ARGS__) : 0)

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
	int r = SS_CALL(put_skb_to_msg, sk->sk_user_data, skb);
	if (r != SS_OK)
		return r;

	r = SS_CALL(connection_recv, sk, data, len);
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
ss_tcp_process_skb(struct sk_buff *skb, struct sock *sk,
		   size_t offset, int *count)
{
	int i, ret = SS_OK;
	int headlen = skb_headlen(skb);
	struct sk_buff *frag_i;

	/* Process linear data. */
	if (offset >= headlen) {
		offset -= headlen;
	} else {
		ret = ss_tcp_process_proto_skb(sk, skb->data + offset,
					       headlen - offset, skb);
		if (ret < 0) {
			return ret;
		}
		*count += headlen - offset;
		offset = 0;
	}
	/* Process paged data. */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; ++i) {
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		unsigned int frag_size = skb_frag_size(frag);
		if (offset >= frag_size) {
			offset -= frag_size;
		} else {
			unsigned char *frag_addr = skb_frag_address(frag);

			ret = ss_tcp_process_proto_skb(sk, frag_addr + offset,
						       frag_size - offset, skb);
			if (ret < 0)
				return ret;
			*count += frag_size - offset;
			offset = 0;
		}
	}
	/* Process packet fragments. */
	skb_walk_frags(skb, frag_i) {
		if (offset >= frag_i->len) {
			offset -= frag_i->len;
		} else {
			ret = ss_tcp_process_skb(frag_i, sk, offset, count);
			if (ret < 0)
				return ret;
			offset = 0;
		}
	}

	return ret;
}

static void
ss_tcp_send_fin(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	int mss_now = tcp_current_mss(sk);
	struct sk_buff *skb = tcp_write_queue_tail(sk);

	if (tcp_send_head(sk) != NULL) {
		TCP_SKB_CB(skb)->tcp_flags |= TCPHDR_FIN;
		TCP_SKB_CB(skb)->end_seq++;
		tp->write_seq++;
	}
	else {
		skb = alloc_skb_fclone(MAX_TCP_HEADER, sk->sk_allocation);
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
	size_t offset;
	struct sk_buff *skb, *tmp;
	struct tcp_sock *tp = tcp_sk(sk);

	skb_queue_walk_safe(&sk->sk_receive_queue, skb, tmp) {
		if (unlikely(before(tp->copied_seq, TCP_SKB_CB(skb)->seq))) {
			SS_WARN("KERN BUG: TCP seq gap at seq %X recvnxt %X\n",
				tp->copied_seq, TCP_SKB_CB(skb)->seq);
			if (tcp_close_state(sk)) {
				ss_tcp_send_fin(sk);
			}
			break;
		}
		offset = tp->copied_seq - TCP_SKB_CB(skb)->seq;
		if (tcp_hdr(skb)->syn)
			offset--;
		if (offset < skb->len) {
			int ret, count = 0;

			__skb_unlink(skb, &sk->sk_receive_queue);
			skb_orphan(skb);

			ret = ss_tcp_process_skb(skb, sk, offset, &count);
			if (ret < 0) {
				__kfree_skb(skb);
				if (tcp_close_state(sk)) {
					ss_tcp_send_fin(sk);
				}
				break;
			}
			tp->copied_seq += count;
			processed += count;
		}
		if (tcp_hdr(skb)->fin) {
			if (offset < skb->len) {
				/* FIXME: "ZERO" the SKB */
			}
			break;
		}
	}
	/*
	 * Recalculate the appropriate TCP receive buffer space
	 * and send ACK to the client with new window.
 	*/
	tcp_rcv_space_adjust(sk);
	if (processed)
		tcp_cleanup_rbuf(sk, processed);
}

void
ss_close(struct sock *sk)
{
	local_bh_disable();
	bh_lock_sock_nested(sk);
	if (tcp_close_state(sk)) {
		ss_tcp_send_fin(sk);
	}
	bh_unlock_sock(sk);
	local_bh_enable();
	sock_put(sk);
}
EXPORT_SYMBOL(ss_close);

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
	if (!skb_queue_empty(&sk->sk_error_queue)) {
		SS_ERR("error data on socket %p\n", sk);
	} else if (!skb_queue_empty(&sk->sk_receive_queue)) {
		ss_tcp_process_data(sk);
	} else {
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
}

/**
 * Make the data socket serviced by synchronous sockets.
 */
void
ss_def_cb_data_ready(struct sock *sk, int bytes)
{
	SS_DBG("Default data_ready called\n");
}
void
ss_def_cb_state_change(struct sock *sk)
{
	SS_DBG("Default state_change called\n");
}
void
ss_def_cb_error_report(struct sock *sk)
{
	SS_DBG("Default error_report called\n");
}

void
ss_set_callbacks(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_allocation = GFP_ATOMIC;
	sk->sk_data_ready = ss_tcp_data_ready;
	sk->sk_state_change = ss_tcp_state_change;
	sk->sk_error_report = ss_tcp_error;
	write_unlock_bh(&sk->sk_callback_lock);
}
EXPORT_SYMBOL(ss_set_callbacks);

static void
ss_del_callbacks(struct sock *sk)
{
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_data_ready = ss_def_cb_data_ready;
	sk->sk_state_change = ss_def_cb_state_change;
	sk->sk_error_report = ss_def_cb_error_report;
	write_unlock_bh(&sk->sk_callback_lock);
}

/*
 * Socket state change callback.
 * This callback is set on a listening socket, and all sockets
 * that are forked off by incoming connections inherit it as well.
 */
static void
ss_tcp_state_change(struct sock *sk)
{
	SS_DBG("state_change: sk %p, state %s\n",
		sk, ss_statename[sk->sk_state]);

	if (sk->sk_state == TCP_ESTABLISHED) {
		/*
		 * We get here when a connection request on a listening
		 * socket has been accepted, and a new TCP connection
		 * has been established by completing the TCP handshake.
		 * The main goal is to let Linux kernel handle all that
		 * is required. We just add a little to it here.
		 * Allocate and set up any user resources associated
		 * with the socket, and set our socket callbacks that
		 * will handle data processing. Initiate socket close
		 * in case of an error in this process.
		 */
		int ret = SS_CALL(connection_new, sk);
		if (ret) {
			if (tcp_close_state(sk)) {
				ss_tcp_send_fin(sk);
			}
			return;
		}
		ss_set_callbacks(sk);
	} else if ((sk->sk_state == TCP_CLOSE_WAIT)
		   || (sk->sk_state == TCP_FIN_WAIT1)) {
		/*
		 * Release any user resources associated with the socket
		 * as soon as the socket leaves the ESTABLISHED state.
		 * Remove our callbacks from the socket and let Linux
		 * kernel handle the actual socket closing process.
		 */
		/*
		 * TODO: This is where we put the code to force Linux
		 * close the socket faster and free system resources.
		 */
		BUG_ON(!sk->sk_user_data);
		SS_CALL(connection_drop, sk);
		ss_del_callbacks(sk);
	}
}

/**
 * Set protocol handler and initialize first callbacks.
 */
void
ss_tcp_set_listen(struct socket *sock, SsProto *handler)
{
	struct sock *sk = sock->sk;

	write_lock_bh(&sk->sk_callback_lock);
	BUG_ON(sk->sk_user_data);
	sk->sk_allocation = GFP_ATOMIC;
	sk->sk_state_change = ss_tcp_state_change;
	sk->sk_user_data = handler;
	handler->listener = sock;
	write_unlock_bh(&sk->sk_callback_lock);
}
EXPORT_SYMBOL(ss_tcp_set_listen);

/*
 * ------------------------------------------------------------------------
 *  	Sockets initialization
 * ------------------------------------------------------------------------
 */

/*
 * FIXME Only one user for now, don't care about registration races.
 */
int
ss_hooks_register(SsHooks* hooks)
{
	if (ss_hooks)
		return -EEXIST;
	ss_hooks = hooks;

	return 0;
}
EXPORT_SYMBOL(ss_hooks_register);

void
ss_hooks_unregister(SsHooks* hooks)
{
	BUG_ON(hooks != ss_hooks);
	ss_hooks = NULL;
}
EXPORT_SYMBOL(ss_hooks_unregister);

int __init
ss_init(void)
{
	return 0;
}

void __exit
ss_exit(void)
{
}

module_init(ss_init);
module_exit(ss_exit);
