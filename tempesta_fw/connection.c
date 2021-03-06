/**
 *		Tempesta FW
 *
 * Generic connection management.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITFWOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include "connection.h"
#include "gfsm.h"
#include "lib.h"
#include "log.h"
#include "sync_socket.h"

#define TFW_CONN_MAX_PROTOS	TFW_GFSM_FSM_N

static TfwConnHooks *conn_hooks[TFW_CONN_MAX_PROTOS];

#define TFW_CONN_HOOK_CALL(conn, hook_name) \
	conn_hooks[TFW_CONN_TYPE2IDX(TFW_CONN_TYPE(conn))]->hook_name(conn)

void
tfw_connection_hooks_register(TfwConnHooks *hooks, int type)
{
	unsigned hid = TFW_CONN_TYPE2IDX(type);

	BUG_ON(hid >= TFW_CONN_MAX_PROTOS || conn_hooks[hid]);

	conn_hooks[hid] = hooks;
}

void
tfw_connection_init(TfwConnection *conn)
{
	memset(conn, 0, sizeof(*conn));

	INIT_LIST_HEAD(&conn->list);
	INIT_LIST_HEAD(&conn->msg_queue);
}

void
tfw_connection_link_sk(TfwConnection *conn, struct sock *sk)
{
	BUG_ON(conn->sk || sk->sk_user_data);
	conn->sk = sk;
	sk->sk_user_data = conn;
}

void
tfw_connection_unlink_sk(TfwConnection *conn)
{
	BUG_ON(!conn->sk || !conn->sk->sk_user_data);
	conn->sk->sk_user_data = NULL;
	conn->sk = NULL;
}

void
tfw_connection_link_peer(TfwConnection *conn, TfwPeer *peer)
{
	BUG_ON(conn->peer || !list_empty(&conn->list));
	conn->peer = peer;
	tfw_peer_add_conn(peer, &conn->list);
}

void
tfw_connection_unlink_peer(TfwConnection *conn)
{
	BUG_ON(!conn->peer || list_empty(&conn->list));
	tfw_peer_del_conn(conn->peer, &conn->list);
	conn->peer = NULL;
}

/**
 * Publish the "connection is established" event via TfwConnHooks.
 */
int
tfw_connection_new(TfwConnection *conn)
{
	int r = TFW_CONN_HOOK_CALL(conn, conn_init);
	if (r)
		TFW_DBG("conn_init() hook returned error: %d\n", r);
	return r;
}

/**
 * Publish the "connection is closed" event via TfwConnHooks.
 */
void
tfw_connection_destruct(TfwConnection *conn)
{
	/* Ask higher levels to free resources. */
	TFW_CONN_HOOK_CALL(conn, conn_destruct);
	BUG_ON(conn->msg);
	BUG_ON(!list_empty(&conn->msg_queue));
}

void
tfw_connection_send(TfwConnection *conn, TfwMsg *msg)
{
	ss_send(conn->sk, &msg->skb_list);
}

int
tfw_connection_recv(struct sock *sk, unsigned char *data, size_t len)
{
	TfwConnection *conn = sk->sk_user_data;

	return tfw_gfsm_dispatch(conn, data, len);
}

int
tfw_connection_put_skb_to_msg(SsProto *proto, struct sk_buff *skb)
{
	TfwConnection *conn = (TfwConnection *)proto;

	if (!conn->msg) {
		TFW_CONN_HOOK_CALL(conn, conn_msg_alloc);
		if (!conn->msg)
			return -ENOMEM;
		TFW_DBG("Link new msg %p with connection %p\n",
			conn->msg, conn);
	}

	TFW_DBG("Add skb %p to message %p\n", skb, conn->msg);

	ss_skb_queue_tail(&conn->msg->skb_list, skb);

	return 0;
}

int
tfw_connection_postpone_skb(SsProto *proto, struct sk_buff *skb)
{
	TfwConnection *conn = (TfwConnection *)proto;

	TFW_DBG("postpone skb %p\n", skb);

	ss_skb_queue_tail(&conn->msg->skb_list, skb);

	return 0;
}
