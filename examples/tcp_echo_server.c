/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Isaac Boukris
 * Copyright (c) 2025 Hagit Levit
 */

#include "example.h"

static err_t tcp_echo_recv_handler(void *arg, struct tcp_pcb *tpcb, struct rte_mbuf *p, err_t err)
{
	if (arg)
		fprintf(stdout, "recv: got unexpected arg\n");
	if (err != ERR_OK)
		return err;
	if (!p) {
		fprintf(stdout, "recv: empty mbuf, closing pcb: %p\n", tpcb);
		tcp_close(tpcb);
		return ERR_OK;
	}

	char *buf = rte_pktmbuf_mtod(p, char *);
	int len = rte_pktmbuf_pkt_len(p);
	assert(tcp_sndbuf(tpcb) >= len);
	assert(tcp_write(tpcb, buf, len, TCP_WRITE_FLAG_COPY) == ERR_OK);
	assert(tcp_output(tpcb) == ERR_OK);
	tcp_recved(tpcb, rte_pktmbuf_pkt_len(p));
	rte_pktmbuf_free(p);
	return ERR_OK;
}

static void error_cb(void *arg, err_t err)
{
	fprintf(stdout, "error_cb: arg=%p err=%d\n", arg, err);
	tcp_debug_print_pcbs();
}

static void set_sock_opt(struct tcp_pcb *tpcb)
{
	tcp_setprio(tpcb, TCP_PRIO_MAX);
	tcp_nagle_disable(tpcb);
	//tpcb->so_options |= SOF_KEEPALIVE;
	tpcb->keep_intvl = (60 * 1000);
	tpcb->keep_idle = (60 * 1000);
	tpcb->keep_cnt = 1;
}

static err_t tcp_echo_accept_handler(void *arg
				     __attribute__((unused)), struct tcp_pcb *tpcb, err_t err)
{
	if (err != ERR_OK)
		return err;

	tcp_recv(tpcb, tcp_echo_recv_handler);
	tcp_err(tpcb, error_cb);
	set_sock_opt(tpcb);

	return err;
}

struct tcp_pcb *setup_tcp_echo_server(int tcp_echo_port)
{
	struct tcp_pcb *echo_tpcb;

	assert((echo_tpcb = tcp_new()) != NULL);
	assert(tcp_bind(echo_tpcb, IP_ANY_TYPE, tcp_echo_port) == ERR_OK);
	assert(tcp_listen(echo_tpcb) == ERR_OK);
	tcp_accept(echo_tpcb, tcp_echo_accept_handler);

	return echo_tpcb;
}
