/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 Isaac Boukris
 * Copyright (c) 2025 Hagit Levit
 */

#include "example.h"

ip_addr_t proxy_target;
int proxy_target_port;

static err_t tcp_proxy_sent_handler(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
	struct tcp_pcb *other_tpcb = arg;
	tcp_recved(other_tpcb, len);
	tcp_recved(tpcb, len);
	fprintf(stdout, "sent: pcb: %p (%d), other pcb: %p (%d)\n", tpcb, tpcb->state, other_tpcb,
		other_tpcb->state);
	fprintf(stdout, "sent: len %d, qlen %d\n", len, tpcb->snd_queuelen);
	if (other_tpcb->state >= FIN_WAIT_1 && tpcb->snd_queuelen == 0)
		tcp_shutdown(tpcb, 0, 1);
	return ERR_OK;
}

static err_t tcp_proxy_recv_handler(void *arg, struct tcp_pcb *tpcb, struct rte_mbuf *p, err_t err)
{
	fprintf(stdout, "proxy_recv: mbuf on pcb: %p (%d)\n", tpcb, tpcb->state);
	if (err != ERR_OK)
		return err;
	if (!arg) {
		fprintf(stdout, "proxy_recv: no other proxy pcb\n");
		tcp_close(tpcb);
		return ERR_OK;
	}
	struct tcp_pcb *other_tpcb = arg;
	if (!p) {
		fprintf(stdout, "recv: empty mbuf on pcb: %p (%d) shutdown rx\n", tpcb,
			tpcb->state);
		fprintf(stdout, "recv: other proxy pcb (state): %p (%d)\n", other_tpcb,
			other_tpcb->state);
		tcp_shutdown(tpcb, 1, 0);
		return ERR_OK;
	}

	fprintf(stdout, "proxy_recv: send mbuf on pcb: %p (%d)\n", other_tpcb, other_tpcb->state);
	char *buf = rte_pktmbuf_mtod(p, char *);
	int len = rte_pktmbuf_data_len(p);
	assert(tcp_sndbuf(other_tpcb) >= len);
	assert(tcp_write(other_tpcb, buf, len, TCP_WRITE_FLAG_COPY) == ERR_OK);
	assert(tcp_output(other_tpcb) == ERR_OK);
	tcp_sent(other_tpcb, tcp_proxy_sent_handler);
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
	tpcb->so_options |= SOF_KEEPALIVE;
	tpcb->keep_intvl = (60 * 1000);
	tpcb->keep_idle = (60 * 1000);
	tpcb->keep_cnt = 1;
}

static err_t tcp_proxy_connected_handler(void *arg
					 __attribute__((unused)), struct tcp_pcb *tpcb, err_t err)
{
	if (err != ERR_OK)
		return err;

	fprintf(stdout, "connected proxy pcb=%p arg=%p\n", tpcb, arg);
	tcp_recv(tpcb, tcp_proxy_recv_handler);
	tcp_err(tpcb, error_cb);
	set_sock_opt(tpcb);

	return ERR_OK;
}

static err_t tcp_proxy_accept_handler(void *arg
				      __attribute__((unused)), struct tcp_pcb *tpcb, err_t err)
{
	if (err != ERR_OK)
		return err;

	struct tcp_pcb *client_tpcb;
	assert((client_tpcb = tcp_new()) != NULL);
	tcp_err(client_tpcb, error_cb);
	set_sock_opt(client_tpcb);

	tcp_arg(client_tpcb, (void *)tpcb);
	tcp_arg(tpcb, (void *)client_tpcb);

	tcp_recv(tpcb, tcp_proxy_recv_handler);
	tcp_err(tpcb, error_cb);
	set_sock_opt(tpcb);

	assert(tcp_connect
	       (client_tpcb, &proxy_target, proxy_target_port,
		tcp_proxy_connected_handler) == ERR_OK);

	return err;
}

struct tcp_pcb *setup_tcp_proxy_server(int tcp_proxy_port, ip_addr_t tcp_proxy_target,
				       int tcp_proxy_target_port)
{
	struct tcp_pcb *prox_tpcb;

	assert((prox_tpcb = tcp_new()) != NULL);
	assert(tcp_bind(prox_tpcb, IP_ANY_TYPE, tcp_proxy_port) == ERR_OK);
	assert(tcp_listen(prox_tpcb) == ERR_OK);

	proxy_target = tcp_proxy_target;
	proxy_target_port = tcp_proxy_target_port;
	tcp_accept(prox_tpcb, tcp_proxy_accept_handler);

	return prox_tpcb;
}
