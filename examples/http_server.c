/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Kenichi Yasukata
 * Copyright (c) 2025 Isaac Boukris
 * Copyright (c) 2025 Hagit Levit
 */

#include "example.h"

static char *httpbuf;
static size_t httpdatalen;

static err_t http_sent_handler(void *arg, struct tcp_pcb *tpcb, uint16_t len)
{
	assert(arg == NULL);
	assert(len == httpdatalen);
	tcp_close(tpcb);

	return ERR_OK;
}

static err_t http_recv_handler(void *arg, struct tcp_pcb *tpcb, struct rte_mbuf *p, err_t err)
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
	assert(rte_pktmbuf_data_len(p) >= 3);
	if (!strncmp(buf, "GET", 3)) {
		assert(tcp_sndbuf(tpcb) >= httpdatalen);
		assert(tcp_write(tpcb, httpbuf, httpdatalen, TCP_WRITE_FLAG_COPY) == ERR_OK);
		assert(tcp_output(tpcb) == ERR_OK);
		if (rte_pktmbuf_data_len(p) >= 10 && !strncmp(buf, "GET /close", 10)) {
			tcp_sent(tpcb, http_sent_handler);
		}
	}
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

static err_t http_accept_handler(void *arg __attribute__((unused)), struct tcp_pcb *tpcb, err_t err)
{
	if (err != ERR_OK)
		return err;

	tcp_recv(tpcb, http_recv_handler);
	tcp_err(tpcb, error_cb);
	set_sock_opt(tpcb);

	return err;
}

struct tcp_pcb *setup_http_server(int http_port, size_t content_len)
{
	size_t buflen = content_len + 256 /* for http hdr */ ;
	char *content;
	struct tcp_pcb *http_tpcb;

	assert((httpbuf = (char *)malloc(buflen)) != NULL);
	assert((content = (char *)malloc(content_len + 1)) != NULL);
	memset(content, 'A', content_len);
	content[content_len] = '\0';
	httpdatalen =
	    snprintf(httpbuf, buflen,
		     "HTTP/1.1 200 OK\r\nContent-Length: %lu\r\nConnection: keep-alive\r\n\r\n%s",
		     content_len, content);
	free(content);
	printf("http data length: %lu bytes\n", httpdatalen);

	assert((http_tpcb = tcp_new()) != NULL);
	assert(tcp_bind(http_tpcb, IP_ANY_TYPE, http_port) == ERR_OK);
	assert(tcp_listen(http_tpcb) == ERR_OK);
	tcp_accept(http_tpcb, http_accept_handler);

	return http_tpcb;
}
