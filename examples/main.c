/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Kenichi Yasukata
 * Copyright (c) 2025 Isaac Boukris
 * Copyright (c) 2025 Hagit Levit
 */

#include "example.h"

#define MAX_PKT_BURST 128U
#define NUM_SLOT 256U
#define MEMPOOL_CACHE_SIZE 256U

static struct rte_mempool *pktmbuf_pool = NULL;

static int tx_idx = 0;
static struct rte_mbuf *tx_mbufs[MAX_PKT_BURST] = { 0 };

static void tx_flush(void)
{
	int xmit = tx_idx, xmitted = 0;
	while (xmitted != xmit)
		xmitted += rte_eth_tx_burst(0, 0, &tx_mbufs[xmitted], xmit - xmitted);
	tx_idx = 0;
}

static err_t low_level_output(struct netif *netif __attribute__((unused)), struct rte_mbuf *p)
{

	rte_pktmbuf_refcnt_update(p, 1);

	tx_mbufs[tx_idx] = p;

	if (++tx_idx == MAX_PKT_BURST)
		tx_flush();

	return ERR_OK;
}

static err_t if_init(struct netif *netif)
{
	struct rte_ether_addr ports_eth_addr;
	uint16_t _mtu;

	assert(rte_eth_macaddr_get(0, &ports_eth_addr) >= 0);

	for (int i = 0; i < 6; i++) {
		netif->hwaddr[i] = ports_eth_addr.addr_bytes[i];
	}

	assert(rte_eth_dev_get_mtu(0, &_mtu) >= 0);
	netif->mtu = _mtu;

	netif->output = etharp_output;
	netif->output_ip6 = ethip6_output;
	netif->linkoutput = low_level_output;
	netif->hwaddr_len = RTE_ETHER_ADDR_LEN;
	netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET;

	netif->name[0] = 'd';
	netif->name[1] = 'p';

	return ERR_OK;
}

struct netif *netif;
struct tcp_pcb *http_tpcb;
struct tcp_pcb *echo_tpcb;
struct tcp_pcb *prox_tpcb;

void sig_handler(int num)
{
	assert(signal(num, SIG_DFL) != SIG_ERR);

	printf("DPIP stats on exit:\n");
	stats_display();
	fflush(stdout);

	if (http_tpcb != NULL) {
		tcp_close(http_tpcb);
		http_tpcb = NULL;
	}
	if (echo_tpcb != NULL) {
		tcp_close(echo_tpcb);
		echo_tpcb = NULL;
	}
	if (prox_tpcb != NULL) {
		tcp_close(prox_tpcb);
		prox_tpcb = NULL;
	}
	if (netif != NULL) {
		netif_remove(netif);
		netif = NULL;
	}

	kill(getpid(), num);
}

int main(int argc, char *const *argv)
{
	struct netif _netif = { 0 };
	ip4_addr_t _addr, _mask, _gate;
	ip6_addr_t _addr6;
	int http_port, tcp_echo_port, tcp_proxy_port;
	size_t content_len = 1;
	ip_addr_t tcp_proxy_target;
	int tcp_proxy_target_port;
	char *env_p;

	setbuf(stdout, NULL);

	assert(signal(SIGQUIT, sig_handler) != SIG_ERR);
	assert(signal(SIGTERM, sig_handler) != SIG_ERR);

	/* get config */

	assert((env_p = getenv("DPIP_IP4_ADDR")) != NULL);
	inet_pton(AF_INET, env_p, &_addr);

	assert((env_p = getenv("DPIP_IP4_MASK")) != NULL);
	inet_pton(AF_INET, env_p, &_mask);

	assert((env_p = getenv("DPIP_IP4_GW")) != NULL);
	inet_pton(AF_INET, env_p, &_gate);

	assert((env_p = getenv("DPIP_IP6_ADDR")) != NULL);
	ip6addr_aton(env_p, &_addr6);

	env_p = getenv("CONTENT_LEN");
	if (env_p) {
		content_len = atol(env_p);
	}

	assert((env_p = getenv("HTTP_PORT")) != NULL);
	http_port = atoi(env_p);
	fprintf(stdout, "env: HTTP_PORT: %i\n", http_port);

	assert((env_p = getenv("TCP_ECHO_PORT")) != NULL);
	tcp_echo_port = atoi(env_p);
	fprintf(stdout, "env: TCP_ECHO_PORT: %i\n", tcp_echo_port);

	assert((env_p = getenv("TCP_PROXY_PORT")) != NULL);
	tcp_proxy_port = atoi(env_p);
	fprintf(stdout, "env: TCP_PROXY_PORT: %i\n", tcp_proxy_port);

	assert((env_p = getenv("TCP_PROXY_TARGET")) != NULL);
	ipaddr_aton(env_p, &tcp_proxy_target);

	assert((env_p = getenv("TCP_PROXY_TARGET_PORT")) != NULL);
	tcp_proxy_target_port = atoi(env_p);
	fprintf(stdout, "env: TCP_PROXY_TARGET_PORT: %i\n", tcp_proxy_target_port);

	/* setup dpdk */

	assert(rte_eal_init(argc, (char **)argv) >= 0);

	assert(rte_eth_dev_count_avail() == 1);

	{
		struct rte_eth_dev_info dev_info;
		struct rte_eth_conf local_port_conf = { 0 };
		uint16_t nb_rxd = NUM_SLOT;
		uint16_t nb_txd = NUM_SLOT;

		assert((pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
							       RTE_MAX(1 *
								       (nb_rxd + nb_txd +
									MAX_PKT_BURST +
									1 * MEMPOOL_CACHE_SIZE),
								       8192), MEMPOOL_CACHE_SIZE, 0,
							       RTE_MBUF_DEFAULT_BUF_SIZE,
							       rte_socket_id())) != NULL);

		assert(rte_eth_dev_info_get(0, &dev_info) >= 0);

		assert(rte_eth_dev_configure(0, 1, 1, &local_port_conf) >= 0);

		assert(rte_eth_dev_adjust_nb_rx_tx_desc(0, &nb_rxd, &nb_txd) >= 0);

		assert(rte_eth_rx_queue_setup(0, 0, nb_rxd,
					      rte_eth_dev_socket_id(0),
					      &dev_info.default_rxconf, pktmbuf_pool) >= 0);

		assert(rte_eth_tx_queue_setup(0, 0, nb_txd,
					      rte_eth_dev_socket_id(0),
					      &dev_info.default_txconf) >= 0);

		assert(rte_eth_dev_start(0) >= 0);
		assert(rte_eth_promiscuous_enable(0) >= 0);

	}

	/* setup dpip */

	{
		s8_t idx6;
		dpip_init(pktmbuf_pool);
		assert(netif_add_noaddr(&_netif, NULL, if_init, ip_input) == &_netif);
		netif_set_addr(&_netif, &_addr, &_mask, &_gate);
		assert(netif_add_ip6_address(&_netif, &_addr6, &idx6) == ERR_OK);
		netif_ip6_addr_set_state(&_netif, idx6, IP6_ADDR_VALID);
		netif_set_default(&_netif);
		netif_set_link_up(&_netif);
		netif_set_up(&_netif);
		netif = &_netif;
	}

	/* setup servers */

	assert((http_tpcb = setup_http_server(http_port, content_len)) != NULL);
	assert((echo_tpcb = setup_tcp_echo_server(tcp_echo_port)) != NULL);
	assert((prox_tpcb =
		setup_tcp_proxy_server(tcp_proxy_port, tcp_proxy_target,
				       tcp_proxy_target_port)) != NULL);
	printf("-- servers started --\n");

	while (1) {
		struct rte_mbuf *rx_mbufs[MAX_PKT_BURST];
		unsigned short i, nb_rx;

		nb_rx = rte_eth_rx_burst(0, 0, rx_mbufs, MAX_PKT_BURST);
		for (i = 0; i < nb_rx; i++) {
			assert(ethernet_input(rx_mbufs[i], &_netif) == ERR_OK);
		}
		tx_flush();
		sys_check_timeouts();
	}

	return 0;
}
