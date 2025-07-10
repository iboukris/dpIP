#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include <dpip/init.h>
#include <dpip/pbuf.h>
#include <dpip/netif.h>
#include <dpip/etharp.h>
#include <dpip/ethip6.h>
#include <dpip/tcp.h>
#include <dpip/timeouts.h>

#include <dpip/ethernet.h>

void tcp_debug_print_pcbs(void);
struct tcp_pcb *setup_http_server(int http_port, size_t content_len);
struct tcp_pcb *setup_tcp_echo_server(int tcp_echo_port);
struct tcp_pcb *setup_tcp_proxy_server(int tcp_proxy_port, ip_addr_t tcp_proxy_target,
				       int tcp_proxy_target_port);
