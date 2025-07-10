#include "dpip/opt.h"
#include "dpip/config.h"

/* include everything we need for size calculation */
#include "dpip/tcp.h"
#include "dpip/priv/tcp_priv.h"
#include "dpip/etharp.h"
#include "dpip/priv/nd6_priv.h"

struct dpip_config dpip_global_cfg = {
	.place_hold = 777,
	.memp = {
		 {0, MEMP_NUM_TCP_PCB, sizeof(struct tcp_pcb), "MEMP_TCP_PCB"},
		 {0, MEMP_NUM_TCP_SEG, sizeof(struct tcp_seg), "MEMP_TCP_SEG"},
		 {0, MEMP_NUM_ARP_QUEUE, sizeof(struct etharp_q_entry),
		  "MEMP_ARP_QUEUE"},
		 {0, MEMP_NUM_ND6_QUEUE, sizeof(struct nd6_q_entry),
		  "MEMP_ND6_QUEUE"}
		 }
};
