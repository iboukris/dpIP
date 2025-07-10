#ifndef DPIP_HDR_MEMP_H
#define DPIP_HDR_MEMP_H

#include "dpip/opt.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Create the list of all memory pools managed by memp. MEMP_MAX represents a NULL pool at the end */
typedef enum {
	MEMP_TCP_PCB,
	MEMP_TCP_SEG,
	MEMP_ARP_QUEUE,
	MEMP_ND6_QUEUE,
	MEMP_MAX
} memp_t;

void memp_init(void);

void *memp_malloc(memp_t type);
void memp_free(memp_t type, void *mem);

#ifdef __cplusplus
}
#endif
#endif				/* DPIP_HDR_MEMP_H */
