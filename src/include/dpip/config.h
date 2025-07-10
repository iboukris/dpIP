#ifndef DPIP_HDR_CONFIG_H
#define DPIP_HDR_CONFIG_H

#include "dpip/opt.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dpip_config_tcp {
	unsigned hash_size;
};

struct dpip_config_memp_desc {
	unsigned cache_size;
	unsigned num;
	unsigned size;
	const char *name;
};

struct dpip_config {
	int place_hold;
	struct dpip_config_memp_desc memp[];
};

extern struct dpip_config dpip_global_cfg;

#ifdef __cplusplus
}
#endif
#endif				/* DPIP_HDR_CONFIG_H */
