#include "dpip/opt.h"
#include "dpip/config.h"

#include "dpip/memp.h"
#include "dpip/sys.h"

#include <string.h>
#include <rte_mbuf.h>
#include <rte_errno.h>

struct rte_mempool *memp_pool[MEMP_MAX];

/**
 * Initializes dpIP built-in pools.
 * Related functions: memp_malloc, memp_free
 */

void memp_init(void)
{
	u16_t i;

	/* for every pool: */
	for (i = 0; i < MEMP_MAX; i++) {
		memp_pool[i] = rte_mempool_create(dpip_global_cfg.memp[i].name,
						  dpip_global_cfg.memp[i].num,
						  dpip_global_cfg.memp[i].size,
						  dpip_global_cfg.memp[i].
						  cache_size, 0, NULL, NULL,
						  NULL, NULL, SOCKET_ID_ANY, 0);
		if (memp_pool[i] == NULL) {
			// TODO: free cteated pools?
			rte_exit(EXIT_FAILURE,
				 "failed to create mpool %d, %s\n", i,
				 rte_strerror(rte_errno));
		}
	}
}

/**
 * Get an element from a specific pool.
 *
 * @param type the pool to get an element from
 *
 * @return a pointer to the allocated memory or a NULL pointer on error
 */
void *memp_malloc(memp_t type)
{
	void *memp;

	DPIP_ASSERT("memp_free: type < MEMP_MAX", type < MEMP_MAX);

	if (rte_mempool_get(memp_pool[type], &memp)) {
		DPIP_ERROR("memp_malloc: rte_mempool_get failed", 0,
			   return NULL;
		    );
	}

	return memp;
}

void memp_free(memp_t type, void *mem)
{
	if (mem == NULL) {
		return;
	}

	DPIP_ASSERT("memp_free: type < MEMP_MAX", type < MEMP_MAX);

	rte_mempool_put(memp_pool[type], mem);
}
