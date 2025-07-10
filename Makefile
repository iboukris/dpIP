PROGS = dpip_app

CC = gcc
PKGCONF = pkg-config

CLEANFILES = $(PROGS) *.o *.d

CFLAGS = -O0 -g3
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -Wextra
CFLAGS += -I.

C_SRCS = examples/main.c examples/http_server.c examples/tcp_echo_server.c examples/tcp_proxy_server.c

C_OBJS = $(C_SRCS:.c=.o)

# for dpdk
CFLAGS += $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS += $(shell $(PKGCONF) --static --libs libdpdk)


# for dpip
DPIP_DIR = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DPIP_SRC_DIR = $(DPIP_DIR)
CFLAGS += -I$(DPIP_SRC_DIR)/src/include

DPIP_OBJS = \
			$(DPIP_SRC_DIR)/src/core/err.o \
			$(DPIP_SRC_DIR)/src/core/config.o \
			$(DPIP_SRC_DIR)/src/core/def.o \
			$(DPIP_SRC_DIR)/src/core/inet_chksum.o \
			$(DPIP_SRC_DIR)/src/core/init.o \
			$(DPIP_SRC_DIR)/src/core/ip.o \
			$(DPIP_SRC_DIR)/src/core/ipv4/etharp.o \
			$(DPIP_SRC_DIR)/src/core/ipv4/icmp.o \
			$(DPIP_SRC_DIR)/src/core/ipv4/ip4_addr.o \
			$(DPIP_SRC_DIR)/src/core/ipv4/ip4.o \
			$(DPIP_SRC_DIR)/src/core/ipv6/ethip6.o \
			$(DPIP_SRC_DIR)/src/core/ipv6/icmp6.o \
			$(DPIP_SRC_DIR)/src/core/ipv6/ip6_addr.o \
			$(DPIP_SRC_DIR)/src/core/ipv6/ip6.o \
			$(DPIP_SRC_DIR)/src/core/ipv6/nd6.o   \
			$(DPIP_SRC_DIR)/src/core/memp.o \
			$(DPIP_SRC_DIR)/src/core/netif.o \
			$(DPIP_SRC_DIR)/src/core/pbuf.o \
			$(DPIP_SRC_DIR)/src/core/stats.o \
			$(DPIP_SRC_DIR)/src/core/tcp.o \
			$(DPIP_SRC_DIR)/src/core/tcp_in.o \
			$(DPIP_SRC_DIR)/src/core/tcp_out.o \
			$(DPIP_SRC_DIR)/src/core/timeouts.o \
			$(DPIP_SRC_DIR)/src/core/sys.o \
			$(DPIP_SRC_DIR)/src/core/ethernet.o \


OBJS = $(C_OBJS) $(DPIP_OBJS)

CLEANFILES += $(DPIP_OBJS)

.PHONY: all
all: $(PROGS)


$(OBJS): $(DPIP_SRC_DIR) #$(DPDK_PKG_CONFIG_FILE)

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-@rm -rf $(CLEANFILES)
