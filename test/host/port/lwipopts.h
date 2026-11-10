/* SPDX-License-Identifier: MIT. Same IPv4 NAPT branches; no sockets/devices. */
#pragma once
#include <stdint.h>
#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define ESP_LWIP 1
#define LWIP_IPV4 1
#ifndef LWIP_IPV6
#define LWIP_IPV6 0   /* build.sh also builds a dual-stack variant with -DLWIP_IPV6=1, as ESP-IDF does */
#endif
#define IP_FORWARD 1
#define IP_NAPT 1
#define IP_NAPT_PORTMAP 0
#define IP_NAPT_MAX 16
#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_ICMP 1
#define LWIP_STATS 0
#define LWIP_TIMERS 1
#define LWIP_TCPIP_CORE_LOCKING 0
#define MEM_LIBC_MALLOC 0
#define LWIP_CHECKSUM_CTRL_PER_NETIF 0
#define LWIP_RAND() napt_test_random()
uint32_t napt_test_random(void);
