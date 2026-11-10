/* SPDX-License-Identifier: MIT. Test-only compiler port; no host networking. */
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#undef htons
#undef ntohs
#undef htonl
#undef ntohl
#define LWIP_PLATFORM_DIAG(x) do { printf x; } while(0)
#define LWIP_PLATFORM_ASSERT(x) do { fprintf(stderr,"lwIP assert: %s\n",x);abort(); } while(0)
#define PACK_STRUCT_STRUCT __attribute__((packed))
