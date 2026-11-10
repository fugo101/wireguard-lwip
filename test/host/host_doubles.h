/* SPDX-License-Identifier: MIT. Host doubles shared by the test/host programs: the four platform functions, the
 * few lwIP functions wireguardif.c calls, packet capture, EXPECT and helpers. Include it right after wireguardif.c.
 * Based on the host reproduction by Tomasz Fiedoruk. */
#ifndef HOST_DOUBLES_H
#define HOST_DOUBLES_H
#include "crypto/refc/blake2s.h"
#include "crypto/refc/chacha20poly1305.h"
#include <assert.h>
#include <stdio.h>

static uint32_t clock_ms = 100000;
static uint32_t rng = 0x2468ace1u;
uint32_t wireguard_sys_now(void) { return clock_ms; }
bool wireguard_is_under_load(void) { return false; }
void wireguard_random_bytes(void *out, size_t n) {
    uint8_t *p = out;
    while (n--) { rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5; *p++ = (uint8_t)rng; }
}
void wireguard_tai64n_now(uint8_t *out) {
    static uint32_t stamp = 1;
    U64TO8_BIG(out, UINT64_C(0x400000000000000a) + 1800000000);
    U32TO8_BIG(out + 8, stamp++);
}
uint32_t napt_test_random(void) { return rng; }

/* --- minimal lwIP doubles (no host networking) --- */
struct pbuf *pbuf_alloc(pbuf_layer l, u16_t len, pbuf_type t) {
    (void)l; (void)t;
    struct pbuf *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->payload = calloc(1, len ? len : 1); assert(p->payload);
    p->len = p->tot_len = len; p->ref = 1;
    return p;
}
u8_t pbuf_free(struct pbuf *p) { free(p->payload); free(p); return 1; }
err_t pbuf_take(struct pbuf *p, const void *d, u16_t n) { if (n > p->tot_len) return ERR_ARG; memcpy(p->payload, d, n); return ERR_OK; }
u16_t pbuf_copy_partial(const struct pbuf *p, void *d, u16_t n, u16_t off) {
    if (off >= p->tot_len) return 0;
    if (n > p->tot_len - off) n = p->tot_len - off;
    memcpy(d, (const uint8_t *)p->payload + off, n); return n;
}
void *mem_malloc(mem_size_t n) { return malloc(n); }
void *mem_calloc(mem_size_t n, mem_size_t s) { return calloc(n, s); }
void mem_free(void *p) { free(p); }
void sys_timeout(u32_t ms, sys_timeout_handler h, void *a) { (void)ms; (void)h; (void)a; }
void sys_untimeout(sys_timeout_handler h, void *a) { (void)h; (void)a; }
void netif_set_link_up(struct netif *n) { n->flags |= NETIF_FLAG_LINK_UP; }
void netif_set_link_down(struct netif *n) { n->flags &= (u8_t)~NETIF_FLAG_LINK_UP; }
struct udp_pcb *udp_new(void) { return NULL; }
err_t udp_bind(struct udp_pcb *p, const ip_addr_t *a, u16_t port) { (void)p; (void)a; (void)port; return ERR_OK; }
void udp_bind_netif(struct udp_pcb *p, const struct netif *n) { (void)p; (void)n; }
void udp_recv(struct udp_pcb *p, udp_recv_fn f, void *a) { (void)p; (void)f; (void)a; }
void udp_remove(struct udp_pcb *p) { (void)p; }

static unsigned delivered, sent;
static ip_addr_t last_dst; static u16_t last_port;
static uint8_t last_wire[256]; static size_t last_len;
/* netif->input: in the firmware this is tcpip_input; here it counts what reaches the IP layer. */
static err_t test_input(struct pbuf *p, struct netif *inp) { (void)inp; delivered++; pbuf_free(p); return ERR_OK; }
err_t udp_sendto(struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *dst, u16_t port) {
    (void)pcb; sent++; last_dst = *dst; last_port = port;
    last_len = p->tot_len < sizeof(last_wire) ? p->tot_len : sizeof(last_wire);
    memcpy(last_wire, p->payload, last_len); return ERR_OK;
}

static unsigned checks, failures;
#define EXPECT(cond, what) do { checks++; if (!(cond)) { failures++; printf("FAIL %s (line %d)\n", what, __LINE__); } else printf("ok   %s\n", what); } while (0)

static void rx(struct wireguard_device *dev, const void *bytes, size_t n, uint32_t ip_host, u16_t port) {
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)n, PBUF_RAM);
    memcpy(p->payload, bytes, n);
    ip_addr_t a; IP_ADDR4(&a, ip_host >> 24, (ip_host >> 16) & 255, (ip_host >> 8) & 255, ip_host & 255);
    wireguardif_network_rx(dev, NULL, p, &a, port); /* frees p */
}
static uint32_t host_of(const ip_addr_t *a) { return lwip_ntohl(ip_2_ip4(a)->addr); }

#endif /* HOST_DOUBLES_H */
