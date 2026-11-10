/* SPDX-License-Identifier: MIT. Host test for the responder-side handshake limits and the session timers: the
 * initiation rate limit, saving and restoring the greatest handshake timestamp, and the reset after
 * 3 x Reject-After-Time, through both wireguardif_tmr and wireguardif_periodic. It #includes the component's own
 * wireguardif.c and uses its real handshake and receive paths; lwIP and time are small doubles.
 * Build: see build.sh. Each "BUG:" line states what must NOT happen; controls must pass either way. */
#include "wireguardif.c"
#include "host_doubles.h"

#define EP_S    0xc6336402u   /* 198.51.100.2, the server's configured endpoint */
#define EP_ROAM 0xcb00710au   /* 203.0.113.10, where its initiation actually comes from */

struct server { struct wireguard_device dev; struct wireguard_peer *peer; u8_t idx; };

static ip_addr_t ip4(uint32_t h) { ip_addr_t a; IP_ADDR4(&a, h >> 24, (h >> 16) & 255, (h >> 8) & 255, h & 255); return a; }

static unsigned accepted_calls, derp_sent; static u8_t accepted_idx;
static err_t derp_out(const uint8_t *key, const uint8_t *data, size_t len, void *ctx) { (void)key; (void)data; (void)len; (void)ctx; derp_sent++; return ERR_OK; }
static void on_accepted(struct netif *n, u8_t idx) { (void)n; accepted_calls++; accepted_idx = idx; }

static struct wireguard_device *new_device(struct netif *wg) {
    struct wireguard_device *a = calloc(1, sizeof(*a));
    uint8_t k[32]; wireguard_random_bytes(k, 32);
    assert(wireguard_device_init(a, k));
    memset(wg, 0, sizeof(*wg));
    a->netif = wg; wg->state = a; wg->input = test_input;
    return a;
}

/* Register s as a peer of a (endpoint 0 = no configured endpoint, as for a DERP-only peer). The device never
 * connects to it, so the device is only ever the responder. */
static void add_server(struct netif *wg, struct wireguard_device *a, struct server *s, uint32_t endpoint, const uint8_t *timestamp) {
    char pub_b64[64]; size_t blen = sizeof(pub_b64);
    assert(wireguard_base64_encode(s->dev.public_key, 32, pub_b64, &blen));
    struct wireguardif_peer cfg; wireguardif_peer_init(&cfg);
    cfg.public_key = pub_b64; cfg.keep_alive = 25; cfg.endport_port = endpoint ? 51820 : 0;
    cfg.endpoint_ip = ip4(endpoint); cfg.allowed_ip = ip4(0x0a000002u); cfg.allowed_mask = ip4(0xffffffffu);
    if (timestamp) memcpy(cfg.greatest_timestamp, timestamp, sizeof(cfg.greatest_timestamp));
    cfg.remote_initiation_accepted = on_accepted;
    s->idx = 0xff;
    assert(wireguardif_add_peer(wg, &cfg, &s->idx) == ERR_OK && s->idx != 0xff);
}

static void new_server(struct wireguard_device *a, struct server *s) {
    uint8_t k[32]; wireguard_random_bytes(k, 32);
    assert(wireguard_device_init(&s->dev, k));
    s->peer = &s->dev.peers[0];
    assert(wireguard_peer_init(&s->dev, s->peer, a->public_key, NULL));
}

/* Deliver one initiation from the given outer address; return whether the device answered it. */
static bool deliver(struct wireguard_device *a, const struct message_handshake_initiation *init, uint32_t from) {
    sent = 0;
    rx(a, init, sizeof(*init), from, 51820);
    return sent == 1 && last_wire[0] == MESSAGE_HANDSHAKE_RESPONSE;
}
static bool initiate(struct wireguard_device *a, struct server *s, uint32_t from, struct message_handshake_initiation *out) {
    struct message_handshake_initiation init;
    assert(wireguard_create_handshake_initiation(&s->dev, s->peer, &init));
    if (out) *out = init;
    return deliver(a, &init, from);
}

/* Run the device's timer for the given number of seconds, through wireguardif_tmr or wireguardif_periodic. */
static void run_for(struct netif *wg, unsigned seconds, bool periodic) {
    for (unsigned t = 0; t < seconds * 1000; t += 400) {
        clock_ms += 400;
        if (periodic) wireguardif_periodic(wg); else wireguardif_tmr(wg->state);
    }
}

static void reset_after_three_reject_times(bool periodic) {
    struct netif wg; struct wireguard_device *a = new_device(&wg);
    static struct server s, d, g;
    new_server(a, &s); add_server(&wg, a, &s, EP_S, NULL);
    new_server(a, &d); add_server(&wg, a, &d, 0, NULL);
    new_server(a, &g); add_server(&wg, a, &g, EP_S, NULL);
    struct wireguard_peer *p = &a->peers[s.idx], *pd = &a->peers[d.idx], *pg = &a->peers[g.idx];
    wireguardif_set_derp_output(&wg, derp_out, NULL);
    clock_ms += 1000;
    assert(initiate(a, &s, EP_ROAM, NULL) && initiate(a, &d, EP_ROAM, NULL) && initiate(a, &g, EP_S, NULL));
    EXPECT(host_of(&p->ip) == EP_ROAM && p->next_keypair.valid, "control: the initiation moved the endpoint and left an unconfirmed session");
    /* g's direct path dies and the application falls back to DERP, as microlink does; nothing answers. */
    assert(wireguardif_connect_derp(&wg, g.idx) == ERR_OK && ip_addr_isany(&pg->ip));

    run_for(&wg, REJECT_AFTER_TIME + 1, periodic);
    EXPECT(!p->next_keypair.valid, "BUG: an unconfirmed session outlived Reject-After-Time");

    /* An initiation of our own is outstanding when the reset comes. */
    p->handshake.valid = true; memset(p->handshake.ephemeral_private, 0xaa, sizeof(p->handshake.ephemeral_private));
    run_for(&wg, 2 * REJECT_AFTER_TIME, periodic);
    EXPECT(host_of(&p->ip) == EP_S, "BUG: after 3 x Reject-After-Time without a session the endpoint was not restored");
    EXPECT(p->last_session_millis == 0 && !p->handshake.valid, "the session state was discarded");
    bool zero = true;
    for (size_t i = 0; i < sizeof(p->handshake.ephemeral_private); i++) zero &= p->handshake.ephemeral_private[i] == 0;
    EXPECT(zero, "BUG: handshake keys stayed in memory after the reset");
    EXPECT(host_of(&pd->ip) == EP_ROAM, "a peer with no configured endpoint keeps the one it learned");
    EXPECT(ip_addr_isany(&pg->ip), "BUG: the reset moved a peer that fell back to DERP onto its dead direct endpoint");
    derp_sent = 0; sent = 0;
    run_for(&wg, 2 * REKEY_TIMEOUT, periodic);
    EXPECT(derp_sent > 0 && sent == 0, "BUG: after the reset, handshake retries for the DERP peer left on the direct path");

    wireguardif_shutdown(&wg); free(a);
}

int main(void) {
    wireguard_init();

    puts("== 1. initiation rate limit");
    {
        struct netif wg; struct wireguard_device *a = new_device(&wg);
        static struct server s;
        new_server(a, &s); add_server(&wg, a, &s, EP_S, NULL);
        EXPECT(initiate(a, &s, EP_S, NULL), "control: the first initiation is answered");
        clock_ms += 100;
        EXPECT(!initiate(a, &s, EP_S, NULL), "BUG: a second initiation 100 ms later was answered (limit is 2 per second)");
        clock_ms += 500;
        EXPECT(initiate(a, &s, EP_S, NULL), "control: an initiation after the limit window is answered");
        wireguardif_shutdown(&wg); free(a);
    }

    puts("== 2. greatest handshake timestamp across a restart");
    {
        struct netif wg; struct wireguard_device *a = new_device(&wg);
        static struct server s;
        new_server(a, &s); add_server(&wg, a, &s, EP_S, NULL);
        struct message_handshake_initiation old;
        clock_ms += 1000; accepted_calls = 0;
        assert(initiate(a, &s, EP_S, &old));
        EXPECT(accepted_calls == 1 && accepted_idx == s.idx, "the accepted initiation is reported to the application");
        uint8_t saved[WIREGUARDIF_TIMESTAMP_LEN], small[4];
        EXPECT(wireguardif_peer_greatest_timestamp(&wg, s.idx, saved, sizeof(saved)) == ERR_OK
               && memcmp(saved, a->peers[s.idx].greatest_timestamp, sizeof(saved)) == 0, "the timestamp can be read back");
        EXPECT(wireguardif_peer_greatest_timestamp(&wg, s.idx, small, sizeof(small)) == ERR_ARG, "a short buffer is refused");

        /* "Restart": remove the peer and add it again, once with the saved timestamp and once without. */
        assert(wireguardif_remove_peer(&wg, s.idx) == ERR_OK);
        add_server(&wg, a, &s, EP_S, saved);
        clock_ms += 1000; accepted_calls = 0;
        EXPECT(!deliver(a, &old, EP_ROAM) && accepted_calls == 0, "with the saved timestamp restored, the replayed initiation is refused");
        EXPECT(host_of(&a->peers[s.idx].ip) == EP_S, "and the endpoint stays where it was");
        assert(wireguardif_remove_peer(&wg, s.idx) == ERR_OK);
        add_server(&wg, a, &s, EP_S, NULL);
        clock_ms += 1000;
        EXPECT(deliver(a, &old, EP_ROAM), "control: without it, the same replay is accepted (why the timestamp must be saved)");
        wireguardif_shutdown(&wg); free(a);
    }

    puts("== 3. reset after 3 x Reject-After-Time, wireguardif_tmr");
    reset_after_three_reject_times(false);
    puts("== 4. reset after 3 x Reject-After-Time, wireguardif_periodic");
    reset_after_three_reject_times(true);

    printf("Session timer test: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
