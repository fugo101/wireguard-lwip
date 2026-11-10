/* SPDX-License-Identifier: MIT. Host test for issue #22: the DERP flag on every path that sets a direct endpoint,
 * link-up only on a down->up transition, no output on the per-packet receive and periodic paths (and a rate-limited
 * error when an initiation cannot be built), and no cookie reply to an "any" (DERP-injected) source. It #includes the component's own wireguardif.c and uses its real handshake
 * and receive paths; lwIP and time are small doubles.
 * Build: see build.sh. Each "BUG:" line states what must NOT happen; controls must pass either way. */
#include "wireguardif.c"
#include "host_doubles.h"

#define EP_S    0xc6336402u   /* 198.51.100.2, the server's configured endpoint */
#define EP_ROAM 0xcb00710au   /* 203.0.113.10, another source address */
#define DERP    0u            /* wireguardif_inject_packet() passes DERP packets as 0.0.0.0:0 */
#define INNER_S 0x0a000002u   /* 10.0.0.2, the server's allowed IP */

struct server { struct wireguard_device dev; struct wireguard_peer *peer; u8_t idx; };

static ip_addr_t ip4(uint32_t h) { ip_addr_t a; IP_ADDR4(&a, h >> 24, (h >> 16) & 255, (h >> 8) & 255, h & 255); return a; }

static unsigned derp_sent;
static err_t derp_out(const uint8_t *key, const uint8_t *data, size_t len, void *ctx) { (void)key; (void)data; (void)len; (void)ctx; derp_sent++; return ERR_OK; }

static struct wireguard_device *new_device(struct netif *wg) {
    struct wireguard_device *a = calloc(1, sizeof(*a));
    uint8_t k[32]; wireguard_random_bytes(k, 32);
    assert(wireguard_device_init(a, k));
    memset(wg, 0, sizeof(*wg));
    a->netif = wg; wg->state = a; wg->input = test_input;
    wireguardif_set_derp_output(wg, derp_out, NULL);
    return a;
}

/* A server s that knows the device, registered on the device with a direct endpoint. */
static struct wireguard_peer *add_server(struct netif *wg, struct wireguard_device *a, struct server *s) {
    uint8_t k[32]; wireguard_random_bytes(k, 32);
    assert(wireguard_device_init(&s->dev, k));
    s->peer = &s->dev.peers[0];
    assert(wireguard_peer_init(&s->dev, s->peer, a->public_key, NULL));
    char pub_b64[64]; size_t blen = sizeof(pub_b64);
    assert(wireguard_base64_encode(s->dev.public_key, 32, pub_b64, &blen));
    struct wireguardif_peer cfg; wireguardif_peer_init(&cfg);
    cfg.public_key = pub_b64; cfg.keep_alive = 25; cfg.endport_port = 51820;
    cfg.endpoint_ip = ip4(EP_S); cfg.allowed_ip = ip4(INNER_S); cfg.allowed_mask = ip4(0xffffffffu);
    s->idx = 0xff;
    assert(wireguardif_add_peer(wg, &cfg, &s->idx) == ERR_OK && s->idx != 0xff);
    return &a->peers[s->idx];
}

static void reset_counts(void) { sent = 0; derp_sent = 0; }

/* The server initiates; deliver it from the given outer address (DERP = injected through DERP). */
static void server_initiates(struct wireguard_device *a, struct server *s, uint32_t from) {
    struct message_handshake_initiation init;
    assert(wireguard_create_handshake_initiation(&s->dev, s->peer, &init));
    rx(a, &init, sizeof(init), from, from == DERP ? 0 : 51820);
}

/* The device's initiation is in last_wire: the server answers it. */
static void server_responds(struct server *s, struct message_handshake_response *resp) {
    struct message_handshake_initiation init;
    assert(last_wire[0] == MESSAGE_HANDSHAKE_INITIATION);
    memcpy(&init, last_wire, sizeof(init));
    assert(wireguard_process_initiation_message(&s->dev, &init) == s->peer);
    assert(wireguard_create_handshake_response(&s->dev, s->peer, resp));
    wireguard_start_session(s->peer, false);
}

static size_t make_data(struct wireguard_peer *bp, uint8_t *buf) {
    uint8_t inner[32] = {0x45, 0, 0, 32, 0, 0, 0, 0, 64, 17};
    U32TO8_BIG(inner + 12, INNER_S); U32TO8_BIG(inner + 16, 0x0a000001u);
    struct message_transport_data *h = (struct message_transport_data *)buf;
    memset(buf, 0, 16); h->type = MESSAGE_TRANSPORT_DATA; h->receiver = bp->curr_keypair.remote_index;
    U64TO8_LITTLE(h->counter, bp->curr_keypair.sending_counter);
    wireguard_encrypt_packet(&h->enc_packet[0], inner, sizeof(inner), &bp->curr_keypair);
    return 16 + sizeof(inner) + 16;
}

/* stdout position, to tell whether a code path printed anything. build.sh sends stdout to a file; on a terminal or
 * pipe ftell() fails and the check passes without testing anything. */
static long out_pos(void) { fflush(stdout); return ftell(stdout); }
static bool quiet_since(long pos) { return pos < 0 || out_pos() == pos; }

static void run_for(struct netif *wg, unsigned seconds, bool periodic) {
    for (unsigned t = 0; t < seconds * 1000; t += 400) {
        clock_ms += 400;
        if (periodic) wireguardif_periodic(wg); else wireguardif_tmr(wg->state);
    }
}

static void reset_restores_direct(bool periodic) {
    struct netif wg; struct wireguard_device *a = new_device(&wg);
    static struct server s;
    struct wireguard_peer *p = add_server(&wg, a, &s);
    clock_ms += 1000;
    assert(wireguardif_connect(&wg, s.idx) == ERR_OK);       /* active, direct; nothing answers it */
    clock_ms += 1000; reset_counts();
    server_initiates(a, &s, DERP);
    EXPECT(p->last_rx_via_derp && host_of(&p->ip) == EP_S && derp_sent == 1, "control: the server's initiation came over DERP and was answered there");

    run_for(&wg, 3 * REJECT_AFTER_TIME + 1, periodic);
    EXPECT(p->last_session_millis == 0 && host_of(&p->ip) == EP_S, "control: the reset ran and restored the configured endpoint");
    EXPECT(!p->last_rx_via_derp, "BUG: the reset set the direct endpoint but left last_rx_via_derp set");
    reset_counts(); long pos = out_pos();
    run_for(&wg, 2 * REKEY_TIMEOUT, periodic);
    bool quiet = quiet_since(pos);
    EXPECT(sent > 0 && derp_sent == 0 && host_of(&last_dst) == EP_S, "BUG: after the reset, handshake retries to the restored endpoint went through DERP");
    EXPECT(quiet, "BUG: the timer printed on handshake retries (bare printf on the periodic path)");
    wireguardif_shutdown(&wg); free(a);
}

int main(void) {
    wireguard_init();

    puts("== 1. wireguardif_connect() after a packet over DERP");
    {
        struct netif wg; struct wireguard_device *a = new_device(&wg);
        static struct server s;
        struct wireguard_peer *p = add_server(&wg, a, &s);
        clock_ms += 1000; reset_counts();
        server_initiates(a, &s, DERP);
        EXPECT(p->last_rx_via_derp && host_of(&p->ip) == EP_S && derp_sent == 1 && sent == 0,
               "control: an initiation over DERP is answered over DERP and marks the peer");
        reset_counts();
        EXPECT(wireguardif_connect(&wg, s.idx) == ERR_OK, "control: connect to the configured endpoint is accepted");
        EXPECT(sent == 1 && derp_sent == 0 && host_of(&last_dst) == EP_S && last_wire[0] == MESSAGE_HANDSHAKE_INITIATION,
               "BUG: the handshake of wireguardif_connect() went through DERP instead of to the direct endpoint");
        EXPECT(!p->last_rx_via_derp, "BUG: wireguardif_connect() set a direct endpoint but left last_rx_via_derp set");
        clock_ms += REKEY_TIMEOUT * 1000 + 1; reset_counts();
        EXPECT(wireguardif_connect_derp(&wg, s.idx) == ERR_OK && derp_sent == 1 && sent == 0,
               "control: wireguardif_connect_derp() still goes through DERP");
        wireguardif_shutdown(&wg); free(a);
    }

    puts("== 2. wireguardif_add_peer() with a direct endpoint");
    {
        struct netif wg; struct wireguard_device *a = new_device(&wg);
        static struct server s;
        struct wireguard_peer *p = add_server(&wg, a, &s);
        EXPECT(!p->last_rx_via_derp && host_of(&p->ip) == EP_S, "control: a new peer starts direct with the DERP flag clear");
        clock_ms += 1000; reset_counts();
        EXPECT(wireguardif_connect(&wg, s.idx) == ERR_OK && sent == 1 && derp_sent == 0, "control: its first handshake goes direct");
        wireguardif_shutdown(&wg); free(a);
    }

    puts("== 3. reset after 3 x Reject-After-Time restores a direct endpoint, wireguardif_tmr");
    reset_restores_direct(false);
    puts("== 4. reset after 3 x Reject-After-Time restores a direct endpoint, wireguardif_periodic");
    reset_restores_direct(true);

    puts("== 5. data receive changes the link state only on down->up");
    {
        struct netif wg; struct wireguard_device *a = new_device(&wg);
        static struct server s;
        struct wireguard_peer *p = add_server(&wg, a, &s);
        clock_ms += 1000; reset_counts();
        assert(wireguardif_connect(&wg, s.idx) == ERR_OK && sent == 1);
        struct message_handshake_response resp; server_responds(&s, &resp);
        link_up_calls = 0;
        rx(a, &resp, sizeof(resp), EP_S, 51820);
        EXPECT(p->curr_keypair.valid && netif_is_link_up(&wg) && link_up_calls == 1, "control: the completed handshake set the link up");
        keypair_update(s.peer, &s.peer->next_keypair);      /* the server confirms with the device's keepalive */

        uint8_t pkt[128]; size_t n;
        unsigned before = delivered; link_up_calls = 0; long pos = out_pos();
        for (int i = 0; i < 5; i++) { n = make_data(s.peer, pkt); rx(a, pkt, n, EP_S, 51820); }
        bool quiet = quiet_since(pos);
        EXPECT(delivered == before + 5, "control: five data packets reached IP");
        EXPECT(link_up_calls == 0, "BUG: data packets set the link up (netif->state workaround) while it was already up");
        EXPECT(quiet, "BUG: the receive path printed on every data packet (bare printf)");
        netif_set_link_down(&wg); link_up_calls = 0;
        n = make_data(s.peer, pkt); rx(a, pkt, n, EP_S, 51820);
        EXPECT(link_up_calls == 1 && netif_is_link_up(&wg) && wg.state == a, "control: a data packet brings a down link up and restores netif->state");

        clock_ms += REKEY_TIMEOUT * 1000 + 1; reset_counts();  /* rekey: a second handshake while the link is up */
        assert(wireguardif_connect(&wg, s.idx) == ERR_OK && sent == 1);
        server_responds(&s, &resp);
        link_up_calls = 0;
        rx(a, &resp, sizeof(resp), EP_S, 51820);
        EXPECT(p->curr_keypair.valid && netif_is_link_up(&wg), "control: the rekey handshake completed");
        EXPECT(link_up_calls == 0, "BUG: a completed handshake set the link up (netif->state workaround) while it was already up");
        wireguardif_shutdown(&wg); free(a);
    }

    puts("== 6. under load, no cookie reply to a source address of 0.0.0.0 (DERP injection)");
    {
        struct netif wg; struct wireguard_device *a = new_device(&wg);
        static struct server s;
        add_server(&wg, a, &s);
        clock_ms += 1000; under_load = true; reset_counts();
        server_initiates(a, &s, EP_ROAM);
        EXPECT(sent == 1 && last_wire[0] == MESSAGE_COOKIE_REPLY && host_of(&last_dst) == EP_ROAM,
               "control: under load, a direct initiation without mac2 gets a cookie reply at its source");
        clock_ms += 1000; reset_counts();
        server_initiates(a, &s, DERP);
        EXPECT(sent == 0 && derp_sent == 0, "BUG: under load, an initiation over DERP got a cookie reply (sent to 0.0.0.0)");

        under_load = false; clock_ms += 1000; reset_counts();
        assert(wireguardif_connect(&wg, s.idx) == ERR_OK && sent == 1);
        struct message_handshake_response resp; server_responds(&s, &resp);
        under_load = true; reset_counts();
        rx(a, &resp, sizeof(resp), DERP, 0);
        EXPECT(sent == 0 && derp_sent == 0, "BUG: under load, a handshake response over DERP got a cookie reply (sent to 0.0.0.0)");
        under_load = false;
        wireguardif_shutdown(&wg); free(a);
    }

    puts("== 7. a duplicate (replayed) initiation is dropped without output");
    {
        struct netif wg; struct wireguard_device *a = new_device(&wg);
        static struct server s;
        add_server(&wg, a, &s);
        clock_ms += 1000; reset_counts();
        struct message_handshake_initiation init;
        assert(wireguard_create_handshake_initiation(&s.dev, s.peer, &init));
        rx(a, &init, sizeof(init), EP_S, 51820);
        EXPECT(sent == 1 && last_wire[0] == MESSAGE_HANDSHAKE_RESPONSE, "control: the first copy is answered");
        clock_ms += 1000; reset_counts(); long pos = out_pos();
        rx(a, &init, sizeof(init), EP_S, 51820);           /* the same bytes again, e.g. the DERP copy of a direct one */
        bool quiet = quiet_since(pos);
        EXPECT(sent == 0 && derp_sent == 0, "control: the duplicate is rejected");
        EXPECT(quiet, "BUG: the receive path printed on a duplicate initiation (bare printf)");
        wireguardif_shutdown(&wg); free(a);
    }

    puts("== 8. a handshake that cannot be built is logged once per REKEY_TIMEOUT, not every tick");
    {
        struct netif wg; struct wireguard_device *a = new_device(&wg);
        static struct server s;
        add_server(&wg, a, &s);
        clock_ms += 1000; reset_counts();
        long pos = out_pos();
        pbuf_alloc_fails = true;
        wireguardif_connect(&wg, s.idx);                    /* active; the initiation fails (no pbuf) */
        long first = out_pos();
        run_for(&wg, REKEY_TIMEOUT - 1, true);              /* the timer retries on every tick */
        bool quiet = quiet_since(first);
        EXPECT(pos < 0 || first > pos, "control: the failure is reported");
        EXPECT(sent == 0 && derp_sent == 0, "control: every retry failed");
        EXPECT(quiet, "BUG: the periodic path printed the failure on every tick");
        pos = out_pos();
        run_for(&wg, 2, true);
        EXPECT(pos < 0 || out_pos() > pos, "control: it is reported again after REKEY_TIMEOUT");
        pbuf_alloc_fails = false;
        run_for(&wg, 1, true);
        EXPECT(sent == 1 && last_wire[0] == MESSAGE_HANDSHAKE_INITIATION, "control: once memory is back the retry goes out");
        wireguardif_shutdown(&wg); free(a);
    }

    printf("Small fixes test: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
