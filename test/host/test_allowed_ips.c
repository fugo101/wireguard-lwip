/* SPDX-License-Identifier: MIT. Host test for cryptokey routing with several peers: on transmit, a packet goes to the
 * peer whose allowed IP is the longest prefix match, whatever its session state. It #includes the component's own
 * wireguardif.c and uses its real handshake, AEAD, transmit and receive paths; lwIP and time are small doubles.
 * Build: see build.sh. Each "BUG:" line states what must NOT happen; controls must pass either way. */
#include "wireguardif.c"
#include "host_doubles.h"

/* Outer endpoints of the three servers, and their addresses inside the tunnel. */
#define EP_B 0xc6336402u   /* 198.51.100.2 */
#define EP_C 0xc6336403u   /* 198.51.100.3, the exit node: allowed 0.0.0.0/0 */
#define EP_D 0xc6336404u   /* 198.51.100.4 */
#define EP_E 0xc6336405u   /* 198.51.100.5, B after a key rotation: same tunnel address */
#define IN_B 0x0a000002u   /* 10.0.0.2/32 */
#define IN_D 0x0a000004u   /* 10.0.0.4/32 */
#define IN_X 0x0a090909u   /* 10.9.9.9, no peer of its own: only the exit node routes it */
#define IN_A 0x0a000001u   /* the device itself */

struct server { struct wireguard_device dev; struct wireguard_peer *peer; uint32_t endpoint; u8_t idx; };

static ip_addr_t ip4(uint32_t h) { ip_addr_t a; IP_ADDR4(&a, h >> 24, (h >> 16) & 255, (h >> 8) & 255, h & 255); return a; }

/* Register server s as a peer of device a with allowed IP ip/mask and its outer endpoint. */
static void add_server(struct netif *wg, struct wireguard_device *a, struct server *s, uint32_t ip, uint32_t mask, uint32_t endpoint) {
    uint8_t key[32]; wireguard_random_bytes(key, 32);
    assert(wireguard_device_init(&s->dev, key));
    char pub_b64[64]; size_t blen = sizeof(pub_b64);
    assert(wireguard_base64_encode(s->dev.public_key, 32, pub_b64, &blen));
    struct wireguardif_peer cfg; wireguardif_peer_init(&cfg);
    cfg.public_key = pub_b64; cfg.keep_alive = 25; cfg.endport_port = 51820;
    cfg.endpoint_ip = ip4(endpoint); cfg.allowed_ip = ip4(ip); cfg.allowed_mask = ip4(mask);
    s->idx = 0xff;
    assert(wireguardif_add_peer(wg, &cfg, &s->idx) == ERR_OK && s->idx != 0xff);
    s->peer = &s->dev.peers[0]; s->endpoint = endpoint;
    assert(wireguard_peer_init(&s->dev, s->peer, a->public_key, NULL));
}

/* Device a initiates to server s (wireguardif_connect sends the initiation), s responds, both sides get a session. */
static void establish(struct netif *wg, struct wireguard_device *a, struct server *s) {
    sent = 0; assert(wireguardif_connect(wg, s->idx) == ERR_OK);
    assert(sent == 1 && host_of(&last_dst) == s->endpoint && last_len == sizeof(struct message_handshake_initiation));
    struct message_handshake_initiation init; memcpy(&init, last_wire, sizeof(init));
    assert(wireguard_check_mac1(&s->dev, (uint8_t *)&init, sizeof(init) - 32, init.mac1));
    assert(wireguard_process_initiation_message(&s->dev, &init) == s->peer);
    struct message_handshake_response resp;
    assert(wireguard_create_handshake_response(&s->dev, s->peer, &resp));
    wireguard_start_session(s->peer, false);
    rx(a, &resp, sizeof(resp), s->endpoint, 51820);
    assert(a->peers[s->idx].curr_keypair.valid);
    keypair_update(s->peer, &s->peer->next_keypair);
}

/* Send one IPv4 packet from the device to inner address dst through the netif output; return where it went. */
static uint32_t tx(struct netif *wg, uint32_t dst, err_t *err) {
    uint8_t inner[28] = {0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17};
    inner[12] = IN_A >> 24; inner[13] = (IN_A >> 16) & 255; inner[14] = (IN_A >> 8) & 255; inner[15] = IN_A & 255;
    inner[16] = dst >> 24; inner[17] = (dst >> 16) & 255; inner[18] = (dst >> 8) & 255; inner[19] = dst & 255;
    struct pbuf *q = pbuf_alloc(PBUF_IP, sizeof(inner), PBUF_RAM);
    memcpy(q->payload, inner, sizeof(inner));
    ip4_addr_t d; IP4_ADDR(&d, dst >> 24, (dst >> 16) & 255, (dst >> 8) & 255, dst & 255);
    sent = 0;
    *err = wireguardif_output(wg, q, &d);
    pbuf_free(q);
    return sent ? host_of(&last_dst) : 0;
}

int main(void) {
    wireguard_init();
    struct netif wg = {0};
    struct wireguard_device *a = calloc(1, sizeof(*a));
    uint8_t ka[32]; wireguard_random_bytes(ka, 32);
    assert(wireguard_device_init(a, ka));
    a->netif = &wg; a->udp_pcb = NULL; wg.state = a; wg.input = test_input;
    static struct server b, c, d, e;
    add_server(&wg, a, &b, IN_B, 0xffffffffu, EP_B);
    add_server(&wg, a, &c, 0, 0, EP_C);
    add_server(&wg, a, &d, IN_D, 0xffffffffu, EP_D);
    err_t err;

    puts("== 1. transmit: the most specific peer has no session, a wider peer (the exit node) does");
    establish(&wg, a, &c);
    EXPECT(!a->peers[b.idx].curr_keypair.valid && a->peers[c.idx].curr_keypair.valid, "control: only the exit node has a session");
    EXPECT(tx(&wg, IN_X, &err) == EP_C && err == ERR_OK, "control: an address only the exit node covers goes to the exit node");
    uint32_t to = tx(&wg, IN_B, &err);
    EXPECT(to != EP_C, "BUG: a packet for B was encrypted to the exit node because B has no session");
    EXPECT(to == 0 && err == ERR_CONN, "a packet for a peer without a session is dropped");

    puts("== 2. transmit while B's handshake is in flight, once B has a session, and after it loses it");
    clock_ms += 1000;
    sent = 0; assert(wireguardif_connect(&wg, b.idx) == ERR_OK); assert(sent == 1 && host_of(&last_dst) == EP_B);
    struct message_handshake_initiation init; memcpy(&init, last_wire, sizeof(init));
    EXPECT(tx(&wg, IN_B, &err) == 0 && err == ERR_CONN, "BUG: a packet sent while B's handshake is in flight left through the exit node");
    assert(wireguard_check_mac1(&b.dev, (uint8_t *)&init, sizeof(init) - 32, init.mac1));
    assert(wireguard_process_initiation_message(&b.dev, &init) == b.peer);
    struct message_handshake_response resp; assert(wireguard_create_handshake_response(&b.dev, b.peer, &resp));
    wireguard_start_session(b.peer, false);
    clock_ms += 300; rx(a, &resp, sizeof(resp), EP_B, 51820);
    keypair_update(b.peer, &b.peer->next_keypair);
    unsigned initiations = 0;
    for (unsigned i = 0; i < 20; i++) {   /* 8 s of timer ticks, longer than REKEY_TIMEOUT */
        clock_ms += 400; sent = 0; wireguardif_tmr(a);
        if (sent && last_wire[0] == MESSAGE_HANDSHAKE_INITIATION && host_of(&last_dst) == EP_B) initiations++;
    }
    EXPECT(a->peers[b.idx].curr_keypair.valid && initiations == 0, "the dropped packet does not cause a second handshake once the session is up");
    EXPECT(tx(&wg, IN_B, &err) == EP_B && err == ERR_OK, "control: with a session, a packet for B goes to B");
    EXPECT(tx(&wg, IN_X, &err) == EP_C, "control: the exit node still carries the rest");
    keypair_destroy(&a->peers[b.idx].curr_keypair); keypair_destroy(&a->peers[b.idx].prev_keypair);
    EXPECT(tx(&wg, IN_B, &err) != EP_C, "BUG: after B's session ended, its traffic fell back to the exit node");
    EXPECT(tx(&wg, IN_D, &err) != EP_C, "BUG: a packet for D (never connected) was encrypted to the exit node");

    puts("== 5. two peers with the same prefix: the last one added owns it");
    add_server(&wg, a, &e, IN_B, 0xffffffffu, EP_E);
    bool b_holds = false;
    for (int y = 0; y < WIREGUARD_MAX_SRC_IPS; y++) b_holds |= a->peers[b.idx].allowed_source_ips[y].valid;
    EXPECT(!b_holds, "adding E with B's /32 removes it from B");
    clock_ms += 1000; establish(&wg, a, &e);
    EXPECT(tx(&wg, IN_B, &err) == EP_E, "BUG: traffic for the shared /32 went to the older peer B");

    wireguardif_shutdown(&wg); free(a); wg.state = NULL;
    printf("Allowed-IP routing test: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
