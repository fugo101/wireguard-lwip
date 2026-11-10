/* SPDX-License-Identifier: MIT. Host test for the transport data receive path: replayed packets must not move the peer
 * endpoint or change any peer state. Based on the host reproduction by Tomasz Fiedoruk, adapted to this fork (netif->input
 * delivery, wireguardif_shutdown, magicsock/DERP injection). It #includes the component's own wireguardif.c and uses its
 * real handshake, AEAD and receive path; lwIP and time are small doubles, so no network or device is involved.
 * Build: see build.sh. Each "BUG:" line states what must NOT happen; controls must pass either way. */
#include "wireguardif.c"
#include "host_doubles.h"

#define ENDPOINT 0x5db8f001u /* 93.184.240.1, the configured server */
#define ATTACKER 0xc0a80142u /* 192.168.1.66, another host on the same LAN */

static void teardown(struct netif *wg) { wireguardif_shutdown(wg); free(wg->state); wg->state = NULL; }

/* Establish device (A, the real wireguardif) <-> server (B, protocol functions only). */
static void establish(struct netif *wg, struct wireguard_device **out_a,
                      struct wireguard_device *b, struct wireguard_peer **ap_out, struct wireguard_peer **bp_out) {
    static uint8_t ka[32], kb[32];
    wireguard_random_bytes(ka, 32); wireguard_random_bytes(kb, 32);
    struct wireguard_device *a = calloc(1, sizeof(*a));
    assert(wireguard_device_init(a, ka) && wireguard_device_init(b, kb));
    a->netif = wg; a->udp_pcb = NULL; wg->state = a; wg->input = test_input;
    char pub_b64[64]; size_t blen = sizeof(pub_b64);
    assert(wireguard_base64_encode(b->public_key, 32, pub_b64, &blen));
    struct wireguardif_peer cfg; wireguardif_peer_init(&cfg);
    cfg.public_key = pub_b64; cfg.keep_alive = 25; cfg.endport_port = 51820;
    IP_ADDR4(&cfg.endpoint_ip, ENDPOINT >> 24, (ENDPOINT >> 16) & 255, (ENDPOINT >> 8) & 255, ENDPOINT & 255);
    u8_t idx = 0xff;
    assert(wireguardif_add_peer(wg, &cfg, &idx) == ERR_OK && idx == 0);
    /* A sends the initiation: this fork's wireguardif_connect() starts the handshake immediately. */
    sent = 0; assert(wireguardif_connect(wg, idx) == ERR_OK);
    assert(sent == 1 && last_len == sizeof(struct message_handshake_initiation));
    struct wireguard_peer *ap = &a->peers[0], *bp = &b->peers[0];
    assert(wireguard_peer_init(b, bp, a->public_key, NULL));
    struct message_handshake_initiation init; memcpy(&init, last_wire, sizeof(init));
    assert(wireguard_check_mac1(b, (uint8_t *)&init, sizeof(init) - 32, init.mac1));
    assert(wireguard_process_initiation_message(b, &init) == bp);
    struct message_handshake_response resp;
    assert(wireguard_create_handshake_response(b, bp, &resp));
    wireguard_start_session(bp, false);
    rx(a, &resp, sizeof(resp), ENDPOINT, 51820);         /* A: session up, sends keepalive */
    assert(ap->curr_keypair.valid);
    keypair_update(bp, &bp->next_keypair);               /* B confirms with A's first packet */
    *out_a = a; *ap_out = ap; *bp_out = bp;
}

static size_t make_data_from(struct wireguard_peer *bp, uint8_t *buf, uint32_t inner_src, uint32_t inner_dst) {
    uint8_t inner[32] = {0x45, 0, 0, 32, 0, 0, 0, 0, 64, 17};
    inner[12] = (uint8_t)(inner_src >> 24); inner[13] = (uint8_t)(inner_src >> 16);
    inner[14] = (uint8_t)(inner_src >> 8); inner[15] = (uint8_t)inner_src;
    inner[16] = (uint8_t)(inner_dst >> 24); inner[17] = (uint8_t)(inner_dst >> 16);
    inner[18] = (uint8_t)(inner_dst >> 8); inner[19] = (uint8_t)inner_dst;
    struct message_transport_data *h = (struct message_transport_data *)buf;
    memset(buf, 0, 16); h->type = MESSAGE_TRANSPORT_DATA; h->receiver = bp->curr_keypair.remote_index;
    U64TO8_LITTLE(h->counter, bp->curr_keypair.sending_counter);
    wireguard_encrypt_packet(&h->enc_packet[0], inner, sizeof(inner), &bp->curr_keypair);
    return 16 + sizeof(inner) + 16;
}
static size_t make_data(struct wireguard_peer *bp, uint8_t *buf, uint32_t inner_dst) { return make_data_from(bp, buf, 0, inner_dst); }

int main(int argc, char **argv) {
    wireguard_init();
    struct netif wg = {0};
    struct wireguard_device *a, b = {0};
    struct wireguard_peer *ap, *bp;

    if (argc > 1 && !strcmp(argv[1], "short")) {
        puts("== 9. an authenticated 1-byte inner packet 0x45 (an IPv4 version nibble without a header)");
        establish(&wg, &a, &b, &ap, &bp);
        uint8_t one = 0x45, wire[64]; struct message_transport_data *h = (struct message_transport_data *)wire;
        memset(wire, 0, 16); h->type = MESSAGE_TRANSPORT_DATA; h->receiver = bp->curr_keypair.remote_index;
        U64TO8_LITTLE(h->counter, bp->curr_keypair.sending_counter);
        wireguard_encrypt_packet(&h->enc_packet[0], &one, 1, &bp->curr_keypair);
        unsigned before9 = delivered; rx(a, wire, 16 + 1 + 16, ENDPOINT, 51820);
        EXPECT(delivered == before9, "a 1-byte inner packet is dropped without reading an IP header (under ASan the unpatched code aborts here)");
        teardown(&wg);
        printf("short inner packet: %u checks, %u failures\n", checks, failures);
        return failures != 0;
    }
    puts("== 1. an authenticated data packet replayed from another address");
    establish(&wg, &a, &b, &ap, &bp);
    uint8_t pkt[128]; size_t n = make_data(bp, pkt, 0x0a020002u);
    delivered = 0;
    rx(a, pkt, n, ENDPOINT, 51820);
    EXPECT(delivered == 1, "control: the original packet from the endpoint reaches IP once");
    EXPECT(host_of(&ap->ip) == ENDPOINT, "control: endpoint after the original = configured");
    clock_ms += 60000; uint32_t replay_time = clock_ms;
    rx(a, pkt, n, ATTACKER, 4444);                         /* same bytes, different sender */
    EXPECT(delivered == 1, "control: the replay does not reach IP (the replay window works)");
    EXPECT(!(host_of(&ap->ip) == ATTACKER && ap->port == 4444), "BUG: the replay moved the peer endpoint to the other address");
    EXPECT(!(ap->last_rx == replay_time), "BUG: the replay refreshed peer->last_rx");

    puts("== 2. persistence: 10 minutes of the WireGuard timer (400 ms ticks), the real server silent");
    unsigned to_attacker = 0, to_endpoint = 0;
    for (unsigned i = 0; i < 1500; i++) {
        clock_ms += 400; sent = 0; wireguardif_tmr(a);
        if (sent) { if (host_of(&last_dst) == ATTACKER) to_attacker++; else if (host_of(&last_dst) == ENDPOINT) to_endpoint++; }
    }
    EXPECT(!ap->curr_keypair.valid, "control: the current keys expired (REJECT_AFTER_TIME)");
    EXPECT(!(to_attacker > 0 && to_endpoint == 0), "BUG: for 10 minutes keepalives and initiations go only to the other address");
    EXPECT(!(host_of(&ap->ip) == ATTACKER), "BUG: the configured endpoint is never restored (should_reset_peer needs a valid current keypair)");
    printf("     sent after the move: to the other address=%u, to the endpoint=%u\n", to_attacker, to_endpoint);

    puts("== 3. a cookie reply built only from public data (server public key + mac1 seen on the air)");
    teardown(&wg); crypto_zero(&b, sizeof(b));
    establish(&wg, &a, &b, &ap, &bp);
    EXPECT(host_of(&ap->ip) == ENDPOINT, "control: new session on the configured endpoint");
    clock_ms += 200000;
    struct message_handshake_initiation seen; int got = 0;
    for (unsigned i = 0; i < 20 && !got; i++) {
        clock_ms += 400; sent = 0; wireguardif_tmr(a);
        if (sent && last_wire[0] == MESSAGE_HANDSHAKE_INITIATION) { memcpy(&seen, last_wire, sizeof(seen)); got = 1; }
    }
    EXPECT(got, "control: the device sent an initiation (sender index and mac1 are visible on the air)");
    uint8_t label_cookie_key[32]; blake2s_ctx c;
    blake2s_init(&c, 32, NULL, 0); blake2s_update(&c, (const uint8_t *)"cookie--", 8);
    blake2s_update(&c, b.public_key, 32); blake2s_final(&c, label_cookie_key); /* only the server's PUBLIC key */
    struct message_cookie_reply forged; memset(&forged, 0, sizeof(forged));
    forged.type = MESSAGE_COOKIE_REPLY; forged.receiver = seen.sender;
    for (int i = 0; i < 24; i++) forged.nonce[i] = (uint8_t)(i * 7);
    uint8_t junk_cookie[16] = {1, 2, 3};
    uint8_t wrong_mac1[16]; memset(wrong_mac1, 0x5a, 16);
    xchacha20poly1305_encrypt(forged.enc_cookie, junk_cookie, 16, wrong_mac1, 16, forged.nonce, label_cookie_key);
    rx(a, &forged, sizeof(forged), ATTACKER, 5555);
    EXPECT(ap->handshake_mac1_valid, "control: the wrong-mac1 cookie reply was rejected by wireguard_process_cookie_message itself");
    EXPECT(host_of(&ap->ip) == ENDPOINT, "control: a cookie reply with the wrong mac1 is rejected, endpoint unchanged");
    xchacha20poly1305_encrypt(forged.enc_cookie, junk_cookie, 16, seen.mac1, 16, forged.nonce, label_cookie_key);
    rx(a, &forged, sizeof(forged), ATTACKER, 5555);
    EXPECT(!ap->handshake_mac1_valid && ap->cookie_millis == clock_ms, "control: the forged cookie reply WAS accepted (only public data needed), so the endpoint check above is not vacuous");
    EXPECT(!(host_of(&ap->ip) == ATTACKER && ap->port == 5555), "BUG: the cookie reply moved the endpoint");
    unsigned init_to_attacker = 0;
    for (unsigned i = 0; i < 100; i++) { clock_ms += 400; sent = 0; wireguardif_tmr(a); if (sent && host_of(&last_dst) == ATTACKER) init_to_attacker++; }
    EXPECT(!(init_to_attacker > 0), "BUG: the next initiations go to the other address");
    struct message_handshake_initiation cur; memcpy(&cur, last_wire, sizeof(cur));
    if (cur.type == MESSAGE_HANDSHAKE_INITIATION && wireguard_process_initiation_message(&b, &cur) == bp) {
        struct message_handshake_response r2;
        if (wireguard_create_handshake_response(&b, bp, &r2)) { wireguard_start_session(bp, false); rx(a, &r2, sizeof(r2), ENDPOINT, 51820); }
    }
    EXPECT(host_of(&ap->ip) == ENDPOINT && ap->curr_keypair.valid, "control: a real response from the server restores the endpoint");

    puts("== 4. replay after recovery; a fresh packet from the server still roams back");
    keypair_update(bp, &bp->next_keypair);
    n = make_data(bp, pkt, 0x0a020002u); rx(a, pkt, n, ENDPOINT, 51820);
    rx(a, pkt, n, ATTACKER, 4444);
    EXPECT(!(host_of(&ap->ip) == ATTACKER), "BUG: the replay moves the endpoint again");
    uint8_t fresh[128]; size_t fn = make_data(bp, fresh, 0x0a020002u); rx(a, fresh, fn, ENDPOINT, 51820);
    EXPECT(host_of(&ap->ip) == ENDPOINT, "control: the next authentic packet from the server keeps or restores the endpoint");

    puts("== 5. an authenticated zero-length keepalive replayed from another address");
    struct message_transport_data *keep = (struct message_transport_data *)pkt;
    memset(pkt, 0, 16); keep->type = MESSAGE_TRANSPORT_DATA;
    keep->receiver = bp->curr_keypair.remote_index;
    U64TO8_LITTLE(keep->counter, bp->curr_keypair.sending_counter);
    wireguard_encrypt_packet(keep->enc_packet, (const uint8_t *)"", 0, &bp->curr_keypair);
    clock_ms += 100; rx(a, pkt, 32, ENDPOINT, 51820);
    EXPECT(ap->last_rx == clock_ms, "control: a fresh keepalive updates the receive time");
    struct wireguard_peer saved = *ap;
    clock_ms += 100; rx(a, pkt, 32, ATTACKER, 4444);
    EXPECT(!memcmp(&saved, ap, sizeof(saved)), "BUG: the replayed keepalive changed peer state (endpoint, last_rx or keypair)");

    unsigned before = delivered;
    puts("== 6. responder-side keypair promotion: the server initiates, the device answers, the first data packet is replayed");
    {
        struct message_handshake_initiation bi; clock_ms += 1000;
        EXPECT(wireguard_create_handshake_initiation(&b, bp, &bi), "control: the server builds an initiation");
        sent = 0; rx(a, &bi, sizeof(bi), ENDPOINT, 51820);
        EXPECT(sent == 1 && last_wire[0] == MESSAGE_HANDSHAKE_RESPONSE && ap->next_keypair.valid && !ap->next_keypair.initiator,
               "control: the device answered and placed the new keypair in next_keypair");
        struct message_handshake_response br; memcpy(&br, last_wire, sizeof(br));
        EXPECT(wireguard_process_handshake_response(&b, bp, &br), "control: the server accepts the response");
        wireguard_start_session(bp, true);
        before = delivered; clock_ms += 100;
        n = make_data(bp, pkt, 0x0a020002u); rx(a, pkt, n, ENDPOINT, 51820);
        EXPECT(delivered == before + 1 && !ap->next_keypair.valid, "control: the first packet promoted next->curr and reached IP");
        EXPECT(ap->curr_keypair.replay_counter == 1, "BUG: the promoting packet is not recorded in the promoted keypair's replay window");
        saved = *ap; clock_ms += 100; rx(a, pkt, n, ATTACKER, 4444);
        EXPECT(!memcmp(&saved, ap, sizeof(saved)) && delivered == before + 1, "BUG: the replayed first packet of a responder-side session was accepted");
    }
    puts("== 7. related, same function: cryptokey routing on receive (whitepaper: the inner SOURCE must be an allowed IP)");
    IP_ADDR4(&ap->allowed_source_ips[0].ip, 198, 51, 100, 0); IP_ADDR4(&ap->allowed_source_ips[0].mask, 255, 255, 255, 0); ap->allowed_source_ips[0].valid = true;
    before = delivered; n = make_data_from(bp, pkt, 0xc6336407, 0x0a020002); rx(a, pkt, n, ENDPOINT, 51820);
    EXPECT(delivered == before + 1, "BUG: a packet from an allowed source was dropped because its destination is outside the allowed prefix");
    before = delivered; n = make_data_from(bp, pkt, 0xc0000207, 0xc6336409); rx(a, pkt, n, ENDPOINT, 51820);
    EXPECT(delivered == before, "BUG: a packet from a source outside the allowed prefix was accepted because its destination matches");
    IP_ADDR4(&ap->allowed_source_ips[0].ip, 0, 0, 0, 0); IP_ADDR4(&ap->allowed_source_ips[0].mask, 0, 0, 0, 0);
    before = delivered; n = make_data_from(bp, pkt, 0xc0000207, 0x0a020002); rx(a, pkt, n, ENDPOINT, 51820);
    EXPECT(delivered == before + 1, "control: a full tunnel (0.0.0.0/0) accepts any source");
    puts("== 8. an unauthenticated packet with a far-ahead counter (replay check only AFTER authentication)");
    {
        uint8_t forged8[64]; memset(forged8, 0, sizeof(forged8));
        struct message_transport_data *f = (struct message_transport_data *)forged8;
        f->type = MESSAGE_TRANSPORT_DATA; f->receiver = bp->curr_keypair.remote_index;
        U64TO8_LITTLE(f->counter, bp->curr_keypair.sending_counter + 1000);
        memset(f->enc_packet, 0xa5, 48);
        saved = *ap; rx(a, forged8, 16 + 48, ATTACKER, 4444);
        EXPECT(!memcmp(&saved, ap, sizeof(saved)), "BUG: a packet that fails authentication changed peer state (replay window)");
        before = delivered; n = make_data(bp, pkt, 0x0a020002u); rx(a, pkt, n, ENDPOINT, 51820);
        EXPECT(delivered == before + 1, "BUG: a forged far-ahead counter blocked the next authentic packet");
    }
    puts("== 10. fork: replays through wireguardif_inject_packet (magicsock direct and DERP)");
    {
        n = make_data(bp, pkt, 0x0a020002u);
        before = delivered; clock_ms += 100;
        EXPECT(wireguardif_inject_packet(&wg, lwip_htonl(ENDPOINT), 51820, pkt, n) == ERR_OK && delivered == before + 1,
               "control: a magicsock packet injected from the endpoint reaches IP");
        saved = *ap; clock_ms += 100;
        wireguardif_inject_packet(&wg, lwip_htonl(ATTACKER), 4444, pkt, n);
        EXPECT(!memcmp(&saved, ap, sizeof(saved)) && delivered == before + 1, "BUG: a magicsock replay from another address changed peer state");
        clock_ms += 100;
        wireguardif_inject_packet(&wg, 0, 0, pkt, n);
        EXPECT(!memcmp(&saved, ap, sizeof(saved)) && delivered == before + 1,
               "BUG: a replay injected through DERP changed peer state (last_rx_via_derp, last_rx)");
        n = make_data(bp, pkt, 0x0a020002u); clock_ms += 100;
        wireguardif_inject_packet(&wg, 0, 0, pkt, n);
        EXPECT(delivered == before + 2 && ap->last_rx_via_derp && host_of(&ap->ip) == ENDPOINT,
               "an authentic DERP packet marks the peer DERP-routed and keeps the direct endpoint");
    }
    teardown(&wg);
    printf("Receive-path replay test: %u checks, %u failures\n", checks, failures);
    return failures != 0;
}
