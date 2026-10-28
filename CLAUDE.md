# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

An ESP-IDF component (`fugo101/wireguard_lwip`) — a fork of `smartalock/wireguard-lwip`
(BSD-3-Clause, Daniel Hope). It is a malloc-free C implementation of WireGuard that
registers as an lwIP `netif`. The fork adds DERP relay + magicsock integration,
16-peer support, ESP-IDF 6.x/GCC 15 compat, and lwIP thread-safety fixes. It is
consumed by `fugo101/microlink`.

There is no standalone build or test suite here — the component is compiled by the
ESP-IDF build of a consuming project. Validation in this repo is manifest/packaging only.

## Commands

```bash
pip install idf-component-manager          # 3.x; the 2.5.0 bundled with IDF 6.0.1 lacks `manifest lint`
compote manifest lint idf_component.yml    # validate the component manifest
compote -W component pack --project-dir . --name wireguard_lwip   # same validation the registry runs on upload
```

Both are what CI runs (`.github/workflows/ci.yml`). To compile-check real changes,
build a consuming ESP-IDF project against a local override of this component.

## Release / publish

- Conventional commits drive `release-please`; extra changelog types beyond the defaults:
  `compat` ("ESP-IDF compatibility"), plus `refactor`/`perf` are visible sections.
- `release-please` bumps `version:` in `idf_component.yml` via the
  `# x-release-please-version` marker — never hand-edit that version.
- On release, `publish-component` uploads to the ESP Component Registry under the
  `fugo101` namespace using GitHub OIDC (no stored registry token).
- `upstream-drift.yml` runs weekly, diffs against `smartalock/wireguard-lwip` by
  patch-id, and opens/updates a single `upstream-drift`-labelled issue. Keep changes
  rebase-friendly: upstream files are kept in git even when not compiled
  (`src/crypto/cortex/**` is excluded from the registry archive, not deleted).

## Architecture

Three layers, deliberately separated:

- **`src/wireguard.c` / `wireguard.h`** — protocol core (Noise_IK handshake, keypairs,
  replay window, cookies, base64 key parsing). No IP-stack dependency.
- **`src/wireguardif.c` / `wireguardif.h`** — lwIP glue: the `netif` driver, peer table,
  cryptokey routing, UDP rx/tx, and the periodic timer. Everything fork-specific lives here.
- **`src/crypto.h`** — the crypto swap point. It is *only* `#define`s mapping
  `wireguard_blake2s*` / `wireguard_x25519` / `wireguard_aead_*` onto an implementation.
  Swapping in hardware or vendor crypto means editing this header, not call sites.
  Default is `src/crypto/refc/` (portable C); `src/crypto/cortex/` is an unused
  Cortex-M0 asm X25519 kept for upstream parity.

Platform integration is four functions declared in `wireguard-platform.h`
(`wireguard_sys_now`, `wireguard_random_bytes`, `wireguard_tai64n_now`,
`wireguard_is_under_load`). `src/wireguard-platform-esp32.c` is the ESP32
implementation compiled into the component; `example/wireguard-platform.c` is the
upstream reference sample and is excluded from the package.

`WIREGUARD_MAX_PEERS` (16) and `WIREGUARD_MAX_SRC_IPS` live in `wireguard-platform.h`.
All peers are statically allocated inside `struct wireguard_device` — raising the count
grows every device struct.

### Two operating modes

The interface runs in one of two modes, chosen at init:

1. **Standard lwIP mode** — `wireguardif_init` creates its own `udp_pcb`, binds
   `listen_port`, and arms a `sys_timeout(400ms, wireguardif_tmr)` that runs handshakes
   and keepalives on the lwIP tcpip thread.
2. **Magicsock mode** — the caller owns a single unified UDP socket. Call
   `wireguardif_disable_socket_bind()` *before* `wireguardif_init`, then
   `wireguardif_set_udp_output()` for tx and `wireguardif_inject_packet()` for rx
   (use `wireguardif_is_wireguard_packet()` to demux). In this mode the internal timer
   is **not** armed — the caller must call `wireguardif_periodic()` every ~400ms from its
   own task, so X25519/ChaCha20 never run on the tcpip thread.

`wireguardif_tmr` and `wireguardif_periodic` do the same work; changes to peer
expiry/keepalive/rekey logic must be made in **both**.

### DERP relay

Peers with no direct endpoint (`ip == 0.0.0.0` or `port == 0`) are sent via the
`wireguardif_set_derp_output()` callback, keyed by peer public key.
`wireguardif_force_derp_output(true)` routes everything through DERP (cellular mode).
`wireguardif_connect_derp()` starts a handshake for a DERP-only peer, where the normal
`wireguardif_connect()` would fail on the missing endpoint.

Invariant: `update_peer_addr()` must never overwrite a valid endpoint with `0.0.0.0` —
DERP-injected packets carry no real source address, and doing so breaks DERP routing
after the first packet.

### Thread safety

Only the tcpip thread may enter lwIP core functions. On the rx path, decrypted packets
are handed to `netif->input` (set to `tcpip_input` by the consumer) rather than
`ip_input()` directly — calling `ip_input()` from the caller's task races the tcpip
thread. Preserve this when touching `wireguardif_process_data_message`.

`wireguardif_shutdown()` cancels the timer and **must** be called before
`netif_remove`/`mem_free`, or `wireguardif_tmr` fires on freed memory.

### lwIP version compat

`src/lwip_compat.h` hides the dual-stack `ip_addr_t` layout change (the `u_addr` union
in lwIP 2.2.0 / ESP-IDF 5.3+). Use `IP_ADDR_GET_IP4_U32` / `IP_ADDR_SET_IP4_U32` /
`IP_ADDR_NETCMP_COMPAT` rather than touching `ipaddr->addr` directly.

## Conventions

- Debug output is gated behind `WG_DEBUG_LOGGING` (default 0) in `wireguardif.c`;
  use `WG_DEBUG(...)`, not bare `printf`, on hot paths — verbose logging costs CPU and
  thermal headroom on ESP32.
- Upstream files use tabs and the original BSD-3-Clause header; keep both when editing
  them so the upstream diff stays readable.
- Two GCC 15 warning suppressions are pinned per-file in `CMakeLists.txt`
  (`-Wno-unterminated-string-initialization` on `wireguard.c`, `-Wno-stringop-overread`
  on `x25519.c`). Both are deliberate — do not "fix" the underlying code.

## Agent skills

### Issue tracker

GitHub Issues on `fugo101/wireguard-lwip` via `gh` (always `-R fugo101/wireguard-lwip`, never the `ghsa` fork). See `docs/agents/issue-tracker.md`.

### Triage labels

Default five-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: root `GLOSSARY.md` + `docs/adr/`. See `docs/agents/domain.md`.
