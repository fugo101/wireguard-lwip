# Changelog

## [1.0.1](https://github.com/fugo101/wireguard-lwip/compare/v1.0.0...v1.0.1) (2026-08-18)


### Bug Fixes

* use wall-clock time for the WireGuard handshake timestamp ([#13](https://github.com/fugo101/wireguard-lwip/issues/13)) ([dd5e921](https://github.com/fugo101/wireguard-lwip/commit/dd5e921cd57253d8b428c949fe06034f522059bc))

## 1.0.0 (2026-08-14)


### Features

* **esp32:** add ESP-IDF platform port ([#4](https://github.com/fugo101/wireguard-lwip/issues/4)) ([2933dd4](https://github.com/fugo101/wireguard-lwip/commit/2933dd44e9c7429ecff8f328210efee787981d50))
* **platform:** raise WIREGUARD_MAX_PEERS from 1 to 16 ([#1](https://github.com/fugo101/wireguard-lwip/issues/1)) ([b107f9f](https://github.com/fugo101/wireguard-lwip/commit/b107f9f783e9f02bd97b74ec05601ac6d7d4a1a5))
* **wireguard:** add DERP relay and magicsock UDP output API surface ([#2](https://github.com/fugo101/wireguard-lwip/issues/2)) ([3b85a12](https://github.com/fugo101/wireguard-lwip/commit/3b85a1235a8c4c52350d00a5e8a9c9ec7bb31f11))
* **wireguard:** implement DERP relay, magicsock output, dual-stack IP compat, and lwIP thread-safety fixes ([#3](https://github.com/fugo101/wireguard-lwip/issues/3)) ([193aac6](https://github.com/fugo101/wireguard-lwip/commit/193aac6483e08b97493bc2d6e3d368bfb6d719ad))


### Bug Fixes

* check source IP in cryptokey routing, not destination ([ac84f4c](https://github.com/fugo101/wireguard-lwip/commit/ac84f4cb2aa4c2e53682aa8914d7e93d88e25c84))


### Build

* add ESP-IDF component packaging ([88c4dcb](https://github.com/fugo101/wireguard-lwip/commit/88c4dcbb9e9b80ce8db9cf477fde8c569d68e9ef))
