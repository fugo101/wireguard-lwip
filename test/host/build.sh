#!/bin/sh
# Build and run the host receive-path test against this component's src/.
#   WG_SRC   = <component>/src                       (default ../../src)
#   LWIP_SRC = $IDF_PATH/components/lwip/lwip/src    (any lwIP 2.1+ source tree; only headers, def.c and ip4_addr.c are used)
# Two runs: the main checks, then the short inner packet alone, because on unpatched code AddressSanitizer aborts there.
# Based on the host reproduction by Tomasz Fiedoruk (MIT).
set -u
here=$(cd "$(dirname "$0")" && pwd)
WG_SRC=${WG_SRC:-$here/../../src}
LWIP_SRC=${LWIP_SRC:-$IDF_PATH/components/lwip/lwip/src}
out=${OUT:-$here/test_rx_replay}
cc -std=c11 -D_DARWIN_C_SOURCE -D_DEFAULT_SOURCE -O0 -g -Wall -Wno-sign-compare -Wno-unused-parameter -Wno-unused-but-set-variable -Wno-unused-variable \
  -Wno-unterminated-string-initialization -Wno-unknown-warning-option -fsanitize=address,undefined \
  -DBYTE_ORDER=__BYTE_ORDER__ -DLITTLE_ENDIAN=__ORDER_LITTLE_ENDIAN__ \
  -I"$here/port" -I"$LWIP_SRC/include" -I"$WG_SRC" \
  "$here/test_rx_replay.c" "$WG_SRC/wireguard.c" "$WG_SRC/crypto.c" \
  "$WG_SRC/crypto/refc/blake2s.c" "$WG_SRC/crypto/refc/chacha20.c" "$WG_SRC/crypto/refc/chacha20poly1305.c" \
  "$WG_SRC/crypto/refc/poly1305-donna.c" "$WG_SRC/crypto/refc/x25519.c" \
  "$LWIP_SRC/core/def.c" "$LWIP_SRC/core/ipv4/ip4_addr.c" -o "$out" || exit 2
"$out" >"$out.log"; main=$?
grep -E "^(ok|FAIL|==)|checks" "$out.log"
"$out" short >"$out.short.log" 2>"$out.asan.txt"; short=$?
grep -E "^(ok|FAIL|==)|checks" "$out.short.log"
[ $short -ne 0 ] && grep -m1 -E "ERROR: AddressSanitizer|READ of size" "$out.asan.txt" | sed 's/^/     /'
echo "main run exit $main, short-packet run exit $short (0 = pass)"
[ $main -eq 0 ] && [ $short -eq 0 ]
