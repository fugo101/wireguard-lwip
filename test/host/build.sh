#!/bin/sh
# Build and run the host tests against this component's src/.
#   WG_SRC   = <component>/src                       (default ../../src)
#   LWIP_SRC = $IDF_PATH/components/lwip/lwip/src    (any lwIP 2.1+ source tree; only headers, def.c and ip4_addr.c are used)
# test_rx_replay runs twice: the main checks, then the short inner packet alone, because on unpatched code
# AddressSanitizer aborts there. test_allowed_ips runs once.
# Based on the host reproduction by Tomasz Fiedoruk (MIT).
set -u
here=$(cd "$(dirname "$0")" && pwd)
WG_SRC=${WG_SRC:-$here/../../src}
LWIP_SRC=${LWIP_SRC:-$IDF_PATH/components/lwip/lwip/src}
outdir=${OUT:-$here}

build() {
  cc -std=c11 -D_DARWIN_C_SOURCE -D_DEFAULT_SOURCE -O0 -g -Wall -Wno-sign-compare -Wno-unused-parameter -Wno-unused-but-set-variable -Wno-unused-variable \
    -Wno-unterminated-string-initialization -Wno-unknown-warning-option -fsanitize=address,undefined \
    -DBYTE_ORDER=__BYTE_ORDER__ -DLITTLE_ENDIAN=__ORDER_LITTLE_ENDIAN__ \
    -I"$here/port" -I"$here" -I"$LWIP_SRC/include" -I"$WG_SRC" \
    "$here/$1.c" "$WG_SRC/wireguard.c" "$WG_SRC/crypto.c" \
    "$WG_SRC/crypto/refc/blake2s.c" "$WG_SRC/crypto/refc/chacha20.c" "$WG_SRC/crypto/refc/chacha20poly1305.c" \
    "$WG_SRC/crypto/refc/poly1305-donna.c" "$WG_SRC/crypto/refc/x25519.c" \
    "$LWIP_SRC/core/def.c" "$LWIP_SRC/core/ipv4/ip4_addr.c" -o "$outdir/$1" || exit 2
}

# run <binary> <label> [args]: print the check lines; the program's exit code is the result.
run() {
  bin=$1; label=$2; shift 2
  "$outdir/$bin" "$@" >"$outdir/$bin.$label.log" 2>"$outdir/$bin.$label.asan.txt"; rc=$?
  grep -E "^(ok|FAIL|==)|checks" "$outdir/$bin.$label.log"
  [ $rc -ne 0 ] && grep -m1 -E "ERROR: AddressSanitizer|READ of size|runtime error" "$outdir/$bin.$label.asan.txt" | sed 's/^/     /'
  return $rc
}

build test_rx_replay
build test_allowed_ips
run test_rx_replay main; replay=$?
run test_rx_replay short short; short=$?
run test_allowed_ips main; routing=$?
echo "exit codes (0 = pass): rx replay $replay, short packet $short, allowed IPs $routing"
[ $replay -eq 0 ] && [ $short -eq 0 ] && [ $routing -eq 0 ]
