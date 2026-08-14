idf_component_register(
    SRCS
        "src/wireguard.c"
        "src/wireguardif.c"
        "src/crypto.c"
        "src/wireguard-platform-esp32.c"
        "src/crypto/refc/blake2s.c"
        "src/crypto/refc/chacha20.c"
        "src/crypto/refc/chacha20poly1305.c"
        "src/crypto/refc/poly1305-donna.c"
        "src/crypto/refc/x25519.c"
    INCLUDE_DIRS
        "src"
        "src/crypto/refc"
    REQUIRES
        lwip
        esp_timer
)

target_compile_definitions(${COMPONENT_LIB} PRIVATE
    WIREGUARD_CRYPTO_REFC=1
)

# GCC 15 errors on the sigma constant initialized as char[32] = "expand 32-byte k"
# (32 chars, no null terminator) — a deliberate, correct pattern for this crypto code.
set_source_files_properties(src/wireguard.c
    PROPERTIES COMPILE_FLAGS "-Wno-unterminated-string-initialization"
)

# False-positive GCC array-bounds check on this X25519 implementation.
set_source_files_properties(
    src/crypto/refc/x25519.c
    PROPERTIES COMPILE_FLAGS "-Wno-stringop-overread"
)
