#include "../src/handshake.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failed = 0;

#define CHECK(cond) do {                                                  \
    if (!(cond)) {                                                        \
        fprintf(stderr, "FAIL %s:%d: %s\n",                               \
                __FILE__, __LINE__, #cond);                               \
        failed++;                                                         \
    }                                                                     \
} while (0)

static void fill_random(uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xff);
    }
}

static void test_identity_roundtrip(void) {
    const char* path = "/tmp/test_identity.pem";

    identity* id1 = identity_generate();
    CHECK(id1 != NULL);
    if (!id1) {
        return;
    }

    CHECK(identity_save(id1, path) == 0);

    identity* id2 = identity_load(path);
    CHECK(id2 != NULL);
    if (!id2) {
        identity_free(id1);
        unlink(path);
        return;
    }

    uint8_t pub1[X25519_KEY_LEN];
    uint8_t pub2[X25519_KEY_LEN];
    CHECK(identity_pubkey_bytes(id1, pub1) == 0);
    CHECK(identity_pubkey_bytes(id2, pub2) == 0);
    CHECK(memcmp(pub1, pub2, X25519_KEY_LEN) == 0);

    identity_free(id1);
    identity_free(id2);
    unlink(path);
}

static void test_identity_unique(void) {
    identity* a = identity_generate();
    identity* b = identity_generate();
    CHECK(a && b);
    if (!a || !b) {
        identity_free(a);
        identity_free(b);
        return;
    }

    uint8_t pa[X25519_KEY_LEN];
    uint8_t pb[X25519_KEY_LEN];
    CHECK(identity_pubkey_bytes(a, pa) == 0);
    CHECK(identity_pubkey_bytes(b, pb) == 0);
    CHECK(memcmp(pa, pb, X25519_KEY_LEN) != 0);

    identity_free(a);
    identity_free(b);
}

static void test_hex_roundtrip(void) {
    uint8_t in[X25519_KEY_LEN];
    fill_random(in, sizeof(in));

    char hex[X25519_PUBKEY_HEX_LEN];
    pubkey_to_hex(in, hex);
    CHECK(strlen(hex) == X25519_KEY_LEN * 2);

    uint8_t out[X25519_KEY_LEN];
    CHECK(pubkey_from_hex(hex, out) == 0);
    CHECK(memcmp(in, out, X25519_KEY_LEN) == 0);
}

static void test_hex_invalid(void) {
    uint8_t out[X25519_KEY_LEN];

    CHECK(pubkey_from_hex("abcd", out) == -1);
    CHECK(pubkey_from_hex("000000000000000000000000000000000000000000000000000000000000000", out) == -1);
    CHECK(pubkey_from_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",out) == -1);
}

static void test_hex_uppercase(void) {
    uint8_t out_lower[X25519_KEY_LEN];
    uint8_t out_upper[X25519_KEY_LEN];

    CHECK(pubkey_from_hex("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", out_lower) == 0);
    CHECK(pubkey_from_hex("ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", out_upper) == 0);
    CHECK(memcmp(out_lower, out_upper, X25519_KEY_LEN) == 0);
}

static void test_hkdf_deterministic(void) {
    uint8_t dh1[X25519_KEY_LEN];
    uint8_t dh2[X25519_KEY_LEN];
    uint8_t dh3[X25519_KEY_LEN];
    fill_random(dh1, sizeof(dh1));
    fill_random(dh2, sizeof(dh2));
    fill_random(dh3, sizeof(dh3));

    uint8_t tx_a[SESSION_KEY_LEN], rx_a[SESSION_KEY_LEN];
    uint8_t tx_b[SESSION_KEY_LEN], rx_b[SESSION_KEY_LEN];

    CHECK(derive_session_keys(dh1, dh2, dh3, tx_a, rx_a) == 0);
    CHECK(derive_session_keys(dh1, dh2, dh3, tx_b, rx_b) == 0);

    CHECK(memcmp(tx_a, tx_b, SESSION_KEY_LEN) == 0);
    CHECK(memcmp(rx_a, rx_b, SESSION_KEY_LEN) == 0);
}

static void test_hkdf_tx_rx_differ(void) {
    uint8_t dh1[X25519_KEY_LEN];
    uint8_t dh2[X25519_KEY_LEN];
    uint8_t dh3[X25519_KEY_LEN];
    fill_random(dh1, sizeof(dh1));
    fill_random(dh2, sizeof(dh2));
    fill_random(dh3, sizeof(dh3));

    uint8_t tx[SESSION_KEY_LEN], rx[SESSION_KEY_LEN];
    CHECK(derive_session_keys(dh1, dh2, dh3, tx, rx) == 0);
    CHECK(memcmp(tx, rx, SESSION_KEY_LEN) != 0);
}

static void test_hkdf_different_inputs(void) {
    uint8_t dh1_a[X25519_KEY_LEN], dh2_a[X25519_KEY_LEN], dh3_a[X25519_KEY_LEN];
    uint8_t dh1_b[X25519_KEY_LEN], dh2_b[X25519_KEY_LEN], dh3_b[X25519_KEY_LEN];
    fill_random(dh1_a, sizeof(dh1_a));
    fill_random(dh2_a, sizeof(dh2_a));
    fill_random(dh3_a, sizeof(dh3_a));
    fill_random(dh1_b, sizeof(dh1_b));
    fill_random(dh2_b, sizeof(dh2_b));
    fill_random(dh3_b, sizeof(dh3_b));

    uint8_t tx_a[SESSION_KEY_LEN], rx_a[SESSION_KEY_LEN];
    uint8_t tx_b[SESSION_KEY_LEN], rx_b[SESSION_KEY_LEN];

    CHECK(derive_session_keys(dh1_a, dh2_a, dh3_a, tx_a, rx_a) == 0);
    CHECK(derive_session_keys(dh1_b, dh2_b, dh3_b, tx_b, rx_b) == 0);

    CHECK(memcmp(tx_a, tx_b, SESSION_KEY_LEN) != 0);
    CHECK(memcmp(rx_a, rx_b, SESSION_KEY_LEN) != 0);
}

static void test_hkdf_single_change(void) {
    uint8_t dh1[X25519_KEY_LEN];
    uint8_t dh2[X25519_KEY_LEN];
    uint8_t dh3[X25519_KEY_LEN];
    fill_random(dh1, sizeof(dh1));
    fill_random(dh2, sizeof(dh2));
    fill_random(dh3, sizeof(dh3));

    uint8_t tx_orig[SESSION_KEY_LEN], rx_orig[SESSION_KEY_LEN];
    CHECK(derive_session_keys(dh1, dh2, dh3, tx_orig, rx_orig) == 0);

    dh2[0] ^= 0x01;

    uint8_t tx_mod[SESSION_KEY_LEN], rx_mod[SESSION_KEY_LEN];
    CHECK(derive_session_keys(dh1, dh2, dh3, tx_mod, rx_mod) == 0);

    CHECK(memcmp(tx_orig, tx_mod, SESSION_KEY_LEN) != 0);
    CHECK(memcmp(rx_orig, rx_mod, SESSION_KEY_LEN) != 0);
}

static void test_hkdf_edges(void) {
    uint8_t buf[X25519_KEY_LEN];
    uint8_t out[SESSION_KEY_LEN];
    memset(buf, 0, sizeof(buf));

    CHECK(derive_session_keys(NULL, buf, buf, out, out) == -1);
    CHECK(derive_session_keys(buf, NULL, buf, out, out) == -1);
    CHECK(derive_session_keys(buf, buf, NULL, out, out) == -1);
    CHECK(derive_session_keys(buf, buf, buf, NULL, out) == -1);
    CHECK(derive_session_keys(buf, buf, buf, out, NULL) == -1);
}

int main(void) {
    srand(0xC0FFEE);

    test_identity_roundtrip();
    test_identity_unique();
    test_hex_roundtrip();
    test_hex_invalid();
    test_hex_uppercase();
    test_hkdf_deterministic();
    test_hkdf_tx_rx_differ();
    test_hkdf_different_inputs();
    test_hkdf_single_change();
    test_hkdf_edges();

    if (failed) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failed);
        return 1;
    }

    printf("all handshake tests passed\n");
    return 0;
}