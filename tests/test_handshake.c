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
    uint8_t dh_ee[X25519_KEY_LEN], dh_se[X25519_KEY_LEN], dh_es[X25519_KEY_LEN];
    fill_random(dh_ee, sizeof(dh_ee));
    fill_random(dh_se, sizeof(dh_se));
    fill_random(dh_es, sizeof(dh_es));

    uint8_t ir_a[SESSION_KEY_LEN], ri_a[SESSION_KEY_LEN];
    uint8_t ir_b[SESSION_KEY_LEN], ri_b[SESSION_KEY_LEN];

    CHECK(derive_session_keys(dh_ee, dh_se, dh_es, ir_a, ri_a) == 0);
    CHECK(derive_session_keys(dh_ee, dh_se, dh_es, ir_b, ri_b) == 0);

    CHECK(memcmp(ir_a, ir_b, SESSION_KEY_LEN) == 0);
    CHECK(memcmp(ri_a, ri_b, SESSION_KEY_LEN) == 0);
}

static void test_hkdf_directions_differ(void) {
    uint8_t dh_ee[X25519_KEY_LEN], dh_se[X25519_KEY_LEN], dh_es[X25519_KEY_LEN];
    fill_random(dh_ee, sizeof(dh_ee));
    fill_random(dh_se, sizeof(dh_se));
    fill_random(dh_es, sizeof(dh_es));

    uint8_t key_ir[SESSION_KEY_LEN], key_ri[SESSION_KEY_LEN];
    CHECK(derive_session_keys(dh_ee, dh_se, dh_es, key_ir, key_ri) == 0);
    CHECK(memcmp(key_ir, key_ri, SESSION_KEY_LEN) != 0);
}

static void test_hkdf_different_inputs(void) {
    uint8_t dh_ee_a[X25519_KEY_LEN], dh_se_a[X25519_KEY_LEN], dh_es_a[X25519_KEY_LEN];
    uint8_t dh_ee_b[X25519_KEY_LEN], dh_se_b[X25519_KEY_LEN], dh_es_b[X25519_KEY_LEN];
    fill_random(dh_ee_a, sizeof(dh_ee_a));
    fill_random(dh_se_a, sizeof(dh_se_a));
    fill_random(dh_es_a, sizeof(dh_es_a));
    fill_random(dh_ee_b, sizeof(dh_ee_b));
    fill_random(dh_se_b, sizeof(dh_se_b));
    fill_random(dh_es_b, sizeof(dh_es_b));

    uint8_t ir_a[SESSION_KEY_LEN], ri_a[SESSION_KEY_LEN];
    uint8_t ir_b[SESSION_KEY_LEN], ri_b[SESSION_KEY_LEN];

    CHECK(derive_session_keys(dh_ee_a, dh_se_a, dh_es_a, ir_a, ri_a) == 0);
    CHECK(derive_session_keys(dh_ee_b, dh_se_b, dh_es_b, ir_b, ri_b) == 0);

    CHECK(memcmp(ir_a, ir_b, SESSION_KEY_LEN) != 0);
    CHECK(memcmp(ri_a, ri_b, SESSION_KEY_LEN) != 0);
}

static void test_hkdf_single_change(void) {
    uint8_t dh_ee[X25519_KEY_LEN], dh_se[X25519_KEY_LEN], dh_es[X25519_KEY_LEN];
    fill_random(dh_ee, sizeof(dh_ee));
    fill_random(dh_se, sizeof(dh_se));
    fill_random(dh_es, sizeof(dh_es));

    uint8_t ir_orig[SESSION_KEY_LEN], ri_orig[SESSION_KEY_LEN];
    CHECK(derive_session_keys(dh_ee, dh_se, dh_es, ir_orig, ri_orig) == 0);

    dh_se[0] ^= 0x01;

    uint8_t ir_mod[SESSION_KEY_LEN], ri_mod[SESSION_KEY_LEN];
    CHECK(derive_session_keys(dh_ee, dh_se, dh_es, ir_mod, ri_mod) == 0);

    CHECK(memcmp(ir_orig, ir_mod, SESSION_KEY_LEN) != 0);
    CHECK(memcmp(ri_orig, ri_mod, SESSION_KEY_LEN) != 0);
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

static void make_pair(identity** a, identity** b,
    uint8_t pub_a[X25519_KEY_LEN], uint8_t pub_b[X25519_KEY_LEN]) {
    memset(pub_a, 0, X25519_KEY_LEN);
    memset(pub_b, 0, X25519_KEY_LEN);

    *a = identity_generate();
    *b = identity_generate();
    if (!*a || !*b) {
        return;
    }
    if (identity_pubkey_bytes(*a, pub_a) < 0) {
        return;
    }
    if (identity_pubkey_bytes(*b, pub_b) < 0) {
        return;
    }
}

static void test_handshake_full(void) {
    identity* id_a = NULL;
    identity* id_b = NULL;
    uint8_t pub_a[X25519_KEY_LEN], pub_b[X25519_KEY_LEN];
    make_pair(&id_a, &id_b, pub_a, pub_b);
    CHECK(id_a != NULL);
    CHECK(id_b != NULL);
    if (!id_a || !id_b) {
        identity_free(id_a);
        identity_free(id_b);
        return;
    }

    handshake* hs_a = hs_new(id_a, pub_b, true);   /* initiator */
    handshake* hs_b = hs_new(id_b, pub_a, false);  /* responder */
    CHECK(hs_a != NULL);
    CHECK(hs_b != NULL);
    if (!hs_a || !hs_b) {
        goto cleanup;
    }

    uint8_t init_msg[HS_MSG_SIZE];
    ssize_t ilen = hs_make_init(hs_a, init_msg, sizeof(init_msg));
    CHECK(ilen == HS_MSG_SIZE);
    CHECK(hs_consume(hs_b, init_msg, (size_t)ilen) == 0);

    uint8_t resp_msg[HS_MSG_SIZE];
    ssize_t rlen = hs_make_resp(hs_b, resp_msg, sizeof(resp_msg));
    CHECK(rlen == HS_MSG_SIZE);
    CHECK(hs_done(hs_b));
    CHECK(hs_consume(hs_a, resp_msg, (size_t)rlen) == 0);

    CHECK(hs_done(hs_a));
    CHECK(hs_done(hs_b));

    uint8_t tx_a[SESSION_KEY_LEN], rx_a[SESSION_KEY_LEN];
    uint8_t tx_b[SESSION_KEY_LEN], rx_b[SESSION_KEY_LEN];
    CHECK(hs_get_session_keys(hs_a, tx_a, rx_a) == 0);
    CHECK(hs_get_session_keys(hs_b, tx_b, rx_b) == 0);

    CHECK(memcmp(tx_a, rx_b, SESSION_KEY_LEN) == 0);
    CHECK(memcmp(rx_a, tx_b, SESSION_KEY_LEN) == 0);
    CHECK(memcmp(tx_a, rx_a, SESSION_KEY_LEN) != 0);
cleanup:
    hs_free(hs_a);
    hs_free(hs_b);
    identity_free(id_a);
    identity_free(id_b);
}

static void test_handshake_wrong_peer(void) {
    identity* id_a = identity_generate();
    identity* id_b = identity_generate();
    identity* id_c = identity_generate();
    CHECK(id_a != NULL);
    CHECK(id_b != NULL);
    CHECK(id_c != NULL);
    if (!id_a || !id_b || !id_c) {
        goto cleanup;
    }

    uint8_t pub_a[X25519_KEY_LEN], pub_b[X25519_KEY_LEN], pub_c[X25519_KEY_LEN];
    CHECK(identity_pubkey_bytes(id_a, pub_a) == 0);
    CHECK(identity_pubkey_bytes(id_b, pub_b) == 0);
    CHECK(identity_pubkey_bytes(id_c, pub_c) == 0);

    handshake* hs_a = hs_new(id_a, pub_b, true);   /* expects B */
    handshake* hs_c = hs_new(id_c, pub_a, false);  /* is C */
    CHECK(hs_a != NULL);
    CHECK(hs_c != NULL);

    if (!hs_a || !hs_c) {
        hs_free(hs_a);
        hs_free(hs_c);
        goto cleanup;
    }

    uint8_t init_msg[HS_MSG_SIZE], resp_msg[HS_MSG_SIZE];
    ssize_t ilen = hs_make_init(hs_a, init_msg, sizeof(init_msg));
    CHECK(ilen == HS_MSG_SIZE);
    CHECK(hs_consume(hs_c, init_msg, (size_t)ilen) == 0);

    ssize_t rlen = hs_make_resp(hs_c, resp_msg, sizeof(resp_msg));
    CHECK(rlen == HS_MSG_SIZE);
    CHECK(hs_consume(hs_a, resp_msg, (size_t)rlen) == 0);

    uint8_t tx_a[SESSION_KEY_LEN], rx_a[SESSION_KEY_LEN];
    uint8_t tx_c[SESSION_KEY_LEN], rx_c[SESSION_KEY_LEN];
    CHECK(hs_get_session_keys(hs_a, tx_a, rx_a) == 0);
    CHECK(hs_get_session_keys(hs_c, tx_c, rx_c) == 0);
    CHECK(memcmp(tx_a, rx_c, SESSION_KEY_LEN) != 0);

    hs_free(hs_a);
    hs_free(hs_c);
cleanup:
    identity_free(id_a);
    identity_free(id_b);
    identity_free(id_c);
}

static void test_handshake_state(void) {
    identity* id_a = NULL;
    identity* id_b = NULL;
    uint8_t pub_a[X25519_KEY_LEN], pub_b[X25519_KEY_LEN];
    make_pair(&id_a, &id_b, pub_a, pub_b);
    CHECK(id_a != NULL);
    CHECK(id_b != NULL);
    if (!id_a || !id_b) {
        identity_free(id_a);
        identity_free(id_b);
        return;
    }

    handshake* hs_a = hs_new(id_a, pub_b, true);
    handshake* hs_b = hs_new(id_b, pub_a, false);
    CHECK(hs_a != NULL);
    CHECK(hs_b != NULL);
    if (!hs_a || !hs_b) {
        goto cleanup;
    }

    uint8_t msg[HS_MSG_SIZE];
    CHECK(hs_make_init(hs_b, msg, sizeof(msg)) == -1);
    CHECK(hs_make_resp(hs_a, msg, sizeof(msg)) == -1);
    CHECK(hs_make_resp(hs_b, msg, sizeof(msg)) == -1);
    CHECK(hs_make_init(hs_a, msg, sizeof(msg)) == HS_MSG_SIZE);
    CHECK(hs_make_init(hs_a, msg, sizeof(msg)) == -1);

    CHECK(hs_consume(hs_b, msg, sizeof(msg)) == 0);
    CHECK(hs_consume(hs_b, msg, HS_MSG_SIZE - 1) == -1);

    handshake* hs_fresh = hs_new(id_b, pub_a, false);
    CHECK(hs_fresh != NULL);

    if (hs_fresh) {
        uint8_t bad[HS_MSG_SIZE] = {0};
        bad[0] = HS_MSG_TYPE_RESP;
        CHECK(hs_consume(hs_fresh, bad, sizeof(bad)) == -1);
        hs_free(hs_fresh);
    }

cleanup:
    hs_free(hs_a);
    hs_free(hs_b);
    identity_free(id_a);
    identity_free(id_b);
}

static void test_handshake_not_done(void) {
    identity* id_a = NULL;
    identity* id_b = NULL;
    uint8_t pub_a[X25519_KEY_LEN], pub_b[X25519_KEY_LEN];
    make_pair(&id_a, &id_b, pub_a, pub_b);
    CHECK(id_a != NULL);
    CHECK(id_b != NULL);
    if (!id_a || !id_b) {
        identity_free(id_a);
        identity_free(id_b);
        return;
    }

    handshake* hs = hs_new(id_a, pub_b, true);
    CHECK(hs != NULL);
    if (!hs) {
        goto cleanup;
    }

    uint8_t tx[SESSION_KEY_LEN], rx[SESSION_KEY_LEN];
    CHECK(hs_get_session_keys(hs, tx, rx) == -1);
    CHECK(!hs_done(hs));

cleanup:
    hs_free(hs);
    identity_free(id_a);
    identity_free(id_b);
}

int main(void) {
    srand(0xC0FFEE);

    test_identity_roundtrip();
    test_identity_unique();
    test_hex_roundtrip();
    test_hex_invalid();
    test_hex_uppercase();
    test_hkdf_deterministic();
    test_hkdf_directions_differ();
    test_hkdf_different_inputs();
    test_hkdf_single_change();
    test_hkdf_edges();
    test_handshake_full();
    test_handshake_wrong_peer();
    test_handshake_state();
    test_handshake_not_done();

    if (failed) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failed);
        return 1;
    }

    printf("all handshake tests passed\n");
    return 0;
}