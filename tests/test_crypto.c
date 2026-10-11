#include "../src/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void test_roundtrip(void) {
    uint8_t key[KEY_LEN];
    fill_random(key, sizeof(key));

    tunnel_crypto* tx = tc_new(key);
    tunnel_crypto* rx = tc_new(key);
    CHECK(tx != NULL);
    CHECK(rx != NULL);
    if (!tx || !rx) {
        tc_free(tx);
        tc_free(rx);
        return;
    }

    const char* msg = "hello, tunnel";
    size_t msg_len = strlen(msg);

    uint8_t ciphertext[256];
    uint8_t recovered[256];

    ssize_t ct_len = tc_seal(tx, (const uint8_t*)msg, msg_len, ciphertext, sizeof(ciphertext));
    CHECK(ct_len == (ssize_t)(NONCE_LEN + msg_len + TAG_LEN));

    ssize_t pt_len = tc_open(rx, ciphertext, (size_t)ct_len, recovered, sizeof(recovered));
    CHECK(pt_len == (ssize_t)msg_len);
    CHECK(memcmp(recovered, msg, msg_len) == 0);

    tc_free(tx);
    tc_free(rx);
}

static void test_tamper_ciphertext(void) {
    uint8_t key[KEY_LEN];
    fill_random(key, sizeof(key));

    tunnel_crypto* tx = tc_new(key);
    tunnel_crypto* rx = tc_new(key);
    if (!tx || !rx) {
        tc_free(tx);
        tc_free(rx);
        return;
    }

    uint8_t plaintext[64];
    uint8_t ciphertext[128];
    uint8_t recovered[128];
    fill_random(plaintext, sizeof(plaintext));

    ssize_t ct_len = tc_seal(tx, plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext));
    CHECK(ct_len > 0);

    ciphertext[NONCE_LEN + 3] ^= 0xff;
    CHECK(tc_open(rx, ciphertext, (size_t)ct_len, recovered, sizeof(recovered)) == -1);

    tc_free(tx);
    tc_free(rx);
}

static void test_tamper_tag(void) {
    uint8_t key[KEY_LEN];
    fill_random(key, sizeof(key));

    tunnel_crypto* tx = tc_new(key);
    tunnel_crypto* rx = tc_new(key);
    if (!tx || !rx) {
        tc_free(tx);
        tc_free(rx);
        return;
    }

    uint8_t plaintext[32];
    uint8_t ciphertext[128];
    uint8_t recovered[128];
    fill_random(plaintext, sizeof(plaintext));

    ssize_t ct_len = tc_seal(tx, plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext));
    CHECK(ct_len > 0);

    ciphertext[ct_len - 1] ^= 0x01;
    CHECK(tc_open(rx, ciphertext, (size_t)ct_len, recovered, sizeof(recovered)) == -1);

    tc_free(tx);
    tc_free(rx);
}

static void test_replay_single(void) {
    uint8_t key[KEY_LEN];
    fill_random(key, sizeof(key));

    tunnel_crypto* tx = tc_new(key);
    tunnel_crypto* rx = tc_new(key);
    if (!tx || !rx) {
        tc_free(tx);
        tc_free(rx);
        return;
    }

    uint8_t plaintext[32];
    uint8_t ciphertext[128];
    uint8_t recovered[128];
    fill_random(plaintext, sizeof(plaintext));

    ssize_t ct_len = tc_seal(tx, plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext));
    CHECK(ct_len > 0);
    CHECK(tc_open(rx, ciphertext, (size_t)ct_len, recovered, sizeof(recovered)) == (ssize_t)sizeof(plaintext));
    CHECK(tc_open(rx, ciphertext, (size_t)ct_len, recovered, sizeof(recovered)) == -1);

    tc_free(tx);
    tc_free(rx);
}

static void test_replay_order(void) {
    uint8_t key[KEY_LEN];
    fill_random(key, sizeof(key));

    tunnel_crypto* tx = tc_new(key);
    tunnel_crypto* rx = tc_new(key);
    if (!tx || !rx) {
        tc_free(tx);
        tc_free(rx);
        return;
    }

    uint8_t plaintext[16] = "0123456789abcdef";
    uint8_t ciphertexts[5][128];
    size_t  ct_lens[5];
    uint8_t recovered[64];

    for (int i = 0; i < 5; i++) {
        ssize_t ct_len = tc_seal(tx, plaintext, sizeof(plaintext), ciphertexts[i], sizeof(ciphertexts[i]));
        CHECK(ct_len > 0);
        ct_lens[i] = (size_t)ct_len;
    }

    CHECK(tc_open(rx, ciphertexts[0], ct_lens[0], recovered, sizeof(recovered)) > 0);
    CHECK(tc_open(rx, ciphertexts[1], ct_lens[1], recovered, sizeof(recovered)) > 0);
    CHECK(tc_open(rx, ciphertexts[2], ct_lens[2], recovered, sizeof(recovered)) > 0);
    CHECK(tc_open(rx, ciphertexts[3], ct_lens[3], recovered, sizeof(recovered)) > 0);

    CHECK(tc_open(rx, ciphertexts[1], ct_lens[1], recovered, sizeof(recovered)) == -1);
    CHECK(tc_open(rx, ciphertexts[4], ct_lens[4], recovered, sizeof(recovered)) > 0);

    tc_free(tx);
    tc_free(rx);
}

static void test_wrong_key(void) {
    uint8_t k1[KEY_LEN];
    uint8_t k2[KEY_LEN];
    fill_random(k1, sizeof(k1));
    fill_random(k2, sizeof(k2));

    tunnel_crypto* tx = tc_new(k1);
    tunnel_crypto* rx = tc_new(k2);
    if (!tx || !rx) {
        tc_free(tx);
        tc_free(rx);
        return;
    }

    uint8_t plaintext[32];
    uint8_t ciphertext[128];
    uint8_t recovered[128];
    fill_random(plaintext, sizeof(plaintext));

    ssize_t ct_len = tc_seal(tx, plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext));
    CHECK(ct_len > 0);
    CHECK(tc_open(rx, ciphertext, (size_t)ct_len, recovered, sizeof(recovered)) == -1);

    tc_free(tx);
    tc_free(rx);
}

static void test_edges(void) {
    CHECK(tc_new(NULL) == NULL);

    tc_free(NULL);

    uint8_t key[KEY_LEN] = {0};
    tunnel_crypto* tc = tc_new(key);
    CHECK(tc != NULL);
    if (!tc) {
        return;
    }

    uint8_t buf[128];

    CHECK(tc_seal(tc, buf, 32, buf, 16) == -1);
    CHECK(tc_open(tc, buf, 4, buf, sizeof(buf)) == -1);

    CHECK(tc_seal(tc, NULL, 16, buf, sizeof(buf)) == -1);
    CHECK(tc_seal(tc, buf, 16, NULL, sizeof(buf)) == -1);
    CHECK(tc_open(tc, NULL, 64, buf, sizeof(buf)) == -1);
    CHECK(tc_open(tc, buf, 64, NULL, sizeof(buf)) == -1);

    tc_free(tc);
}

static void test_empty_payload(void) {
    uint8_t key[KEY_LEN];
    fill_random(key, sizeof(key));

    tunnel_crypto* tx = tc_new(key);
    tunnel_crypto* rx = tc_new(key);
    if (!tx || !rx) {
        tc_free(tx);
        tc_free(rx);
        return;
    }

    uint8_t ciphertext[64];
    uint8_t recovered[64];

    ssize_t ct_len = tc_seal(tx, ciphertext, 0, ciphertext, sizeof(ciphertext));
    CHECK(ct_len == NONCE_LEN + TAG_LEN);

    ssize_t pt_len = tc_open(rx, ciphertext, (size_t)ct_len, recovered, sizeof(recovered));
    CHECK(pt_len == 0);

    tc_free(tx);
    tc_free(rx);
}

int main(void) {
    srand(0xC0FFEE);

    test_roundtrip();
    test_tamper_ciphertext();
    test_tamper_tag();
    test_replay_single();
    test_replay_order();
    test_wrong_key();
    test_edges();
    test_empty_payload();

    if (failed) {
        fprintf(stderr, "\n%d check(s) FAILED\n", failed);
        return 1;
    }

    printf("all tests passed\n");
    return 0;
}