#include "crypto.h"
#include "log.h"

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define REPLAY_WINDOW 64
#define NONCE_PREFIX_LEN 4
#define NONCE_COUNTER_LEN 8

struct tunnel_crypto {
    uint8_t key[KEY_LEN];
    uint8_t tx_prefix[NONCE_PREFIX_LEN];
    uint64_t tx_counter;
    uint8_t rx_prefix[NONCE_PREFIX_LEN];
    bool rx_prefix_set;
    uint64_t rx_highest_ctr;
    uint64_t rx_window_bitmap;
    EVP_CIPHER_CTX* encrypt_ctx;
    EVP_CIPHER_CTX* decrypt_ctx;
};

tunnel_crypto* tc_new(const uint8_t key[KEY_LEN]) {
    if (!key) {
        log_error("key is NULL");
        return NULL;
    }

    tunnel_crypto* tc = calloc(1, sizeof(*tc));
    if (!tc) {
        log_error("calloc failed: %s", strerror(errno));
        return NULL;
    }

    memcpy(tc->key, key, KEY_LEN);
    if (RAND_bytes(tc->tx_prefix, sizeof(tc->tx_prefix)) != 1) {
        log_error("RAND_bytes failed");
        goto err_free;
    }

    tc->encrypt_ctx = EVP_CIPHER_CTX_new();
    tc->decrypt_ctx = EVP_CIPHER_CTX_new();
    if (!tc->encrypt_ctx || !tc->decrypt_ctx) {
        log_error("EVP_CIPHER_CTX_new failed");
        goto err_free;
    }

    /* Cipher and IV length are set once. Key and nonce are set per call in tc_seal/tc_open, so we only allocate contexts here. */
    if (EVP_EncryptInit_ex(tc->encrypt_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        log_error("EVP_EncryptInit_ex (aes-256-gcm) failed");
        goto err_free;
    }
    if (EVP_CIPHER_CTX_ctrl(tc->encrypt_ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) {
        log_error("encrypt_ctx: SET_IVLEN(%d) failed", NONCE_LEN);
        goto err_free;
    }
    if (EVP_DecryptInit_ex(tc->decrypt_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        log_error("EVP_DecryptInit_ex (aes-256-gcm) failed");
        goto err_free;
    }
    if (EVP_CIPHER_CTX_ctrl(tc->decrypt_ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) {
        log_error("decrypt_ctx: SET_IVLEN(%d) failed", NONCE_LEN);
        goto err_free;
    }

    log_debug("context created");
    return tc;
err_free:
    tc_free(tc);
    return NULL;
}

void tc_free(tunnel_crypto* tc) {
    if (!tc) {
        log_debug("tc_free(NULL): no-op");
        return;
    }

    EVP_CIPHER_CTX_free(tc->encrypt_ctx);
    EVP_CIPHER_CTX_free(tc->decrypt_ctx);
    OPENSSL_cleanse(tc, sizeof(*tc));
    free(tc);
    log_debug("context destroyed");
}

ssize_t tc_seal(tunnel_crypto* tc, const uint8_t* plaintext, size_t pt_len, uint8_t* ciphertext, size_t ct_cap) {
    if (!tc || !plaintext || !ciphertext) {
        log_error("NULL argument (tc=%p plaintext=%p ciphertext=%p)", (const void*)tc, (const void*)plaintext, (void*)ciphertext);
        return -1;
    }
    if (pt_len > INT_MAX) {
        log_error("pt_len=%zu exceeds INT_MAX", pt_len);
        return -1;
    }
    if (ct_cap < NONCE_LEN + pt_len + TAG_LEN) {
        log_error("ct_cap=%zu too small for %zu bytes payload (need %zu)", ct_cap, pt_len, NONCE_LEN + pt_len + TAG_LEN);
        return -1;
    }

    /* nonce = tx_prefix || counter_be.
     * Together they guarantee no reuse even across process restarts. */
    uint8_t nonce[NONCE_LEN];
    memcpy(nonce, tc->tx_prefix, NONCE_PREFIX_LEN);
    uint64_t ctr_be = htobe64(tc->tx_counter);
    memcpy(nonce + NONCE_PREFIX_LEN, &ctr_be, NONCE_COUNTER_LEN);
    tc->tx_counter++;

    memcpy(ciphertext, nonce, NONCE_LEN);
    int evp_len = 0;
    int ct_len  = 0;    

    if (EVP_EncryptInit_ex(tc->encrypt_ctx, NULL, NULL, tc->key, nonce) != 1) {
        log_error("EVP_EncryptInit_ex failed (counter=%" PRIu64 ")", tc->tx_counter - 1);
        return -1;
    }
    if (EVP_EncryptUpdate(tc->encrypt_ctx, ciphertext + NONCE_LEN, &evp_len, plaintext, (int)pt_len) != 1) {
        log_error("EVP_EncryptUpdate failed (pt_len=%zu)", pt_len);
        return -1;
    }
    ct_len = evp_len;

    if (EVP_EncryptFinal_ex(tc->encrypt_ctx, ciphertext + NONCE_LEN + ct_len, &evp_len) != 1) {
        log_error("EVP_EncryptFinal_ex failed");
        return -1;
    }
    ct_len += evp_len;

    if (EVP_CIPHER_CTX_ctrl(tc->encrypt_ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, ciphertext + NONCE_LEN + ct_len) != 1) {
        log_error("GET_TAG failed");
        return -1;
    }

    return NONCE_LEN + ct_len + TAG_LEN;
}

/* Pure predicate, no state mutation. Returns 0 if the packet may
 * proceed, -1 if it must be dropped (out-of-window or replay).
 * Sets *is_new_prefix so the caller knows whether to reset the window
 * in replay_commit() after successful authentication. */
static int replay_check(tunnel_crypto* tc, const uint8_t nonce[NONCE_LEN], bool* is_new_prefix) {
    uint64_t ctr_be;
    memcpy(&ctr_be, nonce + NONCE_PREFIX_LEN, NONCE_COUNTER_LEN);
    uint64_t ctr = be64toh(ctr_be);
    *is_new_prefix = false;

    if (!tc->rx_prefix_set ||
        memcmp(nonce, tc->rx_prefix, NONCE_PREFIX_LEN) != 0) {
        *is_new_prefix = true;
        return 0;
    }

    if (ctr > tc->rx_highest_ctr) {
        return 0;
    }

    uint64_t diff = tc->rx_highest_ctr - ctr;
    if (diff >= REPLAY_WINDOW) {
        return -1;  
    }

    if (tc->rx_window_bitmap & (UINT64_C(1) << diff)) {
        return -1;  
    }

    return 0;
}

/* Mutates replay-window state. Must be called ONLY after the packet
has been authenticated (EVP_DecryptFinal_ex). Calling it before
verification lets forged packets poison the window. */
static void replay_commit(tunnel_crypto* tc, const uint8_t nonce[NONCE_LEN], bool is_new_prefix) {
    uint64_t ctr_be;
    memcpy(&ctr_be, nonce + NONCE_PREFIX_LEN, NONCE_COUNTER_LEN);
    uint64_t ctr = be64toh(ctr_be);

    if (is_new_prefix) {
        memcpy(tc->rx_prefix, nonce, NONCE_PREFIX_LEN);
        tc->rx_prefix_set = true;
        tc->rx_highest_ctr = ctr;
        tc->rx_window_bitmap = UINT64_C(1);
        return;
    }

    if (ctr <= tc->rx_highest_ctr) {
        uint64_t diff = tc->rx_highest_ctr - ctr;
        tc->rx_window_bitmap |= (UINT64_C(1) << diff);
        return;
    }

    uint64_t shift = ctr - tc->rx_highest_ctr;
    if (shift >= REPLAY_WINDOW) {
        tc->rx_window_bitmap = 0;
    } else {
        tc->rx_window_bitmap <<= shift;
    }

    tc->rx_window_bitmap |= UINT64_C(1);
    tc->rx_highest_ctr = ctr;
}

ssize_t tc_open(tunnel_crypto* tc, const uint8_t* ciphertext, size_t ct_len, uint8_t* plaintext, size_t pt_cap) {
    if (!tc || !ciphertext || !plaintext) {
        log_error("NULL argument (tc=%p ciphertext=%p plaintext=%p)", (const void*)tc, (const void*)ciphertext, (void*)plaintext);
        return -1;
    }
    if (ct_len < NONCE_LEN + TAG_LEN) {
        log_debug("packet too short: %zu bytes", ct_len);
        return -1;
    }

    const uint8_t* nonce = ciphertext;
    const uint8_t* ct_body = ciphertext + NONCE_LEN;
    size_t body_len = ct_len - NONCE_LEN - TAG_LEN;
    const uint8_t* tag = ciphertext + ct_len - TAG_LEN;

    if (body_len > INT_MAX) {
        log_debug("body_len=%zu exceeds INT_MAX", body_len);
        return -1;
    }
    if (body_len > pt_cap) {
        log_debug("body_len=%zu > pt_cap=%zu", body_len, pt_cap);
        return -1;
    }

    bool is_new_prefix = false;
    if (replay_check(tc, nonce, &is_new_prefix) < 0) {
        log_warn("replay or out-of-window packet rejected");
        return -1;
    }

    if (EVP_DecryptInit_ex(tc->decrypt_ctx, NULL, NULL, tc->key, nonce) != 1) {
        log_error("EVP_DecryptInit_ex failed");
        return -1;
    }

    int evp_len = 0;
    int pt_len  = 0;
    if (EVP_DecryptUpdate(tc->decrypt_ctx, plaintext, &evp_len, ct_body, (int)body_len) != 1) {
        log_error("EVP_DecryptUpdate failed (body_len=%zu)", body_len);
        return -1;
    }
    pt_len = evp_len;

    /* OpenSSL API takes a non-const pointer for SET_TAG but does not modify the buffer. */
    if (EVP_CIPHER_CTX_ctrl(tc->decrypt_ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag) != 1) {
        log_error("SET_TAG failed");
        return -1;
    }

    if (EVP_DecryptFinal_ex(tc->decrypt_ctx, plaintext + pt_len, &evp_len) != 1) {
        log_warn("authentication failed (tamper or key mismatch?)");
        return -1;  
    }

    pt_len += evp_len;
    replay_commit(tc, nonce, is_new_prefix);
    return pt_len;
}