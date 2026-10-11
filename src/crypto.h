#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define KEY_LEN 32
#define NONCE_LEN 12
#define TAG_LEN 16
#define CRYPTO_OVERHEAD (NONCE_LEN + TAG_LEN)

typedef struct tunnel_crypto tunnel_crypto;

tunnel_crypto* tc_new(const uint8_t key[KEY_LEN]);
void tc_free(tunnel_crypto* tc);
ssize_t tc_seal(tunnel_crypto* tc, const uint8_t* plaintext, size_t pt_len, uint8_t* ciphertext, size_t ct_cap);
ssize_t tc_open(tunnel_crypto* tc, const uint8_t* ciphertext, size_t ct_len, uint8_t* plaintext, size_t pt_cap);

#endif