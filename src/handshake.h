#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define X25519_KEY_LEN 32
#define X25519_PUBKEY_HEX_LEN (X25519_KEY_LEN * 2 + 1)
#define SESSION_KEY_LEN 32

typedef struct identity identity;

identity* identity_generate(void);
identity* identity_load(const char* path);
void identity_free(identity* id);
int identity_save(const identity* id, const char* path);
int identity_write_pem(const identity* id, FILE* out);
int identity_pubkey_bytes(const identity* id, uint8_t out[X25519_KEY_LEN]);
int  pubkey_from_hex(const char* hex, uint8_t out[X25519_KEY_LEN]);
void pubkey_to_hex(const uint8_t in[X25519_KEY_LEN], char out[X25519_KEY_LEN * 2 + 1]);

int derive_session_keys(
    const uint8_t dh1[X25519_KEY_LEN], const uint8_t dh2[X25519_KEY_LEN],
    const uint8_t dh3[X25519_KEY_LEN], uint8_t tx_key[SESSION_KEY_LEN], 
    uint8_t rx_key[SESSION_KEY_LEN]
);

#endif