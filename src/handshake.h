#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define X25519_KEY_LEN 32
#define X25519_PUBKEY_HEX_LEN (X25519_KEY_LEN * 2 + 1)
#define SESSION_KEY_LEN 32
#define HS_MSG_TYPE_INIT 0x02
#define HS_MSG_TYPE_RESP 0x03
#define HS_MSG_SIZE (1 + X25519_KEY_LEN)

typedef struct identity identity;
typedef struct handshake handshake;

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
    const uint8_t dh3[X25519_KEY_LEN], uint8_t key_ir[SESSION_KEY_LEN], 
    uint8_t key_ri[SESSION_KEY_LEN]
);

handshake* hs_new(const identity* self, const uint8_t peer_pubkey[X25519_KEY_LEN], bool is_initiator);
void hs_free(handshake* hs);
ssize_t hs_make_init(handshake* hs, uint8_t* out, size_t cap);
ssize_t hs_make_resp(handshake* hs, uint8_t* out, size_t cap);
int hs_consume(handshake* hs, const uint8_t* in, size_t in_len);
bool hs_done(const handshake* hs);
int hs_get_session_keys(const handshake* hs, uint8_t tx_key[SESSION_KEY_LEN], uint8_t rx_key[SESSION_KEY_LEN]);
bool hs_is_initiator(const handshake* hs);

#endif