#include "handshake.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/core_names.h> 
#include <openssl/crypto.h>  
#include <openssl/err.h>
#include <openssl/evp.h> 
#include <openssl/kdf.h>          
#include <openssl/pem.h>

#define HKDF_INFO_IR "udp-tunnel v1 i->r"
#define HKDF_INFO_RI "udp-tunnel v1 r->i"

struct identity {
    EVP_PKEY* pkey;
};

struct handshake {
    const identity* self /* borrowed, must outlive hs */;
    EVP_PKEY* peer_static_pub;
    bool is_initiator;
    EVP_PKEY* eph_priv;
    uint8_t   eph_pub[X25519_KEY_LEN];
    EVP_PKEY* peer_eph_pub;
    bool sent_init;
    bool sent_resp;
    bool recv_init;
    bool done;
    uint8_t tx_key[SESSION_KEY_LEN];
    uint8_t rx_key[SESSION_KEY_LEN];
};

identity* identity_generate(void) {
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (!pkey) {
        log_error("EVP_PKEY_Q_keygen(X25519) failed");
        return NULL;
    }

    identity* id = calloc(1, sizeof(*id));
    if (!id) {
        log_error("calloc failed: %s", strerror(errno));
        EVP_PKEY_free(pkey);
        return NULL;
    }

    id->pkey = pkey;
    return id;
}

static void log_openssl_failure(const char* what, const char* path) {
    unsigned long err = ERR_get_error();
    if (err == 0) {
        log_error("%s(\"%s\") failed", what, path);
        return;
    }

    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    log_error("%s(\"%s\") failed: %s", what, path, buf);
}

identity* identity_load(const char* path) {
    if (!path) {
        log_error("path is NULL");
        return NULL;
    }

    FILE* file = fopen(path, "r");
    if (!file) {
        log_error("fopen(\"%s\") failed: %s", path, strerror(errno));
        return NULL;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);

    if (!pkey) {
        log_openssl_failure("PEM_read_PrivateKey", path);
        return NULL;
    }

    if (EVP_PKEY_is_a(pkey, "X25519") != 1) {
        log_error("identity \"%s\" is not an X25519 key", path);
        EVP_PKEY_free(pkey);
        return NULL;
    }

    identity* id = calloc(1, sizeof(*id));
    if (!id) {
        log_error("calloc failed: %s", strerror(errno));
        EVP_PKEY_free(pkey);
        return NULL;
    }

    id->pkey = pkey;
    return id;
}

int identity_save(const identity* id, const char* path) {
    if (!id || !path) {
        log_error("NULL argument");
        return -1;
    }

    /* Open with 0600: a private key must not be readable by others, even before we write anything to it. */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        log_error("open(\"%s\", O_CREAT, 0600) failed: %s", path, strerror(errno));
        return -1;
    }

    FILE* file = fdopen(fd, "w");
    if (!file) {
        log_error("fdopen failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* No encryption of the private key itself. If you want a passphrase, pass an EVP_CIPHER here. */
    int rc = PEM_write_PrivateKey(file, id->pkey, NULL, NULL, 0, NULL, NULL);
    fclose(file);

    if (rc != 1) {
        log_openssl_failure("PEM_write_PrivateKey", path);
        return -1;
    }

    return 0;
}

void identity_free(identity* id) {
    if (!id) {
        return;
    }

    if (id->pkey) {
        EVP_PKEY_free(id->pkey);
    }

    free(id);
}

static int x25519_pub_to_bytes(EVP_PKEY* pkey, uint8_t out[X25519_KEY_LEN]) {
    size_t len = X25519_KEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, out, &len) != 1) {
        log_error("EVP_PKEY_get_raw_public_key failed");
        return -1;
    }
    if (len != X25519_KEY_LEN) {
        log_error("unexpected X25519 pubkey length: %zu", len);
        return -1;
    }

    return 0;
}

int identity_pubkey_bytes(const identity* id, uint8_t out[X25519_KEY_LEN]) {
    if (!id || !out) {
        log_error("NULL argument");
        return -1;
    }

    return x25519_pub_to_bytes(id->pkey, out);
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }

    return -1;
}

int pubkey_from_hex(const char* hex, uint8_t out[X25519_KEY_LEN]) {
    size_t len = strlen(hex);
    if (len != X25519_KEY_LEN * 2) {
        log_error("hex pubkey must be exactly %d chars, got %zu", X25519_KEY_LEN * 2, len);
        return -1;
    }

    for (size_t i = 0; i < X25519_KEY_LEN; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            log_error("invalid hex at offset %zu", 2 * i);
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

void pubkey_to_hex(const uint8_t in[X25519_KEY_LEN], char out[X25519_KEY_LEN * 2 + 1]) {
    if (!in || !out) {
        return;
    }

    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < X25519_KEY_LEN; i++) {
        out[2 * i] = hex_chars[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hex_chars[in[i] & 0xf];
    }
    out[X25519_KEY_LEN * 2] = '\0';
}

static int hkdf_derive(EVP_KDF_CTX* kdf_ctx, const uint8_t* 
    ikm, size_t ikm_len, const char* info, uint8_t key_out[SESSION_KEY_LEN]) {
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)ikm, ikm_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info, strlen(info)),
        OSSL_PARAM_construct_end()
    };

    if (EVP_KDF_derive(kdf_ctx, key_out, SESSION_KEY_LEN, params) != 1) {
        log_error("EVP_KDF_derive(HKDF, info=\"%s\") failed", info);
        return -1;
    }

    return 0;
}

int derive_session_keys(const uint8_t dh_ee[X25519_KEY_LEN], const uint8_t dh_se[X25519_KEY_LEN],
    const uint8_t dh_es[X25519_KEY_LEN], uint8_t key_ir[SESSION_KEY_LEN], uint8_t key_ri[SESSION_KEY_LEN]) {
    if (!dh_ee || !dh_se || !dh_es || !key_ir || !key_ri) {
        log_error("NULL argument");
        return -1;
    }

    uint8_t ikm[X25519_KEY_LEN * 3];
    memcpy(ikm, dh_ee, X25519_KEY_LEN);
    memcpy(ikm + X25519_KEY_LEN, dh_se, X25519_KEY_LEN);
    memcpy(ikm + X25519_KEY_LEN * 2, dh_es, X25519_KEY_LEN);

    int rc = -1;
    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) {
        log_error("EVP_KDF_fetch(HKDF) failed");
        goto out_ikm;
    }

    EVP_KDF_CTX* kdf_ctx = EVP_KDF_CTX_new(kdf);
    if (!kdf_ctx) {
        log_error("EVP_KDF_CTX_new failed");
        EVP_KDF_free(kdf);
        goto out_ikm;
    }

    if (hkdf_derive(kdf_ctx, ikm, sizeof(ikm), HKDF_INFO_IR, key_ir) < 0) {
        goto out_ctx;
    }
    if (hkdf_derive(kdf_ctx, ikm, sizeof(ikm), HKDF_INFO_RI, key_ri) < 0) {
        goto out_ctx;
    }

    rc = 0;
out_ctx:
    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);
out_ikm:
    OPENSSL_cleanse(ikm, sizeof(ikm));
    return rc;
}

static EVP_PKEY* x25519_pub_from_bytes(const uint8_t raw[X25519_KEY_LEN]) {
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, raw, X25519_KEY_LEN);
}

static int x25519_dh(EVP_PKEY* priv, EVP_PKEY* peer_pub, uint8_t out[X25519_KEY_LEN]) {
    int rc = -1;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) {
        log_error("EVP_PKEY_CTX_new failed");
        return -1;
    }

    if (EVP_PKEY_derive_init(ctx) != 1) {
        log_error("EVP_PKEY_derive_init failed");
        goto out;
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer_pub) != 1) {
        log_error("EVP_PKEY_derive_set_peer failed");
        goto out;
    }

    size_t len = X25519_KEY_LEN;
    if (EVP_PKEY_derive(ctx, out, &len) != 1) {
        log_error("EVP_PKEY_derive failed");
        goto out;
    }
    if (len != X25519_KEY_LEN) {
        log_error("unexpected DH output length: %zu", len);
        goto out;
    }

    rc = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

handshake* hs_new(const identity* self, const uint8_t peer_pubkey[X25519_KEY_LEN], bool is_initiator) {
    if (!self || !peer_pubkey) {
        log_error("NULL argument");
        return NULL;
    }

    handshake* hs = calloc(1, sizeof(*hs));
    if (!hs) {
        log_error("calloc failed: %s", strerror(errno));
        return NULL;
    }

    hs->self = self;
    hs->is_initiator = is_initiator;

    hs->peer_static_pub = x25519_pub_from_bytes(peer_pubkey);
    if (!hs->peer_static_pub) {
        log_error("EVP_PKEY_new_raw_public_key(peer) failed");
        goto err_free;
    }

    hs->eph_priv = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (!hs->eph_priv) {
        log_error("EVP_PKEY_Q_keygen(ephemeral) failed");
        goto err_free;
    }
    if (x25519_pub_to_bytes(hs->eph_priv, hs->eph_pub) < 0) {
        goto err_free;
    }

    return hs;
err_free:
    hs_free(hs);
    return NULL;
}

void hs_free(handshake* hs) {
    if (!hs) {
        return;
    }

    if (hs->peer_static_pub) {
        EVP_PKEY_free(hs->peer_static_pub);
    }
    if (hs->eph_priv) {
        EVP_PKEY_free(hs->eph_priv);
    }
    if (hs->peer_eph_pub) {
        EVP_PKEY_free(hs->peer_eph_pub);
    }

    OPENSSL_cleanse(hs->tx_key, sizeof(hs->tx_key));
    OPENSSL_cleanse(hs->rx_key, sizeof(hs->rx_key));
    free(hs);
}

static int hs_derive_session_keys(handshake* hs) {
    uint8_t dh_ee[X25519_KEY_LEN] = {0};
    uint8_t dh_se[X25519_KEY_LEN] = {0};
    uint8_t dh_es[X25519_KEY_LEN] = {0};
    uint8_t key_ir[SESSION_KEY_LEN];
    uint8_t key_ri[SESSION_KEY_LEN];

    if (x25519_dh(hs->eph_priv, hs->peer_eph_pub, dh_ee) < 0) {
        goto out_dh;
    }

    /* se and es each mix our key with peer'. Which side is static vs
     * ephemeral depends on our role. DH is symmetric, so we just swap. */
    EVP_PKEY* se_priv = hs->is_initiator ? hs->self->pkey : hs->eph_priv;
    EVP_PKEY* se_peer = hs->is_initiator ? hs->peer_eph_pub : hs->peer_static_pub;
    if (x25519_dh(se_priv, se_peer, dh_se) < 0) {
        goto out_dh;
    }

    EVP_PKEY* es_priv = hs->is_initiator ? hs->eph_priv : hs->self->pkey;
    EVP_PKEY* es_peer = hs->is_initiator ? hs->peer_static_pub : hs->peer_eph_pub;
    if (x25519_dh(es_priv, es_peer, dh_es) < 0) {
        goto out_dh;
    }

    if (derive_session_keys(dh_ee, dh_se, dh_es, key_ir, key_ri) < 0) {
        goto out_dh;
    }

    /* Map canonical directions to tx/rx so initiator.tx == responder.rx. */
    if (hs->is_initiator) {
        memcpy(hs->tx_key, key_ir, SESSION_KEY_LEN);
        memcpy(hs->rx_key, key_ri, SESSION_KEY_LEN);
    } else {
        memcpy(hs->tx_key, key_ri, SESSION_KEY_LEN);
        memcpy(hs->rx_key, key_ir, SESSION_KEY_LEN);
    }

    OPENSSL_cleanse(key_ir, sizeof(key_ir));
    OPENSSL_cleanse(key_ri, sizeof(key_ri));
    OPENSSL_cleanse(dh_ee, sizeof(dh_ee));
    OPENSSL_cleanse(dh_se, sizeof(dh_se));
    OPENSSL_cleanse(dh_es, sizeof(dh_es));
    hs->done = true;
    return 0;
out_dh:
    OPENSSL_cleanse(dh_ee, sizeof(dh_ee));
    OPENSSL_cleanse(dh_se, sizeof(dh_se));
    OPENSSL_cleanse(dh_es, sizeof(dh_es));
    return -1;
}

ssize_t hs_make_init(handshake* hs, uint8_t* out, size_t cap) {
    if (!hs || !out) {
        log_error("NULL argument");
        return -1;
    }
    if (!hs->is_initiator) {
        log_error("hs_make_init called on non-initiator");
        return -1;
    }
    if (hs->sent_init) {
        log_error("HS_INIT already sent");
        return -1;
    }
    if (cap < HS_MSG_SIZE) {
        log_error("output buffer too small: %zu < %d", cap, HS_MSG_SIZE);
        return -1;
    }

    out[0] = HS_MSG_TYPE_INIT;
    memcpy(out + 1, hs->eph_pub, X25519_KEY_LEN);
    hs->sent_init = true;
    return HS_MSG_SIZE;
}

ssize_t hs_make_resp(handshake* hs, uint8_t* out, size_t cap) {
    if (!hs || !out) {
        log_error("NULL argument");
        return -1;
    }
    if (hs->is_initiator) {
        log_error("hs_make_resp called on initiator");
        return -1;
    }
    if (!hs->recv_init) {
        log_error("HS_RESP cannot be created before receiving HS_INIT");
        return -1;
    }
    if (hs->sent_resp) {
        log_error("HS_RESP already sent");
        return -1;
    }
    if (cap < HS_MSG_SIZE) {
        log_error("output buffer too small: %zu < %d", cap, HS_MSG_SIZE);
        return -1;
    }

    out[0] = HS_MSG_TYPE_RESP;
    memcpy(out + 1, hs->eph_pub, X25519_KEY_LEN);
    hs->sent_resp = true;

    if (hs_derive_session_keys(hs) < 0) {
        return -1;
    }

    return HS_MSG_SIZE;
}

int hs_consume(handshake* hs, const uint8_t* in, size_t in_len) {
    if (!hs || !in) {
        log_error("NULL argument");
        return -1;
    }
    if (in_len != HS_MSG_SIZE) {
        log_error("handshake message has wrong size: %zu != %d", in_len, HS_MSG_SIZE);
        return -1;
    }
    if (hs->peer_eph_pub) {
        log_error("peer ephemeral already received");
        return -1;
    }

    uint8_t msg_type = in[0];
    const uint8_t* eph_pub  = in + 1;
    uint8_t expected_type = hs->is_initiator ? HS_MSG_TYPE_RESP : HS_MSG_TYPE_INIT;

    if (msg_type != expected_type) {
        log_error("%s expected 0x%02x, got 0x%02x",  hs->is_initiator ? "initiator" : "responder", expected_type, msg_type);
        return -1;
    }

    if (hs->is_initiator && !hs->sent_init) {
        log_error("received HS_RESP before sending HS_INIT");
        return -1;
    }

    hs->peer_eph_pub = x25519_pub_from_bytes(eph_pub);
    if (!hs->peer_eph_pub) {
        log_error("EVP_PKEY_new_raw_public_key(peer_eph) failed");
        return -1;
    }

    if (hs->is_initiator) {
        return hs_derive_session_keys(hs);
    }

    hs->recv_init = true;
    return 0;
}

bool hs_done(const handshake* hs) {
    return hs && hs->done;
}

int hs_get_session_keys(const handshake* hs, uint8_t tx_key[SESSION_KEY_LEN], uint8_t rx_key[SESSION_KEY_LEN]) {
    if (!hs || !tx_key || !rx_key) {
        log_error("NULL argument");
        return -1;
    }
    if (!hs->done) {
        log_error("handshake not complete");
        return -1;
    }

    memcpy(tx_key, hs->tx_key, SESSION_KEY_LEN);
    memcpy(rx_key, hs->rx_key, SESSION_KEY_LEN);
    return 0;
}

bool hs_is_initiator(const handshake* hs) {
    return hs && hs->is_initiator;
}