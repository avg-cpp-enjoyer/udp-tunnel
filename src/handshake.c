#include "handshake.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

struct identity {
    EVP_PKEY* pkey;
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

    /* Reject anything that is not X25519 */
    if (!EVP_PKEY_is_a(pkey, "X25519")) {
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
    int saved_errno = errno;
    fclose(file);

    if (rc != 1) {
        log_error("PEM_write_PrivateKey(\"%s\") failed: %s",  path, strerror(saved_errno));
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

int identity_pubkey_bytes(const identity* id, uint8_t out[X25519_KEY_LEN]) {
    if (!id || !out) {
        log_error("NULL argument");
        return -1;
    }

    size_t len = X25519_KEY_LEN;
    if (EVP_PKEY_get_raw_public_key(id->pkey, out, &len) != 1) {
        log_error("EVP_PKEY_get_raw_public_key failed");
        return -1;
    }

    if (len != X25519_KEY_LEN) {
        log_error("unexpected X25519 pubkey length: %zu", len);
        return -1;
    }

    return 0;
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
        out[2 * i]     = hex_chars[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hex_chars[in[i] & 0xf];
    }
    out[X25519_KEY_LEN * 2] = '\0';
}