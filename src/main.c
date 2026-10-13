#include "crypto.h"
#include "handshake.h"
#include "log.h"
#include "tun.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_PACKET_BYTES 65536
#define MAX_EVENTS 8

static volatile sig_atomic_t stop = 0;

static void on_signal(int signum) {
    (void)signum;
    stop = 1;
}

static int install_signal_handlers(void) {
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);

    /* NO SA_RESTART! We want epoll_wait() to return EINTR promptly
     * so the loop sees the stop flag. With SA_RESTART, shutdown would
     * block until the next packet arrives. */
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) < 0 ||
        sigaction(SIGTERM, &sa, NULL) < 0) {
        log_error("sigaction failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static int set_nonblock(int fd, const char* tag) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        log_error("fcntl(%s, F_GETFL) failed: %s", tag, strerror(errno));
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        log_error("fcntl(%s, F_SETFL, O_NONBLOCK) failed: %s", tag, strerror(errno));
        return -1;
    }

    return 0;
}

static int split_addr_port(const char* str, char* host, size_t host_size, char* port, size_t port_size) {
    const char* colon = strrchr(str, ':');
    if (!colon) {
        log_error("address \"%s\" has no ':port' suffix", str);
        return -1;
    }

    size_t host_len = (size_t)(colon - str);
    if (host_len == 0) {
        log_error("address \"%s\" has empty host part", str);
        return -1;
    }
    if (host_len >= host_size) {
        log_error("host part too long: %zu >= %zu", host_len, host_size);
        return -1;
    }

    size_t port_len = strlen(colon + 1);
    if (port_len == 0) {
        log_error("address \"%s\" has empty port part", str);
        return -1;
    }
    if (port_len >= port_size) {
        log_error("port part too long: %zu >= %zu", port_len, port_size);
        return -1;
    }

    memcpy(host, str, host_len);
    host[host_len] = '\0';
    memcpy(port, colon + 1, port_len + 1);
    return 0;
}

static int udp_open(const char* listen_addr, const char* peer_addr) {
    char local_host[64];
    char local_port[16];
    char peer_host[64];
    char peer_port[16];

    if (split_addr_port(listen_addr, local_host, sizeof(local_host), local_port, sizeof(local_port)) < 0) { 
        return -1;
    }
    if (split_addr_port(peer_addr, peer_host, sizeof(peer_host), peer_port, sizeof(peer_port)) < 0) {
        return -1;
    }

    struct addrinfo hints_local = {0};
    hints_local.ai_family = AF_INET;
    hints_local.ai_socktype = SOCK_DGRAM;
    hints_local.ai_flags = AI_PASSIVE;

    struct addrinfo* local_res = NULL;
    int gai = getaddrinfo(local_host, local_port, &hints_local, &local_res);
    if (gai != 0) {
        log_error("getaddrinfo(%s:%s) failed: %s", local_host, local_port, gai_strerror(gai));
        return -1;
    }

    struct addrinfo hints_peer = {0};
    hints_peer.ai_family   = AF_INET;
    hints_peer.ai_socktype = SOCK_DGRAM;

    struct addrinfo* peer_res = NULL;
    gai = getaddrinfo(peer_host, peer_port, &hints_peer, &peer_res);
    if (gai != 0) {
        log_error("getaddrinfo(%s:%s) failed: %s", peer_host, peer_port, gai_strerror(gai));
        freeaddrinfo(local_res);
        return -1;
    }

    int fd = -1;
    for (struct addrinfo* ai = local_res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if (fd < 0) {
            continue;
        }

        int one = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
            log_warn("setsockopt(SO_REUSEADDR) failed: %s", strerror(errno));
        }

        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;  
        }

        log_debug("bind(%s:%s) failed: %s", local_host, local_port, strerror(errno));
        close(fd);
        fd = -1;
    }

    freeaddrinfo(local_res);

    if (fd < 0) {
        log_error("failed to bind UDP socket on %s:%s", local_host, local_port);
        freeaddrinfo(peer_res);
        return -1;
    }

    if (connect(fd, peer_res->ai_addr, peer_res->ai_addrlen) < 0) {
        log_error("connect(%s:%s) failed: %s", peer_host, peer_port, strerror(errno));
        freeaddrinfo(peer_res);
        close(fd);
        return -1;
    }

    freeaddrinfo(peer_res);
    return fd;
}

static int load_key(const char* path, uint8_t key[KEY_LEN]) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        log_error("fopen(\"%s\") failed: %s", path, strerror(errno));
        return -1;
    }

    size_t nread = fread(key, 1, KEY_LEN, file);
    int io_error = ferror(file);
    int saved_errno = errno; /* fclose may clobber errno */
    fclose(file);

    if (nread == KEY_LEN) {
        return 0;      
    }     

    if (io_error) {
        log_error("fread(\"%s\") failed: %s", path, strerror(saved_errno));
        return -1;
    }

    log_error("key file \"%s\" must be exactly %d bytes, got %zu", path, KEY_LEN, nread);
    return -1;
}

static int genkey(const char* path) {
    identity* id = identity_generate();
    if (!id) {
        return 1;
    }

    int rc = 0;
    if (identity_save(id, path) < 0) {
        rc = 1;
        goto out;
    }

    uint8_t pub[X25519_KEY_LEN];
    char hex[X25519_KEY_LEN * 2 + 1];

    if (identity_pubkey_bytes(id, pub) < 0) {
        rc = 1;
        goto out;
    }

    pubkey_to_hex(pub, hex);
    printf("%s\n", hex);
    fprintf(stderr, "identity saved to %s (mode 0600)\n", path);
out:
    identity_free(id);
    return rc;
}

static void usage(FILE* out, const char* prog) {
    fprintf(out,
        "Usage: %s [OPTIONS]\n"
        "  --tun    NAME          TUN interface name (default: tun0)\n"
        "  --listen ADDR:PORT     Local UDP bind address\n"
        "  --peer   ADDR:PORT     Peer UDP address\n"
        "  --key    FILE          Path to 32-byte AES key\n"
        "  --identity FILE        Path to our X25519 identity (PEM)\n"
        "  --peer-pubkey HEX      Peer's X25519 public key (64 hex chars)\n"
        "  --genkey FILE          Generate a new identity and save to FILE\n"
        "  -h, --help             This help\n",
        prog
    );
}

/* Transient errors: do not log, wait for the next event. 
 * EAGAIN and EWOULDBLOCK mean no data is ready yet.
 * EINTR means the syscall was interrupted by a signal.
 * The main loop will re-check the stop flag on the next iteration. */
static int errno_is_transient(int err) {
    return err == EAGAIN || err == EWOULDBLOCK || err == EINTR;
}

static void handle_tun_read(int tun_fd, int udp_fd, tunnel_crypto* tc,
    uint8_t* plaintext, size_t pt_cap, uint8_t* ciphertext, size_t ct_cap) {
    ssize_t nread = read(tun_fd, plaintext, pt_cap);
    if (nread < 0 && errno_is_transient(errno)) {
        return;
    }
    /* EIO on read(tun) is unusual. Typically the interface went down. */
    if (nread < 0 && errno == EIO) {
        log_debug("read(tun_fd): kernel returned EIO (interface down?)");
        return;
    }
    if (nread < 0) {
        log_error("read(tun_fd) failed: %s", strerror(errno));
        return;
    }
    if (nread == 0) {
        log_warn("read(tun_fd) returned 0");
        return;
    }

    ssize_t ct_len = tc_seal(tc, plaintext, (size_t)nread, ciphertext, ct_cap);
    if (ct_len <= 0) {
        return; /* tc_seal already logged the reason */
    }

    ssize_t nsent = send(udp_fd, ciphertext, (size_t)ct_len, 0);
    if (nsent < 0 && errno_is_transient(errno)) {
        return;
    }
    if (nsent < 0) {
        log_error("send(udp_fd) failed: %s", strerror(errno));
        return;
    }
    if (nsent != ct_len) {
        log_error("send(udp_fd) partial: %zd of %zd bytes", nsent, ct_len);
    }
}

static void handle_udp_read(int tun_fd, int udp_fd, tunnel_crypto* tc,
    uint8_t* plaintext, size_t pt_cap, uint8_t* ciphertext, size_t ct_cap) {
    ssize_t nread = recv(udp_fd, ciphertext, ct_cap, 0);
    if (nread < 0 && errno_is_transient(errno)) {
        return;
    }
    if (nread < 0) {
        log_error("recv(udp_fd) failed: %s", strerror(errno));
        return;
    }
    if (nread == 0) {
        log_debug("recv(udp_fd) returned 0 (empty datagram)");
        return;
    }

    ssize_t pt_len = tc_open(tc, ciphertext, (size_t)nread, plaintext, pt_cap);
    if (pt_len <= 0) {
        return;  /* tc_open already logged the reason */
    }

    ssize_t nwritten = write(tun_fd, plaintext, (size_t)pt_len);
    if (nwritten < 0 && errno_is_transient(errno)) {
        return;
    }
    /* EIO: kernel refused the packet (no route/ARP/IPv6). Not our error. */
    if (nwritten < 0 && errno == EIO) {
        log_debug("write(tun_fd): packet rejected by kernel (EIO)");
        return;
    }
    if (nwritten < 0) {
        log_error("write(tun_fd) failed: %s", strerror(errno));
        return;
    }
    if (nwritten != pt_len) {
        log_error("write(tun_fd) partial: %zd of %zd bytes", nwritten, pt_len);
    }
}

static int load_own_identity(const char* path, identity** out_id) {
    if (!path) {
        return 0;
    }

    identity* id = identity_load(path);
    if (!id) {
        return -1;
    }

    uint8_t pub[X25519_KEY_LEN];
    char hex[X25519_PUBKEY_HEX_LEN];

    if (identity_pubkey_bytes(id, pub) < 0) {
        identity_free(id);
        return -1;
    }

    pubkey_to_hex(pub, hex);
    log_info("own identity: %s", hex);

    *out_id = id;
    return 0;
}

static int log_peer_pubkey(const char* hex) {
    if (!hex) {
        return 0;
    }

    uint8_t peer_pub[X25519_KEY_LEN];
    if (pubkey_from_hex(hex, peer_pub) < 0) {
        return -1;
    }

    log_info("peer pubkey: %s", hex);
    return 0;
}

int main(int argc, char** argv) {
    const char* tun_name = "tun0";
    const char* listen_addr = NULL;
    const char* peer_addr = NULL;
    const char* key_path = NULL;
    const char* identity_path = NULL;
    const char* peer_pubkey_hex = NULL;

    static const struct option long_opts[] = {
        {"tun",         required_argument, 0, 't'},
        {"listen",      required_argument, 0, 'l'},
        {"peer",        required_argument, 0, 'p'},
        {"key",         required_argument, 0, 'k'},
        {"identity",    required_argument, 0, 'i'},
        {"peer-pubkey", required_argument, 0, 'P'},
        {"genkey",      required_argument, 0, 'g'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "t:l:p:k:i:P:g:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 't': tun_name         = optarg; break;
            case 'l': listen_addr      = optarg; break;
            case 'p': peer_addr        = optarg; break;
            case 'k': key_path         = optarg; break;
            case 'i': identity_path    = optarg; break;
            case 'P': peer_pubkey_hex  = optarg; break;
            case 'g': return genkey(optarg);
            case 'h': usage(stdout, argv[0]); return 0;
            default:  usage(stderr, argv[0]); return 1;
        }
    }

    if (!listen_addr || !peer_addr || !key_path) {
        usage(stderr, argv[0]);
        return 1;
    }

    int ret = 1;
    int tun_fd = -1;
    int udp_fd = -1;
    int epfd = -1;
    identity* id = NULL;
    tunnel_crypto* tc = NULL;
    uint8_t key[KEY_LEN] = {0};

    if (load_key(key_path, key) < 0) {
        goto cleanup;
    }

    if (install_signal_handlers() < 0) {
        goto cleanup;
    }

    tc = tc_new(key);
    if (!tc) {
        goto cleanup;
    }

    if (load_own_identity(identity_path, &id) < 0) {
        goto cleanup;
    }

    if (log_peer_pubkey(peer_pubkey_hex) < 0) {
        goto cleanup;
    }

    if (id && !peer_pubkey_hex) {
        log_warn("--identity given without --peer-pubkey");
    }

    tun_fd = tun_open(tun_name);
    if (tun_fd < 0) {
        goto cleanup;
    }
    if (set_nonblock(tun_fd, "tun") < 0) {
        goto cleanup;
    }

    udp_fd = udp_open(listen_addr, peer_addr);
    if (udp_fd < 0) {
        goto cleanup;
    }
    if (set_nonblock(udp_fd, "udp") < 0) {
        goto cleanup;
    }

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        log_error("epoll_create1 failed: %s", strerror(errno));
        goto cleanup;
    }

    struct epoll_event ev = {0};
    ev.events = EPOLLIN;

    ev.data.fd = tun_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, tun_fd, &ev) < 0) {
        log_error("epoll_ctl(ADD, tun_fd) failed: %s", strerror(errno));
        goto cleanup;
    }

    ev.data.fd = udp_fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, udp_fd, &ev) < 0) {
        log_error("epoll_ctl(ADD, udp_fd) failed: %s", strerror(errno));
        goto cleanup;
    }

    log_info("tunnel up: tun=%s listen=%s peer=%s", tun_name, listen_addr, peer_addr);

    static uint8_t plaintext[MAX_PACKET_BYTES];
    static uint8_t ciphertext[MAX_PACKET_BYTES + CRYPTO_OVERHEAD];

    while (!stop) {
        struct epoll_event events[MAX_EVENTS];
        int nready = epoll_wait(epfd, events, MAX_EVENTS, -1);

        if (nready < 0 && errno == EINTR) {
            continue;
        }
        if (nready < 0) {
            log_error("epoll_wait failed: %s", strerror(errno));
            goto cleanup;
        }

        for (int i = 0; i < nready; i++) {
            int fd = events[i].data.fd;
            if (fd == tun_fd) {
                handle_tun_read(tun_fd, udp_fd, tc, plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext));
            } else if (fd == udp_fd) {
                handle_udp_read(tun_fd, udp_fd, tc, plaintext, sizeof(plaintext), ciphertext, sizeof(ciphertext));
            } else {
                log_warn("epoll returned unknown fd=%d", fd);
            }
        }
    }

    log_info("shutting down");
    ret = 0;
cleanup:
    OPENSSL_cleanse(key, sizeof(key));
    tc_free(tc);
    identity_free(id);

    if (tun_fd >= 0) {
        close(tun_fd);
    }

    if (udp_fd >= 0) { 
        close(udp_fd);
    }

    if (epfd >= 0) { 
        close(epfd);
    }

    return ret;
}