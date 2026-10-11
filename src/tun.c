#include "tun.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stddef.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static int set_iface_name(struct ifreq* ifr, const char* name) {
    if (!name) {
        return 0;
    }
    if (name[0] == '\0') {
        log_error("interface name is empty");
        return -1;
    }

    size_t len = strlen(name);
    if (len >= IFNAMSIZ) {
        log_error("interface name too long: %zu chars (max %d)", len, IFNAMSIZ - 1);
        return -1;
    }

    memcpy(ifr->ifr_name, name, len + 1);
    return 0;
}

int tun_open(const char* name) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        log_error("open(/dev/net/tun) failed: %s", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    if (set_iface_name(&ifr, name) < 0) {
        close(fd);
        return -1;
    }

    /* IFF_TUN: L3, raw IP packets. IFF_NO_PI: no 4-byte packet-info prefix. */
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        log_error("TUNSETIFF(name=\"%s\") failed: %s", name ? name : "<auto>", strerror(errno));
        close(fd);
        return -1;
    }

    /* ifr_name now holds the kernel-assigned name. */
    log_info("TUN interface \"%s\" opened (fd=%d)", ifr.ifr_name, fd);
    return fd;
}