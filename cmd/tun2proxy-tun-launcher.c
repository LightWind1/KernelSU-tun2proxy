// Create an Android TUN device and pass its fd to tun2proxy.
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s <tun2proxy> <tun-name> <args...>\n", argv[0]); return 2; }
    const char *tun_path = "/dev/net/tun";
    int fd = open(tun_path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        tun_path = "/dev/tun";
        fd = open(tun_path, O_RDWR | O_CLOEXEC);
    }
    if (fd < 0) {
        fprintf(stderr, "TUN unavailable: tried /dev/net/tun and /dev/tun; enable CONFIG_TUN or create the device node\n");
        return 1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[2], IFNAMSIZ - 1);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) { perror("TUNSETIFF"); close(fd); return 1; }
    if (dup2(fd, 3) < 0) { perror("dup2"); close(fd); return 1; }
    if (fd != 3) close(fd);
    // open() uses O_CLOEXEC. dup2() clears it only when it actually
    // duplicates to a different descriptor; when fd is already 3, dup2(3,3)
    // is a no-op and execv() would silently close the TUN fd.
    int fd_flags = fcntl(3, F_GETFD);
    if (fd_flags < 0 || fcntl(3, F_SETFD, fd_flags & ~FD_CLOEXEC) < 0) {
        perror("clear FD_CLOEXEC");
        close(3);
        return 1;
    }
    char **child = calloc((size_t)argc + 3, sizeof(char *));
    if (!child) return 1;
    child[0] = argv[1]; child[1] = "--tun-fd"; child[2] = "3";
    child[3] = "--close-fd-on-drop"; child[4] = "false";
    for (int i = 3; i < argc; ++i) child[i + 2] = argv[i];
    execv(child[0], child);
    perror("exec tun2proxy");
    return 1;
}
