#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>         // open
#include <unistd.h>        // close, read, write
#include <sys/ioctl.h>     // ioctl
#include <net/if.h>        // struct ifreq
#include <linux/if.h>      // struct ifreq
#include <linux/if_tun.h>  // TUNSETIFF, IFF_T
#include <netinet/ip.h>     // struct iphdr
#include <netinet/tcp.h>    // struct tcphdr
#include <netinet/udp.h>    // struct udphdr
#include <net/ethernet.h>   // struct ether_header
#include <arpa/inet.h>      // inet_addr, inet_ntoa, htons, ntohs
#include <string.h>        // memcpy

int tun_open (char *dev_name) {

    // estruturas para a configuração da interface TUN
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("open");
        return fd;
    }

    // configura e nomeia a interface TUN - memset limpa ifr e em seguida se define os flags
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    // IFF_TUN define uma interface TUN e IFF_NO_PI indica que não haverá cabeçalho de protocolo adicional

    if (dev_name) {
        strncpy(ifr.ifr_name, dev_name, IFNAMSIZ - 1);
    }

    // chama ioctl para configurar a interface TUN como dispositivo de rede
    err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (err < 0) {
        perror("ioctl");
        close(fd);
        return err;
    }

    return fd;
}

int main(void) {

    char tun_name[IFNAMSIZ] = "tun0"; // nome da interface TUN
    int tun_fd = tun_open(tun_name);
    if (tun_fd < 0) {
        fprintf(stderr, "Erro ao abrir a interface TUN\n");
        return 1;
    }

    

    return 0;
}
