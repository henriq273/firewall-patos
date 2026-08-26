#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
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
#include <time.h>          // struct timespec

int main(void) {

    srand(NULL);

    printf("Hello world!\n");

    // abre e obtem o descritor do dispositivo TUN
    int tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun_fd < 0) {
        fprintf(stderr, "Erro ao abrir /dev/net/tun: %s\n",
             strerror(errno));
        return 1;
    }

    // inicializa e zera a struct ifreq
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    int err = ioctl (tun_fd, TUNSETIFF, (void *)&ifr);
    if (err < 0) {
        fprintf(stderr, "Erro ao configurar o dispositivo TUN: %s\n",
             strerror(errno));
        close(tun_fd);
        return 1;
    }

    char* tun_name = ifr.ifr_name; // ! cuidado com dangling pointer, se ifr sair de escopo, tun_name fica inválido

    // cria um socket auxiliar para enviar pacotes
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        fprintf(stderr, "Erro ao criar socket: %s\n", strerror(errno));
        close(tun_fd);
        return 1;
    }

    // ativa a interface TUN via ioctl pelo socket auxiliar
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "Erro ao obter flags da interface: %s\n", strerror(errno));
        close(tun_fd);
        close(sock);
        return 1;
    }

    // ativa a interface TUN
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        fprintf(stderr, "Erro ao configurar flags da interface: %s\n", strerror(errno));
        close(tun_fd);
        close(sock);
        return 1;
    }

    close(sock);

    struct packet_info {
        struct timespec timestamp;
        uint32_t src_ip, dst_ip;
        uint16_t src_port, dst_port; // 0 quando não se aplica (ICMP)
        uint8_t protocol;
        uint8_t ip_flags;            // DF/MF
        uint16_t frag_offset;
        int has_transport_header;    // false se for fragmento não-inicial
        uint8_t tcp_flags;           // já como bitmask pronto pra comparar
        uint32_t seq, ack;
        uint8_t icmp_type, icmp_code;
        const uint8_t *payload;
        size_t payload_len;
        const uint8_t *raw;          // buffer original (necessário pra forjar RST depois)
        size_t raw_len;
    };

    close(tun_fd);    
    close(sock);

    return 0;
}
