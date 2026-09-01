#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>       // malloc, free
#include <time.h>         // time, localtime, strftime
#include <fcntl.h>         // open
#include <unistd.h>        // close, read, write
#include <sys/ioctl.h>     // ioctl
#include <net/if.h>        // struct ifreq
#include <linux/if.h>      // struct ifreq
#include <linux/if_tun.h>  // TUNSETIFF, IFF_T
#include <netinet/ip.h>     // struct iphdr
#include <netinet/tcp.h>    // struct tcphdr
#include <netinet/udp.h>    // struct udphdr
#include <netinet/ip_icmp.h> // struct icmphdr
#include <net/ethernet.h>   // struct ether_header
#include <arpa/inet.h>      // inet_addr, inet_ntoa, htons, ntohs
#include <string.h>        // memcpy

#define MAX_PACKET_SIZE 65536 // tamanho máximo recomendado (UDP como referência)

typedef enum {
    PARSE_OK,
    PARSE_TOO_SHORT,
    PARSE_BAD_VERSION,
    PARSE_BAD_IHL,
    PARSE_FRAGMENT,
    PARSE_UNSUPPORTED_PROTOCOL
} parse_status_t;

struct packet_info {
    uint32_t src_ip, dst_ip;
    uint8_t protocol;
    unsigned short is_fragment;

    uint16_t frag_offset;         // offset do fragmento, 0 quando não se aplica
    uint16_t total_length;          // tamanho total do pacote, 0 quando não se aplica
    uint16_t frag_id;              // identificador do fragmento, 0 quando não se aplica

    uint16_t ip_checksum;          // checksum do cabeçalho IP, 0 quando não se aplica
    uint16_t transport_checksum;     // checksum do cabeçalho de transporte, 0 quando não se aplica

    uint16_t src_port, dst_port;   // 0 quando não se aplica (ICMP)
    uint8_t tcp_flags;             // bitmask normalizado
    uint32_t seq, ack;

    uint8_t icmp_type, icmp_code;

    const uint8_t *payload;
    size_t payload_len;

    const uint8_t *raw;            // buffer original inteiro, necessário pro RST
    size_t raw_len;
};

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

parse_status_t parse_packet(const uint8_t *packet, size_t packet_len, struct packet_info *pkt_info) {

    if (packet_len < sizeof(struct iphdr)) {
        return PARSE_TOO_SHORT;
    }

    // parsing do cabeçalho IP
    struct iphdr *ip_header = (struct iphdr *)packet;

    // verifica se o pacote é IPv4
    if (ip_header->version != 4) {
        return PARSE_BAD_VERSION;
    }

    // calcula o tamanho correto do cabeçalho IP em bytes
    size_t ip_header_len = ip_header->ihl * 4;
    if (packet_len < ip_header_len) {
        return PARSE_BAD_IHL;
    }

    // preenche packet_info com as informações do pacote
    pkt_info->src_ip = ip_header->saddr;
    pkt_info->dst_ip = ip_header->daddr;
    pkt_info->protocol = ip_header->protocol;

    pkt_info->is_fragment = (ntohs(ip_header->frag_off) & IP_MF) || (ntohs(ip_header->frag_off) & IP_OFFMASK);
    pkt_info->frag_id = ntohs(ip_header->id);
    pkt_info->ip_checksum = ntohs(ip_header->check);
    pkt_info->total_length = ntohs(ip_header->tot_len);
    pkt_info->frag_offset = ntohs(ip_header->frag_off);

    pkt_info->raw = packet;
    pkt_info->raw_len = packet_len;

    if (pkt_info->is_fragment) {
        return PARSE_FRAGMENT;
    }

    // parsing do cabeçalho de transporte (TCP, UDP, ICMP)
    const uint8_t *payload = packet + ip_header_len;
    size_t payload_len = packet_len - ip_header_len;

    switch (ip_header->protocol) {
        case IPPROTO_TCP: {
            if (payload_len < sizeof(struct tcphdr)) {
                return PARSE_TOO_SHORT;
            }
            struct tcphdr *tcp_header = (struct tcphdr *)payload;
            pkt_info->src_port = ntohs(tcp_header->source);
            pkt_info->dst_port = ntohs(tcp_header->dest);
            pkt_info->tcp_flags = tcp_header->th_flags;
            pkt_info->seq = ntohl(tcp_header->seq);
            pkt_info->ack = ntohl(tcp_header->ack_seq);
            pkt_info->payload = payload + tcp_header->doff * 4;
            pkt_info->payload_len = payload_len - tcp_header->doff * 4;
            pkt_info->transport_checksum = ntohs(tcp_header->check);

            uint8_t flags = 0;
            flags |= tcp_header->fin << 0;
            flags |= tcp_header->syn << 1;
            flags |= tcp_header->rst << 2;
            flags |= tcp_header->psh << 3;
            flags |= tcp_header->ack << 4;
            flags |= tcp_header->urg << 5;
            break;
        }

        case IPPROTO_UDP: {
            if (payload_len < sizeof(struct udphdr)) {
                return PARSE_TOO_SHORT;
            }
            struct udphdr *udp_header = (struct udphdr *)payload;
            pkt_info->src_port = ntohs(udp_header->source);
            pkt_info->dst_port = ntohs(udp_header->dest);
            pkt_info->payload = payload + sizeof(struct udphdr);
            pkt_info->payload_len = payload_len - sizeof(struct udphdr);
            pkt_info->transport_checksum = ntohs(udp_header->check);
            break;
        }

        case IPPROTO_ICMP: {
            if (payload_len < sizeof(struct icmphdr)) {
                return PARSE_TOO_SHORT;
            }
            struct icmphdr *icmp_header = (struct icmphdr *)payload;
            pkt_info->icmp_type = icmp_header->type;
            pkt_info->icmp_code = icmp_header->code;
            pkt_info->payload = payload + sizeof(struct icmphdr);
            pkt_info->payload_len = payload_len - sizeof(struct icmphdr);
            pkt_info->transport_checksum = ntohs(icmp_header->checksum);
            break;
        }

        default:
            return PARSE_UNSUPPORTED_PROTOCOL;
    }

    return PARSE_OK;
}

char* get_parse_status_message(parse_status_t status) {
    switch (status) {
        case PARSE_OK:
            return "parse_success";
        case PARSE_TOO_SHORT:
            return "parse_too_short";
        case PARSE_BAD_VERSION:
            return "parse_bad_version";
        case PARSE_BAD_IHL:
            return "parse_bad_ipheader_length";
        case PARSE_FRAGMENT:
            return "parse_fragment";
        case PARSE_UNSUPPORTED_PROTOCOL:
            return "parse_unsupported_protocol";
        default:
            return "parse_unknown";
    }
}

char* get_proto_str (uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        default:
            return "OTHER";
    }
}

void log_event (FILE* log_file, const char* event, const char* level, struct packet_info* pkt_info) {
    time_t now = time(NULL);
    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    char* proto_str = get_proto_str(pkt_info->protocol);

    fprintf(log_file, "%s level=%s ", time_str, level);

    fprintf(log_file, "proto=%s src=%s sport=%u dst=%s dport=%u\n", proto_str,
            inet_ntoa(*(struct in_addr*)&pkt_info->src_ip), pkt_info->src_port,
            inet_ntoa(*(struct in_addr*)&pkt_info->dst_ip), pkt_info->dst_port);
    
    fprintf(log_file, "reason=%s\n", event);

    fflush(log_file);
}

int main(void) {

    char tun_name[IFNAMSIZ] = "tun0"; // nome da interface TUN
    int tun_fd = tun_open(tun_name);
    if (tun_fd < 0) {
        fprintf(stderr, "Erro ao abrir a interface TUN\n");
        return 1;
    }

    FILE* log_file = fopen("firewall.log", "a");
    if (!log_file) {
        perror("fopen");
        close(tun_fd);
        return 1;
    }
    // define o buffer do log para linha por linha
    setvbuf(log_file, NULL, _IOLBF, 0);

    FILE* blocklist_file = fopen("blocklist.txt", "r");
    if (!blocklist_file) {
        perror("fopen");
        fclose(log_file);
        close(tun_fd);
        return 1;
    }

    while (1) {
        uint8_t buffer[MAX_PACKET_SIZE]; // buffer para armazenar o pacote recebido
        ssize_t nread = read(tun_fd, buffer, sizeof(buffer));
        if (nread < 0) {
            perror("read");
            break;
        }

        struct packet_info pkt_info;
        parse_status_t status = parse_packet(buffer, nread, &pkt_info);
        if (status != PARSE_OK) {
            log_event(log_file, get_parse_status_message(status), "ERROR", &pkt_info);
            continue;
        }

        // verifica se o pacote deve ser bloqueado
        int blocked = 0;

    }

    close(tun_fd);

    return 0;
}
