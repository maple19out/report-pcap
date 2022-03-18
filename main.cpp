#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

struct Param{
    char* dev_;
};

Param param {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
       usage();
       return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_ethernet(const libnet_ethernet_hdr* ether) {
    const uint8_t* src = ether->ether_shost;
    const uint8_t* dsc = ether->ether_dhost;

    printf("src mac : ");
    for(int i = 0; i < 5; i++)
        printf("%02x:", src[i]);
    printf("%02x\n", src[5]);

    printf("dsc mac : ");
    for(int i = 0; i < 5; i++)
        printf("%02x:", dsc[i]);
    printf("%02x\n", dsc[5]);
}

void print_ip(const struct libnet_ipv4_hdr* ip) {
    const char* src_str = inet_ntoa(ip->ip_src);
    printf("src ip : %s\n", src_str);

    const char* dst_str = inet_ntoa(ip->ip_dst);
    printf("dsc ip : %s\n", dst_str);
}

void print_tcp(const struct libnet_tcp_hdr* tcp) {
    printf("src port : %d\n", ntohs(tcp->th_sport));
    printf("dst port : %d\n", ntohs(tcp->th_dport));
}

void print_data(const u_char* start, const u_char* end) {
    printf("data : ");
    for(int i = 0; i < 8 && start + i <= end; i++)
        printf("%02x ", *(start + i));
    printf("\n");
}

int main(int argc, char *argv[]) {
    if(!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const uint8_t* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        /* check whether captured packet has IP header */
        struct libnet_ethernet_hdr* ether = (struct libnet_ethernet_hdr*)packet;
        if (ether->ether_type != htons(ETHERTYPE_IP))
            continue;
        /* check whether captured packet has TCP header */
        struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*)((uint8_t*)ether + sizeof(struct libnet_ethernet_hdr));
        if (ip->ip_p != 6)
            continue;
        struct libnet_tcp_hdr* tcp = (struct libnet_tcp_hdr*)((uint8_t*)ip + ip->ip_hl * 4);

        printf("\n");
        print_ethernet(ether);
        print_ip(ip);
        print_tcp(tcp);
        uint8_t* data_start = (uint8_t*)tcp + tcp->th_off * 4;
        uint8_t* data_end = (uint8_t*)packet + header->caplen;
        print_data(data_start, data_end);
        printf("\n");
    }
    pcap_close(pcap);

    return 0;
}
