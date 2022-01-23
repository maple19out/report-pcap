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

void print_ethernet(const u_char* frame) {
    u_char* src = ((struct libnet_ethernet_hdr*)frame)->ether_shost;
    u_char* dsc = ((struct libnet_ethernet_hdr*)frame)->ether_dhost;

    printf("src mac : ");
    for(int i = 0; i < 5; i++)
        printf("%02x:", src[i]);
    printf("%02x\n", src[5]);

    printf("dsc mac : ");
    for(int i = 0; i < 5; i++)
        printf("%02x:", dsc[i]);
    printf("%02x\n", dsc[5]);
}

void print_ip(const u_char* packet) {
    const char* src_str = inet_ntoa(((struct libnet_ipv4_hdr*)packet)->ip_src);
    printf("src ip : %s\n", src_str);

    const char* dst_str = inet_ntoa(((struct libnet_ipv4_hdr*)packet)->ip_dst);
    printf("dsc ip : %s\n", dst_str);
}

void print_tcp(const u_char* segment) {
    printf("src port : %d\n", ntohs(((struct libnet_tcp_hdr*)segment)->th_sport));
    printf("dst port : %d\n", ntohs(((struct libnet_tcp_hdr*)segment)->th_dport));
}

void print_payload(const u_char* start, const u_char* end) {
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
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        /*To Do*/
        //check whether packet has ip header
        if (((struct libnet_ethernet_hdr*)packet)->ether_type != htons(ETHERTYPE_IP))
            continue;
        //check whether packet has TCP header
        if (((struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr)))->ip_p != 6)
            continue;

        printf("\n");
        print_ethernet(packet);
        print_ip(packet + sizeof(struct libnet_ethernet_hdr));
        print_tcp(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));

        u_char header_len = ((struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr)))->th_off * 4;
        print_payload(packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + header_len, packet + header->caplen);
        printf("\n");
    }

    pcap_close(pcap);

    return 0;
}
