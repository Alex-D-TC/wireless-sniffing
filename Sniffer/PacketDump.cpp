#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
//#include <winsock.h>
#include <string.h>
#include <time.h>

#include <string>

#define MAC_HDR_SZ 14

#define IPV4_TYPE 0x0800
#define PROTOCOL_TCP 0x06
#define PROTOCOL_UDP 0x11

#define MAC_ADDR1_IEEE(p) ((uint8_t*)p)
#define MAC_ADDR2_IEEE(p) ((uint8_t*)p + 6)
#define PKT_TYPE(p) (((uint8_t*)p)[12])
#define IP_VERSION(p) ((uint8_t)(p[0] >> 4))
#define IP_LEN(p) ((uint8_t)(&p[0] << 4))
#define TCP_LEN(p) ((uint8_t)(p >> 4))

void dump_raw(const uint8_t* pkt_data, size_t bytes_count) {
    printf("Raw packet");
    for (size_t i = 0; i < bytes_count;) {
        printf("\n");
        for (size_t j = 0; j != 15; i++, j++) {
            printf("%02x ", pkt_data[i]);
        }
    }
    printf("\n");
}

#pragma push
#pragma pack(1)
struct ieee80211_radiotap_header {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
};

/* 4 bytes IP address */
typedef struct ip_address {
    uint8_t byte1;
    uint8_t byte2;
    uint8_t byte3;
    uint8_t byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
    uint8_t ver_ihl;            // Version (4 bits) + Internet header length (4 bits)
    uint8_t tos;                // Type of service 
    uint16_t tlen;              // Total length 
    uint16_t identification;    // Identification
    uint16_t flags_fo;          // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t ttl;                // Time to live
    uint8_t proto;              // Protocol
    uint16_t crc;               // Header checksum
    ip_address saddr;           // Source address
    ip_address daddr;           // Destination address
    unsigned int op_pad;        // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header {
    uint16_t sport;          // Source port
    uint16_t dport;          // Destination port
    uint16_t len;            // Datagram length
    uint16_t crc;            // Checksum
}udp_header;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;  // 4 bits
    uint8_t  flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_p;
} tcp_header;

#pragma pop

#ifdef WIN32

#include <tchar.h>

BOOL LoadNpcapDlls() {
    if (SetDllDirectory(L"C:\\Program Files\\Npcap\\") == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }

    return TRUE;
}

#endif

/* prototype of the packet handler */
void packet_handler(uint8_t* param, const struct pcap_pkthdr* header, const uint8_t* pkt_data);

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* devices;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

#ifdef WIN32
    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls()) {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }
#endif

    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for (devices = alldevs; devices; devices = devices->next) {
        printf("%d. %s", ++i, devices->name);

        if (devices->description) {
            printf(" (%s)\n", devices->description);
        } else {
            printf(" (No description available)\n");
        }
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure Npcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):", i);
    scanf("%d", &inum);

    if (inum < 1 || inum > i) {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    /* Jump to the selected adapter */
    for (devices = alldevs, i = 0; i < inum - 1; devices = devices->next, i++);

    /* Open the device */
    /* Open the adapter */
    adhandle = pcap_open_live(
        devices->name,  // name of the device
        65536,          // portion of the packet to capture. 65536 grants that the whole packet will be captured on all the MACs.
        1,              // promiscuous mode (nonzero means promiscuous)
        1000,           // read timeout
        errbuf          // error buffer
    );
    if (adhandle == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", devices->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    printf("\nlistening on %s...\n", devices->description);

    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);
    return 0;
}

std::string timestampToReadableString(time_t seconds, long microseconds) {
    char timestr[16], fulltimestr[22];

    auto time = localtime(&seconds);
    strftime(timestr, sizeof timestr, "%H:%M:%S", time);
    sprintf(fulltimestr, "%s.%.6ld", timestr, microseconds);

    return fulltimestr;
}

std::string ieee80211HeaderToString(const uint8_t* pkt_data, uint16_t* type) {
    char macAddr1[100], macAddr2[100], formated[1000];
    const uint8_t* mac;
    //auto hdr = (struct ieee80211_radiotap_header*)pkt_data;
    //auto len = EXTRACT_LE_16BITS(&hdr->it_len);

    mac = MAC_ADDR1_IEEE(pkt_data);
    sprintf(macAddr1, "%02x:%02x:%02x:%02x:%02x:%02x\0", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    mac = MAC_ADDR2_IEEE(pkt_data);
    sprintf(macAddr2, "%02x:%02x:%02x:%02x:%02x:%02x\0", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    sprintf(formated, "Source Mac %s Dest Mac %s\0", macAddr2, macAddr1);

    *type = ntohs(PKT_TYPE(pkt_data));

    return formated;
}

std::string ipHeaderToString(const uint8_t* pkt_data, uint8_t* protocol, size_t* ip_size) {
    const ip_header* ip = (const ip_header*)pkt_data;
    char formated[1000] = "";

    if (IP_VERSION(pkt_data) != 4 && IP_VERSION(pkt_data) != 6) {
        return "";
    }

    if (IP_VERSION(pkt_data) == 4) {
        sprintf(formated, "IpV%d Source Ip %d.%d.%d.%d Dest Ip %d.%d.%d.%d\0", IP_VERSION(pkt_data),
            ip->saddr.byte1, ip->saddr.byte2, ip->saddr.byte3, ip->saddr.byte4,
            ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4
        );

        *protocol = ip->proto;
        *ip_size = IP_LEN(ip->ver_ihl);
    } 
    else if (IP_VERSION(pkt_data) == 6) {
        return "";
    }

    return std::string{ formated } + "\n";
}

std::string udpHeaderToString(const uint8_t* pkt_data) {
    const udp_header* udp = (const udp_header*)pkt_data;
    char formated[1000];

    sprintf(formated, "Protocol UDP Source Port %d Dest Port %d\0", udp->sport, udp->dport);

    return std::string{ formated } + "\n";
}

std::string tcpHeaderToString(const uint8_t* pkt_data, size_t* len) {
    const tcp_header* tcp = (const tcp_header*)pkt_data;
    char formated[1000], http[1000];
    std::string httpHDR;
    sprintf(formated, "Protocol TCP Source Port %d Dest Port %d Seq %u Ack %u\0",
        tcp->src_port, tcp->dst_port, tcp->seq, tcp->ack);

    *len = TCP_LEN(tcp->data_offset) * 4;
    if (tcp->dst_port == 80 || tcp->src_port ==  80) {
        memcpy(http, pkt_data + *len, 32); formated[32] = '\0';
        httpHDR = std::string{ "HTTP " } + http + "\n";
    } 

    return std::string{ formated } + "\n" + httpHDR;
}

/*std::string httpHeaderToString(const uint8_t* pkt_data) {
    const tcp_header* tcp = (const tcp_header*)pkt_data;
    char formated[10000];

    //dump_raw(pkt_data, 32);
    if (isHTTP) {
        memcpy(formated, pkt_data, 32); formated[32] = '\0';
        return std::string{ formated } + "\n";
    }

    /*if (pkt_data[0] == 'H' && pkt_data[1] == 'T' &&
        pkt_data[2] == 'T' && pkt_data[3] == 'P'
    ) {
        for (size_t i = 0; ; i++) {
            if (pkt_data[i] == '\n' && pkt_data[i + 1] == '\n') {
                memcpy(formated, pkt_data, i);
                formated[i] = '\0';
                return std::string{ formated };
            }
        }

        return "http\n";
    }

    return "";
}*/

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(uint8_t* param, const struct pcap_pkthdr* header, const uint8_t* pkt_data) {
    const uint8_t* data = pkt_data; (void)(param);
    size_t ipHeaderSize, tcpHeaderSize;
    uint16_t type;
    uint8_t protocol;

    /* convert the timestamp to readable format */
    auto time = timestampToReadableString(header->ts.tv_sec, header->ts.tv_usec);
    auto macAddrs = ieee80211HeaderToString(data, &type);
    
    printf("Time %s Length %d bytes\n%s\n", time.c_str(), header->len, macAddrs.c_str());
    //dump_raw(pkt_data, header->caplen);
    
    data = data + MAC_HDR_SZ;
    if (type != IPV4_TYPE || data >= pkt_data + header->caplen) {
        return;
    }

    printf("%s", ipHeaderToString(data, &protocol, &ipHeaderSize).c_str());

    data = data + ipHeaderSize;
    if (data >= pkt_data + header->caplen) {
        return;
    }
    
    if (protocol == PROTOCOL_UDP) {
        printf("%s", udpHeaderToString(data).c_str());
    }
    else if (protocol == PROTOCOL_TCP) {
        printf("%s", tcpHeaderToString(data, &tcpHeaderSize).c_str());
        data += tcpHeaderSize;
        //printf("%s", httpHeaderToString(data).c_str());
    }
}
