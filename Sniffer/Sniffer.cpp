#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <stdio.h>

#ifdef WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

#include <string.h>
#include <time.h>

#include <string>

#include "InternetStructs.h"
#include "HttpTest.h"

#ifdef WIN32

#include <tchar.h>

bool LoadNpcapDlls() {
    if (SetDllDirectory(L"C:\\Program Files\\Npcap\\") == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return false;
    }

    return true;
}

#else

bool LoadNpcapDlls() {
    return true;
}

#endif

void dump_raw(const uint8_t* pkt_data, size_t bytes_count) {
    printf("Raw packet");

    for (size_t i = 0; i < bytes_count;) {
        printf("\n");
        for (size_t j = 0; j < 32; i++, j++) {
            printf("%02x ", pkt_data[i]);
        }
    }

    printf("\n");
}

/* prototype of the packet handler */
void packet_handler(uint8_t* param, const struct pcap_pkthdr* header, const uint8_t* pkt_data);


int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* devices;
    int inum;
    int i = 0;
    pcap_t* adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];

    dump_raw((uint8_t*)&gHttpTestPacket, sizeof(gHttpTestPacket));
    packet_handler(nullptr, &gHttpTestPcapHeader, (uint8_t*)gHttpTestPacket);
    printf("\n");

    /* Load Npcap and its functions. */
    if (!LoadNpcapDlls()) {
        fprintf(stderr, "Couldn't load Npcap\n");
        exit(1);
    }

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

    *type = ntohs(PKT_TYPE(pkt_data));

    mac = MAC_ADDR1_IEEE(pkt_data);
    sprintf(macAddr1, "%02x:%02x:%02x:%02x:%02x:%02x\0", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    mac = MAC_ADDR2_IEEE(pkt_data);
    sprintf(macAddr2, "%02x:%02x:%02x:%02x:%02x:%02x\0", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    sprintf(formated, "Source Mac %s Dest Mac %s Packet Type %04X\0", macAddr2, macAddr1, *type);

    return formated;
}

std::string ipHeaderToString(const uint8_t* pkt_data, uint8_t* protocol, size_t* ip_size) {
    const ip_header* ip = (const ip_header*)pkt_data;
    char formated[1000] = "";

    if (IP_VERSION(pkt_data) != 4 && IP_VERSION(pkt_data) != 6) {
        return "";
    }

    if (IP_VERSION(pkt_data) == 4) {
        *protocol = ip->proto;
        *ip_size = IP_LEN(ip->ver_ihl);

        sprintf(formated, "IpV%d Source Ip %d.%d.%d.%d Dest Ip %d.%d.%d.%d Header length %u Total Length %d TTL %u Checksum %u",
            IP_VERSION(pkt_data),
            ip->saddr.byte1, ip->saddr.byte2, ip->saddr.byte3, ip->saddr.byte4,
            ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4,
            *ip_size, ntohs(ip->tlen), ip->ttl, ntohs(ip->crc)
        );
    } 
    else if (IP_VERSION(pkt_data) == 6) {
        return "";
    }

    return std::string{ formated } + "\n";
}

std::string udpHeaderToString(const uint8_t* pkt_data) {
    const udp_header* udp = (const udp_header*)pkt_data;
    char formated[1000];

    sprintf(formated, "Protocol UDP Source Port %d Dest Port %d Datagram Length %u Checksum %u",
        ntohs(udp->sport), ntohs(udp->dport), ntohs(udp->len), ntohs(udp->crc)
    );

    return std::string{ formated } + "\n";
}

std::string tcpHeaderToString(const uint8_t* pkt_data, size_t* len) {
    const tcp_header* tcp = (const tcp_header*)pkt_data;
    char formated[1000];

    sprintf(formated, "Protocol TCP Source Port %d Dest Port %d Seq %u Ack %u Window Size %u Checksum %u",
        ntohs(tcp->src_port), ntohs(tcp->dst_port), ntohl(tcp->seq), ntohl(tcp->ack), 
        ntohs(tcp->window_size), ntohs(tcp->checksum)
    );

    *len = TCP_LEN(tcp->data_offset) * 4;

    return std::string{ formated } + "\n";
}

std::string httpHeaderToString(const uint8_t* pkt_data) {
    const char* data = reinterpret_cast<const char*>(pkt_data);

    if (strstr(data, "HTTP") != NULL) {
        return std::string{ data, strstr(data, "\r\n\r\n") } + "\n";
    } else {
       return "";
    }
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(uint8_t* param, const struct pcap_pkthdr* header, const uint8_t* pkt_data) {
    const uint8_t* data = pkt_data; (void)(param);
    size_t ipHeaderSize, tcpHeaderSize;
    uint16_t type;
    uint8_t protocol;

    /* dump_raw(pkt_data, header->caplen); */
    /* convert the timestamp to readable format */
    auto time = timestampToReadableString(header->ts.tv_sec, header->ts.tv_usec);
    auto macAddrs = ieee80211HeaderToString(data, &type);
    
    printf("Time %s Length %d bytes\n%s\n", time.c_str(), header->len, macAddrs.c_str());

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
    } else if (protocol == PROTOCOL_TCP) {
        printf("%s", tcpHeaderToString(data, &tcpHeaderSize).c_str());
        data += tcpHeaderSize;
        printf("%s", httpHeaderToString(data).c_str());
    }
}
