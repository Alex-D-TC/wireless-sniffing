#ifndef _INTERNET_STRUCTS_H_
#define _INTERNET_STRUCTS_H_

#include <stdint.h>

#pragma pack(push)
#pragma pack(1)

#define MAC_HDR_SZ 14

#define IPV4_TYPE 0x0800
#define PROTOCOL_TCP 0x06
#define PROTOCOL_UDP 0x11

#define MAC_ADDR1_IEEE(p) ((uint8_t*)p)
#define MAC_ADDR2_IEEE(p) ((uint8_t*)p + 6)
#define PKT_TYPE(p) (((uint8_t*)p)[12])
#define IP_VERSION(p) ((uint8_t)(p[0] >> 4))
#define IP_LEN(p) (((size_t)(p & 0x0F)) * 4)
#define TCP_LEN(p) ((size_t)(p >> 4))

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

#pragma pack(pop)

#endif // !_INTERNET_STRUCTS_H_
