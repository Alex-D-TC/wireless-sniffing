#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <cstdint>
#include "ieee_80211.h"

void dump_raw(const uint8_t* data, uint8_t rows, uint8_t cols)
{
    uint8_t i = 0;
    for (size_t row = 0; row < rows; ++row)
    {
        for (size_t col = 0; col < cols; ++col)
        {
            printf("%02X ", data[i]);
            ++i;
        }
        printf("\n");
    }
}

void mgmt_packet_handler(u_char* user, const pcap_pkthdr* header, const u_char* packet)
{
    const ieee80211_radiotap_hdr* radiotap = reinterpret_cast<const ieee80211_radiotap_hdr*>(packet);
    const ieee80211_mgmt* mgmt_header = reinterpret_cast<const ieee80211_mgmt*>(packet + radiotap->it_len);

    printf("Packet without radiotap\n");
    dump_raw(packet, 6, 16);

    printf("Packet without radiotap\n");
    dump_raw(reinterpret_cast<const uint8_t*>(mgmt_header), 4, 16);

    printf("Total capture size: %d\n", header->caplen);
    printf("Radiotap Version %d\n", radiotap->it_version);
    printf("Radiotap Length: %d\n", radiotap->it_len);
    printf("Present %04X\n", radiotap->it_present);

    auto da = mgmt_header->da;
    printf("DA: %02x:%02x:%02x:%02x:%02x:%02x\n", da[0], da[1], da[2], da[3], da[4], da[5]);

    const ieee80211_ssid* ssid = nullptr;

    printf("Subtype: 0x%X\n", mgmt_header->frame_control.subtype);

    switch (mgmt_header->frame_control.subtype)
    {
    case ieee80211_mgmt_subtype::BEACON:
        printf("Beacon\n");
        ssid = reinterpret_cast<const ieee80211_ssid*>(&(mgmt_header->u.beacon.variable));
        if (ssid->length > 0)
        {
            printf("SSID: ");
            for (auto i = 0; i < ssid->length; ++i)
            {
                printf("%c", ssid->ssid[i]);
            }
            printf("\n");
        }
        break;
    default:
        printf("Unidentified subtype: 0X%X\n", mgmt_header->frame_control.subtype);
    }
}

int main(int argc, char* argv[])
{
    pcap_t* pcap_h;
    struct  bpf_program fp;
    char    errbuf[PCAP_ERRBUF_SIZE];
    int err;
    int status = EXIT_SUCCESS;
    //const char* device = "\\Device\\NPF_{9D9F01F2-F6FF-4E50-A317-48473BA2FD04}";
    const char* device = "wlp3s0";

    printf("Attempting to monitor on device %s\n", device);

    if ((pcap_h = pcap_create(device, errbuf)) == NULL)
    {
        printf("pcap_create() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if ((err = pcap_can_set_rfmon(pcap_h)) <= 0)
    {
        printf("Interface cannot be set in monitor mode\n");
        exit(EXIT_FAILURE);
    }

    if ((err = pcap_set_rfmon(pcap_h, 1)) < 0)
    {
        printf("Failed to set monitor mode. Error %d\n", err);
        exit(EXIT_FAILURE);
    }
    
    if ((err = pcap_activate(pcap_h)) < 0)
    {
        if (err == PCAP_WARNING || err == PCAP_ERROR)
        {
            printf("pcap_activate() failed with error %s\n", pcap_geterr(pcap_h));
        }
        else
        {
            printf("pcap_activate() failed with error %d\n", err);
        }
        exit(EXIT_FAILURE);
    }

    /*
     * Compile a filter to sniff 802.11 probe requests
     * type mgt subtype probe-req
     */
    if (pcap_compile(pcap_h, &fp, "type mgt", 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        printf("pcap_compile() failed: %s\n", pcap_geterr(pcap_h));
        status = EXIT_FAILURE;
        goto cleanup;
    }

    if (pcap_setfilter(pcap_h, &fp) == -1)
    {
        printf("pcap_setfilter() failed: %s\n", pcap_geterr(pcap_h));
        status = EXIT_FAILURE;
        goto cleanup;
    }

    printf("Starting monitoring\n");

    err = pcap_loop(pcap_h, 0, mgmt_packet_handler, nullptr);
    if (-1 == err)
    {
        printf("pcap_loop error occurred: %s", pcap_geterr(pcap_h));
    }

cleanup:
    printf("Stopping monitoring\n");

    // Stop monitoring
    pcap_set_rfmon(pcap_h, 0);
    pcap_close(pcap_h);

    return status;
}
