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

void print_ssid(const ieee80211_ssid* ssid)
{
    if (ssid->length > 0) {
        printf("SSID: ");
        for (auto i = 0; i < ssid->length; ++i) {
            printf("%c", ssid->ssid[i]);
        }
        printf("\n");
    }
}

#define RATE(_r) (.5 * ((_r) & 0x7f))

void print_rates(const ieee80211_rates* rates)
{
    if (rates->length > 0) {
        printf("Rates: ");
        for (auto i = 0; i < rates->length; ++i) {
            printf("%2.1fMbit ", RATE(rates->rate[i]));
        }
        printf("\n");
    }
}

void print_power_capability(const ieee80211_power_capability* power_capability)
{
	printf("Minimum power capability: %d\nMaximum power capability: %d\n", power_capability->min_power, power_capability->max_power);
}

void print_ds(const ieee80211_ds_channel* ds)
{
	printf("Channel: %d\n", ds->channel);
}

void print_wpa(const uint8_t* wpa)
{
	// Skip elem ID and length
	wpa += 2;

	// Print and skip WPA tag
	printf("WPA Tag: %02X:%02X:%02X:%02X\n", wpa[0], wpa[1], wpa[2], wpa[3]);	
	wpa += 4;

	// Skip version
	wpa += 2;

	// Print and skip group cipher suite
	printf("Group cipher suite OUI: %02X:%02X:%02X. Suite type: %d\n", wpa[0], wpa[1], wpa[2], wpa[3]);
	wpa += 4;

	/*
	// Print the pairwise cipher suites
	uint16_t suite_count = (static_cast<uint16_t>(wpa[0]) << 8) + wpa[1];
	wpa += 2;

	printf("Printing %d pairwise ciphers\n", suite_count);
	for (; suite_count; --suite_count)
	{
		// Print and skip group cipher suite
		printf("Pairwise cipher suite OUI: %02X:%02X:%02X. Suite type: %d\n", wpa[0], wpa[1], wpa[2], wpa[3]);
		wpa += 4;
	}
	*/
}

void handle_beacon(uint32_t caplen, const ieee80211_mgmt::messages::beacon_msg* beacon)
{
	printf("Beacon\n");
	printf("Capability: %s\n",
		CAPABILITY_ESS(beacon->capab_info) ? "ESS" : "IBSS");
	printf("Capability privacy: %s\n", CAPABILITY_PRIVACY(beacon->capab_info) ? "True" : "False");

	// Move over the beacon message header
	caplen -= 12;
	bool done = false;
	for (auto generic_info = reinterpret_cast<const uint8_t*>(&(beacon->variable)); caplen;)
	{
		switch (generic_info[0])
		{
		case E_SSID:
			print_ssid(reinterpret_cast<const ieee80211_ssid*>(generic_info));
			goto advance;
		case E_DS:
			print_ds(reinterpret_cast<const ieee80211_ds_channel*>(generic_info));
			goto advance;
		case E_WPA:
			print_wpa(generic_info);
			goto advance;
			break;
		case E_POWER_CAPABILITY:
			print_power_capability(reinterpret_cast<const ieee80211_power_capability*>(generic_info));
			goto advance;
			break;
		case E_RATES:
			print_rates(reinterpret_cast<const ieee80211_rates*>(generic_info));
			goto advance;
		default:
			advance:
			// Jump over information element
			// Overflow detection
			if ((caplen - generic_info[1] - 2) > caplen)
			{
				caplen = 0;
			}
			else
			{
				caplen = caplen - generic_info[1] - 2;
			}
			generic_info = generic_info + generic_info[1] + 2;
			break;
		}
	}
	printf("\n");
}

void mgmt_packet_handler(u_char* user, const pcap_pkthdr* header, const u_char* packet)
{
    const ieee80211_radiotap_hdr* radiotap = reinterpret_cast<const ieee80211_radiotap_hdr*>(packet);
    const ieee80211_mgmt* mgmt_header = reinterpret_cast<const ieee80211_mgmt*>(packet + radiotap->it_len);

    //printf("Packet without radiotap\n");
    //dump_raw(packet, 6, 16);

    //printf("Packet without radiotap\n");
    //dump_raw(reinterpret_cast<const uint8_t*>(mgmt_header), 4, 16);

    printf("\nTotal capture size: %d\n", header->caplen);
    printf("Radiotap Version %d\n", radiotap->it_version);
    printf("Radiotap Length: %d\n", radiotap->it_len);
    printf("Present %04X\n", radiotap->it_present);

    auto da = mgmt_header->sa;
    printf("Source Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", da[0], da[1], da[2], da[3], da[4], da[5]);
    
    da = mgmt_header->da;
    printf("Dest Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", da[0], da[1], da[2], da[3], da[4], da[5]);
    
    da = mgmt_header->bssid;
    printf("Access Point Mac: %02x:%02x:%02x:%02x:%02x:%02x\n", da[0], da[1], da[2], da[3], da[4], da[5]);
    //printf("DA: %02x:%02x:%02x:%02x:%02x:%02x\n", da[0], da[1], da[2], da[3], da[4], da[5]);

    printf("Subtype: 0x%X\n", FC_SUBTYPE(mgmt_header->frame_control));
    switch(FC_SUBTYPE(mgmt_header->frame_control))
    {
    case ST_BEACON:
		handle_beacon(header->caplen - radiotap->it_len - 24, &(mgmt_header->u.beacon));
		break;
    default:
        printf("Unidentified subtype: 0X%X\n", FC_SUBTYPE(mgmt_header->frame_control));
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
