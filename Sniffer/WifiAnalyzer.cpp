#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <cstdint>
//#include <linux/ieee80211.h>

#pragma pack(push)
#pragma pack(1)
struct ieee80211_hdr {
	uint16_t frame_control;
	uint16_t duration_id;
	uint8_t addr1[6];
	uint8_t addr2[6];
	uint8_t addr3[6];
	uint16_t seq_ctrl;
	uint8_t addr4[6];
};
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
struct ieee80211_radiotap_hdr {
	uint8_t it_version;
	uint8_t it_pad;
	uint16_t it_len;
	uint32_t it_present;
};
#pragma pack(pop)

void dump_raw(const uint8_t *data, size_t bytes)
{
	for(size_t i = 0; i < bytes && i + 1 < bytes; i+=2)
	{
		printf("0x%02X%02X ", data[i], data[i+1]);
	}
	printf("\n");
}

void packet_handler(u_char* user, const pcap_pkthdr* header, const u_char* packet)
{
	struct  ieee80211_radiotap_hdr* radiotap;
	struct  ieee80211_hdr* mac_header_80211;

	/*
	 * Radiotap header
	 */
	radiotap = (struct ieee80211_radiotap_hdr*) (packet);

	dump_raw(packet, 16);

	printf("%d\n", radiotap->it_version);
	printf("%04X\n", radiotap->it_present);

	/*
	 * 802.11 management frame: http://lxr.free-electrons.com/source/include/linux/ieee80211.h
	 */
	 /*
	 struct ieee80211_mgmt* mgmt_frame = (struct ieee80211_mgmt*) (packet + radiotap->it_len);
	*/

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

	err = pcap_loop(pcap_h, 20, packet_handler, nullptr);
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
