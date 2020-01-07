#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <cstdint>
//#include <linux/ieee80211.h>

#define ETH_ALEN 6
#define WLAN_SA_QUERY_TR_ID_LEN 2

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

struct ieee80211_mgmt {
         uint16_t frame_control;
         uint16_t duration;
         uint8_t da[6];
         uint8_t sa[6];
         uint8_t bssid[6];
         uint16_t seq_ctrl;
         union {
                 struct {
                         uint16_t auth_alg;
                         uint16_t auth_transaction;
                         uint16_t status_code;
                         /* possibly followed by Challenge text */
                         uint8_t variable[0];
                 } auth;
                 struct {
                         uint16_t reason_code;
                 } deauth;
                 struct {
                         uint16_t capab_info;
                         uint16_t listen_interval;
                         /* followed by SSID and Supported rates */
                         uint8_t variable[0];
                 } assoc_req;
                 struct {
                         uint16_t capab_info;
                         uint16_t status_code;
                         uint16_t aid;
                         /* followed by Supported rates */
                         uint8_t variable[0];
                 } assoc_resp, reassoc_resp;
                 struct {
                         uint16_t capab_info;
                         uint16_t listen_interval;
                         uint8_t current_ap[6];
                         /* followed by SSID and Supported rates */
                         uint8_t variable[0];
                 } reassoc_req;
                 struct {
                         uint16_t reason_code;
                 } disassoc;
                 struct {
                         uint8_t timestamp[8];
                         uint16_t beacon_int;
                         uint16_t capab_info;
                         /* followed by some of SSID, Supported rates,
                          * FH Params, DS Params, CF Params, IBSS Params, TIM */
                         uint8_t variable[0];
                 } beacon;
                 struct {
                         /* only variable items: SSID, Supported rates */
                         uint8_t variable[0];
                 } probe_req;
                 struct {
                         uint8_t timestamp[8];
                         uint16_t beacon_int;
                         uint16_t capab_info;
                         /* followed by some of SSID, Supported rates,
                          * FH Params, DS Params, CF Params, IBSS Params */
                         uint8_t variable[0];
                 } probe_resp;
                 struct {
                         uint8_t category;
                         union {
                                 struct {
                                         uint8_t action_code;
                                         uint8_t dialog_token;
                                         uint8_t status_code;
                                         uint8_t variable[0];
                                 } wmm_action;
                                 struct{
                                         uint8_t action_code;
                                         uint8_t element_id;
                                         uint8_t length;
                                         uint8_t switch_mode;
                                         uint8_t new_chan;
                                         uint8_t switch_count;
                                 } chan_switch;
                                 struct {
                                         uint8_t action;
                                         uint8_t sta_addr[ETH_ALEN];
                                         uint8_t target_ap_addr[ETH_ALEN];
                                         uint8_t variable[0]; /* FT Request */
                                 } ft_action_req;
                                 struct {
                                         uint8_t action;
                                         uint8_t sta_addr[ETH_ALEN];
                                         uint8_t target_ap_addr[ETH_ALEN];
                                         uint16_t status_code;
                                         uint8_t variable[0]; /* FT Request */
                                 } ft_action_resp;
                                 struct {
                                         uint8_t action;
                                         uint8_t trans_id[WLAN_SA_QUERY_TR_ID_LEN];
                                 } sa_query_req;
                                 struct {
                                         uint8_t action; /* */
                                         uint8_t trans_id[WLAN_SA_QUERY_TR_ID_LEN];
                                 } sa_query_resp;
                         } u;
                 } action;
         } u;
};

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

uint16_t get_bit(uint16_t data, uint16_t idx)
{
	return (data >> (15-idx)) & 0x7FFF;
}

void packet_handler(u_char* user, const pcap_pkthdr* header, const u_char* packet)
{
	struct  ieee80211_radiotap_hdr* radiotap;
	struct  ieee80211_hdr* mac_header;
	struct  ieee80211_mgmt* mgmt_header;

	/*
	 * Radiotap header
	 */
	radiotap = (struct ieee80211_radiotap_hdr*) (packet);
	mgmt_header = (struct ieee80211_mgmt*) (packet + radiotap->it_len);
	dump_raw(packet, 16);

	printf("Vesrion %d\n", radiotap->it_version);
	printf("Present %04X\n", radiotap->it_present);

	//mac = mac_header->addr1;
	//printf("Src Mac %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	auto da = mgmt_header->da;
	printf("MAC %02x:%02x:%02x:%02x:%02x:%02x\n", da[0], da[1], da[2], da[3], da[4], da[5]);

	if (mgmt_header->frame_control) {
		printf("SSID: %s\n", mgmt_frame->u.beacon.variable);
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

	err = pcap_loop(pcap_h, 0, packet_handler, nullptr);
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
