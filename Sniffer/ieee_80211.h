#ifndef IEEE_80211_H
#define IEEE_80211_H

const uint8_t ETH_ALEN = 6;
const uint8_t WLAN_SA_QUERY_TR_ID_LEN = 2;

enum ieee80211_mgmt_subtype
{
	ASSOCIATION_REQUEST = 0b0000,
	ASSOCIATION_RESPONSE = 0b1000,
	REASSOCIATION_REQUEST = 0b0100,
	REASSOCIATION_RESPONSE = 0b1100,
	PROBE_REQUEST = 0b0010,
	PROBE_RESPONSE = 0b1010,
	TIMING_ADVERTISEMENT = 0b0110,
	RESERVED = 0b1110,
	BEACON = 0b0001,
	ATIM = 0b1001,
	DISASSOCIATION = 0b0101,
	AUTHENTIFICATION = 0b1101,
	DEAUTHENTICATION = 0b0011,
	ACTION = 0b1011,
	ACTION_NO_ACK = 0b0111,
	RESERVED_2 = 0b1111,
};

#pragma pack(push)
#pragma pack(1)

struct ieee80211_radiotap_hdr {
	uint8_t it_version;
	uint8_t it_pad;
	uint16_t it_len;
	uint32_t it_present;
};

struct ieee80211_mgmt_frame_control
{
	uint8_t protocol_version : 2;
	uint8_t type : 2;
	uint8_t subtype : 4;
	uint8_t toDS : 1;
	uint8_t fromDS : 1;
	uint8_t more_fragments : 1;
	uint8_t retry : 1;
	uint8_t power_mgmt : 1;
	uint8_t more_data : 1;
	uint8_t protected_frame : 1;
	uint8_t htc_order : 1;
};

struct ieee80211_mgmt {
	ieee80211_mgmt_frame_control frame_control;
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
				struct {
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

struct ieee80211_ssid
{
	uint8_t element_id;
	uint8_t length;
	uint8_t ssid[0]; // at most 32 bytes
};

#pragma pack(pop)

#endif
