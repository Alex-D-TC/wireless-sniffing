#ifndef IEEE_80211_H
#define IEEE_80211_H

const uint8_t ETH_ALEN = 6;
const uint8_t WLAN_SA_QUERY_TR_ID_LEN = 2;

#define CAPABILITY_ESS(cap)     ((cap) & 0x0001)
#define CAPABILITY_IBSS(cap)    ((cap) & 0x0002)
#define CAPABILITY_CFP(cap)     ((cap) & 0x0004)
#define CAPABILITY_CFP_REQ(cap) ((cap) & 0x0008)
#define CAPABILITY_PRIVACY(cap) ((cap) & 0x0010)

#define ST_ASSOC_REQUEST        0x0
#define ST_ASSOC_RESPONSE       0x1
#define ST_REASSOC_REQUEST      0x2
#define ST_REASSOC_RESPONSE     0x3
#define ST_PROBE_REQUEST        0x4
#define ST_PROBE_RESPONSE       0x5
/* RESERVED                     0x6  */
/* RESERVED                     0x7  */
#define ST_BEACON               0x8
#define ST_ATIM                 0x9
#define ST_DISASSOC             0xA
#define ST_AUTH                 0xB
#define ST_DEAUTH               0xC
/* RESERVED                     0xD  */
/* RESERVED                     0xE  */
/* RESERVED                     0xF  */

#define FC_VERSION(fc)          ((fc) & 0x3)
#define FC_TYPE(fc)             (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)          (((fc) >> 4) & 0xF)
#define FC_TO_DS(fc)            ((fc) & 0x0100)
#define FC_FROM_DS(fc)          ((fc) & 0x0200)
#define FC_MORE_FLAG(fc)        ((fc) & 0x0400)
#define FC_RETRY(fc)            ((fc) & 0x0800)
#define FC_POWER_MGMT(fc)       ((fc) & 0x1000)
#define FC_MORE_DATA(fc)        ((fc) & 0x2000)
#define FC_WEP(fc)              ((fc) & 0x4000)
#define FC_ORDER(fc)            ((fc) & 0x8000)

#define	E_SSID 0
#define	E_RATES 1
#define	E_FH 2
#define	E_DS 3
#define	E_CF 4
#define	E_TIM 5
#define	E_IBSS 6
/* reserved 		7 */
/* reserved 		8 */
/* reserved 		9 */
/* reserved 		10 */
/* reserved 		11 */
/* reserved 		12 */
/* reserved 		13 */
/* reserved 		14 */
/* reserved 		15 */
/* reserved 		16 */

#define	E_CHALLENGE 16
#define E_POWER_CAPABILITY 33
/* reserved 		17 */
/* reserved 		18 */
/* reserved 		19 */
/* reserved 		16 */
/* reserved 		16 */
#define E_WPA 221

/*
 * True if  "l" bytes of "var" were captured.
 *
 * The "snapend - (l) <= snapend" checks to make sure "l" isn't so large
 * that "snapend - (l)" underflows.
 *
 * The check is for <= rather than < because "l" might be 0.
 */
#define TTEST2(var, l) (snapend - (l) <= snapend && \
			(const u_char *)&(var) <= snapend - (l))

#pragma pack(push)
#pragma pack(1)

struct ieee80211_ds_channel {
	uint8_t	element_id;
	uint8_t	length;
	uint8_t	channel;
};

struct ieee80211_radiotap_hdr {
	uint8_t it_version;
	uint8_t it_pad;
	uint16_t it_len;
	uint32_t it_present;
};

struct ieee80211_mgmt {
	uint16_t frame_control;
	uint16_t duration;
	uint8_t da[6];
	uint8_t sa[6];
	uint8_t bssid[6];
	uint16_t seq_ctrl;
	union messages {
		struct auth_msg {
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
		struct beacon_msg {
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

struct ieee80211_power_capability {
	uint8_t element_id;
	uint8_t length;
	uint8_t min_power;
	uint8_t max_power;
};

struct ieee80211_ssid
{
	uint8_t element_id;
	uint8_t length;
	uint8_t ssid[0]; // at most 32 bytes
};

struct ieee80211_rates
{
	uint8_t element_id;
	uint8_t length;
	uint8_t rate[16];
};

#pragma pack(pop)

#endif
