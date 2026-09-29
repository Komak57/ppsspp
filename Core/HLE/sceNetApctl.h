#pragma once

#include <string>

#include "Common/CommonTypes.h"

// TODO: move sceNetApctl here

// A generated PSP net config ("connection"). On OFW these were authored in the
// VSH network settings and stored in the registry.
//
// Field groups relative to the OFW schema:
//   KEEP        - stored on OFW, still real here.
//   AUTHENTIC   - stored on OFW; synthesized constants here (no radio involved),
//                 kept so games reading them see a plausible record.
//   SYNTHESIZE  - captured from the live adapter at generation time.
//   RESERVE     - games can read these; kept empty/off for future use.
// Dropped outright: wep/wpa/802.1X/wifisvc/bt/at/phone (host-owned or dead tech).
struct NetApctlConfig {
	// KEEP
	std::string cnf_name;
	int device = 0;             // OFW: 0=wlan, 2=Bluetooth DUN; We're using the adapter index
	int dns_flag = 1;           // manual DNS (we always report our DNS explicitly)
	std::string primary_dns;    // empty = resolve from AutoDNS/config at read time
	std::string secondary_dns;
	// AUTHENTIC
	std::string ssid;           // mirrors the adapter name
	int auth_proto = 0;         // 0 = open; no security checks are performed
	int version = 2;            // WPA-era record revision
	// SYNTHESIZE
	int how_to_set_ip = 0;      // 0 = DHCP (the host's lease is our "lease")
	std::string ip_address;
	std::string netmask;
	std::string default_route;
	// RESERVE
	int http_proxy_flag = 0;
	std::string http_proxy_server;
	int http_proxy_port = 0;
	// Host linkage (not a netparam - never surfaced to the game directly)
	std::string adapterId;      // OS interface identifier
	u32 rawIp = 0;              // network byte order
	u32 rawNetmask = 0;
	u32 rawGateway = 0;         // 0 = unknown (fabricate .1 when reporting)
};

enum {
	PSP_NET_APCTL_STATE_DISCONNECTED = 0,
	PSP_NET_APCTL_STATE_SCANNING = 1,
	PSP_NET_APCTL_STATE_JOINING = 2,
	PSP_NET_APCTL_STATE_GETTING_IP = 3,
	PSP_NET_APCTL_STATE_GOT_IP = 4,
	PSP_NET_APCTL_STATE_EAP_AUTH = 5,
	PSP_NET_APCTL_STATE_KEY_EXCHANGE = 6
};

enum {
	PSP_NET_APCTL_EVENT_CONNECT_REQUEST = 0,
	PSP_NET_APCTL_EVENT_SCAN_REQUEST = 1,
	PSP_NET_APCTL_EVENT_SCAN_COMPLETE = 2,
	PSP_NET_APCTL_EVENT_ESTABLISHED = 3,
	PSP_NET_APCTL_EVENT_GET_IP = 4,
	PSP_NET_APCTL_EVENT_DISCONNECT_REQUEST = 5,
	PSP_NET_APCTL_EVENT_ERROR = 6,
	PSP_NET_APCTL_EVENT_INFO = 7,
	PSP_NET_APCTL_EVENT_EAP_AUTH = 8,
	PSP_NET_APCTL_EVENT_KEY_EXCHANGE = 9,
	PSP_NET_APCTL_EVENT_RECONNECT = 10,
	PSP_NET_APCTL_EVENT_SCAN_STOP = 11 // FIXME: not sure what this is, MGS:PW seems to check this value within ApctlHandler during Recruit, related to sceNetApctlScanSSID2 ?
};

const char *ApctlStateToString(int apctlState);

#define 	PSP_NET_APCTL_INFO_PROFILE_NAME			0
#define 	PSP_NET_APCTL_INFO_BSSID				1
#define 	PSP_NET_APCTL_INFO_SSID					2
#define 	PSP_NET_APCTL_INFO_SSID_LENGTH			3
#define 	PSP_NET_APCTL_INFO_SECURITY_TYPE		4
#define 	PSP_NET_APCTL_INFO_STRENGTH				5
#define 	PSP_NET_APCTL_INFO_CHANNEL				6
#define 	PSP_NET_APCTL_INFO_POWER_SAVE			7
#define 	PSP_NET_APCTL_INFO_IP					8
#define 	PSP_NET_APCTL_INFO_SUBNETMASK			9
#define 	PSP_NET_APCTL_INFO_GATEWAY				10
#define 	PSP_NET_APCTL_INFO_PRIMDNS				11
#define 	PSP_NET_APCTL_INFO_SECDNS				12
#define 	PSP_NET_APCTL_INFO_USE_PROXY			13
#define 	PSP_NET_APCTL_INFO_PROXY_URL			14
#define 	PSP_NET_APCTL_INFO_PROXY_PORT			15
#define 	PSP_NET_APCTL_INFO_8021_EAP_TYPE		16
#define 	PSP_NET_APCTL_INFO_START_BROWSER		17
#define 	PSP_NET_APCTL_INFO_WIFISP				18

#define 	PSP_NET_APCTL_INFO_SECURITY_TYPE_NONE           0
#define 	PSP_NET_APCTL_INFO_SECURITY_TYPE_WEP            1
#define 	PSP_NET_APCTL_INFO_SECURITY_TYPE_WPA            2
#define 	PSP_NET_APCTL_INFO_SECURITY_TYPE_UNSUPPORTED    3
#define 	PSP_NET_APCTL_INFO_SECURITY_TYPE_WPA_AES        4

#define 	PSP_NET_APCTL_DESC_IBSS                 0
#define 	PSP_NET_APCTL_DESC_SSID_NAME            1
#define 	PSP_NET_APCTL_DESC_SSID_NAME_LENGTH     2
#define 	PSP_NET_APCTL_DESC_CHANNEL              3 // FIXME: not sure what this 3 is, may be Security Type based on the order of SceNetApctlInfoInternal ?
#define 	PSP_NET_APCTL_DESC_SIGNAL_STRENGTH      4
#define 	PSP_NET_APCTL_DESC_SECURITY             5
