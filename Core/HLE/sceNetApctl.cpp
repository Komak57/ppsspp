// TODO: move apctl here

#include "ppsspp_config.h"

#include <cstring>
#include <vector>

#if PPSSPP_PLATFORM(WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "Common/Data/Encoding/Utf8.h"
#if defined(_MSC_VER)
#pragma comment(lib, "iphlpapi.lib")
#endif
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
// getifaddrs first appeared in glibc 2.3. On Android it's officially supported
// since API 24 (same availability logic as getLocalIp in proAdhoc.cpp).
#if !PPSSPP_PLATFORM(SWITCH) && (defined(__APPLE__) || (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 3))) || (defined(__ANDROID_API__) && __ANDROID_API__ >= 24) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__))
#define PPSSPP_HAS_IFADDRS 1
#include <ifaddrs.h>
#include <net/if.h>
#endif
#endif

#include "Common/Log.h"
#include "Core/HLE/proAdhoc.h"   // getLocalIp for the fallback config
#include "Core/HLE/sceNet.h"     // defaultNetConfigName / defaultNetSSID
#include "Core/HLE/sceNetApctl.h"

const char *ApctlStateToString(int apctlState) {
	switch (apctlState) {
	case PSP_NET_APCTL_STATE_DISCONNECTED: return "DISCONNECTED";
	case PSP_NET_APCTL_STATE_SCANNING: return "SCANNING";
	case PSP_NET_APCTL_STATE_JOINING: return "JOINING";
	case PSP_NET_APCTL_STATE_GETTING_IP: return "GETTING_IP";
	case PSP_NET_APCTL_STATE_GOT_IP: return "GOT_IP";
	case PSP_NET_APCTL_STATE_EAP_AUTH: return "EAP_AUTH";
	case PSP_NET_APCTL_STATE_KEY_EXCHANGE: return "KEY_EXCHANGE";
	default: return "N/A";
	}
}

// The generated config list (see NetApctlGenerateConfigs). Session-only state:
// regenerated on every sceNetApctlInit, never persisted.
static std::vector<NetApctlConfig> g_apctlConfigs;

// One config per usable (up, IPv4, non-loopback) host adapter.
static void EnumerateHostAdapters(std::vector<NetApctlConfig> *out) {
#if PPSSPP_PLATFORM(WINDOWS)
	ULONG bufLen = 16 * 1024;
	std::vector<u8> buffer(bufLen);
	PIP_ADAPTER_ADDRESSES addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
	ULONG flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
	ULONG ret = GetAdaptersAddresses(AF_INET, flags, nullptr, addresses, &bufLen);
	if (ret == ERROR_BUFFER_OVERFLOW) {
		buffer.resize(bufLen);
		addresses = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
		ret = GetAdaptersAddresses(AF_INET, flags, nullptr, addresses, &bufLen);
	}
	if (ret != NO_ERROR) {
		WARN_LOG(Log::sceNet, "GetAdaptersAddresses failed: %lu", ret);
		return;
	}

	for (PIP_ADAPTER_ADDRESSES aa = addresses; aa; aa = aa->Next) {
		if (aa->OperStatus != IfOperStatusUp || aa->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
			continue;
		for (PIP_ADAPTER_UNICAST_ADDRESS ua = aa->FirstUnicastAddress; ua; ua = ua->Next) {
			if (!ua->Address.lpSockaddr || ua->Address.lpSockaddr->sa_family != AF_INET)
				continue;
			NetApctlConfig conf;
			conf.adapterId = aa->AdapterName;  // stable GUID string
			conf.cnf_name = aa->FriendlyName ? ConvertWStringToUTF8(aa->FriendlyName) : conf.adapterId;
			conf.rawIp = reinterpret_cast<sockaddr_in *>(ua->Address.lpSockaddr)->sin_addr.s_addr;
			if (ua->OnLinkPrefixLength > 0 && ua->OnLinkPrefixLength <= 32)
				conf.rawNetmask = htonl(0xFFFFFFFFu << (32 - ua->OnLinkPrefixLength));
			if (aa->FirstGatewayAddress && aa->FirstGatewayAddress->Address.lpSockaddr &&
				aa->FirstGatewayAddress->Address.lpSockaddr->sa_family == AF_INET) {
				conf.rawGateway = reinterpret_cast<sockaddr_in *>(aa->FirstGatewayAddress->Address.lpSockaddr)->sin_addr.s_addr;
			}
			if (conf.rawIp != 0)
				out->push_back(std::move(conf));
			break;  // first IPv4 unicast address per adapter is enough
		}
	}
#elif defined(PPSSPP_HAS_IFADDRS)
	struct ifaddrs *ifAddrStruct = nullptr;
	if (getifaddrs(&ifAddrStruct) != 0 || !ifAddrStruct)
		return;

	for (struct ifaddrs *ifa = ifAddrStruct; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
			continue;
		if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK))
			continue;
		NetApctlConfig conf;
		conf.adapterId = ifa->ifa_name ? ifa->ifa_name : "";
		conf.cnf_name = conf.adapterId;
		conf.rawIp = reinterpret_cast<sockaddr_in *>(ifa->ifa_addr)->sin_addr.s_addr;
		if (ifa->ifa_netmask && ifa->ifa_netmask->sa_family == AF_INET)
			conf.rawNetmask = reinterpret_cast<sockaddr_in *>(ifa->ifa_netmask)->sin_addr.s_addr;
		// Gateway isn't available through getifaddrs - fabricated when reported.
		if (conf.rawIp != 0 && !conf.adapterId.empty())
			out->push_back(std::move(conf));
	}
	freeifaddrs(ifAddrStruct);
#else
	// No adapter enumeration on this platform - the fallback config carries us.
#endif
}

void NetApctlGenerateConfigs() {
	std::vector<NetApctlConfig> configs;
	EnumerateHostAdapters(&configs);

	if (configs.empty()) {
		// No usable adapter found (or no enumeration on this platform): a single
		// legacy config so nothing regresses - name/ssid as before, addressing
		// from the old getLocalIp guesswork.
		NetApctlConfig conf;
		conf.cnf_name = std::string(defaultNetConfigName) + "1";
		conf.ssid = defaultNetSSID;
		sockaddr_in localAddr{};
		if (getLocalIp(&localAddr) == 0)
			conf.rawIp = localAddr.sin_addr.s_addr;
		conf.rawNetmask = htonl(0xFFFFFF00u);  // 255.255.255.0
		configs.push_back(std::move(conf));
	}

	for (size_t i = 0; i < configs.size(); i++) {
		NetApctlConfig &conf = configs[i];
		conf.device = (int)i;  // the adapter selector, netparam "device" slot
		if (conf.ssid.empty())
			conf.ssid = conf.cnf_name;
		if (conf.ssid.length() >= APCTL_SSID_MAXLEN)
			conf.ssid.resize(APCTL_SSID_MAXLEN - 1);
		conf.ip_address = ip2str(conf.rawIp);
		conf.netmask = ip2str(conf.rawNetmask);
		u32 gateway = conf.rawGateway;
		if (gateway == 0 && conf.rawIp != 0) {
			// Fabricate the conventional .1 on the local subnet, like the old
			// NetApctl_InitInfo did.
			gateway = conf.rawIp;
			((u8 *)&gateway)[3] = 1;
		}
		conf.default_route = ip2str(gateway);
		// primary_dns/secondary_dns stay empty: resolved from AutoDNS/config at
		// read time, since the infra json may not have arrived yet at Init.

		INFO_LOG(Log::sceNet, "Net config %d: '%s' (adapter '%s', ip %s, mask %s, gw %s)",
			(int)i + 1, conf.cnf_name.c_str(), conf.adapterId.c_str(),
			conf.ip_address.c_str(), conf.netmask.c_str(), conf.default_route.c_str());
	}

	g_apctlConfigs = std::move(configs);
}

int NetApctlConfCount() {
	return (int)g_apctlConfigs.size();
}

const NetApctlConfig *NetApctlGetConf(int confId) {
	if (confId == 0)
		confId = 1;  // "latest"; refined once connect tracks the last-used id
	if (confId < 1 || confId > (int)g_apctlConfigs.size())
		return nullptr;
	return &g_apctlConfigs[confId - 1];
}
