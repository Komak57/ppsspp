#pragma once

#include <string>
#include <string_view>
#include <vector>

// Infra (RPCN/PSN) server list, modeled after the adhoc server list in
// sceNetAdhoc.h. Loaded from g_Config.sInfraServerListUrl when set (cached
// 24h), falling back to the bundled assets/infra-servers.json.

struct InfraServerListEntry {
	std::string name;
	std::string host;
	std::string web;
	std::string discord;
	std::string location;
	std::string description;
	// RPCN wire protocol version the server speaks (0 = unknown/unspecified).
	// Community servers may pin older protocols than the official one.
	int rpcnVersion = 0;
	bool hidden = false;
};

enum class InfraLoadListMode {
	CacheOnlySync,
	AllSourcesAsync,
};

void InfraLoadServerList(InfraLoadListMode loadMode);
std::vector<InfraServerListEntry> InfraGetServerList(InfraLoadListMode loadMode);
bool InfraGetServerByHost(std::string_view host, InfraServerListEntry *dest);  // CacheOnlySync is enforced.
