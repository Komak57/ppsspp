#include <mutex>
#include <string>

#include "Common/Data/Format/JSONReader.h"
#include "Common/File/FileUtil.h"
#include "Common/File/VFS/VFS.h"
#include "Common/Log.h"
#include "Common/Net/HTTPRequest.h"
#include "Common/StringUtils.h"
#include "Common/System/System.h"
#include "Core/Config.h"
#include "Core/Net/InfraServerList.h"
#include "Core/System.h"

// Mirrors the adhoc server list machinery in sceNetAdhoc.cpp.

static std::mutex g_infraServerListMutex;
static std::vector<InfraServerListEntry> g_infraServerList;
static bool g_infraServerListLoaded = false;

static bool ParseInfraServerListJSON(std::string_view jsonStr) {
	using namespace json;

	json::JsonReader reader(jsonStr.data(), jsonStr.length());
	if (!reader.ok() || !reader.root()) {
		ERROR_LOG(Log::sceNet, "Error parsing infra server list JSON");
		return false;
	}

	const JsonGet root = reader.root();
	const JsonNode *servers = root.getArray("servers");
	if (!servers) {
		ERROR_LOG(Log::sceNet, "Infra server list JSON has no 'servers' array");
		return false;
	}

	std::vector<InfraServerListEntry> newList;
	for (const JsonNode *iter : servers->value) {
		JsonGet server = iter->value;
		InfraServerListEntry entry;
		entry.hidden = server.getBoolOr("hidden", false);
		entry.name = server.getStringOr("name", "");
		entry.host = server.getStringOr("host", "");
		entry.web = server.getStringOr("web", "");
		entry.discord = server.getStringOr("discord", "");
		entry.location = server.getStringOr("location", "");
		if (entry.location == "Unknown") {
			entry.location.clear();
		}
		entry.description = server.getStringOr("description", "");
		entry.rpcnVersion = server.getInt("rpcn_version", 0);

		if (entry.host.empty()) {
			// Skipping invalid entry.
			continue;
		}
		newList.push_back(entry);
	}

	{
		std::lock_guard<std::mutex> guard(g_infraServerListMutex);
		g_infraServerList = newList;
	}
	System_PostUIMessage(UIMessage::INFRA_SERVER_LIST_CHANGED);
	return true;
}

// Last-resort built-in list, used when neither the memstick copy nor the
// bundled asset is usable (e.g. running from a build dir with stale assets).
static const char *g_builtinInfraServerListJson = R"json({
	"servers": [
		{
			"name": "Revurb RPCN",
			"host": "rpcn.revurb.us",
			"description": "Self-hosted RPCN server for PSP infrastructure play.",
			"rpcn_version": 27
		},
		{
			"name": "Official RPCN (RPCS3)",
			"host": "np.rpcs3.net",
			"web": "https://rpcn.net/",
			"description": "The official RPCN server operated by the RPCS3 team. Runs the current RPCN protocol, which may be newer than this build supports.",
			"rpcn_version": 33
		}
	]
})json";

// The user-editable copy lives on the memstick, next to compat.ini etc.
static Path InfraServerListFilePath() {
	return GetSysDirectory(DIRECTORY_SYSTEM) / "infra-servers.json";
}

static void LoadFallbackInfraServerList() {
	// Priority: memstick PSP/SYSTEM/infra-servers.json (user-editable),
	// then the bundled asset (seeding the memstick copy for easy editing),
	// then a built-in list. Don't bother doing any of it on a thread.
	const Path userPath = InfraServerListFilePath();

	std::string jsonStr;
	if (File::ReadTextFileToString(userPath, &jsonStr)) {
		if (ParseInfraServerListJSON(std::string_view(jsonStr.data(), jsonStr.size()))) {
			g_infraServerListLoaded = true;
			return;
		}
		WARN_LOG(Log::sceNet, "Bad JSON in %s, falling back to the bundled list.", userPath.ToVisualString().c_str());
	}

	size_t jsonSize = 0;
	std::unique_ptr<uint8_t[]> asset(g_VFS.ReadFile("infra-servers.json", &jsonSize));
	std::string_view json;
	if (asset) {
		json = std::string_view((char *)asset.get(), jsonSize);
	} else {
		WARN_LOG(Log::sceNet, "infra-servers.json asset missing, using the built-in server list.");
		json = g_builtinInfraServerListJson;
	}

	if (ParseInfraServerListJSON(json) && !File::Exists(userPath)) {
		// Seed the editable memstick copy from whatever we successfully loaded.
		File::WriteDataToFile(true, json.data(), json.size(), userPath);
	}
	g_infraServerListLoaded = true;
}

void InfraLoadServerList(InfraLoadListMode loadMode) {
	if (loadMode == InfraLoadListMode::CacheOnlySync) {
		std::lock_guard<std::mutex> guard(g_infraServerListMutex);
		if (!g_infraServerList.empty()) {
			return;
		}
	}

	// NOTE: A non-http sInfraServerListUrl is treated as a local file path.

	if (startsWith(g_Config.sInfraServerListUrl, "http")) {
		if (loadMode == InfraLoadListMode::CacheOnlySync) {
			std::string jsonStr;
			if (g_DownloadManager.ReadFileFromCache(g_Config.sInfraServerListUrl, &jsonStr)) {
				if (ParseInfraServerListJSON(std::string_view(jsonStr.data(), jsonStr.size()))) {
					g_infraServerListLoaded = true;
					return;
				}
			}
			INFO_LOG(Log::sceNet, "Failed to load cached infra server list %s from cache, falling back.", g_Config.sInfraServerListUrl.c_str());
			LoadFallbackInfraServerList();
			return;
		}

		// Download the list.
		g_DownloadManager.StartDownload(g_Config.sInfraServerListUrl, Path(), http::RequestFlags::Cached24H, nullptr, "infra-servers", [url = g_Config.sInfraServerListUrl](http::Request &request) {
			if (request.Failed()) {
				ERROR_LOG(Log::sceNet, "Failed to download infra server list from %s, falling back.", url.c_str());
				LoadFallbackInfraServerList();
				return;
			}

			INFO_LOG(Log::sceNet, "Successfully downloaded infra server list from %s", url.c_str());

			std::string jsonStr;
			request.buffer().TakeAll(&jsonStr);
			if (!ParseInfraServerListJSON(std::string_view(jsonStr.data(), jsonStr.size()))) {
				LoadFallbackInfraServerList();
				return;
			}
		});
		g_infraServerListLoaded = true;
	} else if (!g_Config.sInfraServerListUrl.empty()) {
		// Try to read local file.
		std::string jsonStr;
		Path path(g_Config.sInfraServerListUrl);
		if (!File::ReadTextFileToString(path, &jsonStr)) {
			ERROR_LOG(Log::sceNet, "Failed to load infra list from %s, falling back.", path.ToVisualString().c_str());
			LoadFallbackInfraServerList();
			return;
		}
		if (!ParseInfraServerListJSON(std::string_view(jsonStr.data(), jsonStr.size()))) {
			LoadFallbackInfraServerList();
		}
	} else {
		LoadFallbackInfraServerList();
	}
}

std::vector<InfraServerListEntry> InfraGetServerList(InfraLoadListMode loadMode) {
	if (!g_infraServerListLoaded) {
		InfraLoadServerList(loadMode);
	}

	std::lock_guard<std::mutex> guard(g_infraServerListMutex);
	return g_infraServerList;
}

bool InfraGetServerByHost(std::string_view host, InfraServerListEntry *dest) {
	std::vector<InfraServerListEntry> entries = InfraGetServerList(InfraLoadListMode::CacheOnlySync);
	for (auto &entry : entries) {
		if (equals(host, entry.host)) {
			*dest = entry;
			return true;
		}
	}
	return false;
}
