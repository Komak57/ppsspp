#include "Core/Util/NPAgent.h"
#include <Core\HLE\HLE.h>
#include <Net\URL.h>
#include "Common/Net/HTTPClient.h"
namespace net {
	// FIXME: Populate with actual connection credentials for PSN
	PSNAuthAgent::PSNAuthAgent(std::string host, int port) {
		this->host_ = host;
		this->port_ = port;

		//std::string certificate = "";
		//InitializeSSL(certificate);
	}
	PSNAuthAgent::~PSNAuthAgent() {
		Disconnect();
	}

	bool PSNAuthAgent::Login(const char* titleId, const char* token, const char* password) {
		return false;
	}

	int PSNAuthAgent::GetServers(SceNpCommunicationId npTitleId, std::map<u16, std::unique_ptr<net::NPAgent>>* serversPtr) {
		Url url("http://static-resource.np.community.playstation.net/np/resource/psp-title/" + std::string(npTitleId.data) + "_00/matching/" + std::string(npTitleId.data) + "_00-matching.xml");
		http::Client client;
		bool cancelled = false;
		net::RequestProgress progress(&cancelled);
		if (!client.Resolve(url.Host().c_str(), url.Port())) {
			return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "HTTP failed to resolve %s", url.Resource().c_str());
		}

		client.SetDataTimeout(20.0);
		if (client.Connect()) {
			char requestHeaders[4096];
			snprintf(requestHeaders, sizeof(requestHeaders),
				"User-Agent: PS3Community-agent/1.0.0 libhttp/1.0.0\r\n");

			DEBUG_LOG(Log::sceNet, "GET URI: %s", url.ToString().c_str());
			http::RequestParams req(url.Resource(), "*/*");
			int err = client.SendRequest("GET", req, requestHeaders, &progress);
			if (err < 0) {
				client.Disconnect();
				return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_FORBIDDEN, "HTTP GET Error = %d", err);
			}

			net::Buffer readbuf;
			std::vector<std::string> responseHeaders;
			int code = client.ReadResponse(&readbuf, &progress);
			if (code != 200) {
				client.Disconnect();
				return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_INTERNAL_SERVER_ERROR, "HTTP Error Code = %d", code);
			}
			client.Disconnect();

			std::string entity;
			size_t readBytes = readbuf.size();
			readbuf.Take(readBytes, &entity);

			INFO_LOG(Log::sceNet, "Entity Data: %d", entity);

			// TODO: Use XML Parser to get the Tag and it's attributes instead of searching for keywords on the string
			std::string text;
			size_t ofs = entity.find("titleid=");
			if (ofs == std::string::npos)
				return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "titleid not found");

			ofs += 9;
			size_t ofs2 = entity.find('"', ofs);
			text = entity.substr(ofs, ofs2 - ofs);
			INFO_LOG(Log::sceNet, "%s - Title ID: %s", __FUNCTION__, text.c_str());

			int i = 1;
			while (true) {
				ofs = entity.find("<agent-fqdn", ++ofs2);
				if (ofs == std::string::npos) {
					if (i == 1)
						return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "agent-fqdn not found");
					else
						break;
				}

				size_t frontPos = ++ofs;
				ofs = entity.find("id=", frontPos);
				if (ofs == std::string::npos)
					return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "agent id not found");

				ofs += 4;
				ofs2 = entity.find('"', ofs);
				text = entity.substr(ofs, ofs2 - ofs);
				int server_id = std::stoi(text.c_str());
				INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d ID: %s", __FUNCTION__, i, text.c_str());

				ofs = entity.find("port=", frontPos);
				if (ofs == std::string::npos)
					return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "agent port not found");

				ofs += 6;
				ofs2 = entity.find('"', ofs);
				text = entity.substr(ofs, ofs2 - ofs);
				int server_port = std::stoi(text.c_str());
				INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d Port: %s", __FUNCTION__, i, text.c_str());

				ofs = entity.find("status=", frontPos);
				if (ofs == std::string::npos)
					return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "agent status not found");

				ofs += 8;
				ofs2 = entity.find('"', ofs);
				text = entity.substr(ofs, ofs2 - ofs);
				std::string alive = { 'a','l','i','v','e' };
				int server_status = SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE;
				if (text == alive)
					server_status = SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE;
				INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d Status: %s", __FUNCTION__, i, text.c_str());

				ofs = entity.find('>', ++ofs2);
				if (ofs == std::string::npos)
					return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "agent host not found");

				ofs2 = entity.find("</agent-fqdn", ++ofs);
				text = entity.substr(ofs, ofs2 - ofs);
				std::string server_host = text;
				INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d Host: %s", __FUNCTION__, i, text.c_str());

				serversPtr->emplace(server_id, net::CreateNPAgent(net::NPAgentType::PSN, server_id, server_host, server_port, server_status));
				i++;
			}
		}
		return 0;
	}
}
