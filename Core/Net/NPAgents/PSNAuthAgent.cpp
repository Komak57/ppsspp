#include "Core/Net/NPAgent.h"
#include <Core/HLE/HLE.h>
#include <Common/Net/URL.h>
#include "Common/Net/HTTPClient.h"
#include <Common/File/FileDescriptor.h>
#include <TimeUtil.h>
#include <Core/Net/Buffer.cpp>
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

	int PSNAuthAgent::Login(const char* titleId, const char* token, const char* password) {
		return false;
	}
	int PSNAuthAgent::CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email) {
		return false;
	}

	void PSNAuthAgent::Disconnect() {
		NOTICE_LOG(Log::sceNet, "NPAuthAgent::Disconnect()");
		cancelled = true;
		if (connected) {
			if (tls.enabled) {
				// First shut down network I/O so ssl_read unblocks
				ResetSSL();
			}
			else {
				if ((intptr_t)sock_ != -1) {
					closesocket(sock_);
					sock_ = -1;
				}
			}
		}
		connected = false;
	}


	bool PSNAuthAgent::Connect(int maxTries, double timeout, bool* cancelConnect) {
		WARN_LOG(Log::sceNet, "UNTESTED RPCNAuthAgent::Connect(%i, %f, %p)", maxTries, timeout, cancelConnect);

		std::string certPem = "-----BEGIN CERTIFICATE-----\n"
			"\n"
			"-----END CERTIFICATE-----\n";
		//InitializeSSL(certPem);
		InitializeSSL();

		if (port_ <= 0) {
			ERROR_LOG(Log::IO, "Connect - Bad port");
			return false;
		}
		if (connected) {
			return true;
		}

		for (int tries = maxTries; tries > 0; --tries) {
			for (addrinfo* possible = resolved_; possible != nullptr; possible = possible->ai_next) {
				if (possible->ai_family != AF_INET && possible->ai_family != AF_INET6)
					continue;

				int sockfd = socket(possible->ai_family, possible->ai_socktype, possible->ai_protocol);
				if (sockfd < 0) {
					ERROR_LOG(Log::sceNet, "Connect - socket() failed");
					continue;
				}

				char ip_address[128]{};
				inet_ntop(possible->ai_family, &((sockaddr_in*)possible->ai_addr)->sin_addr, ip_address, sizeof(ip_address));

				sockaddr* addr = possible->ai_addr;
				socklen_t addrlen = possible->ai_addrlen;
				if (connect(sockfd, addr, addrlen) < 0) {
					ERROR_LOG(Log::sceNet, "Connect - connect() failed");
					close(sockfd);
					continue;
				}

				fd_util::SetNonBlocking(sockfd, true);

				// Create SSL object
				tls.sslCtx = wolfSSL_new(tls.sslConfig);
				if (!tls.sslCtx) {
					ERROR_LOG(Log::sceNet, "Connect - wolfSSL_new() failed");
					close(sockfd);
					continue;
				}

				tls.sockfd = sockfd;
				wolfSSL_set_fd(tls.sslCtx, sockfd);

				// SNI / hostname
				if (wolfSSL_check_domain_name(tls.sslCtx, host_.c_str()) != SSL_SUCCESS) {
					WARN_LOG(Log::sceNet, "Connect - could not set SNI/hostname");
				}

				// TLS Handshake
				NOTICE_LOG(Log::sceNet, "Connect - Performing the SSL/TLS handshake...");
				int ret;
				while ((ret = wolfSSL_connect(tls.sslCtx)) != SSL_SUCCESS) {
					int err = wolfSSL_get_error(tls.sslCtx, ret);
					if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
						ERROR_LOG(Log::sceNet, "Connect - wolfSSL_connect failed: %d", err);
						wolfSSL_free(tls.sslCtx);
						tls.sslCtx = nullptr;
						close(sockfd);
						goto sslretry;
					}
				}

				// Verify certificate
				if (GetOption(28)) {
					const WOLFSSL_X509* cert = wolfSSL_get_peer_certificate(tls.sslCtx);
					if (cert != nullptr) {
						INFO_LOG(Log::sceNet, "Connect - Peer certificate received");
					}
					else {
						WARN_LOG(Log::sceNet, "Connect - No peer certificate received");
					}
				}

				// Save session
				tls.session = wolfSSL_get_session(tls.sslCtx);

				INFO_LOG(Log::sceNet, "Connect - Connection Successful");
				connected = true;
				return true;

			sslretry:
				INFO_LOG(Log::sceNet, "Connect - Connection Failed, retrying");
				if (tls.sslCtx) {
					wolfSSL_free(tls.sslCtx);
					tls.sslCtx = nullptr;
				}
				if (sockfd >= 0) close(sockfd);
				continue;
			}
			sleep_ms(1, "connect");
		}

		return false;
	}

	/*
		22:37:312 user_main    I[SCENET]: Util\PSNAuthAgent.cpp:185 net::PSNAuthAgent::GetServers - Title ID: NPWR01446_00
		22:37:312 user_main    I[SCENET]: Util\PSNAuthAgent.cpp:206 net::PSNAuthAgent::GetServers - Agent-FQDN#1 ID: 1
		22:37:312 user_main    I[SCENET]: Util\PSNAuthAgent.cpp:216 net::PSNAuthAgent::GetServers - Agent-FQDN#1 Port: 3478
		22:37:312 user_main    I[SCENET]: Util\PSNAuthAgent.cpp:229 net::PSNAuthAgent::GetServers - Agent-FQDN#1 Status: alive
		22:37:312 user_main    I[SCENET]: Util\PSNAuthAgent.cpp:238 net::PSNAuthAgent::GetServers - Agent-FQDN#1 Host: agent-20901.ww.np.matching.playstation.net
		22:37:312 user_main    I[SCENET]: Util\PSNAuthAgent.cpp:206 net::PSNAuthAgent::GetServers - Agent-FQDN#2 ID: 2
		22:37:313 user_main    I[SCENET]: Util\PSNAuthAgent.cpp:216 net::PSNAuthAgent::GetServers - Agent-FQDN#2 Port: 3478
		22:37:313 user_main    I[SCENET]: Util\PSNAuthAgent.cpp:229 net::PSNAuthAgent::GetServers - Agent-FQDN#2 Status: alive
		22:37:313 user_main    I[SCENET]: Util\PSNAuthAgent.cpp:238 net::PSNAuthAgent::GetServers - Agent-FQDN#2 Host: agent-20901.ww.np.matching.playstation.net
	*/
	int PSNAuthAgent::GetServers(SceNpCommunicationId npTitleId, std::map<u16, std::unique_ptr<net::NPAgent>>* serversPtr) {
        /*
        Url url("http://static-resource.np.community.playstation.net/np/resource/psp-title/" + std::string(npTitleId.data) + "_00/matching/" + std::string(npTitleId.data) + "_00-matching.xml");
        http::Client client(&ProcessHostnameWithInfraDNS);
        bool cancelled = false;
        net::RequestProgress progress(&cancelled);
        if (!client.Resolve(url.Host().c_str(), url.Port())) {
            return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "HTTP failed to resolve %s", url.Resource().c_str());
        }
        */
		Url url("http://static-resource.np.community.playstation.net/np/resource/psp-title/" + std::string(npTitleId.data) + "_00/matching/" + std::string(npTitleId.data) + "_00-matching.xml");
		http::Client client(nullptr);
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

			core::Buffer readbuf;
			std::vector<std::string> responseHeaders;
			int code = readbuf.ReadHTML(client.sock(), nullptr);
			//int code = client.ReadResponse(&readbuf, &progress);
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
