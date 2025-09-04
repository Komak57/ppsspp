#include <TimeUtil.h>
#include <SysError.h>

#include "Core/Util/NPAgent.h"
#include <Core/HLE/HLE.h>
#include <File/FileDescriptor.h>
#include "Common/Net/HTTPClient.h"
#include <Common/Net/URL.h>
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
	bool PSNAuthAgent::CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email) {
		return false;
	}


	bool PSNAuthAgent::Connect(int maxTries, double timeout, bool* cancelConnect) {
		WARN_LOG(Log::sceNet, "UNTESTED PSNAgent::Connect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);

		if (port_ <= 0) {
			ERROR_LOG(Log::IO, "Bad port");
			return false;
		}
		sock_ = -1;

		for (int tries = maxTries; tries > 0; --tries) {
			std::vector<uintptr_t> sockets;
			fd_set fds;
			int maxfd = 1;
			FD_ZERO(&fds);
			for (addrinfo* possible = resolved_; possible != nullptr; possible = possible->ai_next) {
				if (possible->ai_family != AF_INET && possible->ai_family != AF_INET6)
					continue;

				int sock = socket(possible->ai_family, SOCK_STREAM, IPPROTO_TCP);
				if ((intptr_t)sock == -1) {
					ERROR_LOG(Log::IO, "Bad socket");
					continue;
				}
				// Windows sockets aren't limited by socket number, just by count, so checking FD_SETSIZE there is wrong.
#if !PPSSPP_PLATFORM(WINDOWS)
				if (sock >= FD_SETSIZE) {
					ERROR_LOG(Log::IO, "Socket doesn't fit in FD_SET: %d   We probably have a leak.", sock);
					closesocket(sock);
					continue;
				}
#endif
				fd_util::SetNonBlocking(sock, true);

				// Start trying to connect (async with timeout.)
				errno = 0;
				if (connect(sock, possible->ai_addr, (int)possible->ai_addrlen) < 0) {
					int errorCode = socket_errno;
					std::string errorString = GetStringErrorMsg(errorCode);
					bool unreachable = errorCode == ENETUNREACH;
					bool inProgress = errorCode == EINPROGRESS || errorCode == EWOULDBLOCK;
					if (!inProgress) {
						char addrStr[128]{};
						FormatAddr(addrStr, sizeof(addrStr), possible);
						if (!unreachable) {
							ERROR_LOG(Log::HTTP, "connect(%d) call to %s failed (%d: %s)", sock, addrStr, errorCode, errorString.c_str());
						}
						else {
							INFO_LOG(Log::HTTP, "connect(%d): Ignoring unreachable resolved address %s", sock, addrStr);
						}
						closesocket(sock);
						continue;
					}
				}
				sockets.push_back(sock);
				FD_SET(sock, &fds);
				if (maxfd < sock + 1) {
					maxfd = sock + 1;
				}
			}

			int selectResult = 0;
			long timeoutHalfSeconds = floor(2 * timeout);
			while (timeoutHalfSeconds >= 0 && selectResult == 0) {
				struct timeval tv {};
				tv.tv_sec = 0;
				if (timeoutHalfSeconds > 0) {
					// Wait up to 0.5 seconds between cancel checks.
					tv.tv_usec = 500000;
				}
				else {
					// Wait the remaining <= 0.5 seconds.  Possibly 0, but that's okay.
					tv.tv_usec = (timeout - floor(2 * timeout) / 2) * 1000000.0;
				}
				--timeoutHalfSeconds;

				selectResult = select(maxfd, nullptr, &fds, nullptr, &tv);
				if (cancelConnect && *cancelConnect) {
					WARN_LOG(Log::HTTP, "connect: cancelled (1): %s:%d", host_.c_str(), port_);
					break;
				}
			}
			if (selectResult > 0) {
				// Something connected.  Pick the first one that did (if multiple.)
				for (int sock : sockets) {
					if ((intptr_t)sock_ == -1 && FD_ISSET(sock, &fds)) {
						sock_ = sock;
					}
					else {
						closesocket(sock);
					}
				}

				// TODO: Wrap socket with WolfSSL
				if (tls.enabled) {
					// Optional, based on the hosting servers strictness
					//wolfSSL_UseSNI(tls.ssl, WOLFSSL_SNI_HOST_NAME, host_.c_str(), (unsigned short)host_.length());

					wolfSSL_set_fd(tls.ssl, sock_);
					// Then initiate handshake
					if (wolfSSL_connect(tls.ssl) != WOLFSSL_SUCCESS) {
						if (wolfSSL_is_init_finished(tls.ssl)) {
							ERROR_LOG(Log::HTTP, "Connection failed (%s)", wolfSSL_ERR_reason_error_string(wolfSSL_get_error(tls.ssl, 0)));
						}
						else {
							const char* cipher = wolfSSL_get_cipher(tls.ssl);
							if (cipher == "NONE")	// Reports (NONE) when handshake failed
								ERROR_LOG(Log::HTTP, "TLS handshake failed / Unable to agree on a cipher (%s)", wolfSSL_ERR_reason_error_string(wolfSSL_get_error(tls.ssl, 0)));
							else
								ERROR_LOG(Log::HTTP, "TLS handshake failed / Using Cipher %s (%s)", cipher, wolfSSL_ERR_reason_error_string(wolfSSL_get_error(tls.ssl, 0)));
						}

						break;
					}
				}
				// Great, now we're good to go.
				return true;
			}
			else {
				// Fail. Close all the sockets.
				for (int sock : sockets) {
					closesocket(sock);
				}
			}

			if (cancelConnect && *cancelConnect) {
				WARN_LOG(Log::HTTP, "connect: cancelled (2): %s:%d", host_.c_str(), port_);
				break;
			}

			sleep_ms(1, "connect");
		}

		// Nothing connected, unfortunately.
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
	int PSNAuthAgent::GetServers(net::ResolveFunc func, SceNpCommunicationId npTitleId, std::map<u16, std::unique_ptr<net::NPAgent>>* serversPtr) {
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
		http::Client client(func);
		bool cancelled = false;
		net::RequestProgress progress(&cancelled);
		if (!client.Resolve(url.Host().c_str(), url.Port())) {
			ERROR_LOG(Log::sceNet, "HTTP failed to resolve %s", url.Resource().c_str());
			return SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE;
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
				ERROR_LOG(Log::sceNet, "HTTP GET Error = %d", err);
				return SCE_NP_COMMUNITY_SERVER_ERROR_FORBIDDEN;
			}

			net::Buffer readbuf;
			std::vector<std::string> responseHeaders;
			int code = client.ReadResponse(&readbuf, &progress);
			if (code != 200) {
				client.Disconnect();
				ERROR_LOG(Log::sceNet, "HTTP Error Code = %d", code);
				return SCE_NP_COMMUNITY_SERVER_ERROR_INTERNAL_SERVER_ERROR;
			}
			client.Disconnect();

			std::string entity;
			size_t readBytes = readbuf.size();
			readbuf.Take(readBytes, &entity);

			INFO_LOG(Log::sceNet, "Entity Data: %d", entity);

			// TODO: Use XML Parser to get the Tag and it's attributes instead of searching for keywords on the string
			std::string text;
			size_t ofs = entity.find("titleid=");
			if (ofs == std::string::npos) {
				ERROR_LOG(Log::sceNet, "titleid not found");
				return SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE;
			}

			ofs += 9;
			size_t ofs2 = entity.find('"', ofs);
			text = entity.substr(ofs, ofs2 - ofs);
			INFO_LOG(Log::sceNet, "%s - Title ID: %s", __FUNCTION__, text.c_str());

			int i = 1;
			while (true) {
				ofs = entity.find("<agent-fqdn", ++ofs2);
				if (ofs == std::string::npos) {
					if (i == 1) {
						ERROR_LOG(Log::sceNet, "agent-fqdn not found");
						return SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE;
					}
					else
						break;
				}

				size_t frontPos = ++ofs;
				ofs = entity.find("id=", frontPos);
				if (ofs == std::string::npos) {
					ERROR_LOG(Log::sceNet, "agent id not found");
					return SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE;
				}

				ofs += 4;
				ofs2 = entity.find('"', ofs);
				text = entity.substr(ofs, ofs2 - ofs);
				int server_id = std::stoi(text.c_str());
				INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d ID: %s", __FUNCTION__, i, text.c_str());

				ofs = entity.find("port=", frontPos);
				if (ofs == std::string::npos) {
					ERROR_LOG(Log::sceNet, "agent port not found");
					return SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE;
				}

				ofs += 6;
				ofs2 = entity.find('"', ofs);
				text = entity.substr(ofs, ofs2 - ofs);
				int server_port = std::stoi(text.c_str());
				INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d Port: %s", __FUNCTION__, i, text.c_str());

				ofs = entity.find("status=", frontPos);
				if (ofs == std::string::npos) {
					ERROR_LOG(Log::sceNet, "agent status not found");
					return SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE;
				}

				ofs += 8;
				ofs2 = entity.find('"', ofs);
				text = entity.substr(ofs, ofs2 - ofs);
				std::string alive = { 'a','l','i','v','e' };
				int server_status = SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE;
				if (text == alive)
					server_status = SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE;
				INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d Status: %s", __FUNCTION__, i, text.c_str());

				ofs = entity.find('>', ++ofs2);
				if (ofs == std::string::npos) {
					ERROR_LOG(Log::sceNet, "agent host not found");
					return SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE;
				}

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
