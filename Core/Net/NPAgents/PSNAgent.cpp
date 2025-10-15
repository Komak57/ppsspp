#include "Core/Net/NPAgent.h"
#include <Core/HLE/HLE.h>
#include <Core/Net/Buffer.h>
#include <Common/File/FileDescriptor.h>
#include <TimeUtil.h>
#include <chrono>
#include <Common/Net/URL.h>
#include "Common/Net/HTTPClient.h"
#include <Core/HLE/sceNet.h>

using namespace std::literals::chrono_literals;
/*
	< 12010036100100000100100000000000e288f336a613981d1f8b0253f34d40281010000c4e50575230313434365f3030407300020001
	> 1002002710010000010010000000000019490bc9118fc488581dcbfcb27a4a31001d0003000101

	< 1201002010080000060030009fc689d2397d08a87b9843a0be200fa912534c7a
	> 1002003e100800000600300000000000d0cdabffde20bcc7878039e8d73746350002001a002a0001002a0012000100000000000000000000000000000000

	< 12010093120c00000700f0009fc689d271347aa95b21d64d3913f164fc6f98a040290002000100040004000100140006000c6400000070400004040000000007000901504c00040000004240050002504c40050002504d40050002504e40050002504f400500025050400500025051400500025052400500025053400500022054400500022055400500022056400500027041
	> 1002002c120c00000700f00000000000c809b42f3ca80beaca681dd96b39dfa9000300080045000000000000

	< 1201002612090000080090009fc689d25fc23947f402c1076d1aae5b5dd4e4d0402900020001
	> 100200c6120900000800900000000000eb31affe08c2641c0b37c26be6173cac403d0002067d0002006e000a0002000a00310d971009002b6c6f6f6b75702d32303930322e77772e6e702e6d61746368696e672e706c617973746174696f6e2e6e6574000a00310d971009002b6c6f6f6b75702d32303930312e77772e6e702e6d61746368696e672e706c617973746174696f6e2e6e65742020002a4e50575230313434365f303000010000067d00000000000000006dec27241755dd350bcd017d44b5c6d1

	< 12010250120200000b0090009fc689d258a3977d62e8db08ea0a519a436c0323203a00cc4e50575230313434365f303000010000067d000c028400000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011001100000198191326730000000001001f003a02105601000a00320d981009002c73657373696f6e2d32303930312e77772e6e702e6d61746368696e672e706c617973746174696f6e2e6e6574000b0018466f784c6f766573596f7500000000006234757370737000733f2a272b670ef10729d5c1391fb8ad504c000400000042504d000400000001504e000400000001504f0004000000c850500004000000025051000400000001505200040000000050530004000000002054000e42006c00750065002d0030003100205500f80000000000000000b873eaf120fae2000c000201a90000000000000000000000000000000000000000000000a518940300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002056000e2bff49ff54ff53ff55ff4eff45ff
	> 10020020120200000b00900000000000ab8eeccd790f258682b9a5d037652526

	< 120100f0120a00000d00b0009fc689d29c022c43b7493dd94310f348fafcd211203a00cc4e50575230313434365f303000010000067d000c028400000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011001100000198191326730000000002001f003a02105601000a00320d981009002c73657373696f6e2d32303930312e77772e6e702e6d61746368696e672e706c617973746174696f6e2e6e6574000b0018466f784c6f766573596f7500000000006234757370737000588e71a258cee4ce5a35d3b4d7ee6451
	> 10020020120a00000d00b00000000000643099ebe3108749441c284285423847

	< 00
	> 00

	< 00
	> 00

	< 00
	> 00

	< 00
	> 00

	< 00
	> 00
*/

namespace net {
	PSNAgent::PSNAgent(std::string host, int port) {
		this->host_ = host;
		this->port_ = port;

		this->cache.clear();
	}
	PSNAgent::~PSNAgent() {
		Disconnect();
	}

	void PSNAgent::Disconnect() {
		if (tls.enabled) {
			ResetSSL();
		}
		else {
			if ((intptr_t)sock_ != -1) {
				cancelled = true;
				closesocket(sock_);
				sock_ = -1;
			}
		}
	}

	void PSNAgent::start_read_thread() {
		if (running) return;
		running = true;
	}

	void PSNAgent::stop_read_thread() {
		if (!running) return;
		running = false;
	}

	std::chrono::microseconds PSNAgent::HandleResponses() {
		return std::chrono::duration_cast<std::chrono::microseconds>(10s);
	}

	bool PSNAgent::Connect(int maxTries, double timeout, bool* cancelConnect) {
		WARN_LOG(Log::sceNet, "UNTESTED Connection::SSLConnect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);
		if (port_ <= 0) {
			ERROR_LOG(Log::IO, "SSLConnect - Bad port");
			return false;
		}
		if (connected) {
			return true;
		}


		for (int tries = maxTries; tries > 0; --tries) {
			mbedtls_ssl_setup(&tls.sslCtx, &tls.sslConfig);
			for (addrinfo* possible = resolved_; possible != nullptr; possible = possible->ai_next) {
				if (possible->ai_family != AF_INET && possible->ai_family != AF_INET6)
					continue;

				int ret;
				/*
				 * 1. Start the connection
				 */
				char* ip_address = new char[128];
				inet_ntop(possible->ai_family, &((sockaddr_in*)possible->ai_addr)->sin_addr, ip_address, 128);
				char portStr[8]{};
				memcpy(portStr, std::to_string(port_).c_str(), std::to_string(port_).length());
				if ((ret = mbedtls_net_connect(&tls.netCtx, ip_address, portStr, MBEDTLS_NET_PROTO_TCP)) != 0) {
					ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_net_connect(netCtx, %s, %s, PROTO_TCP) call to %s failed with -0x%04x)", ip_address, portStr, (unsigned int)-ret);
					goto retry;
				}
				// Set NonBlocking
				fd_util::SetNonBlocking(tls.netCtx.fd, true);
				/*
				 * 2. Setup stuff
				 */
				if ((ret = mbedtls_ssl_setup(&tls.sslCtx, &tls.sslConfig)) != 0) {
					ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_setup returned 0x%04x", ret);
					goto retry;
				}

				//if ((ret = mbedtls_ssl_set_hostname(&sslCtx, possible->ai_addr->sa_data)) != 0) {
				if ((ret = mbedtls_ssl_set_hostname(&tls.sslCtx, host_.c_str())) != 0) {
					char errbuf[128];
					mbedtls_strerror(ret, errbuf, sizeof(errbuf));
					ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_set_hostname returned -0x%04x (%s)", (unsigned int)-ret, errbuf);
					goto retry;
				}

				mbedtls_ssl_set_bio(&tls.sslCtx, &tls.netCtx, mbedtls_net_send, mbedtls_net_recv, NULL);

				/*
				 * 4. Handshake
				 */
				NOTICE_LOG(Log::sceNet, "SSLConnect - Performing the SSL/TLS handshake...");

				while ((ret = mbedtls_ssl_handshake(&tls.sslCtx)) != 0) {
					if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
						char errbuf[128];
						mbedtls_strerror(ret, errbuf, sizeof(errbuf));
						ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_handshake ERROR -0x%x: %s", (unsigned int)-ret, errbuf);
						goto retry;
					}
				}

				/*
				 * 5. Verify the server certificate
				 */
				 // HTTPS Option 28 may relate to disabling this check
				NOTICE_LOG(Log::sceNet, "SSLConnect - Verifying peer X.509 certificate...");

				/* In real life, we probably want to bail out when ret != 0 */
				u32 flags;
				if ((flags = mbedtls_ssl_get_verify_result(&tls.sslCtx)) != 0) {
					char vrfy_buf[512];

					mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

					ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_get_verify_result failed: %s", vrfy_buf);
					goto retry;
				}

				INFO_LOG(Log::sceNet, "SSLConnect - Connection Successful");
				connected = true;
				return true;
			retry:
				INFO_LOG(Log::sceNet, "SSLConnect - Connection Failed, retrying");
				mbedtls_ssl_session_reset(&tls.sslCtx);
				mbedtls_ssl_config_free(&tls.sslConfig);

				mbedtls_ssl_free(&tls.sslCtx);
				mbedtls_net_free(&tls.netCtx);

				continue;
			}
			sleep_ms(1, "connect");
		}
		return false;
	}

	int PSNAgent::Login(const char* npid, const char* token, const char* password) {
		return false;
	}

	int PSNAgent::CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email) {
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
	int PSNAgent::GetServers(SceNpCommunicationId npTitleId) {
		Url url("http://static-resource.np.community.playstation.net/np/resource/psp-title/" + std::string(npTitleId.data) + "_00/matching/" + std::string(npTitleId.data) + "_00-matching.xml");
		http::Client client(&ProcessHostnameWithInfraDNS);
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
				NPServerInfo server{};
				server.nptype = NPAgentType::PSN;

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
				server.id = std::stoi(text.c_str());
				INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d ID: %s", __FUNCTION__, i, text.c_str());

				ofs = entity.find("port=", frontPos);
				if (ofs == std::string::npos)
					return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "agent port not found");

				ofs += 6;
				ofs2 = entity.find('"', ofs);
				text = entity.substr(ofs, ofs2 - ofs);
				server.port = std::stoi(text.c_str());
				INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d Port: %s", __FUNCTION__, i, text.c_str());

				ofs = entity.find("status=", frontPos);
				if (ofs == std::string::npos)
					return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "agent status not found");

				ofs += 8;
				ofs2 = entity.find('"', ofs);
				text = entity.substr(ofs, ofs2 - ofs);
				std::string alive = { 'a','l','i','v','e' };
				server.status = SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE;
				if (text == alive)
					server.status = SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE;
				INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d Status: %s", __FUNCTION__, i, text.c_str());

				ofs = entity.find('>', ++ofs2);
				if (ofs == std::string::npos)
					return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "agent host not found");

				ofs2 = entity.find("</agent-fqdn", ++ofs);
				text = entity.substr(ofs, ofs2 - ofs);
				server.host = text;
				INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d Host: %s", __FUNCTION__, i, text.c_str());

				if (!npServer)
					npServer = net::CreateNPAgent(NPAgentType::PSN, server.host, server.port);
				npServer->servers.emplace(server.id, std::make_unique<NPServerInfo>(server));
				//serversPtr->emplace(server_id, net::CreateNPAgent(net::NPAgentType::PSN, server_id, server_host, server_port, server_status));
				i++;
			}
		}
		return 0;
	}

	int PSNAgent::GetWorldInfo(SceNpMatching2RequestId reqId, int server_id, SceNpCommunicationId npCommId) {
		NOTICE_LOG(Log::sceNet, "NPAgent::GetWorldInfo(%s)", npCommId.data);
#ifndef AGENT_TESTING
		if (sock_ <= 0) {
			ERROR_LOG(Log::sceNet, "GetWorldInfo: Socket not connected");
			return -1;
		}
#endif
		if (cancelled) {
			ERROR_LOG(Log::sceNet, "GetWorldInfo: Cancelled");
			return -1;
		}
		// 1201 0036 10010000 01001000 00000000 e288f336a613981d1f8b0253f34d4028 1010 000c 4e50575230313434365f3030 4073 0002 0001
		//
		u32 packet_size = 0x36;
		Packet packet = Packet();

		uint8_t guid[16] = { 0xe2, 0x88, 0xf3, 0x36, 0xa6, 0x13, 0x98, 0x1d,
						 0x1f, 0x8b, 0x02, 0x53, 0xf3, 0x4d, 0x40, 0x28 };

		packet.Write((u16)0x1201);		// OPCODE ?
		packet.Write((u16)packet_size);	// PACKET_LEN
		packet.Write((u32)0x10010000);	// ?
		packet.Write((u32)0x01001000);	// ?
		packet.Write((u32)0x00000000);	// padding?
		int i = 0;
		for (i = 0; i < 16; i++)
			packet.Write((u8)guid[i]);	// GUID?
		packet.Write((u16)0x1010);		// ?

		packet.Write((u16)(sizeof(npCommId.data) + 4));	// TITLE_LEN
		packet.Write(npCommId.data);
		packet.Write("_00");

		packet.Write((u16)0x4073);		// ?
		packet.Write((u16)0x0002);		// ?
		packet.Write((u16)0x0001);		// ?

		std::string hexdata = "";
		for (i = 0; i < packet.Length(); i++) {
			char const c = packet.Data()[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "Request: %s", hexdata.c_str());

		// packet.Pack(0x0112, packet.Length()+4);
		core::Buffer buffer;
		void* dst = buffer.Append(packet_size);
		memcpy(dst, packet.Data(), packet.Length());

		bool flushed = buffer.FlushSocketSSL(&tls, 60.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return -1;
		}
		core::Buffer readbuf;
		// Read response
		int ret;
		if ((ret = readbuf.Read(sock(), 4096, &tls)) < 0) {
			ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
			return -1;
		}

		std::string response;
		readbuf.Take(ret, &response);

		// 1002 0027 10010000 01001000 00000000 19490bc9118fc488581dcbfcb27a4a31 001d 0003 0001 01
		hexdata = "";
		for (i = 0; i < response.length(); i++) {
			int c = response[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "Response: %s", hexdata.c_str());
		//worldInfoOut->clear();
		//// Should get an array of worlds
		//SceNpMatching2World worldInfo = SceNpMatching2World();
		//worldInfo.worldId = 1;

		//worldInfoOut->push_back(worldInfo);

		return 0;
	}

	int PSNAgent::RequestSignalingInfo(std::string npid, u32 conn_id) {
		return 0;
	}

	int PSNAgent::SearchRoom(SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2SearchRoomRequest> req) {
		NOTICE_LOG(Log::sceNet, "NPAgent::SearchRoom()");
		if (sock() <= 0) {
			ERROR_LOG(Log::sceNet, "SearchRoom: Socket not connected");
			return -1;
		}
		if (cancelled) {
			ERROR_LOG(Log::sceNet, "SearchRoom: Cancelled");
			return -1;
		}


		u32 packet_size = 0x36;
		Packet packet = Packet();

		int i = 0;
		std::string hexdata = "";
		for (i = 0; i < packet.Length(); i++) {
			char const c = packet.Data()[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "Request: %s", hexdata.c_str());

		// packet.Pack(0x0112, packet.Length()+4);
		net::Buffer buffer;
		void* dst = buffer.Append(packet_size);
		memcpy(dst, packet.Data(), packet.Length());

		bool flushed = buffer.FlushSocket(sock(), 60.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return -1;
		}

		core::Buffer readbuf;
		// Read response
		int ret;
		if ((ret = readbuf.Read(sock(), 4096, &tls)) < 0) {
			ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
			return -1;
		}

		//std::string response;
		//readbuf.Take(ret, &response);

		//// 1002 0027 10010000 01001000 00000000 19490bc9118fc488581dcbfcb27a4a31 001d 0003 0001 01
		//hexdata = "";
		//for (i = 0; i < response.length(); i++) {
		//	int c = response[i];
		//	hexdata += hex_chars[(c & 0xF0) >> 4];
		//	hexdata += hex_chars[(c & 0x0F) >> 0];
		//}
		//INFO_LOG(Log::sceNet, "Response: %s", hexdata.c_str());

		//roomDataOut->roomId = 0; // No Room
		return 0;
	}

	int PSNAgent::CreateJoinRoom(SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2CreateJoinRoomRequest> req) {
		NOTICE_LOG(Log::sceNet, "NPAgent::CreatJoinRoom()");
		if (sock_ <= 0) {
			ERROR_LOG(Log::sceNet, "CreatJoinRoom: Socket not connected");
			return -1;
		}
		if (cancelled) {
			ERROR_LOG(Log::sceNet, "CreatJoinRoom: Cancelled");
			return -1;
		}


		u32 packet_size = 0x36;
		Packet packet = Packet();

		int i = 0;
		std::string hexdata = "";
		for (i = 0; i < packet.Length(); i++) {
			char const c = packet.Data()[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "Request: %s", hexdata.c_str());

		// packet.Pack(0x0112, packet.Length()+4);
		net::Buffer buffer;
		void* dst = buffer.Append(packet_size);
		memcpy(dst, packet.Data(), packet.Length());

		bool flushed = buffer.FlushSocket(sock(), 60.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return -1;
		}

		core::Buffer readbuf;
		// Read response
		int ret;
		if ((ret = readbuf.Read(sock(), 4096, &tls)) < 0) {
			ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
			return -1;
		}

		std::string response;
		readbuf.Take(ret, &response);

		// 1002 0027 10010000 01001000 00000000 19490bc9118fc488581dcbfcb27a4a31 001d 0003 0001 01
		hexdata = "";
		for (i = 0; i < response.length(); i++) {
			int c = response[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "Response: %s", hexdata.c_str());
		//roomDataOut->roomId = 1;

		return 0;
	}

	int PSNAgent::JoinRoom(SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2JoinRoomRequest> req) {
		return 0;
	}

	int PSNAgent::LeaveRoom(SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2LeaveRoomRequest> req) {
		return 0;
	}

	int PSNAgent::GetRoomDataInternal(SceNpMatching2RequestId reqId, SceNpMatching2GetRoomDataInternalRequest* req) {
		return 0;
	}

	int PSNAgent::SetRoomDataInternal(SceNpMatching2RequestId reqId, SceNpMatching2SetRoomDataInternalRequest* req) {
		return 0;
	}

	int PSNAgent::SendRoomMessage(SceNpMatching2RequestId reqId, SceNpMatching2SendRoomMessageRequest* req) {
		return 0;
	}

	int PSNAgent::SetRoomDataExternal(SceNpMatching2RequestId reqId, SceNpMatching2SetRoomDataExternalRequest* req) {
		return 0;
	}

	int PSNAgent::SetUserInfo(SceNpMatching2RequestId reqId, SceNpMatching2SetUserInfoRequest* req) {
		return 0;
	}

	int PSNAgent::GetRoomDataExternalList(SceNpMatching2RequestId reqId, SceNpMatching2GetRoomDataExternalListRequest* req) {
		return 0;
	}
}
