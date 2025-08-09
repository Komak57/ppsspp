#include "Core/Util/NPAgent.h"
#include <Core\HLE\HLE.h>
#include <File\FileDescriptor.h>
#include <mbedtls\error.h>
#include <TimeUtil.h>
#include "Core/MemMapHelpers.h"

namespace net {
	// FIXME: Populate with actual connection credentials for RPCN
	RPCNAgent::RPCNAgent(int serverId, std::string host, int port, u8 status) {
		this->ID = serverId;
		this->host_ = host;
		this->port_ = port;
		this->status = status;

		this->worlds.clear();
		this->rooms.clear();
		//std::string certificate = "";
		//InitializeSSL(certificate);
	}

	RPCNAgent::~RPCNAgent() {
		stop_read_thread();
		Disconnect();
	}

	void RPCNAgent::start_read_thread() {
		if (running) return;
		running = true;
		read_thread = std::thread(&RPCNAgent::read_loop, this);
	}

	void RPCNAgent::stop_read_thread() {
		running = false;
		if (read_thread.joinable()) {
			read_thread.join();
		}
	}

	// Blocking wait for a specific request_id
	std::vector<u8> RPCNAgent::wait_for_responses(u64 request_id) {
		std::unique_lock<std::mutex> lock(buffer_mutex);
		buffer_cv.wait(lock, [&]() {
			return responses.find(request_id) != responses.end();
		});

		auto data = std::move(responses[request_id]);
		responses.erase(request_id);
		return data;
	}

	void RPCNAgent::read_loop() {
		while (running) {
			Packet packet;
			int ret = Recv(&packet); // Uses NPAuthAgent::Recv
			if (ret <= 0) {
				running = false;
				break;
			}

			PacketHeader header;
			memcpy(&header, packet.Data(), sizeof(PacketHeader));

			std::lock_guard<std::mutex> lock(buffer_mutex);
			auto& buf = responses[header.reqId];
			buf.insert(buf.end(), packet.Data(), packet.Data() + packet.Length());

			int i;
			std::string hexdata = "";
			for (i = 0; i < packet.Length(); i++) {
				char const c = packet.Data()[i];
				hexdata += hex_chars[(c & 0xF0) >> 4];
				hexdata += hex_chars[(c & 0x0F) >> 0];
			}
			INFO_LOG(Log::sceNet, "NPAgent::Recv('%s')", hexdata.c_str());

			buffer_cv.notify_all();
		}
	}

	bool RPCNAgent::Connect(int maxTries, double timeout, bool* cancelConnect) {
		std::string certPem = "-----BEGIN CERTIFICATE-----\n"
			"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\n"
			"-----END CERTIFICATE-----\n";
		InitializeSSL(MBEDTLS_SSL_TRANSPORT_STREAM, certPem);
		WARN_LOG(Log::sceNet, "UNTESTED RPCNAuthAgent::Connect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);

		if (port_ <= 0) {
			ERROR_LOG(Log::IO, "Connect - Bad port");
			return false;
		}
		if (tls.connected) {
			mbedtls_ssl_session_reset(&tls.sslCtx);
			mbedtls_ssl_config_free(&tls.sslConfig);

			mbedtls_ssl_free(&tls.sslCtx);
			mbedtls_net_free(&tls.netCtx);
			tls.connected = false;
		}


		for (int tries = maxTries; tries > 0; --tries) {
			mbedtls_ssl_setup(&tls.sslCtx, &tls.sslConfig);
			for (addrinfo* possible = resolved_; possible != nullptr; possible = possible->ai_next) {
				if (possible->ai_family != AF_INET && possible->ai_family != AF_INET6)
					continue;

				Packet packet = Packet();
				int ret;
				/*
				 * 1. Start the connection
				 */
				char addrStr[128]{};
				FormatAddr(addrStr, sizeof(addrStr), possible);
				char portStr[8]{};
				memcpy(portStr, std::to_string(port_).c_str(), std::to_string(port_).length());
				if ((ret = mbedtls_net_connect(&tls.netCtx, addrStr, portStr, MBEDTLS_NET_PROTO_TCP)) != 0) {
					char errbuf[128];
					mbedtls_strerror(ret, errbuf, sizeof(errbuf));
					ERROR_LOG(Log::sceNet, "Connect - mbedtls_net_connect(netCtx, %s, %s, PROTO_TCP) call failed with -0x%04x (%s))", addrStr, portStr, ret, errbuf);
					goto sslretry;
				}
				// Set NonBlocking
				fd_util::SetNonBlocking(tls.netCtx.fd, true);
				/*
				 * 2. Setup stuff
				 */
				if ((ret = mbedtls_ssl_setup(&tls.sslCtx, &tls.sslConfig)) != 0) {
					ERROR_LOG(Log::sceNet, "Connect - mbedtls_ssl_setup returned 0x%04x", ret);
					goto sslretry;
				}

				//if ((ret = mbedtls_ssl_set_hostname(&sslCtx, possible->ai_addr->sa_data)) != 0) {
				if ((ret = mbedtls_ssl_set_hostname(&tls.sslCtx, host_.c_str())) != 0) {
					char errbuf[128];
					mbedtls_strerror(ret, errbuf, sizeof(errbuf));
					ERROR_LOG(Log::sceNet, "Connect - mbedtls_ssl_set_hostname returned -0x%04x (%s)", (unsigned int)-ret, errbuf);
					goto sslretry;
				}

				mbedtls_ssl_set_bio(&tls.sslCtx, &tls.netCtx, mbedtls_net_send, mbedtls_net_recv, NULL);

				/*
				 * 4. Handshake
				 */
				NOTICE_LOG(Log::sceNet, "Connect - Performing the SSL/TLS handshake...");

				while ((ret = mbedtls_ssl_handshake(&tls.sslCtx)) != 0) {
					if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
						char errbuf[128];
						mbedtls_strerror(ret, errbuf, sizeof(errbuf));
						ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_handshake ERROR -0x%x: %s", (unsigned int)-ret, errbuf);
						goto sslretry;
					}
				}

				/*
				 * 5. Verify the server certificate
				 */
				 // HTTPS Option 28 may relate to disabling this check
				NOTICE_LOG(Log::sceNet, "Connect - Verifying peer X.509 certificate...");

				/* In real life, we probably want to bail out when ret != 0 */
				u32 flags;
				if ((flags = mbedtls_ssl_get_verify_result(&tls.sslCtx)) != 0) {
					char vrfy_buf[512];

					mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

					ERROR_LOG(Log::sceNet, "Connect - mbedtls_ssl_get_verify_result failed: %s", vrfy_buf);
					goto sslretry;
				}

				INFO_LOG(Log::sceNet, "Connect - Connection Successful. TLS: %s, Cipher: %s", mbedtls_ssl_get_version(&tls.sslCtx), mbedtls_ssl_get_ciphersuite(&tls.sslCtx));
				tls.connected = true;

				// Start reading data
				start_read_thread();
				// Get Version Info
				/*ret = Recv(&packet);
				if (ret < 0) {
					ERROR_LOG(Log::sceNet, "Unable to retrieve Version info.");
				}*/
				return true;
			sslretry:
				INFO_LOG(Log::sceNet, "Connect - Connection Failed, retrying");
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

	bool RPCNAgent::Login(const char* npid, const char* token, const char* password) {
		// npid
		// password
		// token

		// Send CommandType::Login, req_id, data, packet_data

		// Get Reply
		// online_name
		// avatar_url
		// user_id 
		// friends (PS3)

		// Disconnect on Error
		// Disconnect on malformed data
		Packet packet = Packet();
		packet.Write(npid);
		packet.Write((u8)0);
		packet.Write(password);
		packet.Write((u8)0);
		packet.Write(token);
		packet.Write((u8)0);

		auto reqId = generate_request_id();
		packet.Pack(CommandType::Login, reqId);

		INFO_LOG(Log::sceNet, "Sending Login Request");

		bool flushed = Send(&packet, 5.0, &canceled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return false;
		}

		/*Packet response = Packet();
		int ret = Recv(&response);
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
			return false;
		}*/
		auto response = wait_for_responses(reqId);

		/*int i;
		std::string hexdata = "";
		for (i = 0; i < response.size(); i++) {
			char const c = response[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "NPAgent::Recv('%s')", hexdata.c_str());*/

		PacketHeader header;
		memcpy(&header, packet.Data(), sizeof(PacketHeader));

		return true;
	}

	bool RPCNAgent::CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email) {
		Packet packet = Packet();
		packet.Write(npid);
		packet.Write((u8)0);
		packet.Write(password);
		packet.Write((u8)0);
		packet.Write(online_name);
		packet.Write((u8)0);
		packet.Write(avatar_url);
		packet.Write((u8)0);
		packet.Write(email);
		packet.Write((u8)0);

		auto reqId = generate_request_id();
		packet.Pack(CommandType::Create, reqId);

		INFO_LOG(Log::sceNet, "Sending Registration Request");

		bool flushed = Send(&packet, 5.0, &canceled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return false;
		}
		/*Packet response = Packet();
		int ret = Recv(&response);
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
			return false;
		}*/
		auto response = wait_for_responses(reqId);

		/*int i;
		std::string hexdata = "";
		for (i = 0; i < response.size(); i++) {
			char const c = response[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "NPAgent::Recv('%s')", hexdata.c_str());*/
		return true;
	}

	int RPCNAgent::GetWorldInfo(int server_id, char npTitleId[], std::map<u32, SceNpMatching2World>* worldInfoOut) {
		Packet packet = Packet();
		packet.Write(npTitleId);
		packet.Write("_00");
		packet.Write((u16)server_id);
		packet.Pack(CommandType::GetWorldList, 3);

		auto reqId = generate_request_id();
		packet.Pack(CommandType::GetWorldList, reqId);

		INFO_LOG(Log::sceNet, "Requesting World Info");

		bool flushed = Send(&packet, 5.0, &canceled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return false;
		}
		/*Packet response = Packet();
		int ret = Recv(&response);
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
			return false;
		}*/
		auto response = wait_for_responses(reqId);

		//int i;
		//std::string hexdata = "";
		//for (i = 0; i < response.size(); i++) {
		//	char const c = response[i];
		//	hexdata += hex_chars[(c & 0xF0) >> 4];
		//	hexdata += hex_chars[(c & 0x0F) >> 0];
		//}
		//INFO_LOG(Log::sceNet, "NPAgent::Recv('%s')", hexdata.c_str());
		// 01 0C00 18000000 0300000000000000 00010000 00010000 00
		// 010C00180000000300000000000000000100000001000000
		worldInfoOut->clear();

		size_t offset = 0;

		SceNpMatching2GetWorldInfoListResponse worldInfoResp;
		memcpy(&worldInfoResp, response.data() + RPCN_HEADER_SIZE, sizeof(worldInfoResp));

		// Now, iterate and read `worldNum` entries of `SceNpMatching2World`
		for (u32 i = 0; i < worldInfoResp.worldNum; ++i)
		{
			SceNpMatching2World world;
			Memory::Memcpy(&world, worldInfoResp.worldNum + offset, sizeof(SceNpMatching2World));
			offset += sizeof(SceNpMatching2World);
			worldInfoOut->emplace(world.worldId, world);
		}

		//worldInfoOut->emplace(worldInfo.worldId, worldInfo);
		return worldInfoOut->size();
	}

	int RPCNAgent::SearchRoom(SceNpMatching2SearchRoomRequest* req, SceNpMatching2RoomDataExternal* roomDataOut) {
		Packet packet = Packet();

		// Header structure
		SceNpMatching2SearchRoomPacket header{};
		header.option = req->option;
		header.worldId = req->worldId;
		header.lobbyId = req->lobbyId;
		header.range_startIndex = req->rangeFilter.startIndex;
		header.range_max = req->rangeFilter.max;
		header.flagFilter = req->flagFilter;
		header.flagAttr = req->flagAttr;
		header.intFilterNum = req->intFilterNum;
		header.binFilterNum = req->binFilterNum;
		header.attrIdNum = req->attrIdNum;


		std::vector<u8> data;
		data.insert(data.end(), reinterpret_cast<u8*>(&header), reinterpret_cast<u8*>(&header) + sizeof(header));

		// Serialize intFilter
		for (u32 i = 0; i < req->intFilterNum; ++i)
		{
			IntFilter f;
			f.searchOperator = req->intFilter[i].searchOperator;
			f.attr_id = req->intFilter[i].attr.id;
			f.attr_num = req->intFilter[i].attr.num;

			data.insert(data.end(), reinterpret_cast<u8*>(&f), reinterpret_cast<u8*>(&f) + sizeof(f));
		}

		// Serialize binFilter
		for (u32 i = 0; i < req->binFilterNum; ++i)
		{
			BinFilter f;
			f.searchOperator = req->binFilter[i].searchOperator;
			f.attr_id = req->binFilter[i].attr.id;
			f.data_size = req->binFilter[i].attr.size;

			data.insert(data.end(), reinterpret_cast<u8*>(&f), reinterpret_cast<u8*>(&f) + sizeof(f));
			data.insert(data.end(), req->binFilter[i].attr.ptr,
				req->binFilter[i].attr.ptr + req->binFilter[i].attr.size);
		}

		// Serialize attrId[]
		for (u32 i = 0; i < req->attrIdNum; ++i)
		{
			u16 attr_id = req->attrId[i];
			data.insert(data.end(), reinterpret_cast<u8*>(&attr_id), reinterpret_cast<u8*>(&attr_id) + sizeof(u16));
		}
		packet.Write(data);

		auto reqId = generate_request_id();
		packet.Pack(CommandType::SearchRoom, reqId);

		INFO_LOG(Log::sceNet, "Requesting Room List");

		bool flushed = Send(&packet, 5.0, &canceled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return false;
		}
		/*Packet response = Packet();
		int ret = Recv(&response);
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
			return false;
		}*/
		auto response = wait_for_responses(reqId);
		// 01 1000 10000000 0100000000000000 01

		roomDataOut->roomId = 0; // No Room
		return 0;
	}

	int RPCNAgent::CreatJoinRoom(SceNpMatching2RoomDataInternal* roomDataOut) {
		roomDataOut->roomId = 1;
		return 0;
	}

	int RPCNAgent::GetRoomDataInternal(SceNpMatching2RoomDataInternal* roomDataOut) {
		return 0;
	}
}
