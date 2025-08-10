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
			u8 error = packet.Data()[RPCN_HEADER_SIZE];
			switch ((ErrorType)error) {
			case ErrorType::NoError:
				{
					auto data_length = packet.Length() - (RPCN_HEADER_SIZE + 1);

					std::lock_guard<std::mutex> lock(buffer_mutex);
					auto& buf = responses[header.reqId];
					buf.insert(buf.end(), packet.Data() + RPCN_HEADER_SIZE, packet.Data() + packet.Length());

					int i;
					std::string hexdata = "";
					for (i = 0; i < packet.Length(); i++) {
						char const c = packet.Data()[i];
						hexdata += hex_chars[(c & 0xF0) >> 4];
						hexdata += hex_chars[(c & 0x0F) >> 0];
					}
					INFO_LOG(Log::sceNet, "NPAgent::Recv('%s')", hexdata.c_str());

					buffer_cv.notify_all();
					break;
				}
			default:
				{
					INFO_LOG(Log::sceNet, "RPCN Read Error 0x%01X: %s", error, PacketTypeNames[error]);

					std::lock_guard<std::mutex> lock(buffer_mutex);
					auto& buf = responses[header.reqId];
					buf.insert(buf.end(), packet.Data() + RPCN_HEADER_SIZE, packet.Data() + packet.Length());

					buffer_cv.notify_all();
					Disconnect();
					break;
				}
			}
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

	int RPCNAgent::Login(const char* npid, const char* token, const char* password) {
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
		u8 error = response.data()[0];
		if (error != (u8)ErrorType::NoError)
			return -error;

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

	int RPCNAgent::CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email) {
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
		u8 error = response.data()[0];
		if (error != (u8)ErrorType::NoError)
			return -error;

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
		// TODO: Possibly unsafe. Need to test
		memcpy(this->npTitleId, npTitleId, sizeof(this->npTitleId));

		Packet packet = Packet();
		packet.Write(this->GetCommHeader());

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
		u8 error = response.data()[0];
		if (error != (u8)ErrorType::NoError)
			return -error;
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

		// Currently under the assumption that the first byte is some error code
		size_t offset = 1;

		u32 num_worlds = 0;
		memcpy(&num_worlds, response.data() + offset, sizeof(num_worlds));
		offset += 4;
		for (u32 i = 0; i < num_worlds; ++i)
		{
			u32 worldId = 0;
			memcpy(&worldId, response.data() + offset, sizeof(worldId));

			SceNpMatching2World world;
			world.worldId = worldId;

			worldInfoOut->emplace(world.worldId, world);
			offset += 4;
		}

		//worldInfoOut->emplace(worldInfo.worldId, worldInfo);
		return worldInfoOut->size();
	}

	int RPCNAgent::SearchRoom(SceNpMatching2SearchRoomRequest* req, SceNpMatching2RoomDataExternal* roomDataOut) {
		flatbuffers::FlatBufferBuilder builder(1024);

		// Build intFilter vector
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<IntSearchFilter>>> final_intfilter_vec;
		if (req->intFilterNum && req->intFilter) {
			std::vector<flatbuffers::Offset<IntSearchFilter>> intFilters;
			intFilters.reserve(req->intFilterNum);

			for (u32 i = 0; i < req->intFilterNum; ++i) {
				auto int_attr = CreateIntAttr(builder, req->intFilter[i].attr.id, req->intFilter[i].attr.num);
				auto filter = CreateIntSearchFilter(builder, req->intFilter[i].searchOperator, int_attr);
				intFilters.push_back(filter);
			}
			final_intfilter_vec = builder.CreateVector(intFilters);
		}

		// Build binFilter vector
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinSearchFilter>>> final_binfilter_vec;
		if (req->binFilterNum && req->binFilter) {
			std::vector<flatbuffers::Offset<BinSearchFilter>> binFilters;
			binFilters.reserve(req->binFilterNum);

			for (u32 i = 0; i < req->binFilterNum; ++i) {
				auto dataVec = builder.CreateVector(
					req->binFilter[i].attr.ptr,
					req->binFilter[i].attr.size
				);
				auto bin_attr = CreateBinAttr(builder, req->binFilter[i].attr.id, dataVec);
				auto filter = CreateBinSearchFilter(builder, req->binFilter[i].searchOperator, bin_attr);
				binFilters.push_back(filter);
			}
			final_binfilter_vec = builder.CreateVector(binFilters);
		}

		// Build attrId vector
		flatbuffers::Offset<flatbuffers::Vector<u16>> attrid_vec;
		if (req->attrIdNum && req->attrId) {
			std::vector<u16> attr_ids(req->attrId, req->attrId + req->attrIdNum);
			attrid_vec = builder.CreateVector(attr_ids);
		}
		// Build the main SearchRoomRequest
		SearchRoomRequestBuilder s_req(builder);
		s_req.add_option(req->option);
		s_req.add_worldId(req->worldId);
		s_req.add_lobbyId(req->lobbyId);
		s_req.add_rangeFilter_startIndex(req->rangeFilter.startIndex);
		s_req.add_rangeFilter_max(req->rangeFilter.max);
		s_req.add_flagFilter(req->flagFilter);
		s_req.add_flagAttr(req->flagAttr);
		if (req->intFilterNum) s_req.add_intFilter(final_intfilter_vec);
		if (req->binFilterNum) s_req.add_binFilter(final_binfilter_vec);
		if (req->attrIdNum) s_req.add_attrId(attrid_vec);

		auto req_finished = s_req.Finish();
		builder.Finish(req_finished);

		// Super overcomplicated system to attach the CommHeader to the packet
		auto bufsize = builder.GetSize();
		std::vector<u8> header = this->GetCommHeader();
		std::vector<u8> data(COMMUNICATION_ID_SIZE + sizeof(u32) + bufsize);
		data.insert(data.begin(), header.begin(), header.end());
		reinterpret_cast<u32&>(data[COMMUNICATION_ID_SIZE]) = static_cast<u32>(bufsize);
		memcpy(data.data() + COMMUNICATION_ID_SIZE + sizeof(u32), builder.GetBufferPointer(), bufsize);

		// Wrap and send the packet
		Packet packet;
		packet.Write(data);

		auto reqId = generate_request_id();
		packet.Pack(CommandType::SearchRoom, reqId);

		INFO_LOG(Log::sceNet, "Requesting Room List");

		// NPAgent::Send('001000BB00000001000000000000004E50575230313434365F303001008C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F0000000000000000000000000000000000')
		bool flushed = Send(&packet, 5.0, &canceled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return false;
		}

		auto response = wait_for_responses(reqId);
		u8 error = response.data()[0];
		if (error != (u8)ErrorType::NoError)
			return -error;
		// 01 1000 10000000 0100000000000000 01

		roomDataOut->roomId = 0; // No Room (or parse from response)

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
