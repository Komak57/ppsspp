#include "Core/Net/NPAgent.h"
#include <TimeUtil.h>
#include <chrono>
#include <Core/HLE/HLE.h>
#include <Common/File/FileDescriptor.h>
#include "Core/MemMapHelpers.h"
#include <Core/Net/SignalingHandler.h>
#include <Core/HLE/proAdhoc.h>

using namespace std::literals::chrono_literals;

namespace net {
	// FIXME: Populate with actual connection credentials for RPCN
	RPCNAgent::RPCNAgent(std::string host, int port) {
		this->host_ = host;
		this->port_ = port;

		this->cache.clear();
		//std::string certificate = "";
		//InitializeSSL(certificate);
	}

	RPCNAgent::~RPCNAgent() {
		NOTICE_LOG(Log::sceNet, "~NPAgent");
		if (connected)
			Disconnect();
	}

	void RPCNAgent::Disconnect() {
		NOTICE_LOG(Log::sceNet, "NPAgent::Disconnect()");
		cancelled = true;
		if (running)
			stop_read_thread();
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

	u64 RPCNAgent::generate_request_id()
	{
		static u64 fallback_id = 1; // In case map is empty

		if (responses.empty())
			return fallback_id++;

		u64 max_key = 0;
		for (const auto& [key, _] : responses)
		{
			if (key > max_key)
				max_key = key;
		}
		return max_key + 1;
	}

	void RPCNAgent::start_read_thread() {
		if (running) return;
		running = true;
		read_thread = std::thread(&RPCNAgent::read_loop, this);
	}

	void RPCNAgent::stop_read_thread() {
		running = false;
		if (read_thread.joinable())
			read_thread.join();
		if (signal_thread.joinable())
			signal_thread.join();
	}

	namespace np {
		bool is_valid_npid(const SceNpId& npid)
		{
			if (!std::all_of(npid.handle.data, npid.handle.data + 16, [](char c) { return std::isalnum(c) || c == '-' || c == '_' || c == 0; })
				|| npid.handle.data[16] != 0
				|| !std::all_of(npid.handle.dummy, npid.handle.dummy + 3, [](char val) { return val == 0; }))
			{
				return false;
			}

			return true;
		}
	}

	// Blocking wait for a specific request_id
	RPCNResponse RPCNAgent::take_pending_request(u64 request_id) {
		std::unique_lock<std::mutex> lock(buffer_mutex);
		buffer_cv.wait(lock, [&]() {
			return running && responses.find(request_id) != responses.end();
		});
		if (!running) {
			RPCNResponse ret{};
			ret.error = (u8)ErrorType::Unsupported;
			return ret;
		}

		auto data = std::move(responses[request_id]);
		responses.erase(request_id);
		return data;
	}

	template <typename T, typename U>
	constexpr void write_to_ptr(U&& array, int pos, const T& value)
	{
		static_assert(sizeof(T) % sizeof(array[0]) == 0);
		std::memcpy(static_cast<void*>(&array[pos]), &value, sizeof(value));
	}

	void RPCNAgent::signaling_loop() {

		while (running)
		{
			if (cancelled)
				return;
			const auto now = std::chrono::steady_clock::now();
			const auto rpcn_msgs = g_signaling.get_rpcn_msgs();

			for (const auto& msg : rpcn_msgs)
			{
				if (cancelled)
					return;
				if (msg.size() == 6)
				{
					DEBUG_LOG(Log::sceNet, "RPCN Signal Pong Received");
					const u32 new_addr_sig = read_from_ptr<u32_le>(&msg[0]);
					const u16 new_port_sig = read_from_ptr<u16_le>(&msg[4]);
					const u32 old_addr_sig = addr_sig;
					const u32 old_port_sig = port_sig;

					if (new_addr_sig != old_addr_sig)
					{
						addr_sig = new_addr_sig;
						NOTICE_LOG(Log::sceNet, "New P2P IP: %s", ip2str(htonl(new_addr_sig)).c_str());
						if (old_addr_sig == 0)
						{
							// wake thread
							sigv.notify_one();
						}
					}

					if (new_port_sig != old_port_sig)
					{
						port_sig = new_port_sig;
						NOTICE_LOG(Log::sceNet, "New P2P PORT: %d", htons(new_port_sig));
						if (old_port_sig == 0)
						{
							// wake thread
							sigv.notify_one();
						}
					}

					last_pong_time_ipv4 = now;
				}
				else if (msg.size() == 18)
				{
					// We don't really need ipv6 info stored so we just update the pong data
					// std::array<u8, 16> new_ipv6_addr;
					// std::memcpy(new_ipv6_addr.data(), &msg[3], 16);
					// const u32 new_ipv6_port = read_from_ptr<be_t<u16>>(&msg[16]);

					//last_pong_time_ipv6 = now;
				}
				else
				{
					ERROR_LOG(Log::sceNet, "Received faulty RPCN UDP message!");
				}
			}

			const std::chrono::nanoseconds time_since_last_ipv4_ping = now - last_ping_time_ipv4;
			const std::chrono::nanoseconds time_since_last_ipv4_pong = now - last_pong_time_ipv4;
			auto forge_ping_packet = [&]() -> std::vector<u8>
			{
				std::vector<u8> ping(13);
				ping[0] = 1;
				//ping.emplace(ping.begin() + 1, _user_id);
				//ping.emplace(ping.begin() + 9, +local_addr);
				write_to_ptr<s64_le>(ping, 1, id_sig.load());
				write_to_ptr<u32_be>(ping, 9, addr_sig.load());
				return ping;
			};

			// Send a packet every 5 seconds and then every 500 ms until reply is received
			if (time_since_last_ipv4_pong >= 5s && time_since_last_ipv4_ping > 500ms)
			{
				const auto ping = forge_ping_packet();

				struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(conn->ai_addr);

				if (!g_signaling.send_packet_ipv4(ping, GetConnAddr(), SCE_RPCN_PORT))
					ERROR_LOG(Log::sceNet, "Failed to send IPv4 PING to RPCN");

				last_ping_time_ipv4 = now;
				continue;
			}

			/*if (np::is_ipv6_supported() && time_since_last_ipv6_pong >= 5s && time_since_last_ipv6_ping > 500ms)
			{
				const auto ping = forge_ping_packet();

				if (!send_packet_from_p2p_port_ipv6(ping, addr_rpcn_udp_ipv6))
					rpcn_log.error("Failed to send IPv6 ping to RPCN!");

				last_ping_time_ipv6 = now;
				continue;
			}*/

			auto min_duration_for = [&](const auto last_ping_time, const auto last_pong_time) -> std::chrono::nanoseconds
			{
				if ((now - last_pong_time) < 5s)
				{
					return (5s - (now - last_pong_time));
				}
				else
				{
					return (500ms - (now - last_ping_time));
				}
			};

			auto duration = min_duration_for(last_ping_time_ipv4, last_pong_time_ipv4);

			/*if (np::is_ipv6_supported())
			{
				const auto duration_ipv6 = min_duration_for(last_ping_time_ipv6, last_pong_time_ipv6);
				duration = std::min(duration, duration_ipv6);
			}*/

			// Expected to fail unless rpcn is terminated
			// The check is there to nuke a msvc warning
			/*if (!sem_rpcn.try_acquire_for(duration))
			{
			}*/
		}
	}

	void RPCNAgent::read_loop() {
		while (running) {
			Packet packet;
			int ret = Recv(&packet, &cancelled); // Uses NPAuthAgent::Recv
			if (cancelled)
				return;
			if (ret <= 0) {
				running = false;
				break;
			}

			//int i;
			std::string hexdata = "";
			//for (i = 0; i < packet.Length(); i++) {
			//	char const c = packet.Data()[i];
			//	hexdata += hex_chars[(c & 0xF0) >> 4];
			//	hexdata += hex_chars[(c & 0x0F) >> 0];
			//}
			//DEBUG_LOG(Log::sceNet, "NPAgent::Recv('%s')", hexdata.c_str());

			if (packet.Length() < RPCN_HEADER_SIZE) {
				ERROR_LOG(Log::sceNet, "RPCN Malformed Packet Length (%d)", packet.Length());
				running = false;
				return;
			}

			PacketHeader header;
			memcpy(&header, packet.Data(), sizeof(PacketHeader));
			// Get data and assign it to the request id related buffer
			RPCNResponse buf;
			buf.header = header;
			buf.data.insert(buf.data.end(), packet.Data() + RPCN_HEADER_SIZE, packet.Data() + packet.Length());
			buf.stream = new vec_stream(buf.data);

			std::lock_guard<std::mutex> lock(buffer_mutex);
			switch ((PacketType)header.request) {
			case PacketType::Reply:
				if (packet.Length() < RPCN_HEADER_SIZE + 1) {
					ERROR_LOG(Log::sceNet, "RPCN Malformed Packet Length (%d)", packet.Length());
					running = false;
					Disconnect();
					return;
				}
				buf.error = buf.stream->get<u8>();
				if ((ErrorType)buf.error != ErrorType::NoError) {
					if (buf.error > sizeof(PacketTypeNames))
						ERROR_LOG(Log::sceNet, "RPCN Read Error %d: %s", buf.error, hexdata.c_str());
					else
						ERROR_LOG(Log::sceNet, "RPCN Read Error 0x0%01X: %s", buf.error, PacketTypeNames[buf.error]);
				}
				responses[header.reqId] = std::move(buf);
				break;
			case PacketType::Notification:
				switch ((NotificationType)header.command) {
				case NotificationType::UserJoinedRoom: g_signaling.UserJoinedRoom(buf); break;
				case NotificationType::RoomMessageReceived: g_signaling.RoomMessageReceived(buf); break;
				case NotificationType::UserLeftRoom: g_signaling.UserLeftRoom(buf); break;
				case NotificationType::RoomDestroyed:g_signaling.RoomDestroyed(buf); break;
				case NotificationType::UpdatedRoomDataInternal: g_signaling.UpdatedRoomDataInternal(buf); break;
				case NotificationType::UpdatedRoomMemberDataInternal: g_signaling.UpdatedRoomMemberDataInternal(buf); break;
				case NotificationType::SignalingHelper: g_signaling.SignalingHelper(buf); break;
				// GUI
				case NotificationType::MemberJoinedRoomGUI: g_signaling.MemberJoinedRoomGUI(buf); break;
				case NotificationType::MemberLeftRoomGUI: g_signaling.MemberLeftRoomGUI(buf); break;
				case NotificationType::RoomDisappearedGUI: g_signaling.RoomDisappearedGUI(buf); break;
				case NotificationType::RoomOwnerChangedGUI: g_signaling.RoomOwnerChangedGUI(buf); break;
				case NotificationType::UserKickedGUI: g_signaling.UserKickedGUI(buf); break;
				case NotificationType::QuickMatchCompleteGUI: g_signaling.QuickMatchCompleteGUI(buf); break;
					ERROR_LOG(Log::sceNet, "Unhandled GUI Notification: %s", NotificationTypeNames[header.command]);
					break;
				default:
					NOTICE_LOG(Log::sceNet, "RPCN Unknown Notification: %d", header.command);
					notifications[header.reqId] = buf;
				}
				break;
			case PacketType::ServerInfo:
			{
				u8 version = buf.stream->get<u8>();
				if (version != RPCNAgent::PROTOCOL_VERSION) {
					ERROR_LOG(Log::sceNet, "Server Version mismatch. Current version %d does not match Server version %d", version, RPCNAgent::PROTOCOL_VERSION);
					// TODO: Version mismatch may interfere with requests and responses. Should disconnect
					break;
				}
				INFO_LOG(Log::sceNet, "Server is communicating on version %d", version);
				break;
			}
			default:
				WARN_LOG(Log::sceNet, "RPCN Responded with UNHANDLED PacketType (%d)", header.request);
				break;
			}

			buffer_cv.notify_all();
		}
	}

	bool RPCNAgent::Connect(int maxTries, double timeout, bool* cancelConnect) {
		std::string certPem = "-----BEGIN CERTIFICATE-----\n"
			"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\n"
			"-----END CERTIFICATE-----\n";
		InitializeSSL(certPem);
		mbedtls_ssl_conf_ciphersuites(&tls.sslConfig, forceCiphers);
		mbedtls_ssl_conf_max_version(&tls.sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
		WARN_LOG(Log::sceNet, "UNTESTED RPCNAuthAgent::Connect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);
		cancelled = false;
		if (port_ <= 0) {
			ERROR_LOG(Log::IO, "Connect - Bad port");
			return false;
		}
		if (connected) {
			ResetSSL();
			connected = false;
		}


		auto start_time = std::chrono::high_resolution_clock::now();
		auto end_time = std::chrono::high_resolution_clock::now();
		long long duration_ms = 0;
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
				char* ip_address = new char[128];
				inet_ntop(possible->ai_family, &((sockaddr_in*)possible->ai_addr)->sin_addr, ip_address, 128);
				char portStr[8]{};
				memcpy(portStr, std::to_string(port_).c_str(), std::to_string(port_).length());
				if ((ret = mbedtls_net_connect(&tls.netCtx, ip_address, portStr, MBEDTLS_NET_PROTO_TCP)) != 0) {
					char errbuf[128];
					mbedtls_strerror(ret, errbuf, sizeof(errbuf));
					ERROR_LOG(Log::sceNet, "Connect - mbedtls_net_connect(netCtx, %s, %s, PROTO_TCP) call failed with -0x%04x (%s))", ip_address, portStr, ret, errbuf);
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

				start_time = std::chrono::high_resolution_clock::now();
				while ((ret = mbedtls_ssl_handshake(&tls.sslCtx)) != 0) {
					if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
						char errbuf[128];
						mbedtls_strerror(ret, errbuf, sizeof(errbuf));
						ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_handshake ERROR -0x%x: %s", (unsigned int)-ret, errbuf);
						goto sslretry;
					}
				}
				end_time = std::chrono::high_resolution_clock::now();
				duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
				if (duration_ms > 100)
					ERROR_LOG(Log::sceNet, "SSLConnect - Handshake took %dms", duration_ms);
				else if (duration_ms > 60)
					WARN_LOG(Log::sceNet, "SSLConnect - Handshake took %dms", duration_ms);
				else
					NOTICE_LOG(Log::sceNet, "SSLConnect - Handshake took %dms", duration_ms);
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
				connected = true;
				conn = std::move(possible);

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
				ResetSSL();
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

		bool flushed = Send(&packet, 5.0, &cancelled);
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
		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return resp.error;
		resp.stream = new vec_stream(resp.data, 1);

		online_name = resp.stream->get_string(false);
		avatar_url = resp.stream->get_string(false);
		user_id = resp.stream->get<s64>();

		return 0;
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

		bool flushed = Send(&packet, 5.0, &cancelled);
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
		auto response = take_pending_request(reqId);
		if (response.error != (u8)ErrorType::NoError)
			return response.error;

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

	void RPCNAgent::StartSignalingThread() {
		signal_thread = std::thread(&RPCNAgent::signaling_loop, this);
	}

	std::pair<int, int> RPCNAgent::GetWorldInfo(int server_id, SceNpCommunicationId npTitleId, std::vector<SceNpMatching2World>* worldInfoOut) {
		memcpy(&this->commId, &npTitleId, sizeof(SceNpCommunicationId));

		Packet packet = Packet();
		packet.Write(this->GetCommHeader());
		packet.Write((u16)this->selected->id);

		auto reqId = generate_request_id();
		packet.Pack(CommandType::GetWorldList, reqId);

		INFO_LOG(Log::sceNet, "Requesting World Info");

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return { (u8)ErrorType::NotFound, 0 };
		}
		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return { resp.error, 0 };
		resp.stream = new vec_stream(resp.data, 1);
		worldInfoOut->clear();

		// Currently under the assumption that the first byte is some error code
		size_t offset = 1;
		u32 num_worlds = resp.stream->get<u32>();
		//memcpy(&num_worlds, resp.data.data() + offset, sizeof(num_worlds));
		//offset += 4;
		for (u32 i = 0; i < num_worlds; ++i)
		{
			SceNpMatching2World world{};
			//memcpy(&world.worldId, resp.data.data() + offset, sizeof(world.worldId));
			world.worldId = resp.stream->get<SceNpMatching2WorldId>();

			worldInfoOut->push_back(world);
			//offset += 4;
		}

		//worldInfoOut->emplace(worldInfo.worldId, worldInfo);
		return { 0, num_worlds };
	}

	int RPCNAgent::RequestSignalingInfo(std::string npid, u32 conn_id) {
		Packet packet = Packet();
		packet.Write(npid);
		packet.Write((u8)0);

		auto reqId = generate_request_id();
		packet.Pack(CommandType::RequestSignalingInfos, reqId);

		INFO_LOG(Log::sceNet, "Requesting Signaling Info for %s", npid.c_str());

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return (u8)ErrorType::NotFound;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError) {

			switch ((ErrorType)resp.error)
			{
			case ErrorType::NotFound:
			{
				ERROR_LOG(Log::sceNet, "Signaling information was requested for a user that doesn't exist or is not online");
				break;
			}
			default:
				ERROR_LOG(Log::sceNet, "Unexpected error in reply to RequestSignalingInfos: %d", resp.error);
				break;
			}
			return resp.error;
		}
		resp.stream = new vec_stream(resp.data, 1);

		const auto* sigAddr = resp.stream->get_flatbuffer<SignalingAddr>();
		if (resp.stream->is_error() || !sigAddr->ip()) {
			ERROR_LOG(Log::sceNet, "Malformed reply to RequestSignalingInfos command");
			return (u8)ErrorType::Malformed;
		}
		const u32 ip = static_cast<u32>(sigAddr->ip()->Get(0)) << 24 | static_cast<u32>(sigAddr->ip()->Get(1)) << 16 |
			static_cast<u32>(sigAddr->ip()->Get(2)) << 8 | static_cast<u32>(sigAddr->ip()->Get(3));
		u32 addr = htonl(ip);
		if (addr == 0)
			addr = htonl(getLocalIp(tls.netCtx.fd));
		g_signaling.connect(conn_id, addr, sigAddr->port());
		return 0;
	}

	int RPCNAgent::SearchRoom(PSPPointer<SceNpMatching2SearchRoomRequest> req, const SearchRoomResponse*& roomResp) {

		flatbuffers::FlatBufferBuilder builder(1024);
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<IntSearchFilter>>> final_intfilter_vec;
		if (req->intFilterNum && req->intFilter.IsValid())
		{
			std::vector<flatbuffers::Offset<IntSearchFilter>> davec{};
			for (u32 i = 0; i < req->intFilterNum; i++)
			{
				auto int_attr = CreateIntAttr(builder, req->intFilter[i].attr.id, req->intFilter[i].attr.num);
				auto bin = CreateIntSearchFilter(builder, req->intFilter[i].searchOperator, int_attr);
				davec.push_back(bin);
			}
			final_intfilter_vec = builder.CreateVector(davec);
		}
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinSearchFilter>>> final_binfilter_vec;
		if (req->binFilterNum && req->binFilter.IsValid())
		{
			std::vector<flatbuffers::Offset<BinSearchFilter>> davec;
			for (u32 i = 0; i < req->binFilterNum; i++)
			{
				auto bin_attr = CreateBinAttr(builder, req->binFilter[i].attr.id, builder.CreateVector(Memory::GetPointer(req->binFilter[i].attr.ptr.ptr), req->binFilter[i].attr.size));
				auto bin = CreateBinSearchFilter(builder, req->binFilter[i].searchOperator, bin_attr);
				davec.push_back(bin);
			}
			final_binfilter_vec = builder.CreateVector(davec);
		}

		flatbuffers::Offset<flatbuffers::Vector<u16>> attrid_vec;
		if (req->attrIdNum && req->attrId.IsValid())
		{
			std::vector<u16> attr_ids;
			for (u32 i = 0; i < req->attrIdNum; i++)
			{
				attr_ids.push_back(req->attrId[i]);
			}
			attrid_vec = builder.CreateVector(attr_ids);
		}

		SearchRoomRequestBuilder s_req(builder);
		s_req.add_option(req->option);
		s_req.add_worldId(req->worldId);
		s_req.add_lobbyId(req->lobbyId);
		s_req.add_rangeFilter_startIndex(req->rangeFilter.startIndex);
		s_req.add_rangeFilter_max(req->rangeFilter.max);
		s_req.add_flagFilter(req->flagFilter);
		s_req.add_flagAttr(req->flagAttr);
		if (req->intFilterNum)
			s_req.add_intFilter(final_intfilter_vec);
		if (req->binFilterNum)
			s_req.add_binFilter(final_binfilter_vec);
		if (req->attrIdNum)
			s_req.add_attrId(attrid_vec);

		auto req_finished = s_req.Finish();
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		auto reqId = generate_request_id();
		packet.Pack(CommandType::SearchRoom, reqId);

		INFO_LOG(Log::sceNet, "Requesting Search Room for World #%d, Lobby #%d", req->worldId, req->lobbyId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return (u8)ErrorType::NotFound;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return resp.error;
		resp.stream = new vec_stream(resp.data, 1);
		//                                                     20       12       0        8        6        1    
		// NPAgent::Recv('01 1000 28000000 0100000000000000 00 14000000 0C000000 00000600 08000400 06000000 01000000')

		//auto stream = new vec_stream(resp.data);
		roomResp = resp.stream->get_flatbuffer<SearchRoomResponse>();
		if (resp.stream->is_error()) {
			return (u8)ErrorType::Malformed;
		}
		//roomResp = _resp;

		return 0;
	}
	
	int RPCNAgent::CreateJoinRoom(PSPPointer<SceNpMatching2CreateJoinRoomRequest> req, const RoomDataInternal*& roomDataOut) {

		flatbuffers::FlatBufferBuilder builder(4096);

		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<IntAttr>>> final_searchintattrexternal_vec;
		if (req->roomSearchableIntAttrExternalNum && req->roomSearchableIntAttrExternal.IsValid())
		{
			std::vector<flatbuffers::Offset<IntAttr>> davec;
			for (u32 i = 0; i < req->roomSearchableIntAttrExternalNum; i++)
			{
				auto bin = CreateIntAttr(builder, req->roomSearchableIntAttrExternal[i].id, req->roomSearchableIntAttrExternal[i].num);
				davec.push_back(bin);
			}
			final_searchintattrexternal_vec = builder.CreateVector(davec);
		}

		// WWE SmackDown vs. RAW 2009 passes roomBinAttrExternal in roomSearchableBinAttrExternal so we parse based on attribute ids

		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinAttr>>> final_binattrinternal_vec;
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinAttr>>> final_searchbinattrexternal_vec;
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinAttr>>> final_binattrexternal_vec;

		std::vector<flatbuffers::Offset<BinAttr>> davec_binattrinternal;
		std::vector<flatbuffers::Offset<BinAttr>> davec_searchable_binattrexternal;
		std::vector<flatbuffers::Offset<BinAttr>> davec_binattrexternal;

		auto put_binattr = [&](SceNpMatching2AttributeId id, flatbuffers::Offset<BinAttr> bin)
		{
			switch (id)
			{
			case SCE_NP_MATCHING2_ROOM_BIN_ATTR_INTERNAL_1_ID:
			case SCE_NP_MATCHING2_ROOM_BIN_ATTR_INTERNAL_2_ID:
				davec_binattrinternal.push_back(bin);
				break;
			case SCE_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_1_ID:
			case SCE_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_2_ID:
				davec_binattrexternal.push_back(bin);
				break;
			case SCE_NP_MATCHING2_ROOM_SEARCHABLE_BIN_ATTR_EXTERNAL_1_ID:
				davec_searchable_binattrexternal.push_back(bin);
				break;
			default:
				ERROR_LOG(Log::sceNet, "Unexpected bin attribute id in createjoin_room request: 0x%x", id);
				break;
			}
		};

		if (req->roomBinAttrInternalNum && req->roomBinAttrInternal.IsValid())
		{
			for (u32 i = 0; i < req->roomBinAttrInternalNum; i++)
			{
				auto bin = CreateBinAttr(builder, req->roomBinAttrInternal[i].id, builder.CreateVector(Memory::GetPointer(req->roomBinAttrInternal[i].ptr.ptr), req->roomBinAttrInternal[i].size));
				put_binattr(req->roomBinAttrInternal[i].id, bin);
			}
		}

		if (req->roomSearchableBinAttrExternalNum && req->roomSearchableBinAttrExternal.IsValid())
		{
			for (u32 i = 0; i < req->roomSearchableBinAttrExternalNum; i++)
			{
				auto bin = CreateBinAttr(builder, req->roomSearchableBinAttrExternal[i].id, builder.CreateVector(Memory::GetPointer(req->roomSearchableBinAttrExternal[i].ptr.ptr), req->roomSearchableBinAttrExternal[i].size));
				put_binattr(req->roomSearchableBinAttrExternal[i].id, bin);
			}
		}

		if (req->roomBinAttrExternalNum && req->roomBinAttrExternal.IsValid())
		{
			for (u32 i = 0; i < req->roomBinAttrExternalNum; i++)
			{
				auto bin = CreateBinAttr(builder, req->roomBinAttrExternal[i].id, builder.CreateVector(Memory::GetPointer(req->roomBinAttrExternal[i].ptr.ptr), req->roomBinAttrExternal[i].size));
				put_binattr(req->roomBinAttrExternal[i].id, bin);
			}
		}

		if (!davec_binattrinternal.empty())
			final_binattrinternal_vec = builder.CreateVector(davec_binattrinternal);

		if (!davec_searchable_binattrexternal.empty())
			final_searchbinattrexternal_vec = builder.CreateVector(davec_searchable_binattrexternal);

		if (!davec_binattrexternal.empty())
			final_binattrexternal_vec = builder.CreateVector(davec_binattrexternal);

		flatbuffers::Offset<flatbuffers::Vector<u8>> final_roompassword;
		if (req->roomPassword.IsValid())
			final_roompassword = builder.CreateVector(req->roomPassword->data, 8);
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<GroupConfig>>> final_groupconfigs_vec;
		if (req->groupConfigNum && req->groupConfig.IsValid())
		{
			std::vector<flatbuffers::Offset<GroupConfig>> davec;
			for (u32 i = 0; i < req->groupConfigNum; i++)
			{
				auto bin = CreateGroupConfig(builder, req->groupConfig[i].slotNum, req->groupConfig[i].withLabel ? builder.CreateVector(req->groupConfig[i].label.data, 8) : 0, req->groupConfig[i].withPassword);
				davec.push_back(bin);
			}
			final_groupconfigs_vec = builder.CreateVector(davec);
		}
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>>> final_allowedusers_vec;
		if (req->allowedUserNum && req->allowedUser.IsValid())
		{
			std::vector<flatbuffers::Offset<flatbuffers::String>> davec;
			for (u32 i = 0; i < req->allowedUserNum; i++)
			{
				// Some games just give us garbage, make sure npid is valid before passing
				// Ex: Aquapazza (gives uninitialized buffer on the stack and allowedUserNum is hardcoded to 100)
				if (!np::is_valid_npid(req->allowedUser[i]))
				{
					ERROR_LOG(Log::sceNet, "AllowedUser is not valid NPID: %s", req->allowedUser[i].handle.data);
					continue;
				}

				auto bin = builder.CreateString(req->allowedUser[i].handle.data);
				davec.push_back(bin);
			}
			final_allowedusers_vec = builder.CreateVector(davec);
		}
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<flatbuffers::String>>> final_blockedusers_vec;
		if (req->blockedUserNum && req->blockedUser.IsValid())
		{
			std::vector<flatbuffers::Offset<flatbuffers::String>> davec;
			for (u32 i = 0; i < req->blockedUserNum; i++)
			{
				if (!np::is_valid_npid(req->blockedUser[i]))
				{
					ERROR_LOG(Log::sceNet, "BlockedUser is not valid NPID: %s", req->allowedUser[i].handle.data);
					continue;
				}

				auto bin = builder.CreateString(req->blockedUser[i].handle.data);
				davec.push_back(bin);
			}
			final_blockedusers_vec = builder.CreateVector(davec);
		}
		flatbuffers::Offset<flatbuffers::Vector<u8>> final_grouplabel;
		if (req->joinRoomGroupLabel.IsValid())
			final_grouplabel = builder.CreateVector(req->joinRoomGroupLabel->data, 8);
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinAttr>>> final_memberbinattrinternal_vec;
		if (req->roomMemberBinAttrInternalNum && req->roomMemberBinAttrInternal.IsValid())
		{
			std::vector<flatbuffers::Offset<BinAttr>> davec;
			for (u32 i = 0; i < req->roomMemberBinAttrInternalNum; i++)
			{
				auto bin = CreateBinAttr(
					builder, req->roomMemberBinAttrInternal[i].id, builder.CreateVector(Memory::GetPointer(req->roomMemberBinAttrInternal[i].ptr.ptr), req->roomMemberBinAttrInternal[i].size));
				davec.push_back(bin);
			}
			final_memberbinattrinternal_vec = builder.CreateVector(davec);
		}
		flatbuffers::Offset<OptParam> final_optparam;
		if (req->sigOptParam.IsValid())
			final_optparam = CreateOptParam(builder, req->sigOptParam->type, req->sigOptParam->flag, req->sigOptParam->hubMemberId);
		u64 final_passwordSlotMask = 0;
		if (req->passwordSlotMask.IsValid())
			final_passwordSlotMask = *req->passwordSlotMask;

		auto req_finished = CreateCreateJoinRoomRequest(builder, req->worldId, req->lobbyId, req->maxSlot, req->flagAttr, final_binattrinternal_vec, final_searchintattrexternal_vec,
			final_searchbinattrexternal_vec, final_binattrexternal_vec, final_roompassword, final_groupconfigs_vec, final_passwordSlotMask, final_allowedusers_vec, final_blockedusers_vec, final_grouplabel,
			final_memberbinattrinternal_vec, req->teamId, final_optparam);
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		auto reqId = generate_request_id();
		packet.Pack(CommandType::CreateRoom, reqId);

		INFO_LOG(Log::sceNet, "Requesting Create Join for World #%d, Lobby #%d", req->worldId, req->lobbyId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return (u8)ErrorType::NotFound;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return resp.error;
		resp.stream = new vec_stream(resp.data, 1);

		// 01 0D00 84010000 0100000000000000 00 700100002000000000001A00280026002000000018000000140010000E000000080004001A000000240000000000008400001000780000000C00000008000000000000000100000000000001020000003800000004000000DAFFFFFF000010000C000000E9118EA058FCE20068FFFFFF00005800040000000000000000000A0014000C00060008000A000000000010000C000000E9118EA058FCE20098FFFFFF000057000400000000000000010000001800000014001C000800140006000000000005000C001000140000000002100058000000000000800C000000FC118EA058FCE200010000000C00000008001000080004000800000014000000FC118EA058FCE20008000C00060008000800000000005900040000000000000000000A001000040008000C000A00000030000000240000000400000015000000687474703A2F2F44756D6D7941766174617255726C00000003000000666F78001000000052504353335F5A53675363633444377800000000

		//auto stream = new vec_stream(resp.data);
		roomDataOut = resp.stream->get_flatbuffer<RoomDataInternal>();
		if (resp.stream->is_error()) {
			return (u8)ErrorType::Malformed;
		}

		return 0;
	}

	int RPCNAgent::JoinRoom(PSPPointer<SceNpMatching2JoinRoomRequest> req, const JoinRoomResponse*& resp) {
		flatbuffers::FlatBufferBuilder builder(1024);

		flatbuffers::Offset<flatbuffers::Vector<u8>> final_roompassword;
		if (req->roomPassword.IsValid())
			final_roompassword = builder.CreateVector(req->roomPassword->data, 8);
		flatbuffers::Offset<flatbuffers::Vector<u8>> final_grouplabel;
		if (req->joinRoomGroupLabel.IsValid())
			final_grouplabel = builder.CreateVector(req->joinRoomGroupLabel->data, 8);
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinAttr>>> final_memberbinattrinternal_vec;
		if (req->roomMemberBinAttrInternalNum && req->roomMemberBinAttrInternal)
		{
			std::vector<flatbuffers::Offset<BinAttr>> davec;
			for (u32 i = 0; i < req->roomMemberBinAttrInternalNum; i++)
			{
				auto bin = CreateBinAttr(builder, req->roomMemberBinAttrInternal[i].id, builder.CreateVector(Memory::GetPointer(req->roomMemberBinAttrInternal[i].ptr.ptr), req->roomMemberBinAttrInternal[i].size));
				davec.push_back(bin);
			}
			final_memberbinattrinternal_vec = builder.CreateVector(davec);
		}
		flatbuffers::Offset<PresenceOptionData> final_optdata = CreatePresenceOptionData(builder, builder.CreateVector(req->optData.data, 16), req->optData.length);

		auto req_finished = CreateJoinRoomRequest(builder, req->roomId, final_roompassword, final_grouplabel, final_memberbinattrinternal_vec, final_optdata, req->teamId);
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		auto reqId = generate_request_id();
		packet.Pack(CommandType::JoinRoom, reqId);

		INFO_LOG(Log::sceNet, "Join Room #%d", req->roomId);

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return (u8)ErrorType::NotFound;
		}

		auto _resp = take_pending_request(reqId);
		if (_resp.error != (u8)ErrorType::NoError)
			return _resp.error;
		_resp.stream = new vec_stream(_resp.data, 1);

		//auto stream = new vec_stream(_resp.data);
		resp = _resp.stream->get_flatbuffer<JoinRoomResponse>();
		if (_resp.stream->is_error()) {
			return (u8)ErrorType::Malformed;
		}

		return 0;
		//return forge_request_with_com_id(builder, communication_id, CommandType::CreateRoomGUI, req_id);
	}

	int RPCNAgent::LeaveRoom(PSPPointer<SceNpMatching2LeaveRoomRequest> req, u64* resp) {
		flatbuffers::FlatBufferBuilder builder(1024);
		flatbuffers::Offset<PresenceOptionData> final_optdata = CreatePresenceOptionData(builder, builder.CreateVector(req->optData.data, 16), req->optData.length);
		auto req_finished = CreateLeaveRoomRequest(builder, req->roomId, final_optdata);
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		auto reqId = generate_request_id();
		packet.Pack(CommandType::LeaveRoom, reqId);

		INFO_LOG(Log::sceNet, "Leaving Room #%d", req->roomId);

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return (u8)ErrorType::Invalid;
		}

		auto _resp = take_pending_request(reqId);
		if (_resp.error != (u8)ErrorType::NoError)
			return _resp.error;
		_resp.stream = new vec_stream(_resp.data, 1);

		//memcpy(resp, &_resp.data, sizeof(u64));
		resp = reinterpret_cast<u64*>(_resp.stream->get<u64>());

		return 0;
	}

	int RPCNAgent::GetRoomDataInternal(SceNpMatching2GetRoomDataInternalRequest* req, const RoomDataInternal* resp) {
		flatbuffers::FlatBufferBuilder builder(1024);

		flatbuffers::Offset<flatbuffers::Vector<u16>> final_attr_ids_vec;
		if (req->attrIdNum && req->attrId.IsValid())
		{
			std::vector<u16> attr_ids;
			for (u32 i = 0; i < req->attrIdNum; i++)
			{
				attr_ids.push_back(req->attrId[i]);
			}
			final_attr_ids_vec = builder.CreateVector(attr_ids);
		}

		auto req_finished = CreateGetRoomDataInternalRequest(builder, req->roomId, final_attr_ids_vec);
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		auto reqId = generate_request_id();
		packet.Pack(CommandType::GetRoomDataInternal, reqId);

		INFO_LOG(Log::sceNet, "Requesting Room Data Internal for Room #%d", req->roomId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return (u8)ErrorType::NotFound;
		}

		auto response = take_pending_request(reqId);
		if (response.error != (u8)ErrorType::NoError)
			return response.error;
		response.stream = new vec_stream(response.data, 1);

		resp = response.stream->get_flatbuffer<RoomDataInternal>();
		if (response.stream->is_error())
			return (u8)ErrorType::Malformed;

		return 0;
	}

	int RPCNAgent::SendRoomMessage(SceNpMatching2SendRoomMessageRequest* req) {

		flatbuffers::FlatBufferBuilder builder(1024);

		std::vector<u16> dst;
		switch (req->castType)
		{
		case SCE_NP_MATCHING2_CASTTYPE_BROADCAST:
			break;
		case SCE_NP_MATCHING2_CASTTYPE_UNICAST:
			dst.push_back(req->dst.unicastTarget);
			break;
		case SCE_NP_MATCHING2_CASTTYPE_MULTICAST:
			for (u32 i = 0; i < req->dst.multicastTarget.memberIdNum && req->dst.multicastTarget.memberId; i++)
			{
				dst.push_back(req->dst.multicastTarget.memberId[i]);
			}
			break;
		case SCE_NP_MATCHING2_CASTTYPE_MULTICAST_TEAM:
			dst.push_back(req->dst.multicastTargetTeamId);
			break;
		default:
			_assert_(false);
			break;
		}

		auto req_finished = CreateSendRoomMessageRequest(builder, req->roomId, req->castType, builder.CreateVector(dst.data(), dst.size()), builder.CreateVector(Memory::GetPointer(req->msg.ptr), req->msgLen), req->option);
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		auto reqId = generate_request_id();
		packet.Pack(CommandType::SendRoomMessage, reqId);

		INFO_LOG(Log::sceNet, "Sending Room #%d a Message", req->roomId);

		// NPAgent::Send()
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return (u8)ErrorType::NotFound;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError) {
			ERROR_LOG(Log::sceNet, "Response Error: %s", PacketTypeNames[resp.error]);
			return resp.error;
		}
		resp.stream = new vec_stream(resp.data, 1);
		return 0;
	}

	int RPCNAgent::SetRoomDataInternal(SceNpMatching2SetRoomDataInternalRequest* req) {
		flatbuffers::FlatBufferBuilder builder(1024);
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinAttr>>> final_binattrinternal_vec;
		if (req->roomBinAttrInternalNum && req->roomBinAttrInternal.IsValid())
		{
			std::vector<flatbuffers::Offset<BinAttr>> davec;
			for (u32 i = 0; i < req->roomBinAttrInternalNum; i++)
			{
				auto bin = CreateBinAttr(builder, req->roomBinAttrInternal[i].id, builder.CreateVector(Memory::GetPointer(req->roomBinAttrInternal[i].ptr.ptr), req->roomBinAttrInternal[i].size));
				davec.push_back(bin);
			}
			final_binattrinternal_vec = builder.CreateVector(davec);
		}
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<RoomGroupPasswordConfig>>> final_grouppasswordconfig_vec;
		if (req->passwordConfigNum && req->passwordConfig.IsValid())
		{
			std::vector<flatbuffers::Offset<RoomGroupPasswordConfig>> davec;
			for (u32 i = 0; i < req->passwordConfigNum; i++)
			{
				auto rg = CreateRoomGroupPasswordConfig(builder, req->passwordConfig[i].groupId, req->passwordConfig[i].withPassword);
				davec.push_back(rg);
			}
			final_grouppasswordconfig_vec = builder.CreateVector(davec);
		}
		u64 final_passwordSlotMask = 0;
		if (req->passwordSlotMask.IsValid())
			final_passwordSlotMask = *req->passwordSlotMask;

		flatbuffers::Offset<flatbuffers::Vector<u16>> final_ownerprivilege_vec;
		if (req->ownerPrivilegeRankNum && req->ownerPrivilegeRank.IsValid())
		{
			std::vector<u16> priv_ranks;
			for (u32 i = 0; i < req->ownerPrivilegeRankNum; i++)
			{
				priv_ranks.push_back(req->ownerPrivilegeRank[i]);
			}
			final_ownerprivilege_vec = builder.CreateVector(priv_ranks);
		}

		auto req_finished =
			CreateSetRoomDataInternalRequest(builder, req->roomId, req->flagFilter, req->flagAttr, final_binattrinternal_vec, final_grouppasswordconfig_vec, final_passwordSlotMask, final_ownerprivilege_vec);
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		auto reqId = generate_request_id();
		packet.Pack(CommandType::SetRoomDataInternal, reqId);

		INFO_LOG(Log::sceNet, "Setting Room Data Internal for Room #%d", req->roomId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return (u8)ErrorType::NotFound;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return resp.error;
		resp.stream = new vec_stream(resp.data, 1);

		return 0;
	}

	int RPCNAgent::SetRoomDataExternal(SceNpMatching2SetRoomDataExternalRequest* req) {
		flatbuffers::FlatBufferBuilder builder(1024);
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<IntAttr>>> final_searchintattrexternal_vec;
		if (req->roomSearchableIntAttrExternalNum && req->roomSearchableIntAttrExternal)
		{
			std::vector<flatbuffers::Offset<IntAttr>> davec;
			for (u32 i = 0; i < req->roomSearchableIntAttrExternalNum; i++)
			{
				auto bin = CreateIntAttr(builder, req->roomSearchableIntAttrExternal[i].id, req->roomSearchableIntAttrExternal[i].num);
				davec.push_back(bin);
			}
			final_searchintattrexternal_vec = builder.CreateVector(davec);
		}

		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinAttr>>> final_searchbinattrexternal_vec;
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinAttr>>> final_binattrexternal_vec;

		std::vector<flatbuffers::Offset<BinAttr>> davec_searchable_binattrexternal;
		std::vector<flatbuffers::Offset<BinAttr>> davec_binattrexternal;

		auto put_binattr = [&](SceNpMatching2AttributeId id, flatbuffers::Offset<BinAttr> bin)
		{
			switch (id)
			{
			case SCE_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_1_ID:
			case SCE_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_2_ID:
				davec_binattrexternal.push_back(bin);
				break;
			case SCE_NP_MATCHING2_ROOM_SEARCHABLE_BIN_ATTR_EXTERNAL_1_ID:
				davec_searchable_binattrexternal.push_back(bin);
				break;
			default:
				ERROR_LOG(Log::sceNet, "Unexpected bin attribute id in set_roomdata_external request: 0x%x", id);
				break;
			}
		};

		if (req->roomSearchableBinAttrExternalNum && req->roomSearchableBinAttrExternal)
		{
			for (u32 i = 0; i < req->roomSearchableBinAttrExternalNum; i++)
			{
				auto bin = CreateBinAttr(builder, req->roomSearchableBinAttrExternal[i].id, builder.CreateVector(Memory::GetPointer(req->roomSearchableBinAttrExternal[i].ptr.ptr), req->roomSearchableBinAttrExternal[i].size));
				put_binattr(req->roomSearchableBinAttrExternal[i].id, bin);
			}
		}

		if (req->roomBinAttrExternalNum && req->roomBinAttrExternal)
		{
			for (u32 i = 0; i < req->roomBinAttrExternalNum; i++)
			{
				auto bin = CreateBinAttr(builder, req->roomBinAttrExternal[i].id, builder.CreateVector(Memory::GetPointer(req->roomBinAttrExternal[i].ptr.ptr), req->roomBinAttrExternal[i].size));
				put_binattr(req->roomBinAttrExternal[i].id, bin);
			}
		}

		if (!davec_searchable_binattrexternal.empty())
			final_searchbinattrexternal_vec = builder.CreateVector(davec_searchable_binattrexternal);

		if (!davec_binattrexternal.empty())
			final_binattrexternal_vec = builder.CreateVector(davec_binattrexternal);

		auto req_finished = CreateSetRoomDataExternalRequest(builder, req->roomId, final_searchintattrexternal_vec, final_searchbinattrexternal_vec, final_binattrexternal_vec);
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		auto reqId = generate_request_id();
		packet.Pack(CommandType::SetRoomDataExternal, reqId);

		INFO_LOG(Log::sceNet, "Setting Room Data External for Room #%d", req->roomId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return (u8)ErrorType::NotFound;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return resp.error;
		resp.stream = new vec_stream(resp.data, 1);

		return 0;
	}

	int RPCNAgent::SetUserInfo(SceNpMatching2SetUserInfoRequest* req) {
		flatbuffers::FlatBufferBuilder builder(1024);
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinAttr>>> final_memberbinattr_vec;
		if (req->userBinAttrNum && req->userBinAttr)
		{
			std::vector<flatbuffers::Offset<BinAttr>> davec;
			for (u32 i = 0; i < req->userBinAttrNum; i++)
			{
				auto bin = CreateBinAttr(builder, req->userBinAttr[i].id, builder.CreateVector(Memory::GetPointer(req->userBinAttr[i].ptr.ptr), req->userBinAttr[i].size));
				davec.push_back(bin);
			}
			final_memberbinattr_vec = builder.CreateVector(davec);
		}

		auto req_finished = CreateSetUserInfo(builder, req->serverId, final_memberbinattr_vec);
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		auto reqId = generate_request_id();
		packet.Pack(CommandType::SetUserInfo, reqId);

		INFO_LOG(Log::sceNet, "Setting UserInfo for Server #%d", req->serverId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return (u8)ErrorType::NotFound;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return resp.error;
		resp.stream = new vec_stream(resp.data, 1);

		return 0;
	}

	int RPCNAgent::GetRoomDataExternalList(SceNpMatching2GetRoomDataExternalListRequest* req, const GetRoomDataExternalListResponse* respData) {

		flatbuffers::FlatBufferBuilder builder(1024);
		std::vector<uint64_t> roomIds;
		for (u32 i = 0; i < req->roomIdNum && req->roomId; i++)
		{
			roomIds.push_back(req->roomId[i]);
		}
		std::vector<u16> attrIds;
		for (u32 i = 0; i < req->attrIdNum && req->attrId; i++)
		{
			attrIds.push_back(req->attrId[i]);
		}

		auto req_finished = CreateGetRoomDataExternalListRequestDirect(builder, &roomIds, &attrIds);
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		auto reqId = generate_request_id();
		packet.Pack(CommandType::GetRoomDataExternalList, reqId);

		INFO_LOG(Log::sceNet, "Getting RoomDataExternalList for Room #%d", req->roomId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return (u8)ErrorType::NotFound;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return resp.error;
		resp.stream = new vec_stream(resp.data, 1);

		respData = resp.stream->get_flatbuffer<GetRoomDataExternalListResponse>();
		if (resp.stream->is_error()) {
			return (u8)ErrorType::Malformed;
		}

		return 0;
	}
}
