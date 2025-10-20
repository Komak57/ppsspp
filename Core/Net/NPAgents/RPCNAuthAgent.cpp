#include "Core/Net/NPAgent.h"
#include <Core/HLE/HLE.h>
#include <Common/File/FileDescriptor.h>
#include <TimeUtil.h>
#include <chrono>
namespace net {
	// FIXME: Populate with actual connection credentials for RPCN
	RPCNAuthAgent::RPCNAuthAgent(std::string host, int port) {
		this->host_ = host;
		this->port_ = port;

		//std::string certificate = "";
		//InitializeSSL(certificate);
	}
	RPCNAuthAgent::~RPCNAuthAgent() {
		Disconnect();
	}

	void RPCNAuthAgent::Disconnect() {
		NOTICE_LOG(Log::sceNet, "NPAuthAgent::Disconnect()");
		cancelled = true;
		if (running)
			stop_read_thread();
		if (tls.enabled) {
			// First shut down network I/O so ssl_read unblocks
			ResetSSL();
		}
		if (connected) {
			if (!tls.enabled) {
				if ((intptr_t)sock_ != -1) {
					closesocket(sock_);
					sock_ = -1;
				}
			}
			connected = false;
		}
	}

	std::string RPCNAuthAgent::generate_npid()
	{
		std::string gen_npid = "RPCS3_";

		const char list_chars[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
			'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

		std::srand(static_cast<u32>(time(nullptr)));

		for (int i = 0; i < 10; i++)
		{
			gen_npid += list_chars[std::rand() % (sizeof(list_chars))];
		}

		return gen_npid;
	}

	u64 RPCNAuthAgent::generate_request_id()
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

	void RPCNAuthAgent::start_read_thread() {
		if (running) return;
		running = true;
		read_thread = std::thread(&RPCNAuthAgent::read_loop, this);
	}

	void RPCNAuthAgent::stop_read_thread() {
		running = false;
		if (read_thread.joinable()) {
			read_thread.join();
		}
	}

	// Blocking wait for a specific request_id
	RPCNResponse RPCNAuthAgent::take_pending_request(u64 request_id) {
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

	void RPCNAuthAgent::read_loop() {
		while (running && !cancelled) {
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
					cancelled = true;
					Disconnect();
					return;
				}
				buf.error = buf.stream->get<u8>();
				if ((ErrorType)buf.error != ErrorType::NoError) {
					if (buf.error > sizeof(PacketTypeNames))
						ERROR_LOG(Log::sceNet, "RPCN Read Error %d: %s", buf.error, hexdata.c_str());
					else
						ERROR_LOG(Log::sceNet, "RPCN Read Error 0x%02X: %s", buf.error, PacketTypeNames[buf.error]);
				}
				responses[header.uid] = std::move(buf);
				break;
			case PacketType::Notification:
				NOTICE_LOG(Log::sceNet, "RPCN Unknown Notification: %d", header.command);
				notifications[header.uid] = buf;
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

	std::unique_ptr<NPAgent> RPCNAuthAgent::CreateAgent() {
		return net::CreateNPAgent(NPAgentType::RPCN, this->host_, this->port_);
	}

	bool RPCNAuthAgent::Connect(int maxTries, double timeout, bool* cancelConnect) {
		std::string certPem = "-----BEGIN CERTIFICATE-----\n"
			"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\n"
			"-----END CERTIFICATE-----\n";
		InitializeSSL(certPem);
		mbedtls_ssl_conf_ciphersuites(&tls.sslConfig, forceCiphers);
		mbedtls_ssl_conf_max_version(&tls.sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
		WARN_LOG(Log::sceNet, "UNTESTED RPCNAuthAgent::Connect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);

		if (port_ <= 0) {
			ERROR_LOG(Log::IO, "Connect - Bad port");
			return false;
		}
		if (connected) {
			ERROR_LOG(Log::IO, "Connect - Already Connected");
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

	int RPCNAuthAgent::Login(const char* npid, const char* token, const char* password) {
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

	int RPCNAuthAgent::CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email) {
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

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return resp.error;
		resp.stream = new vec_stream(resp.data, 1);

		return true;
	}

	int RPCNAuthAgent::ResendToken(const char* npid, const char* password) {
		Packet packet = Packet();
		packet.Write(npid);
		packet.Write((u8)0);
		packet.Write(password);
		packet.Write((u8)0);

		auto reqId = generate_request_id();
		packet.Pack(CommandType::SendToken, reqId);

		INFO_LOG(Log::sceNet, "Sending Login Request");

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return false;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return resp.error;
		//resp.stream = new vec_stream(resp.data, 1);
		DEBUG_LOG(Log::sceNet, "Token has successfully been resent!");
		return 0;
	}

	int RPCNAuthAgent::SendResetToken(const char* npid, const char* email) {
		Packet packet = Packet();
		packet.Write(npid);
		packet.Write((u8)0);
		packet.Write(email);
		packet.Write((u8)0);

		auto reqId = generate_request_id();
		packet.Pack(CommandType::SendResetToken, reqId);

		INFO_LOG(Log::sceNet, "Sending Login Request");

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return (u8)ErrorType::Blocked;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return resp.error;
		//resp.stream = new vec_stream(resp.data, 1);

		DEBUG_LOG(Log::sceNet, "Password reset token has successfully been sent!");
		return 0;
	}

	int RPCNAuthAgent::ResetPassword(const char* npid, const char* token, const char* password) {
		Packet packet = Packet();
		packet.Write(npid);
		packet.Write((u8)0);
		packet.Write(token);
		packet.Write((u8)0);
		packet.Write(password);
		packet.Write((u8)0);

		auto reqId = generate_request_id();
		packet.Pack(CommandType::ResetPassword, reqId);

		INFO_LOG(Log::sceNet, "Sending Login Request");

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return false;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return resp.error;
		//resp.stream = new vec_stream(resp.data, 1);
		DEBUG_LOG(Log::sceNet, "Password has successfully been reset!");
		return 0;
	}

	u64 RPCNAuthAgent::GetNetworkTime() {
		Packet packet = Packet();

		auto reqId = generate_request_id();
		packet.Pack(CommandType::GetNetworkTime, reqId);

		INFO_LOG(Log::sceNet, "Sending Get Network Time Request");

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return -1;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return -2;
		resp.stream = new vec_stream(resp.data, 1);

		u64 tick = resp.stream->get<u64>();

		if (resp.stream->is_error()) {
			ERROR_LOG(Log::sceNet, "Malformed reply to GetNetworkTime command");
			return -3;
		}
		return tick;
	}
}
