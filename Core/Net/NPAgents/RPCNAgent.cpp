#include "Core/Net/NPAgent.h"
#include <TimeUtil.h>
#include <chrono>
#include <Core/HLE/HLE.h>
#include <Common/File/FileDescriptor.h>
#include "Common/File/FileUtil.h"
#include "Core/MemMapHelpers.h"
// #include <Core/Net/SignalingHandler.h>
#include <Core/HLE/proAdhoc.h>
#include <System/OSD.h>
#include <Core/HLE/sceNp.h>
#include <Core/HLE/sceNp2.h>
#include <Core/Net/fb_helpers.h>
#include <Data/Text/I18n.h>
#include <Core/CoreTiming.h>
#include <Core/Net/fb_helpers.h>
#include <Core/Config.h>
#include <Core/Util/PortManager.h>
#include <Core/Debugger/Np2Printer.h>
#include <Core/Net/SIGAgent.h>
#include <Core/System.h>

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

	u64 RPCNAgent::generate_uid(SceNpMatching2ContextId ctxId = 0, SceNpMatching2RequestId reqId = 0)
	{
		if (ctxId != 0 || reqId != 0)
			return static_cast<u64>(ctxId) << 32 | static_cast<u64>(reqId);

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
		cancelled = true;
		running = false;
		if (read_thread.joinable())
			read_thread.join();
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

			SceNpMatching2ContextId ctxId = static_cast<u32>(header.uid >> 32);
			SceNpMatching2RequestId reqId = header.uid & 0xFFFFFFFF;

			std::lock_guard<std::mutex> lock(buffer_mutex);
			switch ((PacketType)header.request) {
				ctxId = static_cast<u32>(header.uid >> 32);
				reqId = header.uid & 0xFFFFFFFF;
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
					switch ((CommandType)header.command) {
					case CommandType::GetWorldList: GetWorldInfo_Reply(ctxId, reqId, buf); break;
					case CommandType::SearchRoom: SearchRoom_Reply(ctxId, reqId, buf); break;
					case CommandType::CreateRoom: CreateJoinRoom_Reply(ctxId, reqId, buf); break;
					case CommandType::JoinRoom: JoinRoom_Reply(ctxId, reqId, buf); break;
					case CommandType::LeaveRoom: LeaveRoom_Reply(ctxId, reqId, buf); break;
					case CommandType::GetRoomDataInternal: GetRoomDataInternal_Reply(ctxId, reqId, buf); break;
					case CommandType::SetRoomDataInternal: SetRoomDataInternal_Reply(ctxId, reqId, buf); break;
					case CommandType::SetRoomDataExternal: SetRoomDataExternal_Reply(ctxId, reqId, buf); break;
					case CommandType::GetRoomDataExternalList: GetRoomDataExternalList_Reply(ctxId, reqId, buf); break;
					case CommandType::SetRoomMemberDataInternal: SetRoomDataInternal_Reply(ctxId, reqId, buf); break;
					case CommandType::GetRoomMemberDataInternal: GetRoomDataInternal_Reply(ctxId, reqId, buf); break;
					case CommandType::SendRoomMessage: SendRoomMessage_Reply(ctxId, reqId, buf); break;
					case CommandType::SetUserInfo: SetUserInfo_Reply(ctxId, reqId, buf); break;
					case CommandType::RequestSignalingInfos: RequestSignalingInfo_Reply(ctxId, reqId, buf); break;
					default: responses[header.uid] = std::move(buf); break; // Response is synchronous
				}
				break;
				case PacketType::Notification:
				switch ((NotificationType)header.command) {
				case NotificationType::UserJoinedRoom: sigServer->UserJoinedRoom(buf); break;
				case NotificationType::RoomMessageReceived: sigServer->RoomMessageReceived(buf); break;
				case NotificationType::UserLeftRoom: sigServer->UserLeftRoom(buf); break;
				case NotificationType::RoomDestroyed: sigServer->RoomDestroyed(buf); break;
				case NotificationType::UpdatedRoomDataInternal: sigServer->UpdatedRoomDataInternal(buf); break;
				case NotificationType::UpdatedRoomMemberDataInternal: sigServer->UpdatedRoomMemberDataInternal(buf); break;
				case NotificationType::SignalingHelper: sigServer->SignalingHelper(buf); break;
					// GUI
				case NotificationType::MemberJoinedRoomGUI: sigServer->MemberJoinedRoomGUI(buf); break;
				case NotificationType::MemberLeftRoomGUI: sigServer->MemberLeftRoomGUI(buf); break;
				case NotificationType::RoomDisappearedGUI: sigServer->RoomDisappearedGUI(buf); break;
				case NotificationType::RoomOwnerChangedGUI: sigServer->RoomOwnerChangedGUI(buf); break;
				case NotificationType::UserKickedGUI: sigServer->UserKickedGUI(buf); break;
				case NotificationType::QuickMatchCompleteGUI: sigServer->QuickMatchCompleteGUI(buf); break;
					ERROR_LOG(Log::sceNet, "Unhandled GUI Notification: %s", NotificationTypeNames[header.command]);
					break;
				default:
					NOTICE_LOG(Log::sceNet, "RPCN Unknown Notification: %d", header.command);
					notifications[header.uid] = buf;
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
		std::string certPem = ""; // No cert, obtain through handshake
		auto cert_path = GetSysDirectory(DIRECTORY_CACHE) / (host_ + ".pem");
		if (File::Exists(cert_path)) {
			File::ReadTextFileToString(cert_path, &certPem);
		}
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

		sockaddr_in client_addr;
		socklen_t client_addr_size;

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
				
				// 6. Certificate Generation / Caching (The new logic)
				if (!File::Exists(cert_path)) {
					const mbedtls_x509_crt* peer_cert = mbedtls_ssl_get_peer_cert(&tls.sslCtx);
					if (peer_cert != nullptr) {
						INFO_LOG(Log::sceNet, "Generating local PEM from server certificate...");
						
						// MbedTLS stores the raw DER format in peer_cert->raw
						// We need to Base64 encode it to create a PEM
						size_t b64_len = 0;
						mbedtls_base64_encode(nullptr, 0, &b64_len, peer_cert->raw.p, peer_cert->raw.len);
						
						std::vector<unsigned char> b64_buf(b64_len + 1);
						mbedtls_base64_encode(b64_buf.data(), b64_buf.size(), &b64_len, peer_cert->raw.p, peer_cert->raw.len);
						
						// Format into standard PEM with 64-character line breaks
						std::string generatedPem = "-----BEGIN CERTIFICATE-----\n";
						std::string b64_str((char*)b64_buf.data(), b64_len);
						
						for (size_t i = 0; i < b64_str.length(); i += 64) {
							generatedPem += b64_str.substr(i, 64) + "\n";
						}
						generatedPem += "-----END CERTIFICATE-----\n";
						
						// Save to disk so next time InitializeSSL(certPem) uses it securely
						File::WriteStringToFile(true, generatedPem, cert_path);
						INFO_LOG(Log::sceNet, "Saved server certificate to %s", cert_path.ToString().c_str());
					} else {
						ERROR_LOG(Log::sceNet, "Server did not provide a certificate during handshake.");
						goto sslretry;
					}
				}

				INFO_LOG(Log::sceNet, "Connect - Connection Successful. TLS: %s, Cipher: %s", mbedtls_ssl_get_version(&tls.sslCtx), mbedtls_ssl_get_ciphersuite(&tls.sslCtx));
				connected = true;
				STUN_addr = std::move(possible);

				// Obtain our local IP address related to our connection to the RPCN server
				client_addr_size = sizeof(client_addr);
				if (getsockname(tls.netCtx.fd, reinterpret_cast<struct sockaddr*>(&client_addr), &client_addr_size) != 0)
				{
					ERROR_LOG(Log::sceNet, "Failed to get the client address from the socket!");
				}
				sigServer->local_addr_sig.store(client_addr.sin_addr.s_addr);
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

		auto reqId = generate_uid();
		packet.Pack(CommandType::Login, reqId);

		INFO_LOG(Log::Matching, "Sending Login Request");

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send, returning Empty");
			return false;
		}

		/*Packet response = Packet();
		int ret = Recv(&response);
		if (ret < 0) {
			ERROR_LOG(Log::Matching, "Failed to read response -0x%04x", -ret);
			return false;
		}*/
		auto resp = take_pending_request(reqId);

		switch ((ErrorType)resp.error) {
		case ErrorType::NoError:
			break;
		case ErrorType::LoginError:
			return hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_BUSY, "Login Error");
		case ErrorType::LoginAlreadyLoggedIn:
			return hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_ALREADY_JOINED, "User is already signed in");
		case ErrorType::LoginInvalidUsername:
			return hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_USER, "Invalid Login Credentials");
		case ErrorType::LoginInvalidPassword:
			return hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_PASSWORD_MISMATCH, "Invalid Login Credentials");
		case ErrorType::LoginInvalidToken:
			return hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_INVALID_TICKET, "Invalid Token");
		default:
			return hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST, "Unable to Log In (%d)", resp.error);
		}
		resp.stream = new vec_stream(resp.data, 1);

		auto name = resp.stream->get_string(false);
		memcpy(&online_name.data, name.c_str(),
			std::min<size_t>(49, name.length()));
		auto avatar = resp.stream->get_string(false);
		memcpy(&avatar_url.data, avatar.c_str(),
			std::min<size_t>(127, avatar.length()));
		user_id.store(resp.stream->get<s64>());

		NpSetNpId(g_Config.sInfraNpId);

		return SCE_NP_MATCHING2_OKAY;
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

		auto reqId = generate_uid();
		packet.Pack(CommandType::Create, reqId);

		INFO_LOG(Log::Matching, "Sending Registration Request");

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send, returning Empty");
			return false;
		}
		/*Packet response = Packet();
		int ret = Recv(&response);
		if (ret < 0) {
			ERROR_LOG(Log::Matching, "Failed to read response -0x%04x", -ret);
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
		INFO_LOG(Log::Matching, "NPAgent::Recv('%s')", hexdata.c_str());*/
		return true;
	}
	int RPCNAgent::GetServers(SceNpCommunicationId npTitleId) {
		memcpy(&this->commId, &npTitleId, sizeof(SceNpCommunicationId));

		Packet packet = Packet();
		packet.Write(this->GetCommHeader());

		auto reqId = generate_uid();
		packet.Pack(CommandType::GetServerList, reqId);

		INFO_LOG(Log::Matching, "Sending Server List Request: %llu", reqId);

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send, returning Empty");
			return SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return resp.error;
		resp.stream = new vec_stream(resp.data, 1);

		u16 num_servs = resp.stream->get<u16>();

		INFO_LOG(Log::Matching, "%d servers returned", num_servs);
		selected = nullptr;
		if (npServer)
			npServer->servers.clear();
		for (u16 i = 0; i < num_servs; i++)
		{
			NPServerInfo server{};
			server.nptype = NPAgentType::RPCN;
			server.id = resp.stream->get<SceNpMatching2ServerId>();
			//server.num = i+1;
			server.host = this->host_;
			server.port = this->port_;
			server.status = SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE;

			INFO_LOG(Log::Matching, " - ID: %d", server.id);
			//INFO_LOG(Log::Matching, " - Num: %d", server.num);
			INFO_LOG(Log::Matching, " - Availability: %d", server.status);

			npServer->servers.push_back(server);
			//serversPtr->emplace(server_id, net::CreateNPAgent(net::NPAgentType::RPCN, server_id, this->host_, this->port_, SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE));
		}
		if (resp.stream->is_error()) {
			npServer->servers.clear();
			ERROR_LOG(Log::Matching, "Malformed reply to GetServerList command");
			return SCE_NP_MATCHING2_ERROR_CONNECTION_CLOSED_BY_SERVER;
		}
		//serversPtr->emplace(1, net::CreateNPAgent(net::NPAgentType::RPCN, 1, "rpcn.revurb.us", 31313, SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE));
		//serversPtr->emplace(2, net::CreateNPAgent(net::NPAgentType::RPCN, 2, "rpcn.revurb.us", 3657, SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE));
		return SCE_NP_MATCHING2_OKAY;
	}
	u64 RPCNAgent::GetNetworkTime() {
		Packet packet = Packet();

		auto reqId = generate_uid();
		packet.Pack(CommandType::GetNetworkTime, reqId);

		INFO_LOG(Log::Matching, "Sending Get Network Time Request");

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send, returning Empty");
			return -1;
		}

		auto resp = take_pending_request(reqId);
		if (resp.error != (u8)ErrorType::NoError)
			return -2;
		resp.stream = new vec_stream(resp.data, 1);

		u64 tick = resp.stream->get<u64>();

		if (resp.stream->is_error()) {
			ERROR_LOG(Log::Matching, "Malformed reply to GetNetworkTime command");
			return -3;
		}
		return tick;
	}
	int RPCNAgent::GetWorldInfo(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, int server_id, SceNpCommunicationId npTitleId) {
		memcpy(&this->commId, &npTitleId, sizeof(SceNpCommunicationId));

		Packet packet = Packet();
		packet.Write(this->GetCommHeader());
		// RPCN takes server_id in Big Endian
		packet.Write(u8((this->selected->id) & 0xFF));
		packet.Write(u8((this->selected->id >> 8) & 0xFF));

		packet.Pack(CommandType::GetWorldList, generate_uid(ctxId, reqId));

		INFO_LOG(Log::Matching, "Requesting World Info for Server %d", this->selected->id);

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send");
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE), 0);
		}
		//worldInfoOut->emplace(worldInfo.worldId, worldInfo);
		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::GetWorldInfo_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp) {
		if (resp.error != (u8)ErrorType::NoError)
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST), 0);
		resp.stream = new vec_stream(resp.data, 1);

		// Currently under the assumption that the first byte is some error code
		size_t offset = 1;
		u32 num_worlds = resp.stream->get<u32>();
		//num_worlds = 8;

		// First attempts for new games won't contain a world.
		if (num_worlds == 0) {
			ERROR_LOG(Log::Matching, "No Worlds Returned");
			// Retry if the server has automatic server creation
			if (tries < RETRY_COUNT) {
				tries++;
				return GetWorldInfo(ctxId, reqId, this->selected->id, this->commId);
			}
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_WORLD), 0);
		}

		static_assert(sizeof(PSPList<SceNpMatching2World>) == 0x40, "Size mismatch!");

		u32 alloc = sizeof(SceNpMatching2GetWorldInfoListResponse);
		auto response = PSPPointer<SceNpMatching2GetWorldInfoListResponse>::Create(np_memory.Alloc(alloc));
		response->worldNum = num_worlds;
		// Allocate space for all worlds
		u32 worldsSize = sizeof(PSPList<SceNpMatching2World>) * num_worlds;
		// We have a maximum size
		if (worldsSize > SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetWorldInfoList)
			worldsSize = SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetWorldInfoList;
		response->world_list = PSPPointer<PSPList<SceNpMatching2World>>::Create(np_memory.Alloc(worldsSize));
		// Transfer WorldID
		NOTICE_LOG(Log::Matching, "Received %d worlds", num_worlds);

		// Phantasy Star MUST start with World Index 1
		// Patapon3 tries to interract with Index 0, which just means an error state
		// Ace Combat similarly does this, and requires 1 server, 8 worlds
		// Both the World Index and World ID are used in CreateJoinRoom requests
		// RPCN requests only use the WorldID, so they must be converted prior to sending requests
		//auto world_id = resp.stream->get<SceNpMatching2WorldId>();
		for (u32 i = 0; i < num_worlds; ++i) {
			response->world_list[i].next = 0;
			if (i + 1 < num_worlds)
				response->world_list[i].next = response->world_list + (i+1);
			response->world_list[i]->worldId = resp.stream->get<SceNpMatching2WorldId>();
			response->world_list[i]->curNumOfRoom = 0;
			response->world_list[i]->curNumOfTotalRoomMember = 0;
			NOTICE_LOG(Log::Matching, " - World %d => WorldId: %d", i, response->world_list[i]->worldId);
			npServer->cache.AddWorld(response->world_list[i].data);
		}

		if (resp.stream->is_error()) {
			ERROR_LOG(Log::Matching, "World Info Malformed");
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_WORLD, 0);
		}


		return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, SCE_NP_MATCHING2_OKAY, response.ptr);
	}
	int RPCNAgent::RequestSignalingInfo(std::string npid, u32 conn_id) {
		Packet packet = Packet();
		packet.Write(npid);
		packet.Write((u8)0);

		auto reqId = generate_uid(1, conn_id);
		packet.Pack(CommandType::RequestSignalingInfos, reqId);

		INFO_LOG(Log::Matching, "Requesting Signaling Info for %s", npid.c_str());

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send, returning Empty");
			return SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE;
		}
		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::RequestSignalingInfo_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId conn_id, RPCNResponse resp) {

		switch ((ErrorType)resp.error)
		{
		case ErrorType::NoError:
			break;
		case ErrorType::NotFound:
		{
			ERROR_LOG(Log::Matching, "Signaling information was requested for a user that doesn't exist or is not online");
			return SCE_NP_MATCHING2_SIGNALING_ERROR_MATCHING2_PEER_NOT_FOUND;
		}
		default:
			ERROR_LOG(Log::Matching, "Unexpected error in RequestSignalingInfo_Reply: %d", resp.error);
			return SCE_NP_MATCHING2_SIGNALING_ERROR_PARSER_FAILED;
		}
		resp.stream = new vec_stream(resp.data, 1);

		const auto* sigAddr = resp.stream->get_flatbuffer<SignalingAddr>();
		if (resp.stream->is_error() || !sigAddr->ip()) {
			ERROR_LOG(Log::Matching, "Malformed RequestSignalingInfo_Reply");
			return SCE_NP_MATCHING2_SIGNALING_ERROR_PARSER_FAILED;
		}

		u32 addr = RegisterIp(sigAddr->ip());
		if (addr == 0)
			addr = sigServer->local_addr_sig.load();

		u16 port = sigAddr->port();
		/*if (port == SCE_SIGN_PORT)
			port = SCE_INTERNAL_PORT;*/

		sigServer->connect(conn_id, addr, port);
		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::SearchRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2SearchRoomRequest> req) {

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

		//auto reqId = generate_uid();
		packet.Pack(CommandType::SearchRoom, generate_uid(ctxId, reqId));

		INFO_LOG(Log::Matching, "Requesting Search Room for World Index #%d, Lobby #%d", req->worldId, req->lobbyId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send");
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE), 0);
		}

		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::SearchRoom_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp) {
		if (resp.error != (u8)ErrorType::NoError)
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SIGNALING_ERROR_PARSER_FAILED), 0);
		resp.stream = new vec_stream(resp.data, 1);
		//                                                     20       12       0        8        6        1    
		// NPAgent::Recv('01 1000 28000000 0100000000000000 00 14000000 0C000000 00000600 08000400 06000000 01000000')

		//auto stream = new vec_stream(resp.data);
		auto roomResp = resp.stream->get_flatbuffer<SearchRoomResponse>();
		if (resp.stream->is_error()) {
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SIGNALING_ERROR_PARSER_FAILED), 0);
		}
		//roomResp = _resp;

		uint32_t room_count = roomResp->rooms() ? roomResp->rooms()->size() : 0;
		uint32_t start_index = roomResp->startIndex();
		uint32_t total_rooms = roomResp->total();

		INFO_LOG(Log::Matching, " - Start Index: %d", start_index);
		INFO_LOG(Log::Matching, " - Total:       %d", total_rooms);
		INFO_LOG(Log::Matching, " - Rooms:       %d", room_count);

		u32 respSize = sizeof(SceNpMatching2SearchRoomResponse);
		u32 respPtr = np_memory.Alloc(respSize);
		auto respData = PSPPointer<SceNpMatching2SearchRoomResponse>::Create(respPtr);

		::np::SearchRoomResponse_to_SceNpMatching2SearchRoomResponse(np_memory, roomResp, respData);
		print_SceNpMatching2SearchRoomResponse(respData);

		return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, SCE_NP_MATCHING2_OKAY, respData.ptr);
	}
	int RPCNAgent::CreateJoinRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2CreateJoinRoomRequest> req) {

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
				NOTICE_LOG(Log::Matching, "Added %d to BinAttrInternal", id);
				davec_binattrinternal.push_back(bin);
				break;
			case SCE_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_1_ID:
			case SCE_NP_MATCHING2_ROOM_BIN_ATTR_EXTERNAL_2_ID:
				NOTICE_LOG(Log::Matching, "Added %d to BinAttrExternal", id);
				davec_binattrexternal.push_back(bin);
				break;
			case SCE_NP_MATCHING2_ROOM_SEARCHABLE_BIN_ATTR_EXTERNAL_1_ID:
				NOTICE_LOG(Log::Matching, "Added %d to sBinAttrInternal", id);
				davec_searchable_binattrexternal.push_back(bin);
				break;
			default:
				ERROR_LOG(Log::Matching, "Unexpected bin attribute id in createjoin_room request: 0x%x", id);
				break;
			}
		};

		if (req->roomBinAttrInternalNum && req->roomBinAttrInternal.IsValid())
		{
			for (u32 i = 0; i < req->roomBinAttrInternalNum; i++)
			{
				auto binAttr = req->roomBinAttrInternal + i;
				auto bin = CreateBinAttr(builder, binAttr->id, builder.CreateVector(Memory::GetPointer(binAttr->ptr.ptr), binAttr->size));
				put_binattr(binAttr->id, bin);
			}
		}

		if (req->roomSearchableBinAttrExternalNum && req->roomSearchableBinAttrExternal.IsValid())
		{
			for (u32 i = 0; i < req->roomSearchableBinAttrExternalNum; i++)
			{
				auto binAttr = req->roomSearchableBinAttrExternal + i;
				auto bin = CreateBinAttr(builder, binAttr->id, builder.CreateVector(Memory::GetPointer(binAttr->ptr.ptr), binAttr->size));
				put_binattr(binAttr->id, bin);
			}
		}

		if (req->roomBinAttrExternalNum && req->roomBinAttrExternal.IsValid())
		{
			for (u32 i = 0; i < req->roomBinAttrExternalNum; i++)
			{
				auto binAttr = req->roomBinAttrExternal + i;
				auto bin = CreateBinAttr(builder, binAttr->id, builder.CreateVector(Memory::GetPointer(binAttr->ptr.ptr), binAttr->size));
				put_binattr(binAttr->id, bin);
			}
		}

		if (!davec_binattrinternal.empty())
			final_binattrinternal_vec = builder.CreateVector(davec_binattrinternal);

		if (!davec_searchable_binattrexternal.empty())
			final_searchbinattrexternal_vec = builder.CreateVector(davec_searchable_binattrexternal);

		if (!davec_binattrexternal.empty())
			final_binattrexternal_vec = builder.CreateVector(davec_binattrexternal);

		flatbuffers::Offset<flatbuffers::Vector<u8>> final_roompassword;
		if (req->passwordSlotMask.IsValid()) {
			if (req->roomPassword.IsValid())
				final_roompassword = builder.CreateVector(req->roomPassword->data, 8);
			else {
				auto default_pwd = new u8[SCE_NP_MATCHING2_SESSION_PASSWORD_SIZE]{ 0x50, 0x77, 0x4E, 0x61, 0x4E, 0x00, 0x00, 0x00 };
				final_roompassword = builder.CreateVector(default_pwd, 8);
			}
		}
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
					ERROR_LOG(Log::Matching, "AllowedUser is not valid NPID: %s", req->allowedUser[i].handle.data);
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
					ERROR_LOG(Log::Matching, "BlockedUser is not valid NPID: %s", req->allowedUser[i].handle.data);
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

		NOTICE_LOG(Log::Matching, "Compiling %d memberBinAttrs from structured request", req->roomMemberBinAttrInternalNum);
		if (req->roomMemberBinAttrInternalNum && req->roomMemberBinAttrInternal.IsValid())
		{
			std::vector<flatbuffers::Offset<BinAttr>> davec;
			for (u32 i = 0; i < req->roomMemberBinAttrInternalNum; i++)
			{
				auto binAttr = req->roomMemberBinAttrInternal + i;
				NOTICE_LOG(Log::Matching, " - ID: %d, Size: %d", binAttr->id, binAttr->size);
				auto bin = CreateBinAttr(builder, binAttr->id, builder.CreateVector(Memory::GetPointer(binAttr->ptr.ptr), binAttr->size));
				davec.push_back(bin);
			}
			final_memberbinattrinternal_vec = builder.CreateVector(davec);
		}
		flatbuffers::Offset<OptParam> final_optparam;
		if (req->sigOptions.IsValid())
			final_optparam = CreateOptParam(builder, req->sigOptions->type, req->sigOptions->flag, req->sigOptions->hubMemberId);
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

		packet.Pack(CommandType::CreateRoom, generate_uid(ctxId, reqId));

		INFO_LOG(Log::Matching, "Requesting Create Join for World #%d, Lobby #%d", req->worldId, req->lobbyId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send, returning Empty");
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE), 0);
		}

		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::CreateJoinRoom_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp) {
		if (resp.error != (u8)ErrorType::NoError) {
			switch ((ErrorType)resp.error) {
			case ErrorType::Malformed:
				return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST, "Malformed Request"), 0);
			case ErrorType::NotFound:
				return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE, "Send Failed"), 0);
			case ErrorType::RoomGroupMaxSlotMismatch:
				return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_INVALID_GROUP_SLOT_NUM, "Group Max Slot Mismatch"), 0);
			case ErrorType::RoomPasswordMissing:
				return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_INVALID_PASSWORD_SLOT_MASK, "Password Slot Mask Missing"), 0);
			case ErrorType::RoomGroupNoJoinLabel:
				return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_DUPLICATE_GROUP_LABEL, "Group No Join Label"), 0);
				break;
			default:
				return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::Matching, resp.error, "Unknown Error creating room"), 0);
			}
		}
		resp.stream = new vec_stream(resp.data, 1);

		auto _context = ctx.find(ctxId);
		if (_context == ctx.end())
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND, "Context not Found"), 0);
		// 01 0D00 84010000 0100000000000000 00 700100002000000000001A00280026002000000018000000140010000E000000080004001A000000240000000000008400001000780000000C00000008000000000000000100000000000001020000003800000004000000DAFFFFFF000010000C000000E9118EA058FCE20068FFFFFF00005800040000000000000000000A0014000C00060008000A000000000010000C000000E9118EA058FCE20098FFFFFF000057000400000000000000010000001800000014001C000800140006000000000005000C001000140000000002100058000000000000800C000000FC118EA058FCE200010000000C00000008001000080004000800000014000000FC118EA058FCE20008000C00060008000800000000005900040000000000000000000A001000040008000C000A00000030000000240000000400000015000000687474703A2F2F44756D6D7941766174617255726C00000003000000666F78001000000052504353335F5A53675363633444377800000000

		//auto stream = new vec_stream(resp.data);
		auto roomData = resp.stream->get_flatbuffer<RoomDataInternal>();
		if (resp.stream->is_error()) {
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST), 0);
		}
		
		u32 respSize = sizeof(SceNpMatching2CreateJoinRoomResponse);
		auto respData = PSPPointer<SceNpMatching2CreateJoinRoomResponse>::Create(np_memory.Alloc(respSize));

		u32 infoSize = sizeof(SceNpMatching2RoomDataInternal);
		respData->roomDataInternal = PSPPointer<SceNpMatching2RoomDataInternal>::Create(np_memory.Alloc(infoSize));
		SceNpId* npId = NpGetNpId();
		::np::RoomDataInternal_to_SceNpMatching2RoomDataInternal(np_memory, roomData, respData->roomDataInternal, npId, _context->second->include_onlinename, _context->second->include_avatarurl);
		print_SceNpMatching2CreateJoinRoomResponse(respData);

		// Cache Rooms
		//rooms.push_back(roomData);
		npServer->cache.AddRoom(*respData->roomDataInternal);
		npServer->cache.SavePassword(respData->roomDataInternal->roomId);

		int ret = notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, SCE_NP_MATCHING2_OKAY, respData.ptr);
		// Force a join-room event
		//auto host = respData->roomDataInternal->memberList.me;
		//if (host) {
		//	u32 _size = sizeof(SceNpMatching2RoomMemberUpdateInfo);
		//	u32 ptr = np_memory.Alloc(_size);
		//	auto notif = PSPPointer<SceNpMatching2RoomMemberUpdateInfo>::Create(ptr);
		//	// Populate from the host's member data
		//	notif->roomMemberDataInternal = host;
		//	notif->eventCause = 0;
		//	notif->optData.length = 0;
		//	notifyRoomEventHandler(respData->roomDataInternal->roomId, host->memberId, SCE_NP_MATCHING2_ROOM_EVENT_MemberJoined, notif.ptr);
		//}

		// RPCS3 triggers this in sceNpSignalingActivateConnection
		//sigServer->init_sig(*npId, respData->roomDataInternal->roomId, respData->roomDataInternal->memberList.me->memberId);
		//sigServer->init_sig(*npId);
		//sigServer->set_self_sig_info(*npId);

		return ret;
	}
	int RPCNAgent::JoinRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2JoinRoomRequest> req) {
		flatbuffers::FlatBufferBuilder builder(1024);

		flatbuffers::Offset<flatbuffers::Vector<u8>> final_roompassword;
		if (req->roomPassword.IsValid())
			final_roompassword = builder.CreateVector(req->roomPassword->data, 8);
		flatbuffers::Offset<flatbuffers::Vector<u8>> final_grouplabel;
		if (req->joinRoomGroupLabel.IsValid())
			final_grouplabel = builder.CreateVector(req->joinRoomGroupLabel->data, 8);
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinAttr>>> final_memberbinattrinternal_vec;
		if (req->roomMemberBinAttrInternalNum && req->roomMemberBinAttrInternal.IsValid())
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

		packet.Pack(CommandType::JoinRoom, generate_uid(ctxId, reqId));

		INFO_LOG(Log::Matching, "Join Room #%d", req->roomId);

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send, returning Empty");
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE), 0);
		}

		return SCE_NP_MATCHING2_OKAY;
		//return forge_request_with_com_id(builder, communication_id, CommandType::CreateRoomGUI, req_id);
	}
	int RPCNAgent::JoinRoom_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp) {
		switch ((ErrorType)resp.error) {
		case ErrorType::NoError:
			break;
		case ErrorType::Malformed:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST, "Malformed Request"), 0);
		case ErrorType::NotFound:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE, "Bad Response"), 0);
		case ErrorType::RoomMissing:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_ERROR_ROOM_NOT_FOUND, "Room Missing"), 0);
		case ErrorType::RoomAlreadyJoined:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_ALREADY_JOINED, "Already Joined Room"), 0);
		case ErrorType::RoomFull:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_ROOM_FULL, "Room is Full"), 0);
		case ErrorType::RoomPasswordMismatch:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_PASSWORD_MISMATCH, "Incorrect Password"), 0);
		case ErrorType::RoomGroupFull:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_GROUP_FULL, "Group is Full"), 0);
		case ErrorType::RoomGroupJoinLabelNotFound:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_DUPLICATE_GROUP_LABEL, "Duplicate Group Label"), 0);
		default:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::Matching, -resp.error, "Unknown Error Joining Room"), 0);
		}
		resp.stream = new vec_stream(resp.data, 1);

		auto _context = ctx.find(ctxId);
		if (_context == ctx.end())
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND, "Context not Found"), 0);

		//auto stream = new vec_stream(_resp.data);
		auto joinRoomResp = resp.stream->get_flatbuffer<JoinRoomResponse>();
		if (resp.stream->is_error()) {
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SIGNALING_ERROR_PARSER_FAILED), 0);
		}
		u32 sizeof_room_resp = sizeof(SceNpMatching2JoinRoomResponse);
		u32 roomRespPtr = np_memory.Alloc(sizeof_room_resp);
		auto room_resp = PSPPointer<SceNpMatching2JoinRoomResponse>::Create(roomRespPtr);

		u32 sizeof_room_info = sizeof(SceNpMatching2RoomDataInternal);
		u32 roomInfoPtr = np_memory.Alloc(sizeof_room_info);
		room_resp->roomDataInternal = PSPPointer<SceNpMatching2RoomDataInternal>::Create(roomInfoPtr);

		SceNpId* npId = NpGetNpId();
		::np::RoomDataInternal_to_SceNpMatching2RoomDataInternal(np_memory, joinRoomResp->room_data(), room_resp->roomDataInternal, npId, _context->second->include_onlinename, _context->second->include_avatarurl);
		print_SceNpMatching2RoomDataInternal(room_resp->roomDataInternal);
		// Cache room_info
		npServer->cache.AddRoom(*room_resp->roomDataInternal);

		// RPCS3 triggers this in sceNpSignalingActivateConnection
		//sigServer->init_sig(*npId, room_resp->roomDataInternal->roomId, room_resp->roomDataInternal->memberList.me->memberId);
		//sigServer->init_sig(*npId);
		//sigServer->set_self_sig_info(*npId);

		// We initiate signaling if necessary
		if (const auto* signaling_data = joinRoomResp->signaling_data())
		{
			const SceNpMatching2RoomId room_id = joinRoomResp->room_data()->roomId();

			for (unsigned int i = 0; i < signaling_data->size(); i++)
			{
				const auto* signaling_info = signaling_data->Get(i);
				//ensure(signaling_info->addr());

				const u32 addr_p2p = RegisterIp(signaling_info->addr()->ip());
				u16 port_p2p = signaling_info->addr()->port();
				//if (port_p2p == SCE_SIGN_PORT)
					//port_p2p = SCE_INTERNAL_PORT;

				const SceNpMatching2RoomMemberId member_id = signaling_info->member_id();

				if (!npServer->cache.Exists(room_id, member_id))
					continue;

				auto p2p_npid = npServer->cache.GetNpId(room_id, member_id);
				NOTICE_LOG(Log::Matching, "JoinRoomResult told to connect to member(%d=%s) of room(%d): %s:%d", member_id, reinterpret_cast<const char*>(p2p_npid.handle.data), room_id, ip2str(addr_p2p).c_str(), port_p2p);

				// Attempt Signaling
				const u32 conn_id = sigServer->init_sig(p2p_npid, room_id, member_id);
				sigServer->connect(conn_id, addr_p2p, port_p2p);
			}
		}

		return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, SCE_NP_MATCHING2_OKAY, room_resp.ptr);
	}
	int RPCNAgent::LeaveRoom(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, PSPPointer<SceNpMatching2LeaveRoomRequest> req) {
		flatbuffers::FlatBufferBuilder builder(1024);
		flatbuffers::Offset<PresenceOptionData> final_optdata = CreatePresenceOptionData(builder, builder.CreateVector(req->optData.data, 16), req->optData.length);
		auto req_finished = CreateLeaveRoomRequest(builder, req->roomId, final_optdata);
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		packet.Pack(CommandType::LeaveRoom, generate_uid(ctxId, reqId));

		INFO_LOG(Log::Matching, "Leaving Room #%d", req->roomId);

		// Send Finished, RPSC3 triggers this in sceNpSignalingTerminateConnection
		//auto connId = sigServer->get_always_conn_id(*NpGetNpId());
		//sigServer->stop_sig_nl(connId, false);

		// Execute signaling callback to update users
		sigServer->DisconnectUsers(req->roomId);

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send, returning Empty");
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE), 0);
		}
		
		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::LeaveRoom_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp) {
		switch ((ErrorType)resp.error) {
		case ErrorType::NoError:
			break;
		case ErrorType::Malformed:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST, "Malformed Request"), 0);
		case ErrorType::Invalid:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE, "Send Failed"), 0);
		case ErrorType::NotFound:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM, "User cannot leave a room they are not in"), 0);
		case ErrorType::RoomMissing:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM, "User cannot leave a room that doesn't exist"), 0);
		default:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SIGNALING_ERROR_PARSER_FAILED, "Unknown Error Leaving Room"), 0);
		}
		resp.stream = new vec_stream(resp.data, 1);

		//memcpy(resp, &_resp.data, sizeof(u64));
		SceNpMatching2RoomId roomId = resp.stream->get<SceNpMatching2RoomId>();
		if (resp.stream->is_error()) {
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::Matching, SCE_NP_MATCHING2_SIGNALING_ERROR_PARSER_FAILED), 0);
		}

		// Remove room from cache
		//npServer->cache.RemoveRoom(roomId);

		//if (npMatching2ThreadID)
			//__KernelStopThread(npMatching2ThreadID, 0, "User Left Room");


		return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, SCE_NP_MATCHING2_OKAY, 0);
	}
	int RPCNAgent::GetRoomDataInternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2GetRoomDataInternalRequest* req) {
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

		packet.Pack(CommandType::GetRoomDataInternal, generate_uid(ctxId, reqId));

		INFO_LOG(Log::Matching, "Requesting Room Data Internal for Room #%d", req->roomId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE, "Unable to Send"), 0);
		}

		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::GetRoomDataInternal_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp) {
		if (resp.error != (u8)ErrorType::NoError) {
			int errorCode;
			switch ((ErrorType)resp.error) {
			case ErrorType::Malformed:
				return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST, "Malformed Request"), 0);
			case ErrorType::NotFound:
				return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE, "Send Failed"), 0);
			case ErrorType::RoomMissing:
				return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM, "Room doesn't Exist"), 0);
			default:
				return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::Matching, -resp.error, "Unknown Error"), 0);
			}
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::Matching, errorCode), 0);
		}
		resp.stream = new vec_stream(resp.data, 1);

		auto _context = ctx.find(ctxId);
		if (_context == ctx.end())
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND, "Context not Found"), 0);

		auto roomDataInternal = resp.stream->get_flatbuffer<RoomDataInternal>();
		if (resp.stream->is_error())
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST), 0);

		u32 alloc = sizeof(SceNpMatching2GetRoomDataInternalResponse);
		auto room_resp = PSPPointer<SceNpMatching2GetRoomDataInternalResponse>::Create(np_memory.Alloc(alloc));

		alloc = sizeof(SceNpMatching2RoomDataInternal);
		room_resp->roomDataInternal = PSPPointer<SceNpMatching2RoomDataInternal>::Create(np_memory.Alloc(alloc));
		::np::RoomDataInternal_to_SceNpMatching2RoomDataInternal(np_memory, roomDataInternal, room_resp->roomDataInternal, NpGetNpId(), _context->second->include_onlinename, _context->second->include_avatarurl);
		print_SceNpMatching2RoomDataInternal(room_resp->roomDataInternal);
		// Cache the new Room Info
		npServer->cache.AddRoom(*room_resp->roomDataInternal);

		return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, SCE_NP_MATCHING2_OKAY, room_resp.ptr);
	}
	int RPCNAgent::SendRoomMessage(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SendRoomMessageRequest* req) {

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
			for (u32 i = 0; i < req->dst.multicastTarget.memberIdNum && req->dst.multicastTarget.memberId.IsValid(); i++)
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

		packet.Pack(CommandType::SendRoomMessage, generate_uid(ctxId, reqId));

		INFO_LOG(Log::Matching, "Sending Room #%d a Message", req->roomId);

		// NPAgent::Send()
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE, "Unable to Send"), 0);
		}
		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::SendRoomMessage_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp) {
		switch ((ErrorType)resp.error) {
		case ErrorType::NoError: break;
		case ErrorType::RoomMissing:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM, "Room doesn't exist"), 0);
		case ErrorType::Unauthorized:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_FORBIDDEN, "Unauthorized"), 0);
		default:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, hleLogError(Log::Matching, SCE_NP_MATCHING2_ERROR_ABORTED, "Unknown Error"), 0);
		}
		resp.stream = new vec_stream(resp.data, 1);
		return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, SCE_NP_MATCHING2_OKAY, 0);
	}
	int RPCNAgent::SetRoomDataInternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SetRoomDataInternalRequest* req) {
		flatbuffers::FlatBufferBuilder builder(1024);
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinAttr>>> final_binattrinternal_vec;
		if (req->roomBinAttrInternalNum && req->roomBinAttrInternal.IsValid())
		{
			std::vector<flatbuffers::Offset<BinAttr>> davec;
			for (u32 i = 0; i < req->roomBinAttrInternalNum; i++)
			{
				auto binAttr = req->roomBinAttrInternal + i;
				auto bin = CreateBinAttr(builder, binAttr->id, builder.CreateVector(Memory::GetPointer(binAttr->ptr.ptr), binAttr->size));
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
				auto pwConfig = req->passwordConfig + i;
				auto rg = CreateRoomGroupPasswordConfig(builder, pwConfig->groupId, pwConfig->withPassword);
				davec.push_back(rg);
			}
			final_grouppasswordconfig_vec = builder.CreateVector(davec);
		}

		flatbuffers::Offset<flatbuffers::Vector<uint64_t>> final_passwordSlotMask;
		if (req->passwordSlotMask.IsValid())
		{
			const uint64_t value = *req->passwordSlotMask;
			final_passwordSlotMask = builder.CreateVector(&value, 1);
		}

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

		packet.Pack(CommandType::SetRoomDataInternal, generate_uid(ctxId, reqId));

		INFO_LOG(Log::Matching, "Setting Room Data Internal for Room #%d", req->roomId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send");
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE), 0);
		}

		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::SetRoomDataInternal_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp) {
		switch ((ErrorType)resp.error) {
		case ErrorType::NoError:
			break;
		case ErrorType::RoomMissing:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM, "Room doesn't exist"), 0);
		default:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST, "Unknown Error: %08X", resp.error), 0);
		}
		
		return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal, SCE_NP_MATCHING2_OKAY, 0);
	}
	int RPCNAgent::SetRoomDataExternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SetRoomDataExternalRequest* req) {
		flatbuffers::FlatBufferBuilder builder(1024);
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<IntAttr>>> final_searchintattrexternal_vec;
		if (req->roomSearchableIntAttrExternalNum && req->roomSearchableIntAttrExternal.IsValid())
		{
			std::vector<flatbuffers::Offset<IntAttr>> davec;
			for (u32 i = 0; i < req->roomSearchableIntAttrExternalNum; i++)
			{
				auto intAttr = req->roomSearchableIntAttrExternal + i;
				auto bin = CreateIntAttr(builder, intAttr->id, intAttr->num);
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
				ERROR_LOG(Log::Matching, "Unexpected bin attribute id in set_roomdata_external request: 0x%x", id);
				break;
			}
		};

		if (req->roomSearchableBinAttrExternalNum && req->roomSearchableBinAttrExternal.IsValid())
		{
			for (u32 i = 0; i < req->roomSearchableBinAttrExternalNum; i++)
			{
				auto binAttr = req->roomSearchableBinAttrExternal + i;
				auto bin = CreateBinAttr(builder, binAttr->id, builder.CreateVector(Memory::GetPointer(binAttr->ptr.ptr), binAttr->size));
				put_binattr(binAttr->id, bin);
			}
		}

		if (req->roomBinAttrExternalNum && req->roomBinAttrExternal.IsValid())
		{
			for (u32 i = 0; i < req->roomBinAttrExternalNum; i++)
			{
				auto binAttr = req->roomBinAttrExternal + i;
				auto bin = CreateBinAttr(builder, binAttr->id, builder.CreateVector(Memory::GetPointer(binAttr->ptr.ptr), binAttr->size));
				put_binattr(binAttr->id, bin);
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

		packet.Pack(CommandType::SetRoomDataExternal, generate_uid(ctxId, reqId));

		INFO_LOG(Log::Matching, "Setting Room Data External for Room #%d", req->roomId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send, returning Empty");
			return (u8)ErrorType::NotFound;
		}

		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::SetRoomDataExternal_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp) {
		if (resp.error != (u8)ErrorType::NoError) {
			int errorCode;
			switch ((ErrorType)resp.error) {
			case ErrorType::Malformed:
				errorCode = SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST;
				ERROR_LOG(Log::Matching, "Malformed Request");
				break;
			case ErrorType::NotFound:
				errorCode = SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE;
				ERROR_LOG(Log::Matching, "Send Failed");
				break;
			case ErrorType::RoomMissing:
				errorCode = SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM;
				ERROR_LOG(Log::Matching, "Room doesn't exist");
				break;
			default:
				errorCode = resp.error;
				ERROR_LOG(Log::Matching, "Unknown Error: %08X", resp.error);
				break;
			}
			return resp.error;
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, hleLogError(Log::Matching, errorCode), 0);
		}
		resp.stream = new vec_stream(resp.data, 1);

		return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, SCE_NP_MATCHING2_OKAY, 0);
	}
	int RPCNAgent::SetRoomMemberDataInternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SetRoomMemberDataInternalRequest* req) {
		flatbuffers::FlatBufferBuilder builder(1024);
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinAttr>>> final_binattrinternal_vec;
		if (req->roomMemberBinAttrInternalNum && req->roomMemberBinAttrInternal.IsValid())
		{
			std::vector<flatbuffers::Offset<BinAttr>> davec;
			for (u32 i = 0; i < req->roomMemberBinAttrInternalNum; i++)
			{
				auto bin = CreateBinAttr(builder, req->roomMemberBinAttrInternal[i].id, builder.CreateVector(Memory::GetPointer(req->roomMemberBinAttrInternal[i].ptr.ptr), req->roomMemberBinAttrInternal[i].size));
				davec.push_back(bin);
			}
			final_binattrinternal_vec = builder.CreateVector(davec);
		}

		auto req_finished = CreateSetRoomMemberDataInternalRequest(builder, req->roomId, req->memberId, req->teamId, final_binattrinternal_vec);
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		packet.Pack(CommandType::SetRoomMemberDataInternal, generate_uid(ctxId, reqId));

		INFO_LOG(Log::Matching, "Setting Room Data Internal for Room #%d", req->roomId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send, returning Empty");
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE, "Service Unavailable"), 0);
		}

		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::SetRoomMemberDataInternal_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp) {

		switch ((ErrorType)resp.error)
		{
		case ErrorType::NoError: break;
		case ErrorType::RoomMissing: return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM, "No such room"), 0);
		case ErrorType::NotFound: return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_USER, "No such member"), 0);
		case ErrorType::Unauthorized: return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_FORBIDDEN, "Forbidden"), 0);
		default: 
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::Matching, resp.error, "Unexpected Reply"), 0);
		}
		
		return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, SCE_NP_MATCHING2_OKAY, 0);
	}
	int RPCNAgent::GetRoomMemberDataInternal(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2GetRoomMemberDataInternalRequest* req) {
		flatbuffers::FlatBufferBuilder builder(1024);
		flatbuffers::Offset<flatbuffers::Vector<u16>> final_attrid_vec;
		if (req->attrIdNum && req->attrId.IsValid())
		{
			std::vector<u16> attrid_vec;
			for (u32 i = 0; i < req->attrIdNum; i++)
			{
				attrid_vec.push_back(req->attrId[i]);
			}
			final_attrid_vec = builder.CreateVector(attrid_vec);
		}

		auto req_finished = CreateGetRoomMemberDataInternalRequest(builder, req->roomId, req->memberId, final_attrid_vec);
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		packet.Pack(CommandType::GetRoomMemberDataInternal, generate_uid(ctxId, reqId));

		INFO_LOG(Log::Matching, "Getting Room Data Internal for Room #%d", req->roomId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send, returning Empty");
			return (u8)ErrorType::NotFound;
		}

		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::GetRoomMemberDataInternal_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp) {
		switch ((ErrorType)resp.error)
		{
		case ErrorType::NoError: break;
		case ErrorType::RoomMissing: return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM, "No such room"), 0);
		case ErrorType::NotFound: return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_USER, "No such member"), 0);
		case ErrorType::Unauthorized: return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_FORBIDDEN, "Forbidden"), 0);
		default:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::Matching, resp.error, "Unexpected Reply"), 0);
		}
		resp.stream = new vec_stream(resp.data, 1);

		auto _context = ctx.find(ctxId);
		if (_context == ctx.end())
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND, "Context not Found"), 0);

		const auto* resp_data = resp.stream->get_flatbuffer<RoomMemberDataInternal>();

		if (resp.stream->is_error())
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST), 0);

		u32 alloc = sizeof(SceNpMatching2GetRoomMemberDataInternalResponse);
		auto mdata_resp = PSPPointer<SceNpMatching2GetRoomMemberDataInternalResponse>::Create(np_memory.Alloc(alloc));
		u32 _alloc = sizeof(SceNpMatching2RoomMemberDataInternal);
		mdata_resp->roomMemberDataInternal = PSPPointer<SceNpMatching2RoomMemberDataInternal>::Create(np_memory.Alloc(_alloc));

		::np::RoomMemberDataInternal_to_SceNpMatching2RoomMemberDataInternal(np_memory, resp_data, PSPPointer<SceNpMatching2RoomDataInternal>(), mdata_resp->roomMemberDataInternal, _context->second->include_onlinename, _context->second->include_avatarurl);
		print_SceNpMatching2RoomMemberDataInternal(mdata_resp->roomMemberDataInternal);

		return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, SCE_NP_MATCHING2_OKAY, mdata_resp.ptr);
	}
	int RPCNAgent::SetUserInfo(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2SetUserInfoRequest* req) {
		flatbuffers::FlatBufferBuilder builder(1024);
		flatbuffers::Offset<flatbuffers::Vector<flatbuffers::Offset<BinAttr>>> final_memberbinattr_vec;
		if (req->userBinAttrNum && req->userBinAttr.IsValid())
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

		packet.Pack(CommandType::SetUserInfo, generate_uid(ctxId, reqId));

		INFO_LOG(Log::Matching, "Setting UserInfo for Server #%d", req->serverId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send");
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE), 0);
		}

		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::SetUserInfo_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp) {
		if (resp.error != (u8)ErrorType::NoError) {
			int errorCode;
			switch ((ErrorType)resp.error) {
			case ErrorType::Malformed:
				errorCode = SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST;
				ERROR_LOG(Log::Matching, "Malformed Request");
				break;
			case ErrorType::NotFound:
				errorCode = SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE;
				ERROR_LOG(Log::Matching, "Send Failed");
				break;
			default:
				errorCode = resp.error;
				ERROR_LOG(Log::Matching, "Unknown Error: %08X", resp.error);
				break;
			}
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, hleLogError(Log::Matching, errorCode), 0);
		}
		resp.stream = new vec_stream(resp.data, 1);

		return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, SCE_NP_MATCHING2_OKAY, 0);
	}
	int RPCNAgent::GetRoomDataExternalList(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2GetRoomDataExternalListRequest* req) {

		flatbuffers::FlatBufferBuilder builder(1024);
		std::vector<uint64_t> roomIds;
		for (u32 i = 0; i < req->roomIdNum && req->roomId.IsValid(); i++)
		{
			roomIds.push_back(req->roomId[i]);
		}
		std::vector<u16> attrIds;
		for (u32 i = 0; i < req->attrIdNum && req->attrId.IsValid(); i++)
		{
			attrIds.push_back(req->attrId[i]);
		}

		auto req_finished = CreateGetRoomDataExternalListRequestDirect(builder, &roomIds, &attrIds);
		builder.Finish(req_finished);

		// Wrap and send the packet
		Packet packet;
		packet.AddCommId(&builder, this->GetCommHeader().data());

		packet.Pack(CommandType::GetRoomDataExternalList, generate_uid(ctxId, reqId));

		INFO_LOG(Log::Matching, "Getting RoomDataExternalList for Room #%016llx", *req->roomId);

		// NPAgent::Send('001000AB00000001000000000000004E50575230313434365F30308C0000001C0000001800240020001C0000001800140010000C0008000000040018000000200000003800000000000004000000641400000001000000CCCCCCCC180000000B0000004C004D004E004F0050005100520053005400550056000000010000000C00000008000C000700080008000000000000040C00000008000C00060008000800000000004C003F000000')
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::Matching, "Unable to Send");
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE), 0);
		}

		return SCE_NP_MATCHING2_OKAY;
	}
	int RPCNAgent::GetRoomDataExternalList_Reply(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, RPCNResponse resp) {
		INFO_LOG(Log::Matching, "RoomDataExternalList Response obtained");
		switch ((ErrorType)resp.error) {
		case ErrorType::NoError:
			break;
		case ErrorType::Malformed:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST, "Malformed Request"), 0);
			break;
		case ErrorType::NotFound:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE, "Send Failed"), 0);
			break;
		default:
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::Matching, -resp.error, "Unknown Error: %08x", resp.error), 0);
			break;
		}

		auto _context = ctx.find(ctxId);
		if (_context == ctx.end())
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::Matching, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND, "Context not Found"), 0);

		auto roomDataExternal = resp.stream->get_flatbuffer<GetRoomDataExternalListResponse>();
		if (resp.stream->is_error())
			return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::Matching, SCE_NP_MATCHING2_SERVER_ERROR_BAD_REQUEST, "Malformed Response"), 0);

		u32 alloc = sizeof(SceNpMatching2GetRoomDataExternalListResponse);
		auto getRoomDataExtListResponse = PSPPointer<SceNpMatching2GetRoomDataExternalListResponse>::Create(np_memory.Alloc(alloc));
		::np::GetRoomDataExternalListResponse_to_SceNpMatching2GetRoomDataExternalListResponse(np_memory, roomDataExternal, getRoomDataExtListResponse, _context->second->include_onlinename, _context->second->include_avatarurl);
		print_SceNpMatching2GetRoomDataExternalListResponse(getRoomDataExtListResponse);

		return notifyRequestHandler(ctxId, reqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, SCE_NP_MATCHING2_OKAY, getRoomDataExtListResponse.ptr);
	}
}
