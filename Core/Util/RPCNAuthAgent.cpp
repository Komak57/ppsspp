#include "Core/Util/NPAgent.h"
#include <Core/HLE/HLE.h>
#include <File/FileDescriptor.h>
#include <TimeUtil.h>
#include <SysError.h>
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

	bool RPCNAuthAgent::Connect(int maxTries, double timeout, bool* cancelConnect) {
		std::string certPem = "-----BEGIN CERTIFICATE-----\n"
			"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\n"
			"-----END CERTIFICATE-----\n";
		InitializeSSL(certPem);
		WARN_LOG(Log::sceNet, "UNTESTED RPCNAuthAgent::Connect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);

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

	bool RPCNAuthAgent::Login(const char* npid, const char* token, const char* password) {
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

		packet.Pack(CommandType::Login, 1);

		//int i;
		//std::string hexdata = "";
		//for (i = 0; i < packet.Length(); i++) {
		//	char const c = packet.Data()[i];
		//	hexdata += hex_chars[(c & 0xF0) >> 4];
		//	hexdata += hex_chars[(c & 0x0F) >> 0];
		//}
		//// 00 0000 4D000000 0100000000000000 52504353335F6969516F34513032494600 6C656D6D65696E00 61363866326362612D326536322D346536382D396330382D37663262303431356564636200
		//// 00 0000 0000004D 0000000000000001 52504353335F5039663465543266377100 6C656D6D65696E00 61363866326362612D326536322D346536382D396330382D37663262303431356564636200
		//INFO_LOG(Log::sceNet, "Request: %s", hexdata.c_str());
		INFO_LOG(Log::sceNet, "Sending Login Request");

		// packet.Pack(0x0112, packet.Length()+4);
		//net::Buffer buffer;
		//void* dst = buffer.Append(packet_size);
		//memcpy(dst, packet.Data(), packet.Length());

		//bool flushed = buffer.FlushSocket(sock_, 60.0, &canceled);
		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return false;
		}
		//net::Buffer readbuf;
		//// Read response
		int ret = Recv(&packet);

		/*if (packet.Length() > 0) {
			hexdata = "";
			for (i = 0; i < packet.Length(); i++) {
				int c = packet.Data()[i];
				hexdata += hex_chars[(c & 0xF0) >> 4];
				hexdata += hex_chars[(c & 0x0F) >> 0];
			}
			INFO_LOG(Log::sceNet, "Response: %s", hexdata.c_str());
		}*/

		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
			return false;
		}

		//std::string response;
		//readbuf.Take(ret, &response);

		// 03 0000 13000000 0000000000000000 1A000000

		PacketHeader header;
		memcpy(&header, packet.Data(), sizeof(PacketHeader));

		return true;
	}

	bool RPCNAuthAgent::CreateAccount(const char* npid, const char* password, const char* online_name, const char* avatar_url, const char* email) {
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

		packet.Pack(CommandType::Create, 2);

		INFO_LOG(Log::sceNet, "Sending Registration Request");

		bool flushed = Send(&packet, 5.0, &cancelled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return false;
		}

		int ret = Recv(&packet);
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
			return false;
		}
		return true;
	}

	int RPCNAuthAgent::GetServers(SceNpCommunicationId npTitleId, std::map<u16, std::unique_ptr<net::NPAgent>>* serversPtr) {
		serversPtr->emplace(1, net::CreateNPAgent(net::NPAgentType::RPCN, 1, "rpcn.revurb.us", 31313, SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE));
		//serversPtr->emplace(2, net::CreateNPAgent(net::NPAgentType::RPCN, 2, "rpcn.revurb.us", 3657, SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE));
		return 0;
	}
}
