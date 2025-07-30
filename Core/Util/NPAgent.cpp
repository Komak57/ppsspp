#include "Core/Util/NPAgent.h"
#include "Common/Net/SocketCompat.h"
#include "Common/Net/Resolve.h"
#include "Common/Net/URL.h"

#include "Common/TimeUtil.h"
#include "Common/File/FileDescriptor.h"
#include "Common/SysError.h"
#include <Net\NetBuffer.h>
#include <Core\HLE\HLE.h>
#include <mbedtls\debug.h>
#include <mbedtls\error.h>
//#define AGENT_TESTING
//#undef MBEDTLS_AES_ALT
//#undef MBEDTLS_SHA256_ALT
//#undef MBEDTLS_RSA_ALT
//#define MBEDTLS_AES_ALT
//#define MBEDTLS_SHA256_ALT
//#define MBEDTLS_RSA_ALT

bool IsBigEndian() {
	uint16_t number = 0x1;
	uint8_t* bytePtr = reinterpret_cast<uint8_t*>(&number);
	return bytePtr[0] == 0 ? true : false;
}

uint16_t Swap16(uint16_t val) {
	return (val >> 8) | (val << 8);
}

uint32_t Swap32(uint32_t val) {
	return (val >> 24) |
		((val & 0x00FF0000) >> 8) |
		((val & 0x0000FF00) << 8) |
		(val << 24);
}

Packet::Packet() {
	memset(data_bytes, 0, sizeof(data_bytes));
	this->dataPtr = data_bytes;
	this->data_length = 0;
}
Packet::~Packet() {

}
inline u64 htonll(u64 value) {
	// Check if the system is little-endian (most common desktop machines)
	// You could also use a compile-time check for more optimization if your environment supports it
	static const int one = 1;
	if (*reinterpret_cast<const char*>(&one) == 1) { // Little-endian system
		return (static_cast<u64>(htonl(static_cast<u32>(value & 0xFFFFFFFFUL))) << 32) |
			static_cast<u64>(htonl(static_cast<u32>(value >> 32)));
	}
	else { // Big-endian system or unknown
		return value; // Already in network byte order
	}
}
bool Packet::Pack(CommandType command, u64 packet_id) {
	int packet_size = this->data_length + RPCN_HEADER_SIZE;

	u8* packet = (u8*)malloc(packet_size);
	if (!packet)
		return false;

	packet[0] = static_cast<u8>(PacketType::Request);
	*reinterpret_cast<u16_le*>(&packet[1]) = static_cast<u16>(command);
	*reinterpret_cast<u32_le*>(&packet[3]) = static_cast<u32>(packet_size);
	*reinterpret_cast<u64_le*>(&packet[7]) = packet_id;

	memcpy(packet + RPCN_HEADER_SIZE, this->dataPtr, this->data_length);
	this->dataPtr = packet;
	this->data_length = packet_size;
	return true;
}

void Packet::Write(u8 data) {
	memcpy(dataPtr + data_length, &data, 1);
	data_length += 1;
}
void Packet::Write(u16 data) {
	if (!IsBigEndian()) data = Swap16(data);
	memcpy(dataPtr + data_length, &data, 2);
	data_length += 2;
}
void Packet::Write(u32 data) {
	if (!IsBigEndian()) data = Swap32(data);
	memcpy(dataPtr + data_length, &data, 4);
	data_length += 4;
}
void Packet::Write(std::string data) {
	int i = 0;
	for (i = 0; i < data.length(); i++)
		memcpy(dataPtr + data_length + i, &data[i], 1);
	data_length += data.length();
}

namespace net {
	int NPAgent::InitializeSSL(int transport, std::string certPEM) {
		WARN_LOG(Log::sceNet, "UNTESTED HTTPConnection::InitializeSSL()");

		mbedtls_net_init(&tls.netCtx);
		mbedtls_ssl_init(&tls.sslCtx);
		mbedtls_ssl_config_init(&tls.sslConfig);
		mbedtls_ctr_drbg_init(&tls.ctrDrbg);
		mbedtls_entropy_init(&tls.entropy);
		mbedtls_debug_set_threshold(4);

		if (mbedtls_ctr_drbg_seed(&tls.ctrDrbg, mbedtls_entropy_func, &tls.entropy, NULL, 0) != 0) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to seed RNG");
			return -1;
		}

		// Note: certPEM MUST be pointing to a valid certificate, or it will cause a strlen crash
		mbedtls_x509_crt_init(&tls.caCert);
		int ret = mbedtls_x509_crt_parse(&tls.caCert, (const unsigned char*)certPEM.c_str(), certPEM.size() + 1);
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to parse cert: -0x%04x", -ret);
			return -1;
		}

		// Setup SSL config
		if (mbedtls_ssl_config_defaults(&tls.sslConfig,
			MBEDTLS_SSL_IS_CLIENT,
			transport,
			MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to set SSL config defaults");
			return -1;
		}

		/* OPTIONAL is not optimal for security,
		 * but makes interop easier in this simplified scenario */
		mbedtls_ssl_conf_authmode(&tls.sslConfig, MBEDTLS_SSL_VERIFY_NONE);
		mbedtls_ssl_conf_ca_chain(&tls.sslConfig, &tls.caCert, NULL);
		mbedtls_ssl_conf_rng(&tls.sslConfig, mbedtls_ctr_drbg_random, &tls.ctrDrbg);
		mbedtls_ssl_conf_dbg(&tls.sslConfig, ssl_debug, NULL);

		// Check compiled Ciphers
		/*const int* ciphers = mbedtls_ssl_list_ciphersuites();
		int cipherCount = 0;
		for (const int* c = ciphers; *c != 0; ++c)
			++cipherCount;
		INFO_LOG(Log::sceNet, "sceHttpsInit: Parsing %i ciphers", cipherCount);
		for (int i = 0; i < cipherCount; i++) {
			INFO_LOG(Log::sceNet, "sceHttpsInit: ciphers[%i] = 0x%04x = %s", i, ciphers[i], mbedtls_ssl_get_ciphersuite_name(ciphers[i]));
		}*/
		//mbedtls_ssl_conf_ciphersuites(&sslConfig, net::legacy_ciphersuites_array)
		static const int forceCiphers[] = {
			MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			0
		};
		mbedtls_ssl_conf_ciphersuites(&tls.sslConfig, forceCiphers);
		// Limit to TLS 1.2 - TLS 1.3
		mbedtls_ssl_conf_min_version(&tls.sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
		mbedtls_ssl_conf_max_version(&tls.sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

		return 0;
	}
	int NPAuthAgent::InitializeSSL(int transport, std::string certPEM) {
		WARN_LOG(Log::sceNet, "UNTESTED NPAuthAgent::InitializeSSL()");

		mbedtls_net_init(&tls.netCtx);
		mbedtls_ssl_init(&tls.sslCtx);
		mbedtls_ssl_config_init(&tls.sslConfig);
		mbedtls_ctr_drbg_init(&tls.ctrDrbg);
		mbedtls_entropy_init(&tls.entropy);
		mbedtls_debug_set_threshold(4);

		if (mbedtls_ctr_drbg_seed(&tls.ctrDrbg, mbedtls_entropy_func, &tls.entropy, NULL, 0) != 0) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to seed RNG");
			return -1;
		}

		// Note: certPEM MUST be pointing to a valid certificate, or it will cause a strlen crash
		mbedtls_x509_crt_init(&tls.caCert);
		int ret = mbedtls_x509_crt_parse(&tls.caCert, (const unsigned char*)certPEM.c_str(), certPEM.size() + 1);
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to parse cert: -0x%04x", -ret);
			return -1;
		}

		// Setup SSL config
		if (mbedtls_ssl_config_defaults(&tls.sslConfig,
			MBEDTLS_SSL_IS_CLIENT,
			transport,
			MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to set SSL config defaults");
			return -1;
		}

		/* OPTIONAL is not optimal for security,
		 * but makes interop easier in this simplified scenario */
		mbedtls_ssl_conf_authmode(&tls.sslConfig, MBEDTLS_SSL_VERIFY_NONE);
		mbedtls_ssl_conf_ca_chain(&tls.sslConfig, &tls.caCert, NULL);
		mbedtls_ssl_conf_rng(&tls.sslConfig, mbedtls_ctr_drbg_random, &tls.ctrDrbg);
		mbedtls_ssl_conf_dbg(&tls.sslConfig, ssl_debug, NULL);

		// Check compiled Ciphers
		/*const int* ciphers = mbedtls_ssl_list_ciphersuites();
		int cipherCount = 0;
		for (const int* c = ciphers; *c != 0; ++c)
			++cipherCount;
		INFO_LOG(Log::sceNet, "sceHttpsInit: Parsing %i ciphers", cipherCount);
		for (int i = 0; i < cipherCount; i++) {
			INFO_LOG(Log::sceNet, "sceHttpsInit: ciphers[%i] = 0x%04x = %s", i, ciphers[i], mbedtls_ssl_get_ciphersuite_name(ciphers[i]));
		}*/
		//mbedtls_ssl_conf_ciphersuites(&sslConfig, net::legacy_ciphersuites_array)
		static const int forceCiphers[] = {
			MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			0
		};
		mbedtls_ssl_conf_ciphersuites(&tls.sslConfig, forceCiphers);
		// Limit to TLS 1.2 - TLS 1.3
		mbedtls_ssl_conf_min_version(&tls.sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
		mbedtls_ssl_conf_max_version(&tls.sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

		SSLEnabled = true;
		return 0;
	}

	bool NPAuthAgent::Resolve(DNSType type) {
		if ((intptr_t)sock() != -1) {
			return false;
		}
		if (status == SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE) {
			ERROR_LOG(Log::IO, "Resolve: Server not available");
			return false;
		}
		if (!host_.c_str() || port_ < 1 || port_ > 65535) {
			ERROR_LOG(Log::IO, "Resolve: Unable to resolve %s:%d", host_.c_str(), port_);
			status = SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE;
			return false;
		}

		char port_str[16];
		snprintf(port_str, sizeof(port_str), "%d", port_);
		std::string err;
		if (!net::DNSResolve(host_.c_str(), port_str, &resolved_, err, type)) {
			switch (type) {
			case DNSType::IPV4:
				WARN_LOG(Log::IO, "Failed to resolve host '%s': '%s' (IPV4)", host_.c_str(), err.c_str());
				break;
			case DNSType::IPV6:
				WARN_LOG(Log::IO, "Failed to resolve host '%s': '%s' (IPV6)", host_.c_str(), err.c_str());
				break;
			case DNSType::ANY:
				WARN_LOG(Log::IO, "Failed to resolve host '%s': '%s' (ANY)", host_.c_str(), err.c_str());
				break;
			default:
				WARN_LOG(Log::IO, "Failed to resolve host '%s': '%s' (N/A)", host_.c_str(), err.c_str());
				break;
			}
			status = SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE;
			return false;
		}
		status = SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE;
		return true;
	}

	bool NPAgent::Resolve(DNSType type) {
		if ((intptr_t)sock_ != -1) {
			return false;
		}
		if (status == SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE) {
			ERROR_LOG(Log::IO, "Resolve: Server not available");
			return false;
		}
		if (!host_.c_str() || port_ < 1 || port_ > 65535) {
			ERROR_LOG(Log::IO, "Resolve: Unable to resolve %s:%d", host_.c_str(), port_);
			return false;
		}

		char port_str[16];
		snprintf(port_str, sizeof(port_str), "%d", port_);
		std::string err;
		if (!net::DNSResolve(host_.c_str(), port_str, &resolved_, err, type)) {
			switch (type) {
			case DNSType::IPV4:
				WARN_LOG(Log::IO, "Failed to resolve host '%s': '%s' (IPV4)", host_.c_str(), err.c_str());
				break;
			case DNSType::IPV6:
				WARN_LOG(Log::IO, "Failed to resolve host '%s': '%s' (IPV6)", host_.c_str(), err.c_str());
				break;
			case DNSType::ANY:
				WARN_LOG(Log::IO, "Failed to resolve host '%s': '%s' (ANY)", host_.c_str(), err.c_str());
				break;
			default:
				WARN_LOG(Log::IO, "Failed to resolve host '%s': '%s' (N/A)", host_.c_str(), err.c_str());
				break;
			}
			status = SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE;
			return false;
		}
		return true;
	}

	void NPAuthAgent::Disconnect() {
		if ((intptr_t)sock_ != -1) {
			canceled = true;
			closesocket(sock_);
			sock_ = -1;
		}
	}
	void NPAgent::Disconnect() {
		if ((intptr_t)sock_ != -1) {
			canceled = true;
			closesocket(sock_);
			sock_ = -1;
		}
	}

	bool NPAuthAgent::Send(Packet* packet, double timeout, bool* cancelled) {
		if (sock() <= 0) {
			ERROR_LOG(Log::IO, "Send Failed - Invalid Socket");
			return false;
		}
		static constexpr float CANCEL_INTERVAL = 0.25f;

		bool ready = false;
		double endTimeout = time_now_d() + timeout;
		const char* data = reinterpret_cast<const char*>(packet->Data());
		for (size_t pos = 0, end = strlen(data); pos < end; ) {
			if (time_now_d() > endTimeout) {
				ERROR_LOG(Log::IO, "Send timed out");
				return false;
			}
			int sent;
			if (SSLEnabled) {
				sent = mbedtls_ssl_write(&tls.sslCtx, (const unsigned char*)data + pos, end - pos);
				//int sent = send(sock, &data[pos], end - pos, MSG_NOSIGNAL);
				// TODO: Do we need some retry logic here, instead of just giving up?
				if (sent <= 0) {
					switch (sent) {
					case MBEDTLS_ERR_NET_CONN_RESET:
					case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
						ERROR_LOG(Log::sceNet, "FlushSocket: Client closed connection gracefully");
						return true;
					default:
						ERROR_LOG(Log::sceNet, "SSL write failed: -0x%04x", -sent);
						return false;
					}
				}
			}
			else {
				sent = send(sock(), data, end - pos, 0);
				// Only await when we failed to receive data we're expecting
				if (sent < 0) {
#if !PPSSPP_PLATFORM(WINDOWS)
					int err = errno;
					if (err > 0 && err != EAGAIN && err != EWOULDBLOCK) {
						ERROR_LOG(Log::IO, "Send Failed - %d", err);
						return false;
					}
#else
					int err = WSAGetLastError();
					if (err > 0 && err != EAGAIN && err != EWOULDBLOCK) {
						ERROR_LOG(Log::IO, "Send Failed - %d", err);
						return false;
					}
#endif
					ready = false;
					while (!ready) {
						if (cancelled && *cancelled)
							return false;
						if (sock() <= 0) {
							ERROR_LOG(Log::IO, "Socket Failed - Socket lost");
							return false;
						}
						ready = fd_util::WaitUntilReady(sock_, CANCEL_INTERVAL, true);
						if (!ready && time_now_d() > endTimeout) {
							ERROR_LOG(Log::IO, "Send timed out");
							return false;
						}
					}
					continue;
				}
			}
			pos += sent;
		}
		packet->Clear();
		return true;
	}

	enum ReadState {
		Headers,
		Body,
		Complete
	};

	int NPAuthAgent::Recv(Packet* packet) {
		static constexpr float CANCEL_INTERVAL = 0.25f;
		char buf[4096];
		// Adjustable read size
		PacketHeader header;
		size_t toRead = sizeof(PacketHeader);
		int retval = 0;
		size_t received = 0;
		ReadState state = ReadState::Headers;
		int content_length = 0;

		while (state != ReadState::Complete) {
			if (SSLEnabled) {
				DEBUG_LOG(Log::HTTP, "mbedtls_ssl_read reading %i bytes", toRead);
				retval = mbedtls_ssl_read(&tls.sslCtx, (unsigned char*)buf, toRead);
				//int ready = 0;
				if (retval < 0) {
					switch (retval) {
					case MBEDTLS_ERR_NET_CONN_RESET:
					case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
						WARN_LOG(Log::HTTP, "Read - Client closed connection gracefully");
						return (int)received > 0 ? (int)received : retval;
					case MBEDTLS_ERR_SSL_TIMEOUT:
						ERROR_LOG(Log::HTTP, "mbedtls_ssl_read returned TIMOUT");
						return retval;
					case MBEDTLS_ERR_SSL_WANT_WRITE:
						ERROR_LOG(Log::HTTP, "mbedtls_ssl_read returned WANT_WRITE");
						return retval;
					case MBEDTLS_ERR_SSL_WANT_READ:
						DEBUG_LOG(Log::HTTP, "mbedtls_ssl_read returned WANT_READ");
						/*while (!ready)
							ready = fd_util::WaitUntilReady(fd, CANCEL_INTERVAL, false);*/
							// Read some more!
						continue;
					default:
						char errbuf[128];
						mbedtls_strerror(retval, errbuf, sizeof(errbuf));
						ERROR_LOG(Log::HTTP, "Read Failed: -0x%04x -> %s", -retval, errbuf);
						return retval;
					}
				}

			}
			else {
				DEBUG_LOG(Log::HTTP, "socket reading %i bytes", toRead);
				retval = recv(sock(), buf, toRead, MSG_NOSIGNAL);

				if (retval < 0)
					break;
			}
			packet->Append(buf, retval);
			received += retval;

			if (state == ReadState::Headers) {
				// More data to read?
				if (received < sizeof(PacketHeader))
					continue;
				// Pull Header
				memcpy(&header, packet->Data(), sizeof(PacketHeader));

				content_length = header.size;
				toRead = content_length - received;
				state = ReadState::Body;
			}
			if (state == ReadState::Body) {
				// Should always be true
				if (received == content_length)
					state = ReadState::Complete;
			}
			if (state == ReadState::Complete) {
				if (header.request == (u8)PacketType::ServerInfo) {
					const int body_length = header.size - sizeof(PacketHeader);
					u32 error = 0;
					memcpy(&error, packet->Data() + sizeof(PacketHeader), body_length);
					switch ((CommandType)header.command) {
					case CommandType::Login:
						ERROR_LOG(Log::HTTP, "Response Error: Login Failed -> %s", PacketTypeNames[error]);
						break;
					default:
						ERROR_LOG(Log::HTTP, "Response Error: UNHANDLED[%d] -> %s", header.command, PacketTypeNames[error]);
						break;
					}
					return -error;
				}
			}
		}
		return received;  // Return HTML Status Code or Error Code
	}

//	int NPAuthAgent::Recv(Packet* packet) {
//		if (sock() <= 0) {
//			ERROR_LOG(Log::IO, "NPAuthAgent::Recv() Failed - Invalid Socket");
//			return -1;
//		}
//		static constexpr float CANCEL_INTERVAL = 0.25f;
//		double endTimeout = time_now_d() + 10; // 10 second standard timeout
//		char buf[4096];
//		int retval = 0;
//		// Pull headers first
//		size_t sz = RPCN_HEADER_SIZE;
//
//		int ready = 0;
//		while (sz > 0) {
//			if (time_now_d() > endTimeout) {
//				ERROR_LOG(Log::IO, "Recv timed out");
//				return -2;
//			}
//			int toRead = (int)std::min(sz, sizeof(buf));
//			if (SSLEnabled) {
//				DEBUG_LOG(Log::HTTP, "mbedtls_ssl_read reading %i bytes", toRead);
//				retval = mbedtls_ssl_read(&tls.sslCtx, (unsigned char*)buf, toRead);
//				int ready = 0;
//				if (retval < 0) {
//					switch (retval) {
//					case MBEDTLS_ERR_NET_CONN_RESET:
//					case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
//						WARN_LOG(Log::HTTP, "Read - Client closed connection gracefully");
//						return (int)packet->Length() > 0 ? (int)packet->Length() : retval;
//					case MBEDTLS_ERR_SSL_TIMEOUT:
//						ERROR_LOG(Log::HTTP, "mbedtls_ssl_read returned TIMOUT");
//						return retval;
//					case MBEDTLS_ERR_SSL_WANT_WRITE:
//						ERROR_LOG(Log::HTTP, "mbedtls_ssl_read returned WANT_WRITE");
//						return retval;
//					case MBEDTLS_ERR_SSL_WANT_READ:
//						DEBUG_LOG(Log::HTTP, "mbedtls_ssl_read returned WANT_READ");
//						while (!ready)
//							ready = fd_util::WaitUntilReady(sock(), CANCEL_INTERVAL, false);
//						// Read some more!
//						continue;
//					default:
//						char errbuf[128];
//						mbedtls_strerror(retval, errbuf, sizeof(errbuf));
//						ERROR_LOG(Log::HTTP, "mbedtls_ssl_read Failed: -0x%04x -> %s", -retval, errbuf);
//						return retval;
//					}
//				}
//
//			}
//			else {
//				//socklen_t addrlen = conn->ai_addrlen;
//				retval = recv(sock(), buf, toRead, MSG_NOSIGNAL);
//
//				if (retval <= 0) {
//#if !PPSSPP_PLATFORM(WINDOWS)
//					int err = errno;
//					if (err > 0 && err != EAGAIN && err != EWOULDBLOCK) {
//						ERROR_LOG(Log::IO, "Recv Failed - %d", err);
//						return false;
//					}
//#else
//					int err = WSAGetLastError();
//					if (err > 0 && err != EAGAIN && err != EWOULDBLOCK) {
//						ERROR_LOG(Log::IO, "Recv Failed - %d", err);
//						return -err;
//					}
//#endif
//					if (sock() <= 0) {
//						ERROR_LOG(Log::IO, "Recv Failed - Socket lost");
//						return -1;
//					}
//					return (int)packet->Length() > 0 ? (int)packet->Length() : retval;
//				}
//			}
//			packet->Append(buf, retval);
//			//memcpy(packet.Data(), buf, retval);
//			sz -= retval;
//			//packet. += retval;
//		}
//
//		return (int)packet->Length() > 0 ? (int)packet->Length() : retval;  // Return -1 or 0 for error, else bytes read
//	}

	u8 NPAgent::GetStatus() {
		return status;
	}


	bool NPAgent::Send(Packet* packet, double timeout, bool* cancelled) {
		if (sock_ <= 0 || conn == nullptr || conn->ai_addr == nullptr) {
			ERROR_LOG(Log::IO, "Send Failed - Invalid Socket");
			return false;
		}
		static constexpr float CANCEL_INTERVAL = 0.25f;

		bool ready = false;
		double endTimeout = time_now_d() + timeout;
		const char* data = reinterpret_cast<const char*>(packet->Data());
		const char* test_data = "Hello, World";
		for (size_t pos = 0, end = strlen(test_data); pos < end; ) {
			if (time_now_d() > endTimeout) {
				ERROR_LOG(Log::IO, "Send timed out");
				return false;
			}
			int sent = send(sock_, test_data, end - pos, 0);
			// Only await when we failed to receive data we're expecting
			if (sent < 0) {
#if !PPSSPP_PLATFORM(WINDOWS)
				int err = errno;
				if (err > 0 && err != EAGAIN && err != EWOULDBLOCK) {
					ERROR_LOG(Log::IO, "Send Failed - %d", err);
					return false;
				}
#else
				int err = WSAGetLastError();
				if (err > 0 && err != EAGAIN && err != EWOULDBLOCK) {
					ERROR_LOG(Log::IO, "Send Failed - %d", err);
					return false;
				}
#endif
				ready = false;
				while (!ready) {
					if (cancelled && *cancelled)
						return false;
					if (sock_ <= 0) {
						ERROR_LOG(Log::IO, "Socket Failed - Socket lost");
						return false;
					}
					ready = fd_util::WaitUntilReady(sock_, CANCEL_INTERVAL, true);
					if (!ready && time_now_d() > endTimeout) {
						ERROR_LOG(Log::IO, "Send timed out");
						return false;
					}
				}
				continue;
			}
			pos += sent;
		}
		packet->Clear();
		return true;
	}

	int NPAgent::Recv(Packet* packet, size_t sz) {
		if (sock_ <= 0 || conn == nullptr || conn->ai_addr == nullptr) {
			ERROR_LOG(Log::IO, "Recv Failed - Invalid Socket");
			return -1;
		}
		static constexpr float CANCEL_INTERVAL = 0.25f;
		double endTimeout = time_now_d() + 5;
		char buf[4096];
		int retval = 0;

		int ready = 0;
		while (sz > 0) {
			if (time_now_d() > endTimeout) {
				ERROR_LOG(Log::IO, "Recv timed out");
				return -2;
			}
			int toRead = (int)std::min(sz, sizeof(buf));
			if (SSLEnabled) {
				DEBUG_LOG(Log::HTTP, "mbedtls_ssl_read reading %i bytes", toRead);
				retval = mbedtls_ssl_read(&tls.sslCtx, (unsigned char*)buf, toRead);
				int ready = 0;
				if (retval < 0) {
					switch (retval) {
					case MBEDTLS_ERR_NET_CONN_RESET:
					case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
						WARN_LOG(Log::HTTP, "Read - Client closed connection gracefully");
						return (int)packet->Length() > 0 ? (int)packet->Length() : retval;
					case MBEDTLS_ERR_SSL_TIMEOUT:
						ERROR_LOG(Log::HTTP, "mbedtls_ssl_read returned TIMOUT");
						return retval;
					case MBEDTLS_ERR_SSL_WANT_WRITE:
						ERROR_LOG(Log::HTTP, "mbedtls_ssl_read returned WANT_WRITE");
						return retval;
					case MBEDTLS_ERR_SSL_WANT_READ:
						DEBUG_LOG(Log::HTTP, "mbedtls_ssl_read returned WANT_READ");
						while (!ready)
							ready = fd_util::WaitUntilReady(sock_, CANCEL_INTERVAL, false);
						// Read some more!
						continue;
					default:
						char errbuf[128];
						mbedtls_strerror(retval, errbuf, sizeof(errbuf));
						ERROR_LOG(Log::HTTP, "Read Failed: -0x%04x -> %s", -retval, errbuf);
						return retval;
					}
				}

			}
			else {
				socklen_t addrlen = conn->ai_addrlen;
				retval = recv(sock_, buf, toRead, MSG_NOSIGNAL);

				if (retval <= 0) {
#if !PPSSPP_PLATFORM(WINDOWS)
					int err = errno;
					if (err > 0 && err != EAGAIN && err != EWOULDBLOCK) {
						ERROR_LOG(Log::IO, "Recv Failed - %d", err);
						return false;
					}
#else
					int err = WSAGetLastError();
					if (err > 0 && err != EAGAIN && err != EWOULDBLOCK) {
						ERROR_LOG(Log::IO, "Recv Failed - %d", err);
						return -err;
					}
#endif
					ready = false;
					while (!ready) {
						if (sock_ <= 0) {
							ERROR_LOG(Log::IO, "Recv Failed - Socket lost");
							return -1;
						}
						ready = fd_util::WaitUntilReady(sock_, CANCEL_INTERVAL, true);
						if (!ready && time_now_d() > endTimeout) {
							ERROR_LOG(Log::IO, "Recv timed out");
							return -2;
						}
					}
					continue;
				}
			}
			packet->Append(buf, retval);
			//memcpy(packet.Data(), buf, retval);
			sz -= retval;
			//packet. += retval;
		}

		return (int)packet->Length() > 0 ? (int)packet->Length() : retval;  // Return -1 or 0 for error, else bytes read
	}
}
