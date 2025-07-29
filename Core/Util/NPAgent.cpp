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
	int NPAuthAgent::InitializeSSL(std::string certPEM) {
		WARN_LOG(Log::sceNet, "UNTESTED HTTPConnection::InitializeSSL()");

		mbedtls_net_init(&netCtx);
		mbedtls_ssl_init(&sslCtx);
		mbedtls_ssl_config_init(&sslConfig);
		mbedtls_ctr_drbg_init(&ctrDrbg);
		mbedtls_entropy_init(&entropy);
		mbedtls_debug_set_threshold(4);

		if (mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to seed RNG");
			return -1;
		}

		// Note: certPEM MUST be pointing to a valid certificate, or it will cause a strlen crash
		mbedtls_x509_crt_init(&caCert);
		int ret = mbedtls_x509_crt_parse(&caCert, (const unsigned char*)certPEM.c_str(), certPEM.size() + 1);
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to parse cert: -0x%04x", -ret);
			return -1;
		}

		// Setup SSL config
		if (mbedtls_ssl_config_defaults(&sslConfig,
			MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to set SSL config defaults");
			return -1;
		}

		/* OPTIONAL is not optimal for security,
		 * but makes interop easier in this simplified scenario */
		mbedtls_ssl_conf_authmode(&sslConfig, MBEDTLS_SSL_VERIFY_NONE);
		mbedtls_ssl_conf_ca_chain(&sslConfig, &caCert, NULL);
		mbedtls_ssl_conf_rng(&sslConfig, mbedtls_ctr_drbg_random, &ctrDrbg);
		mbedtls_ssl_conf_dbg(&sslConfig, ssl_debug, NULL);

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
		mbedtls_ssl_conf_ciphersuites(&sslConfig, forceCiphers);
		// Limit to TLS 1.2 - TLS 1.3
		mbedtls_ssl_conf_min_version(&sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
		mbedtls_ssl_conf_max_version(&sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

		SSLEnabled = true;
		return 0;
	}
	int NPAgent::InitializeSSL(std::string certPEM) {
		WARN_LOG(Log::sceNet, "UNTESTED HTTPConnection::InitializeSSL()");

		mbedtls_net_init(&netCtx);
		mbedtls_ssl_init(&sslCtx);
		mbedtls_ssl_config_init(&sslConfig);
		mbedtls_ctr_drbg_init(&ctrDrbg);
		mbedtls_entropy_init(&entropy);
		mbedtls_debug_set_threshold(4);

		if (mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to seed RNG");
			return -1;
		}

		// Note: certPEM MUST be pointing to a valid certificate, or it will cause a strlen crash
		mbedtls_x509_crt_init(&caCert);
		int ret = mbedtls_x509_crt_parse(&caCert, (const unsigned char*)certPEM.c_str(), certPEM.size() + 1);
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to parse cert: -0x%04x", -ret);
			return -1;
		}

		// Setup SSL config
		if (mbedtls_ssl_config_defaults(&sslConfig,
			MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
			ERROR_LOG(Log::sceNet, "InitializeSSL: Failed to set SSL config defaults");
			return -1;
		}

		/* OPTIONAL is not optimal for security,
		 * but makes interop easier in this simplified scenario */
		mbedtls_ssl_conf_authmode(&sslConfig, MBEDTLS_SSL_VERIFY_OPTIONAL);
		mbedtls_ssl_conf_ca_chain(&sslConfig, &caCert, NULL);
		mbedtls_ssl_conf_rng(&sslConfig, mbedtls_ctr_drbg_random, &ctrDrbg);
		mbedtls_ssl_conf_dbg(&sslConfig, ssl_debug, NULL);

		// Check compiled Ciphers
		/*const int* ciphers = mbedtls_ssl_list_ciphersuites();
		int cipherCount = 0;
		for (const int* c = ciphers; *c != 0; ++c)
			++cipherCount;
		INFO_LOG(Log::sceNet, "sceHttpsInit: Parsing %i ciphers", cipherCount);
		for (int i = 0; i < cipherCount; i++) {
			INFO_LOG(Log::sceNet, "sceHttpsInit: ciphers[%i] = 0x%04x = %s", i, ciphers[i], mbedtls_ssl_get_ciphersuite_name(ciphers[i]));
		}*/

		// Limit to TLS 1.0 - TLS 1.2 to match Hardware Limitations
		mbedtls_ssl_conf_min_version(&sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);
		mbedtls_ssl_conf_max_version(&sslConfig, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

		SSLEnabled = true;
		return 0;
	}

	bool NPAuthAgent::Resolve(DNSType type) {
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

	static void FormatAddr(char* addrbuf, size_t bufsize, const addrinfo* info) {
		switch (info->ai_family) {
		case AF_INET:
		case AF_INET6:
			inet_ntop(info->ai_family, &((sockaddr_in*)info->ai_addr)->sin_addr, addrbuf, bufsize);
			break;
		default:
			snprintf(addrbuf, bufsize, "(Unknown AF %d)", info->ai_family);
			break;
		}
	}

	bool NPAuthAgent::Connect(int maxTries, double timeout, bool* cancelConnect) {
		if (SSLEnabled)
			return SSLConnect(maxTries, timeout, cancelConnect);
		NOTICE_LOG(Log::sceNet, "NPAgent::Connect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);
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
				conn = possible;

				char addrStr[128]{};
				FormatAddr(addrStr, sizeof(addrStr), possible);
				NOTICE_LOG(Log::sceNet, "NPAgent Found Possible at %s", addrStr);
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

				NOTICE_LOG(Log::sceNet, "NPAgent Connected!");
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
		NOTICE_LOG(Log::sceNet, "NPAgent Connection Failed!");
		return false;
	}

	bool NPAuthAgent::SSLConnect(int maxTries, double timeout, bool* cancelConnect) {
		WARN_LOG(Log::sceNet, "UNTESTED Connection::SSLConnect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);
		if (port_ <= 0) {
			ERROR_LOG(Log::IO, "SSLConnect - Bad port");
			return false;
		}
		if (connected) {
			mbedtls_ssl_session_reset(&sslCtx);
			mbedtls_ssl_config_free(&sslConfig);

			mbedtls_ssl_free(&sslCtx);
			mbedtls_net_free(&netCtx);
			connected = false;
		}


		for (int tries = maxTries; tries > 0; --tries) {
			mbedtls_ssl_setup(&sslCtx, &sslConfig);
			for (addrinfo* possible = resolved_; possible != nullptr; possible = possible->ai_next) {
				if (possible->ai_family != AF_INET && possible->ai_family != AF_INET6)
					continue;

				int ret;
				/*
				 * 1. Start the connection
				 */
				char addrStr[128]{};
				FormatAddr(addrStr, sizeof(addrStr), possible);
				char portStr[8]{};
				memcpy(portStr, std::to_string(port_).c_str(), std::to_string(port_).length());
				if ((ret = mbedtls_net_connect(&netCtx, addrStr, portStr, MBEDTLS_NET_PROTO_TCP)) != 0) {
					char errbuf[128];
					mbedtls_strerror(ret, errbuf, sizeof(errbuf));
					ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_net_connect(netCtx, %s, %s, PROTO_TCP) call failed with -0x%04x (%s))", addrStr, portStr, ret, errbuf);
					goto sslretry;
				}
				// Set NonBlocking
				fd_util::SetNonBlocking(netCtx.fd, true);
				/*
				 * 2. Setup stuff
				 */
				if ((ret = mbedtls_ssl_setup(&sslCtx, &sslConfig)) != 0) {
					ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_setup returned 0x%04x", ret);
					goto sslretry;
				}

				//if ((ret = mbedtls_ssl_set_hostname(&sslCtx, possible->ai_addr->sa_data)) != 0) {
				if ((ret = mbedtls_ssl_set_hostname(&sslCtx, host_.c_str())) != 0) {
					char errbuf[128];
					mbedtls_strerror(ret, errbuf, sizeof(errbuf));
					ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_set_hostname returned -0x%04x (%s)", (unsigned int)-ret, errbuf);
					goto sslretry;
				}

				mbedtls_ssl_set_bio(&sslCtx, &netCtx, mbedtls_net_send, mbedtls_net_recv, NULL);

				/*
				 * 4. Handshake
				 */
				NOTICE_LOG(Log::sceNet, "SSLConnect - Performing the SSL/TLS handshake...");

				while ((ret = mbedtls_ssl_handshake(&sslCtx)) != 0) {
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
				NOTICE_LOG(Log::sceNet, "SSLConnect - Verifying peer X.509 certificate...");

				/* In real life, we probably want to bail out when ret != 0 */
				u32 flags;
				if ((flags = mbedtls_ssl_get_verify_result(&sslCtx)) != 0) {
					char vrfy_buf[512];

					mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

					ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_get_verify_result failed: %s", vrfy_buf);
					goto sslretry;
				}

				INFO_LOG(Log::sceNet, "SSLConnect - Connection Successful");
				connected = true;
				return true;
			sslretry:
				INFO_LOG(Log::sceNet, "SSLConnect - Connection Failed, retrying");
				mbedtls_ssl_session_reset(&sslCtx);
				mbedtls_ssl_config_free(&sslConfig);

				mbedtls_ssl_free(&sslCtx);
				mbedtls_net_free(&netCtx);

				continue;
			}
			sleep_ms(1, "connect");
		}
		return false;
	}

	bool NPAgent::Connect(int maxTries, double timeout, bool* cancelConnect) {
		if (SSLEnabled)
			return SSLConnect(maxTries, timeout, cancelConnect);
		NOTICE_LOG(Log::sceNet, "NPAgent::Connect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);
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

				int sock = socket(possible->ai_family, SOCK_DGRAM, IPPROTO_UDP);
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
				conn = possible;

				char addrStr[128]{};
				FormatAddr(addrStr, sizeof(addrStr), possible);
				NOTICE_LOG(Log::sceNet, "NPAgent Found Possible at %s", addrStr);
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

				NOTICE_LOG(Log::sceNet, "NPAgent Connected!");
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
		NOTICE_LOG(Log::sceNet, "NPAgent Connection Failed!");
		return false;
	}

	bool NPAgent::SSLConnect(int maxTries, double timeout, bool* cancelConnect) {
		WARN_LOG(Log::sceNet, "UNTESTED Connection::SSLConnect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);
		if (port_ <= 0) {
			ERROR_LOG(Log::IO, "SSLConnect - Bad port");
			return false;
		}
		if (connected) {
			mbedtls_ssl_session_reset(&sslCtx);
			mbedtls_ssl_config_free(&sslConfig);

			mbedtls_ssl_free(&sslCtx);
			mbedtls_net_free(&netCtx);
			connected = false;
		}


		for (int tries = maxTries; tries > 0; --tries) {
			mbedtls_ssl_setup(&sslCtx, &sslConfig);
			for (addrinfo* possible = resolved_; possible != nullptr; possible = possible->ai_next) {
				if (possible->ai_family != AF_INET && possible->ai_family != AF_INET6)
					continue;

				int ret;
				/*
				 * 1. Start the connection
				 */
				char addrStr[128]{};
				FormatAddr(addrStr, sizeof(addrStr), possible);
				char portStr[8]{};
				memcpy(portStr, std::to_string(port_).c_str(), std::to_string(port_).length());
				if ((ret = mbedtls_net_connect(&netCtx, addrStr, portStr, MBEDTLS_NET_PROTO_TCP)) != 0) {
					ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_net_connect(netCtx, %s, %s, PROTO_TCP) call to %s failed with -0x%04x)", addrStr, portStr, (unsigned int)-ret);
					goto retry;
				}
				// Set NonBlocking
				fd_util::SetNonBlocking(netCtx.fd, true);
				/*
				 * 2. Setup stuff
				 */
				if ((ret = mbedtls_ssl_setup(&sslCtx, &sslConfig)) != 0) {
					ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_setup returned 0x%04x", ret);
					goto retry;
				}

				//if ((ret = mbedtls_ssl_set_hostname(&sslCtx, possible->ai_addr->sa_data)) != 0) {
				if ((ret = mbedtls_ssl_set_hostname(&sslCtx, host_.c_str())) != 0) {
					char errbuf[128];
					mbedtls_strerror(ret, errbuf, sizeof(errbuf));
					ERROR_LOG(Log::sceNet, "SSLConnect - mbedtls_ssl_set_hostname returned -0x%04x (%s)", (unsigned int)-ret, errbuf);
					goto retry;
				}

				mbedtls_ssl_set_bio(&sslCtx, &netCtx, mbedtls_net_send, mbedtls_net_recv, NULL);

				/*
				 * 4. Handshake
				 */
				NOTICE_LOG(Log::sceNet, "SSLConnect - Performing the SSL/TLS handshake...");

				while ((ret = mbedtls_ssl_handshake(&sslCtx)) != 0) {
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
				if ((flags = mbedtls_ssl_get_verify_result(&sslCtx)) != 0) {
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
				mbedtls_ssl_session_reset(&sslCtx);
				mbedtls_ssl_config_free(&sslConfig);

				mbedtls_ssl_free(&sslCtx);
				mbedtls_net_free(&netCtx);

				continue;
			}
			sleep_ms(1, "connect");
		}
		return false;
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
		if (sock_ <= 0) {
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
				sent = mbedtls_ssl_write(&sslCtx, (const unsigned char*)data + pos, end - pos);
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
				sent = send(sock_, data, end - pos, 0);
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
			}
			pos += sent;
		}
		packet->Clear();
		return true;
	}

	int NPAuthAgent::Recv(Packet* packet, size_t sz) {
		if (sock_ <= 0) {
			ERROR_LOG(Log::IO, "NPAuthAgent::Recv() Failed - Invalid Socket");
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
				retval = mbedtls_ssl_read(&sslCtx, (unsigned char*)buf, toRead);
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
						ERROR_LOG(Log::HTTP, "mbedtls_ssl_read Failed: -0x%04x -> %s", -retval, errbuf);
						return retval;
					}
				}

			}
			else {
				//socklen_t addrlen = conn->ai_addrlen;
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
					if (sock_ <= 0) {
						ERROR_LOG(Log::IO, "Recv Failed - Socket lost");
						return -1;
					}
					return (int)packet->Length() > 0 ? (int)packet->Length() : retval;
				}
			}
			packet->Append(buf, retval);
			//memcpy(packet.Data(), buf, retval);
			sz -= retval;
			//packet. += retval;
		}

		return (int)packet->Length() > 0 ? (int)packet->Length() : retval;  // Return -1 or 0 for error, else bytes read
	}

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
				retval = mbedtls_ssl_read(&sslCtx, (unsigned char*)buf, toRead);
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
