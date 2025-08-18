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

uint32_t Swap64(uint64_t val) {
	return ((val & 0x00000000000000FFULL) << 56) |
		((val & 0x000000000000FF00ULL) << 40) |
		((val & 0x0000000000FF0000ULL) << 24) |
		((val & 0x00000000FF000000ULL) << 8) |
		((val & 0x000000FF00000000ULL) >> 8) |
		((val & 0x0000FF0000000000ULL) >> 24) |
		((val & 0x00FF000000000000ULL) >> 40) |
		((val & 0xFF00000000000000ULL) >> 56);
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
	const int packet_size = this->data_length + RPCN_HEADER_SIZE;

	// Transfer data from dataPtr to allocate space for HEADER
	// Can also allocate the space in the first Write() function
	u8 packet[1024];// = new u8[packet_size];
	memcpy(packet + RPCN_HEADER_SIZE, this->dataPtr, this->data_length);
	memset(this->dataPtr, 0, packet_size);
	memcpy(this->dataPtr, packet, packet_size);
	this->data_length = packet_size;

	// Write HEADER
	dataPtr[0] = static_cast<u8>(PacketType::Request);

	*reinterpret_cast<u16*>(&dataPtr[1]) = static_cast<u16>(command);
	*reinterpret_cast<u32*>(&dataPtr[3]) = static_cast<u32>(packet_size);
	*reinterpret_cast<u64*>(&dataPtr[7]) = packet_id;

	return true;
}

void Packet::Write(u8 data) {
	if (data_length + 1 > data_size) {
		ERROR_LOG(Log::IO, "Packet::Write - insufficient buffer size");
		return;
	}
	memcpy(dataPtr + data_length, &data, 1);
	data_length += 1;
}
void Packet::Write(u16 data) {
	if (data_length + 2 > data_size) {
		ERROR_LOG(Log::IO, "Packet::Write - insufficient buffer size");
		return;
	}
	if (!IsBigEndian()) data = Swap16(data);
	memcpy(dataPtr + data_length, &data, 2);
	data_length += 2;
}
void Packet::Write(u32 data) {
	if (data_length + 4 > data_size) {
		ERROR_LOG(Log::IO, "Packet::Write - insufficient buffer size");
		return;
	}
	if (!IsBigEndian()) data = Swap32(data);
	memcpy(dataPtr + data_length, &data, 4);
	data_length += 4;
}
void Packet::Write(u64 data) {
	if (data_length + 8 > data_size) {
		ERROR_LOG(Log::IO, "Packet::Write - insufficient buffer size");
		return;
	}
	if (!IsBigEndian()) data = Swap64(data);
	memcpy(dataPtr + data_length, &data, 8);
	data_length += 8;
}
void Packet::Write(std::string data) {
	if (data_length + data.length() > data_size) {
		ERROR_LOG(Log::IO, "Packet::Write - insufficient buffer size");
		return;
	}
	int i = 0;
	memcpy(dataPtr + data_length, data.c_str(), data.length());
	data_length += data.length();
}
void Packet::Write(const std::vector<u8>& data) {
	if (data_length + data.size() > data_size) {
		ERROR_LOG(Log::IO, "Packet::Write - insufficient buffer size");
		return;
	}
	memcpy(dataPtr + data_length, data.data(), data.size());
	data_length += data.size();
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

		SSLEnabled = true;
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
		if (SSLEnabled) {
			mbedtls_ssl_close_notify(&tls.sslCtx);
			mbedtls_ssl_free(&tls.sslCtx);
			mbedtls_ssl_config_free(&tls.sslConfig);
			mbedtls_net_free(&tls.netCtx);
			SSLEnabled = false;
		}
		else {
			if ((intptr_t)sock_ != -1) {
				canceled = true;
				closesocket(sock_);
				sock_ = -1;
			}
		}
	}
	void NPAgent::Disconnect() {
		if ((intptr_t)sock_ != -1) {
			canceled = true;
			closesocket(sock_);
			sock_ = -1;
		}
	}

	u64 NPAgent::generate_request_id()
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
				switch ((PacketType)header.request) {
				case PacketType::Request:
					ERROR_LOG(Log::HTTP, "Response Error: Request made to Client not allowed");
					break;
				case PacketType::Reply:
					// Proper response to a request
					//u8 body = packet->Data()[sizeof(PacketHeader)];
					//INFO_LOG(Log::HTTP, "Response Error: Login Failed -> %s", PacketTypeNames[error]);
					break;
				case PacketType::Notification:
					switch ((NotificationType)header.command) {
					case NotificationType::FriendNew:
					case NotificationType::FriendLost:
					case NotificationType::FriendQuery:
					case NotificationType::FriendStatus:
					case NotificationType::FriendPresenceChanged:
						// Friends not supported on PSP
						//handle_friend_notification
						break;
					case NotificationType::MessageReceived:
						// Private messages not supported on PSP?
						// handle_message
					default:
						// Append all other notifications for later requests
						// notifications
						break;
					}
					break;
				case PacketType::ServerInfo: {
					u8 version = packet->Data()[sizeof(PacketHeader)];
					INFO_LOG(Log::HTTP, "Server is communicating on version %d", version);
					break;
				}
				default:
					ERROR_LOG(Log::HTTP, "Unexpected Packet Type - %d", header.request);
					break;
				}
			}
		}
		return received;  // Return HTML Status Code or Error Code
	}

	u8 NPAgent::GetStatus() {
		return status;
	}


	bool NPAgent::Send(Packet* packet, double timeout, bool* cancelled) {
		if (sock() <= 0) {
			ERROR_LOG(Log::IO, "Send Failed - Invalid Socket");
			return false;
		}

		int i;
		std::string hexdata = "";
		for (i = 0; i < packet->Length(); i++) {
			char const c = packet->Data()[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		DEBUG_LOG(Log::sceNet, "NPAgent::Send('%s')", hexdata.c_str());
		static constexpr float CANCEL_INTERVAL = 0.25f;

		bool ready = false;
		double endTimeout = time_now_d() + timeout;
		//const char* data = reinterpret_cast<const char*>(packet->Data());
		for (size_t pos = 0, end = packet->Length(); pos < end; ) {
			if (time_now_d() > endTimeout) {
				ERROR_LOG(Log::IO, "Send timed out");
				return false;
			}
			int sent;
			if (SSLEnabled) {
				sent = mbedtls_ssl_write(&tls.sslCtx, packet->Data() + pos, end - pos);
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
				sent = send(sock(), (const char*)packet->Data() + pos, end - pos, 0);
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

	int NPAgent::Recv(Packet* packet) {
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
				switch ((PacketType)header.request) {
				case PacketType::Request:
					ERROR_LOG(Log::HTTP, "Response Error: Request made to Client not allowed");
					break;
				case PacketType::Reply:
					// Proper response to a request
					//u8 body = packet->Data()[sizeof(PacketHeader)];
					//INFO_LOG(Log::HTTP, "Response Error: Login Failed -> %s", PacketTypeNames[error]);
					break;
				case PacketType::Notification:
					switch ((NotificationType)header.command) {
					case NotificationType::FriendNew:
					case NotificationType::FriendLost:
					case NotificationType::FriendQuery:
					case NotificationType::FriendStatus:
					case NotificationType::FriendPresenceChanged:
						// Friends not supported on PSP
						//handle_friend_notification
						break;
					case NotificationType::MessageReceived:
						// Private messages not supported on PSP?
						// handle_message
					default:
						// Append all other notifications for later requests
						// notifications
						break;
					}
					break;
				case PacketType::ServerInfo: {
					u8 version = packet->Data()[sizeof(PacketHeader)];
					if (version != RPCNAgent::PROTOCOL_VERSION) {
						ERROR_LOG(Log::HTTP, "Server Version mismatch. Current version %d does not match Server version %d", version, RPCNAgent::PROTOCOL_VERSION);
						// TODO: Version mismatch may interfere with requests and responses. Should disconnect
						break;
					}
					INFO_LOG(Log::HTTP, "Server is communicating on version %d", version);
					break;
				}
				default:
					ERROR_LOG(Log::HTTP, "Unexpected Packet Type - %d", header.request);
					break;
				}
			}
		}
		return received;  // Return HTML Status Code or Error Code
	}
}
