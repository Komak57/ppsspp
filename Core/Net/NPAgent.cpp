#include "Core/Net/NPAgent.h"
#include "Common/Net/SocketCompat.h"
#include "Common/Net/URL.h"

#include <Core/HLE/HLE.h>

#include "Common/TimeUtil.h"
#include "Common/File/FileDescriptor.h"
#include "Common/SysError.h"

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
void Packet::AddCommId(flatbuffers::FlatBufferBuilder* builder, uint8_t* commId) {
	auto bufsize = builder->GetSize();
	std::vector<u8> data(COMMUNICATION_ID_SIZE + sizeof(u32) + bufsize);
	memcpy(data.data(), commId, COMMUNICATION_ID_SIZE);
	*reinterpret_cast<u32*>(data.data() + COMMUNICATION_ID_SIZE) = static_cast<u32>(bufsize);
	memcpy(data.data() + COMMUNICATION_ID_SIZE + sizeof(u32), builder->GetBufferPointer(), bufsize);
	this->Write(data);
}

namespace net {
	bool NPAuthAgent::Resolve(DNSType type) {
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
			return false;
		}
		return true;
	}

	bool NPAgent::Resolve(DNSType type) {
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
			return false;
		}
		return true;
	}

	//u64 NPAgent::get_signaling_context(u32 ctx_id)
	//{
	//	static u64 fallback_id = 1; // In case map is empty

	//	if (!signaling_ctx.contains(ctx_id))
	//		return fallback_id++;

	//	u64 max_key = 0;
	//	for (const auto& [key, _] : responses)
	//	{
	//		if (key > max_key)
	//			max_key = key;
	//	}
	//	return max_key + 1;
	//}

	bool NPAuthAgent::Send(Packet* packet, double timeout, bool* cancelled) {
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
			if (tls.enabled) {
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

	enum ReadState {
		Headers,
		Body,
		Complete
	};

	int NPAuthAgent::Recv(Packet* packet, bool* cancelled) {
		static constexpr float CANCEL_INTERVAL = 0.25f;
		char buf[4096];
		// Adjustable read size
		PacketHeader header;
		size_t toRead = sizeof(PacketHeader);
		int retval = 0;
		size_t received = 0;
		ReadState state = ReadState::Headers;
		int content_length = 0;
		int ready = 0;

		while (state != ReadState::Complete) {
			if (*cancelled) {
				WARN_LOG(Log::sceNet, "NPAgent::Recv() Cancelled");
				return 0;
			}
			if (tls.enabled) {
				DEBUG_LOG(Log::sceNet, "mbedtls_ssl_read reading %i bytes", toRead);
				retval = mbedtls_ssl_read(&tls.sslCtx, (unsigned char*)buf, toRead);

				if (*cancelled) {
					WARN_LOG(Log::sceNet, "NPAgent::Recv() Cancelled");
					return 0;
				}
				//int ready = 0;
				if (retval < 0) {
					switch (retval) {
					case MBEDTLS_ERR_NET_CONN_RESET:
					case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
						WARN_LOG(Log::sceNet, "Read - Client closed connection gracefully");
						return (int)received > 0 ? (int)received : retval;
					case MBEDTLS_ERR_SSL_TIMEOUT:
						ERROR_LOG(Log::sceNet, "mbedtls_ssl_read returned TIMOUT");
						return retval;
					case MBEDTLS_ERR_SSL_WANT_WRITE:
						ERROR_LOG(Log::sceNet, "mbedtls_ssl_read returned WANT_WRITE");
						return retval;
					case MBEDTLS_ERR_SSL_WANT_READ:
						DEBUG_LOG(Log::sceNet, "mbedtls_ssl_read returned WANT_READ");
						while (!ready && (cancelled && !*cancelled))
							ready = fd_util::WaitUntilReady(tls.netCtx.fd, CANCEL_INTERVAL, false);
						if (cancelled && *cancelled)
							return SCE_NP_AUTH_ERROR_ABORTED;
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
				DEBUG_LOG(Log::sceNet, "socket reading %i bytes", toRead);
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
		}
		return received;  // Return HTML Status Code or Error Code
	}

	/*u8 NPAgent::GetStatus() {
		return status;
	}*/


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
			if (tls.enabled) {
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

	int NPAgent::Recv(Packet* packet, bool* cancelled) {
		static constexpr float CANCEL_INTERVAL = 0.25f;
		char buf[4096];
		// Adjustable read size
		PacketHeader header;
		size_t toRead = sizeof(PacketHeader);
		int retval = 0;
		size_t received = 0;
		ReadState state = ReadState::Headers;
		int content_length = 0;
		int ready = 0;

		while (state != ReadState::Complete) {
			if (*cancelled) {
				WARN_LOG(Log::sceNet, "NPAgent::Recv() Cancelled");
				return 0;
			}
			if (tls.enabled) {
				VERBOSE_LOG(Log::sceNet, "mbedtls_ssl_read reading %i bytes", toRead);
				retval = mbedtls_ssl_read(&tls.sslCtx, (unsigned char*)buf, toRead);

				if (*cancelled) {
					WARN_LOG(Log::sceNet, "NPAgent::Recv() Cancelled");
					return 0;
				}
				//int ready = 0;
				if (retval < 0) {
					switch (retval) {
					case MBEDTLS_ERR_NET_CONN_RESET:
					case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
						WARN_LOG(Log::sceNet, "Read - Client closed connection gracefully");
						return (int)received > 0 ? (int)received : retval;
					case MBEDTLS_ERR_SSL_TIMEOUT:
						ERROR_LOG(Log::sceNet, "mbedtls_ssl_read returned TIMOUT");
						return retval;
					case MBEDTLS_ERR_SSL_WANT_WRITE:
						ERROR_LOG(Log::sceNet, "mbedtls_ssl_read returned WANT_WRITE");
						return retval;
					case MBEDTLS_ERR_SSL_WANT_READ:
						VERBOSE_LOG(Log::sceNet, "mbedtls_ssl_read returned WANT_READ");
						while (!ready && (cancelled && !*cancelled))
							ready = fd_util::WaitUntilReady(tls.netCtx.fd, CANCEL_INTERVAL, false);
						if (cancelled && *cancelled)
							return SCE_NP_MANAGER_ERROR_ABORTED;
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
				DEBUG_LOG(Log::sceNet, "socket reading %i bytes", toRead);
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
		}
		return received;  // Return HTML Status Code or Error Code
	}

}
