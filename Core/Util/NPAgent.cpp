#include "Core/Util/NPAgent.h"
#include "Common/Net/SocketCompat.h"
#include "Common/Net/Resolve.h"
#include "Common/Net/URL.h"

#include "Common/TimeUtil.h"
#include "Common/File/FileDescriptor.h"
#include "Common/SysError.h"
#include <Net\NetBuffer.h>

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

u8* Packet::Pack(u16 opcode, u8* data) {
	return nullptr;
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
	for(i = 0; i < data.length(); i++)
		memcpy(dataPtr + data_length + i, &data[i], 1);
	data_length += data.length();
}

namespace net {
NPAgent::NPAgent(std::string host, int port, u8 status) {
	this->host_ = host;
	this->port_ = port;
	this->status = status;
}

NPAgent::~NPAgent() {
	Disconnect();
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

bool NPAgent::Connect(int maxTries, double timeout, bool* cancelConnect) {
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
void NPAgent::Disconnect() {
	if ((intptr_t)sock_ != -1) {
		canceled = true;
		closesocket(sock_);
		sock_ = -1;
	}
}

u8 NPAgent::GetStatus() {
	return status;
}

std::optional<SceNpMatching2World> NPAgent::GetWorldInfo(char npTitleId[]) {
	NOTICE_LOG(Log::sceNet, "NPAgent::GetWorldInfo(%s)", npTitleId);
	if (sock_ <= 0) {
		ERROR_LOG(Log::sceNet, "GetWorldInfo: Socket not connected");
		return std::nullopt;
	}
	if (canceled) {
		ERROR_LOG(Log::sceNet, "GetWorldInfo: Cancelled");
		return std::nullopt;
	}
	// 1201 0036 10010000 01001000 00000000 e288f336a613981d1f8b0253f34d4028 1010 000c 4e50575230313434365f3030 4073 0002 0001
	//
	u32 packet_size = 0x36;
	Packet packet = Packet();

	uint8_t guid[16] = { 0xe2, 0x88, 0xf3, 0x36, 0xa6, 0x13, 0x98, 0x1d,
					 0x1f, 0x8b, 0x02, 0x53, 0xf3, 0x4d, 0x40, 0x28 };

	packet.Write((u16)0x1201);		// OPCODE ?
	packet.Write((u16)packet_size);	// PACKET_LEN
	packet.Write((u32)0x10010000);	// ?
	packet.Write((u32)0x01001000);	// ?
	packet.Write((u32)0x00000000);	// padding?
	int i = 0;
	for (i = 0; i < 16; i++)
		packet.Write((u8)guid[i]);	// GUID?
	packet.Write((u16)0x1010);		// ?

	packet.Write((u16)(sizeof(npTitleId)+4));	// TITLE_LEN
	packet.Write(npTitleId);
	packet.Write("_00");

	packet.Write((u16)0x4073);		// ?
	packet.Write((u16)0x0002);		// ?
	packet.Write((u16)0x0001);		// ?

	char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	std::string hexdata = "";
	for (i = 0; i < packet.Length(); i++) {
		char const c = packet.Data()[i];
		hexdata += hex_chars[(c & 0xF0) >> 4];
		hexdata += hex_chars[(c & 0x0F) >> 0];
	}
	INFO_LOG(Log::sceNet, "Request: %s", hexdata.c_str());

	// packet.Pack(0x0112, packet.Length()+4);
	net::Buffer buffer;
	void* dst = buffer.Append(packet_size);
	memcpy(dst, packet.Data(), packet.Length());
	
	bool flushed = buffer.FlushSocket(sock(), 60.0, &canceled);
	if (!flushed) {
		ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
		return std::nullopt;
	}

	net::Buffer readbuf;
	// Read response
	int ret;
	if ((ret = readbuf.Read(sock_, 4096)) < 0) {
		ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
		return std::nullopt;
	}

	std::string response;
	readbuf.Take(ret, &response);

	hexdata = "";
	for (i = 0; i < response.length(); i++) {
		int c = response[i];
		hexdata += hex_chars[(c & 0xF0) >> 4];
		hexdata += hex_chars[(c & 0x0F) >> 0];
	}
	SceNpMatching2World worldInfo = SceNpMatching2World();

	INFO_LOG(Log::sceNet, "Response: %s", hexdata.c_str());

	return worldInfo;
}

}
