#include "Core/Util/NPAgent.h"
#include "Common/Net/SocketCompat.h"
#include "Common/Net/Resolve.h"
#include "Common/Net/URL.h"

#include "Common/TimeUtil.h"
#include "Common/File/FileDescriptor.h"
#include "Common/SysError.h"
#include <Net\NetBuffer.h>
#define AGENT_TESTING

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
	for (i = 0; i < data.length(); i++)
		memcpy(dataPtr + data_length + i, &data[i], 1);
	data_length += data.length();
}

namespace net {
	PSNAgent::PSNAgent(int serverId, std::string host, int port, u8 status) {
		this->ID = serverId;
		this->host_ = host;
		this->port_ = port;
		this->status = status;
	}
	// FIXME: Populate with actual connection credentials for RPCN
	RPCNAgent::RPCNAgent(int serverId) {
		this->ID = serverId;
		this->host_ = "host";
		this->port_ = 0;
		this->status = SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE;
	}

	PSNAgent::~PSNAgent() {
		Disconnect();
	}

	RPCNAgent::~RPCNAgent() {
		Disconnect();
	}

	bool NPAgent::Resolve(DNSType type) {
#ifndef AGENT_TESTING
		if ((intptr_t)sock_ != -1) {
			return false;
		}
#endif
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
#ifndef AGENT_TESTING
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
#endif
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
#ifdef AGENT_TESTING
	bool NPAgent::Connect(int maxTries, double timeout, bool* cancelConnect) {
		NOTICE_LOG(Log::sceNet, "NPAgent::Connect(%i, %d, 0x%08x)", maxTries, timeout, cancelConnect);
		return true;
	}
#else
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
#endif
	void NPAgent::Disconnect() {
		if ((intptr_t)sock_ != -1) {
			canceled = true;
#ifndef AGENT_TESTING
			closesocket(sock_);
#endif
			sock_ = -1;
		}
	}

	u8 NPAgent::GetStatus() {
		return status;
	}

	/*
		< 12010036100100000100100000000000e288f336a613981d1f8b0253f34d40281010000c4e50575230313434365f3030407300020001
		> 1002002710010000010010000000000019490bc9118fc488581dcbfcb27a4a31001d0003000101

		< 1201002010080000060030009fc689d2397d08a87b9843a0be200fa912534c7a
		> 1002003e100800000600300000000000d0cdabffde20bcc7878039e8d73746350002001a002a0001002a0012000100000000000000000000000000000000

		< 12010093120c00000700f0009fc689d271347aa95b21d64d3913f164fc6f98a040290002000100040004000100140006000c6400000070400004040000000007000901504c00040000004240050002504c40050002504d40050002504e40050002504f400500025050400500025051400500025052400500025053400500022054400500022055400500022056400500027041
		> 1002002c120c00000700f00000000000c809b42f3ca80beaca681dd96b39dfa9000300080045000000000000
		
		< 1201002612090000080090009fc689d25fc23947f402c1076d1aae5b5dd4e4d0402900020001
		> 100200c6120900000800900000000000eb31affe08c2641c0b37c26be6173cac403d0002067d0002006e000a0002000a00310d971009002b6c6f6f6b75702d32303930322e77772e6e702e6d61746368696e672e706c617973746174696f6e2e6e6574000a00310d971009002b6c6f6f6b75702d32303930312e77772e6e702e6d61746368696e672e706c617973746174696f6e2e6e65742020002a4e50575230313434365f303000010000067d00000000000000006dec27241755dd350bcd017d44b5c6d1
		
		< 12010250120200000b0090009fc689d258a3977d62e8db08ea0a519a436c0323203a00cc4e50575230313434365f303000010000067d000c028400000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011001100000198191326730000000001001f003a02105601000a00320d981009002c73657373696f6e2d32303930312e77772e6e702e6d61746368696e672e706c617973746174696f6e2e6e6574000b0018466f784c6f766573596f7500000000006234757370737000733f2a272b670ef10729d5c1391fb8ad504c000400000042504d000400000001504e000400000001504f0004000000c850500004000000025051000400000001505200040000000050530004000000002054000e42006c00750065002d0030003100205500f80000000000000000b873eaf120fae2000c000201a90000000000000000000000000000000000000000000000a518940300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002056000e2bff49ff54ff53ff55ff4eff45ff
		> 10020020120200000b00900000000000ab8eeccd790f258682b9a5d037652526
		
		< 120100f0120a00000d00b0009fc689d29c022c43b7493dd94310f348fafcd211203a00cc4e50575230313434365f303000010000067d000c028400000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000011001100000198191326730000000002001f003a02105601000a00320d981009002c73657373696f6e2d32303930312e77772e6e702e6d61746368696e672e706c617973746174696f6e2e6e6574000b0018466f784c6f766573596f7500000000006234757370737000588e71a258cee4ce5a35d3b4d7ee6451
		> 10020020120a00000d00b00000000000643099ebe3108749441c284285423847
		
		< 00
		> 00
		
		< 00
		> 00
		
		< 00
		> 00
		
		< 00
		> 00
		
		< 00
		> 00
	*/
	char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	int PSNAgent::GetWorldInfo(char npTitleId[], std::vector<SceNpMatching2World> *worldInfoOut) {
		NOTICE_LOG(Log::sceNet, "NPAgent::GetWorldInfo(%s)", npTitleId);
#ifndef AGENT_TESTING
		if (sock_ <= 0) {
			ERROR_LOG(Log::sceNet, "GetWorldInfo: Socket not connected");
			return -1;
		}
#endif
		if (canceled) {
			ERROR_LOG(Log::sceNet, "GetWorldInfo: Cancelled");
			return -1;
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

		packet.Write((u16)(sizeof(npTitleId) + 4));	// TITLE_LEN
		packet.Write(npTitleId);
		packet.Write("_00");

		packet.Write((u16)0x4073);		// ?
		packet.Write((u16)0x0002);		// ?
		packet.Write((u16)0x0001);		// ?

		std::string hexdata = "";
		for (i = 0; i < packet.Length(); i++) {
			char const c = packet.Data()[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "Request: %s", hexdata.c_str());

#ifndef AGENT_TESTING
		// packet.Pack(0x0112, packet.Length()+4);
		net::Buffer buffer;
		void* dst = buffer.Append(packet_size);
		memcpy(dst, packet.Data(), packet.Length());

		bool flushed = buffer.FlushSocket(sock(), 60.0, &canceled);
		if (!flushed) {
			ERROR_LOG(Log::sceNet, "Unable to Send, returning Empty");
			return -1;
		}
		net::Buffer readbuf;
		// Read response
		int ret;
		if ((ret = readbuf.Read(sock_, 4096, false, nullptr)) < 0) {
			ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
			return -1;
		}

		std::string response;
		readbuf.Take(ret, &response);

		// 1002 0027 10010000 01001000 00000000 19490bc9118fc488581dcbfcb27a4a31 001d 0003 0001 01
		hexdata = "";
		for (i = 0; i < response.length(); i++) {
			int c = response[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "Response: %s", hexdata.c_str());
#endif
		// Should get an array of worlds
		SceNpMatching2World worldInfo = SceNpMatching2World();
		worldInfo.worldId = 1;

		worldInfo.numOfLobby = 2;
		worldInfo.curNumOfTotalLobbyMember = 0;
		worldInfo.maxNumOfTotalLobbyMember = 12;

		worldInfo.curNumOfRoom = 0;
		worldInfo.curNumOfTotalRoomMember = 0;

		worldInfo.withEntitlementId = 0;
		for(i = 0; i < 32; i++)
			worldInfo.entitlementId[i] = 0;

		worldInfoOut->push_back(worldInfo);

		return 0;
	}
	int RPCNAgent::GetWorldInfo(char npTitleId[], std::vector<SceNpMatching2World>* worldInfoOut) {
		return 0;
	}

	int PSNAgent::SearchRoom(SceNpMatching2RoomDataExternal* roomDataOut) {
		NOTICE_LOG(Log::sceNet, "NPAgent::SearchRoom()");
#ifndef AGENT_TESTING
		if (sock_ <= 0) {
			ERROR_LOG(Log::sceNet, "SearchRoom: Socket not connected");
			return -1;
		}
#endif
		if (canceled) {
			ERROR_LOG(Log::sceNet, "SearchRoom: Cancelled");
			return -1;
		}
		 
		
		u32 packet_size = 0x36;
		Packet packet = Packet();

		int i = 0;
		std::string hexdata = "";
		for (i = 0; i < packet.Length(); i++) {
			char const c = packet.Data()[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "Request: %s", hexdata.c_str());

#ifndef AGENT_TESTING
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
		if ((ret = readbuf.Read(sock_, 4096, false, nullptr)) < 0) {
			ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
			return std::nullopt;
		}

		std::string response;
		readbuf.Take(ret, &response);

		// 1002 0027 10010000 01001000 00000000 19490bc9118fc488581dcbfcb27a4a31 001d 0003 0001 01
		hexdata = "";
		for (i = 0; i < response.length(); i++) {
			int c = response[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "Response: %s", hexdata.c_str());
#endif

		return 0;
	}
	int RPCNAgent::SearchRoom(SceNpMatching2RoomDataExternal* roomDataOut) {
		return 0;
	}

	int PSNAgent::CreatJoinRoom(SceNpMatching2RoomDataInternal* roomDataOut) {
		NOTICE_LOG(Log::sceNet, "NPAgent::CreatJoinRoom()");
#ifndef AGENT_TESTING
		if (sock_ <= 0) {
			ERROR_LOG(Log::sceNet, "CreatJoinRoom: Socket not connected");
			return -1;
		}
#endif
		if (canceled) {
			ERROR_LOG(Log::sceNet, "CreatJoinRoom: Cancelled");
			return -1;
		}


		u32 packet_size = 0x36;
		Packet packet = Packet();

		int i = 0;
		std::string hexdata = "";
		for (i = 0; i < packet.Length(); i++) {
			char const c = packet.Data()[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "Request: %s", hexdata.c_str());

#ifndef AGENT_TESTING
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
		if ((ret = readbuf.Read(sock_, 4096, false, nullptr)) < 0) {
			ERROR_LOG(Log::sceNet, "Failed to read response -0x%04x", -ret);
			return std::nullopt;
		}

		std::string response;
		readbuf.Take(ret, &response);

		// 1002 0027 10010000 01001000 00000000 19490bc9118fc488581dcbfcb27a4a31 001d 0003 0001 01
		hexdata = "";
		for (i = 0; i < response.length(); i++) {
			int c = response[i];
			hexdata += hex_chars[(c & 0xF0) >> 4];
			hexdata += hex_chars[(c & 0x0F) >> 0];
		}
		INFO_LOG(Log::sceNet, "Response: %s", hexdata.c_str());
#endif

		return 0;
	}

	int RPCNAgent::CreatJoinRoom(SceNpMatching2RoomDataInternal* roomDataOut) {
		return 0;
	}

}
