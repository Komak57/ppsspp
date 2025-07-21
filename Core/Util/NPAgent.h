#pragma once
#include "Common/Net/Resolve.h"
#include <CommonTypes.h>
#include <optional>

// 0x88 bytes
//struct RoomInfo {
//	u16_le ID;
//	u16 Port;
//	u8 Status;
//	std::string Host;
//	u32_le IPAddr = 910526074; // 910526074 || 0x3645867a || 54.69.134.122 || elb001-mtc-ag09.mtc.usw2.np.cy.s0.playstation.net
//};

// Server status
enum
{
	SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE = 1,
	SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE = 2,
	SCE_NP_MATCHING2_SERVER_STATUS_BUSY = 3,
	SCE_NP_MATCHING2_SERVER_STATUS_MAINTENANCE = 4,
};

// World
struct SceNpMatching2World
{
	u16 worldId;
	u32 numOfLobby;
	u32 maxNumOfTotalLobbyMember;
	u32 curNumOfTotalLobbyMember;
	u32 curNumOfRoom;
	u32 curNumOfTotalRoomMember;
	u8 withEntitlementId;
	u8 entitlementId[32];
	u8 padding[3];
};

class Packet {
public:
	Packet();
	~Packet();

	// Supplies header to packet data
	u8* Pack(u16 opcode, u8* data);

	void Write(u8 data);
	void Write(u16 data);
	void Write(u32 data);
	void Write(std::string data);

	u8* Data() { return dataPtr; }

	int Length() { return data_length; }
private:
	int data_length = 0;
	u8 data_bytes[1024];
	u8* dataPtr;
};

namespace net {

class NPAgent {
public:
	NPAgent() {}
	NPAgent(std::string host, int port, u8 status = SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE);
	~NPAgent();

	// Inits the sockaddr_in.
	bool Resolve(DNSType type = DNSType::ANY);

	bool Connect(int maxTries = 2, double timeout = 20.0f, bool* cancelConnect = nullptr);
	void Disconnect();

	u8 GetStatus();
	std::optional<SceNpMatching2World> GetWorldInfo(char npTitleId[]);

	// Only to be used for bring-up and debugging.
	uintptr_t sock() const { return sock_; }

protected:
	std::string host_;
	int port_ = -1;
	u8 status;
	addrinfo* resolved_ = nullptr;
	bool connected = false;
private:
	uintptr_t sock_ = -1;
	bool canceled = false;
};

}
