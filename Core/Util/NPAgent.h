#pragma once
#include "Common/Net/Resolve.h"
#include <CommonTypes.h>
#include <optional>
#include "Core/HLE/np_types.h"

// 0x88 bytes
//struct RoomInfo {
//	u16_le ID;
//	u16 Port;
//	u8 Status;
//	std::string Host;
//	u32_le IPAddr = 910526074; // 910526074 || 0x3645867a || 54.69.134.122 || elb001-mtc-ag09.mtc.usw2.np.cy.s0.playstation.net
//};

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
// Forward Declare
struct SceNpMatching2World;
struct SceNpMatching2RoomDataExternal;
struct SceNpMatching2RoomDataInternal;
namespace net {
	enum class NPAgentType { PSN, RPCN };
	class NPAgent {
	public:
		virtual ~NPAgent() = default;

		// Inits the sockaddr_in.
		bool Resolve(DNSType type = DNSType::ANY);

		bool Connect(int maxTries = 2, double timeout = 20.0f, bool* cancelConnect = nullptr);
		void Disconnect();

		u8 GetStatus();
		//int GetID() { return ID; }
		SceNpMatching2ServerInfo GetServerInfo() { return { ID, status }; };

		virtual bool Login() = 0;
		virtual int GetWorldInfo(char npTitleId[], std::map<u32, SceNpMatching2World>* worldInfoOut) = 0;
		virtual int SearchRoom(SceNpMatching2RoomDataExternal* roomDataOut) = 0;
		virtual int CreatJoinRoom(SceNpMatching2RoomDataInternal* roomDataOut) = 0;
		virtual int GetRoomDataInternal(SceNpMatching2RoomDataInternal* roomDataOut) = 0;

		// Only to be used for bring-up and debugging.
		uintptr_t sock() const { return sock_; }

	protected:
		u16 ID;
		uintptr_t sock_ = -1;
		bool canceled = false;

		std::string host_;
		int port_ = -1;
		u8 status;
		addrinfo* resolved_ = nullptr;
		bool connected = false;
	};

	class PSNAgent : public NPAgent {
	public:
		~PSNAgent();
		PSNAgent(int serverId, std::string host, int port, u8 status = 2);

		static int GetServers(SceNpCommunicationId npTitleId, std::map<u16, std::unique_ptr<net::NPAgent>>* serversPtr);
		bool Login();
		int GetWorldInfo(char npTitleId[], std::map<u32, SceNpMatching2World>* worldInfoOut);
		int SearchRoom(SceNpMatching2RoomDataExternal* roomDataOut);
		int CreatJoinRoom(SceNpMatching2RoomDataInternal* roomDataOut);
		int GetRoomDataInternal(SceNpMatching2RoomDataInternal* roomDataOut);
	};

	class RPCNAgent : public NPAgent {
	public:
		~RPCNAgent();
		RPCNAgent(int serverId);

		static int GetServers(SceNpCommunicationId npTitleId, std::map<u16, std::unique_ptr<net::NPAgent>>* serversPtr);
		bool Login();
		int GetWorldInfo(char npTitleId[], std::map<u32, SceNpMatching2World>* worldInfoOut);
		int SearchRoom(SceNpMatching2RoomDataExternal* roomDataOut);
		int CreatJoinRoom(SceNpMatching2RoomDataInternal* roomDataOut);
		int GetRoomDataInternal(SceNpMatching2RoomDataInternal* roomDataOut);
	};

	inline std::unique_ptr<NPAgent> CreateNPAgent(NPAgentType type, int serverId, std::string host = "", int port = 0, u8 status = 2) {
		switch (type) {
		case NPAgentType::PSN: return std::make_unique<PSNAgent>(serverId, host, port, status);
		case NPAgentType::RPCN: return std::make_unique<RPCNAgent>(serverId);
		}
		return nullptr;
	}
}
