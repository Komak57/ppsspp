#include "Core/Util/NPAgent.h"
#include <Core\HLE\HLE.h>
namespace net {
	// FIXME: Populate with actual connection credentials for RPCN
	RPCNAgent::RPCNAgent(int serverId, std::string host, int port, u8 status) {
		this->ID = serverId;
		this->host_ = host;
		this->port_ = port;
		this->status = status;

		//std::string certificate = "";
		//InitializeSSL(certificate);
	}

	RPCNAgent::~RPCNAgent() {
		Disconnect();
	}

	int RPCNAgent::GetWorldInfo(char npTitleId[], std::map<u32, SceNpMatching2World>* worldInfoOut) {

		worldInfoOut->clear();
		// Should get an array of worlds
		SceNpMatching2World worldInfo = SceNpMatching2World();
		worldInfo.worldId = 1;

		worldInfo.numOfLobby = 2;
		worldInfo.curNumOfTotalLobbyMember = 0;
		worldInfo.maxNumOfTotalLobbyMember = 12;

		worldInfo.curNumOfRoom = 0;
		worldInfo.curNumOfTotalRoomMember = 0;

		worldInfo.withEntitlementId = 0;
		int i;
		for (i = 0; i < 32; i++)
			worldInfo.entitlementId[i] = 0;

		worldInfoOut->emplace(worldInfo.worldId, worldInfo);
		return 0;
	}

	int RPCNAgent::SearchRoom(SceNpMatching2RoomDataExternal* roomDataOut) {
		roomDataOut->roomId = 0; // No Room
		return 0;
	}

	int RPCNAgent::CreatJoinRoom(SceNpMatching2RoomDataInternal* roomDataOut) {
		roomDataOut->roomId = 1;
		return 0;
	}

	int RPCNAgent::GetRoomDataInternal(SceNpMatching2RoomDataInternal* roomDataOut) {
		return 0;
	}
}
