#pragma once
#include <vector>
#include <optional>
#include "Core/HLE/Np2Types.h"

class Cache {
public:
	void clear();
	void AddWorld(SceNpMatching2World world);
	std::optional<SceNpMatching2World> GetWorld(SceNpMatching2WorldId worldId);
	void RemoveWorld(SceNpMatching2WorldId worldId);
	void AddRoom(SceNpMatching2RoomDataInternal room);
	std::optional<SceNpMatching2RoomDataInternal> GetRoom(SceNpMatching2RoomId roomId);
	void RemoveRoom(SceNpMatching2RoomId roomId);
	void AddMember(SceNpMatching2RoomMemberDataInternal member);
	std::optional<SceNpMatching2RoomMemberDataInternal> GetMember(SceNpMatching2RoomMemberId memberId);
	void RemoveMember(SceNpMatching2RoomMemberId memberId);
private:
	std::vector<SceNpMatching2World> worlds;
	std::vector<SceNpMatching2RoomDataInternal> rooms;
	std::vector<SceNpMatching2RoomMemberDataInternal> members;
};
