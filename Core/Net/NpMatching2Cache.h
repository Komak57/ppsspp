#pragma once
#include <vector>
#include <optional>
#include "Core/HLE/Np2Types.h"
#include <unordered_map>

class Cache {
public:
	void clear();
	void AddWorld(SceNpMatching2World world);
	//std::optional<SceNpMatching2World> GetWorldFromId(SceNpMatching2WorldId worldId);
	bool Exists(SceNpMatching2WorldId worldId);
	void RemoveWorld(SceNpMatching2WorldId worldId);

	void AddRoom(SceNpMatching2RoomDataInternal room);
	bool Exists(SceNpMatching2RoomId roomId);
	// Buffer the password
	void SetPassword(SceNpMatching2SessionPassword password);
	// Save the buffered password
	void SavePassword(SceNpMatching2RoomId roomId);
	bool HasPassword(SceNpMatching2RoomId roomId);
	SceNpMatching2SessionPassword GetRoomPassword(SceNpMatching2RoomId roomId);
	void RemoveRoom(SceNpMatching2RoomId roomId);
	//std::optional<SceNpMatching2RoomDataInternal> GetRoom(SceNpMatching2RoomId roomId);

	void AddMember(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberDataInternal member);
	bool Exists(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId);
	SceNpId GetNpId(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId);
	//std::optional<SceNpMatching2RoomMemberDataInternal> GetMember(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId);
	void RemoveMember(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId);
private:
	SceNpMatching2SessionPassword bufpwd;
	std::unordered_map<SceNpMatching2WorldId, SceNpMatching2World> worlds;
	std::unordered_map<SceNpMatching2RoomId, SceNpMatching2RoomDataInternal> rooms;
	std::unordered_map<SceNpMatching2RoomId, SceNpMatching2SessionPassword> passwords;
	std::unordered_multimap<SceNpMatching2RoomId, SceNpMatching2RoomMemberDataInternal> members;
};
