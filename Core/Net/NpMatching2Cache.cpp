#include "Core/Net/NpMatching2Cache.h"
// Clear all cached objects
void Cache::clear() {
	worlds.clear();
	rooms.clear();
	members.clear();
}
// Update or Insert new World
void Cache::AddWorld(SceNpMatching2World world) {
	worlds.emplace(world.worldId, world);
}

// Check if World exists
bool Cache::Exists(SceNpMatching2WorldId worldId) {
	if (auto it = worlds.find(worldId); it != worlds.end())
		return true;
	return false;
}

// Remove World by WorldId
void Cache::RemoveWorld(SceNpMatching2WorldId worldId) {
	if (auto it = worlds.find(worldId); it != worlds.end())
		worlds.erase(it);
}

// Update or Insert new RoomDataInternal, and extract members
void Cache::AddRoom(SceNpMatching2RoomDataInternal room) {
	rooms.emplace(room.roomId, room);
	for (int i = 0; i < room.memberList.membersNum; i++) {
		AddMember(room.roomId, room.memberList.members[i]);
	}
}

// Check if Room exists
bool Cache::Exists(SceNpMatching2RoomId roomId) {
	if (auto it = rooms.find(roomId); it != rooms.end())
		return true;
	return false;
}

void Cache::SetPassword(SceNpMatching2SessionPassword password) {
	bufpwd = password;
}

void Cache::SavePassword(SceNpMatching2RoomId roomId) {
	passwords.emplace(roomId, bufpwd);
	bufpwd = SceNpMatching2SessionPassword();
}

bool Cache::HasPassword(SceNpMatching2RoomId roomId) {
	if (auto it = passwords.find(roomId); it != passwords.end())
		return true;
	return false;
}

SceNpMatching2SessionPassword Cache::GetRoomPassword(SceNpMatching2RoomId roomId) {
	if (auto it = passwords.find(roomId); it != passwords.end()) {
		return it->second;
	}

	_dbg_assert_msg_(false, "GetRoomPassword called for non-existent RoomId");
	return SceNpMatching2SessionPassword();
}
// Returns matching room or std::nullopt
//std::optional<SceNpMatching2RoomDataInternal> Cache::GetRoom(SceNpMatching2RoomId roomId) {
//	if (auto it = rooms.find(roomId); it != rooms.end()) {
//		return it->second;
//	}
//	return std::nullopt;
//}
// Remove Room by RoomId
void Cache::RemoveRoom(SceNpMatching2RoomId roomId) {
	if (auto room = rooms.find(roomId); room != rooms.end()) {
		auto range = members.equal_range(roomId);
		for (auto member = range.first; member != range.second; ++member) {
			members.erase(member);
		}
		if (auto pwd = passwords.find(roomId); pwd != passwords.end())
			passwords.erase(pwd);

		rooms.erase(room);
	}
}


// Update or Insert new MemberDataInternal
void Cache::AddMember(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberDataInternal member) {
	members.emplace(roomId, member);
}

// Check if Member exists
bool Cache::Exists(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId) {
	auto range = members.equal_range(roomId);
	for (auto it = range.first; it != range.second; ++it) {
		if (it->second.memberId == memberId)
			return true;
	}
	return false;
}

SceNpId Cache::GetNpId(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId) {
	auto range = members.equal_range(roomId);
	for (auto it = range.first; it != range.second; ++it) {
		if (it->second.memberId == memberId)
			return it->second.userInfo.npId;
	}
	_dbg_assert_msg_(false, "GetNpId called for non-existent RoomMember");
	return SceNpId();
}
// Returns matching member or std::nullopt
//std::optional<SceNpMatching2RoomMemberDataInternal> Cache::GetMember(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId) {
//	auto range = members.equal_range(roomId);
//	for (auto it = range.first; it != range.second; ++it) {
//		if (it->second.memberId == memberId)
//			return it->second;
//	}
//	return std::nullopt;
//}
// Remove Member by RoomMemberId
void Cache::RemoveMember(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId) {
	auto range = members.equal_range(roomId);
	for (auto it = range.first; it != range.second; ++it) {
		if (it->second.memberId == memberId) {
			members.erase(it);
			break;
		}
	}
}
