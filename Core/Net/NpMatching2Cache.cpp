#include "Core/Net/NpMatching2Cache.h"
// Clear all cached objects
void Cache::clear() {
	worlds.clear();
	rooms.clear();
	members.clear();
}
// Update or Insert new World
void Cache::AddWorld(SceNpMatching2World world) {
	for (auto& w : worlds) {
		if (w.worldId == world.worldId) {
			w = world;
			return;
		}
	}
	worlds.push_back(world);
}
// Returns matching world or std::nullopt
std::optional<SceNpMatching2World> Cache::GetWorld(SceNpMatching2WorldId worldId) {
	for (auto& world : worlds) {
		if (world.worldId == worldId) {
			return world;
		}
	}
	return std::nullopt;
}
// Remove World by WorldId
void Cache::RemoveWorld(SceNpMatching2WorldId worldId) {
	for (auto it = worlds.begin(); it != worlds.end();) {
		if (it->worldId == worldId) {
			worlds.erase(it);
			return;
		}
	}
}
// Update or Insert new RoomDataInternal, and extract members
void Cache::AddRoom(SceNpMatching2RoomDataInternal room) {
	for (int i = 0; i < room.memberList.membersNum; i++) {
		AddMember(room.memberList.members[i]);
	}
	for (auto& r : rooms) {
		if (r.roomId == room.roomId) {
			for (int i = 0; i < r.memberList.membersNum; i++) {
				AddMember(r.memberList.members[i]);
			}
			r = room;
			return;
		}
	}
	rooms.push_back(room);
}

// Returns matching room or std::nullopt
std::optional<SceNpMatching2RoomDataInternal> Cache::GetRoom(SceNpMatching2RoomId roomId) {
	for (auto& room : rooms) {
		if (room.roomId == roomId) {
			return room;
		}
	}
	return std::nullopt;
}
// Remove Room by RoomId
void Cache::RemoveRoom(SceNpMatching2RoomId roomId) {
	for (auto it = rooms.begin(); it != rooms.end();) {
		if (it->roomId == roomId) {
			rooms.erase(it);
			return;
		}
	}
}
// Update or Insert new MemberDataInternal
void Cache::AddMember(SceNpMatching2RoomMemberDataInternal member) {
	for (auto& m : members) {
		if (m.memberId == member.memberId) {
			m = member;
			return;
		}
	}
	members.push_back(member);
}

// Returns matching member or std::nullopt
std::optional<SceNpMatching2RoomMemberDataInternal> Cache::GetMember(SceNpMatching2RoomMemberId memberId) {
	for (auto& member : members) {
		if (member.memberId == memberId) {
			return member;
		}
	}
	return std::nullopt;
}
// Remove Member by RoomMemberId
void Cache::RemoveMember(SceNpMatching2RoomMemberId memberId) {
	for (auto it = members.begin(); it != members.end();) {
		if (it->memberId == memberId) {
			members.erase(it);
			return;
		}
	}
}
