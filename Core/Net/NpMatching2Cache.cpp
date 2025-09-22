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
// Update or Insert new RoomDataInternal
void Cache::AddRoom(SceNpMatching2RoomDataInternal room) {
	for (auto& r : rooms) {
		if (r.roomId == room.roomId) {
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
