#include "Core/Net/NpMatching2Cache.h"
void Cache::clear() {
	worlds.clear();
	rooms.clear();
	members.clear();
}
void Cache::AddWorld(SceNpMatching2World world) {

}

std::optional<SceNpMatching2World> Cache::GetWorld(SceNpMatching2WorldId worldId) {
	for (auto& world : worlds) {
		if (world.worldId == worldId) {
			return world;
		}
	}
	return std::nullopt;
}

void Cache::AddRoom(SceNpMatching2RoomDataInternal room) {

}

std::optional<SceNpMatching2RoomDataInternal> Cache::GetRoom(SceNpMatching2RoomId roomId) {
	return std::nullopt;
}

void Cache::AddMember(SceNpMatching2RoomMemberDataInternal member) {

}

std::optional<SceNpMatching2RoomMemberDataInternal> Cache::GetMember(SceNpMatching2RoomMemberId memberId) {
	return std::nullopt;
}
