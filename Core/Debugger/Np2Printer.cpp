#include "Core/Debugger/Np2Printer.h"
#include <numeric>
#include <Core/HLE/sceRtc.h>

void print_ScePspDateTime(const char* header, const u64 ticks) {
	ScePspDateTime updateDate;
	{
		int tz_seconds;
	#ifdef _WIN32
		long timezone_val;
		_get_timezone(&timezone_val);
		tz_seconds = -timezone_val;
	#elif !defined(_AIX) && !defined(__sgi) && !defined(__hpux) && !defined(HAVE_LIBNX)
		time_t timezone = 0;
		tm* time = localtime(&timezone);
		tz_seconds = time->tm_gmtoff;
	#endif

		u64 Day = 24ull * 60ull * 60ull * TICKS_PER_SECOND;
		updateDate.microsecond = ticks % TICKS_PER_SECOND;
		updateDate.second = ticks / TICKS_PER_SECOND % 60ull;
		updateDate.minute = ticks / TICKS_PER_SECOND / 60ull % 60ull;
		updateDate.hour = ticks / TICKS_PER_SECOND / 60ull / 60ull % 24ull;
		s64 z = s64(ticks / Day) - s64(rtcMagicOffset / Day);
		s64 out_y;
		u32 out_m, out_d;
		{
			z += 719468;
			const s64 era = (z >= 0 ? z : z - 146096) / 146097;
			const u32 doe = static_cast<u32>(z - era * 146097);              // [0, 146096]
			const u32 yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
			const s64 y = static_cast<s64>(yoe) + era * 400;
			const u32 doy = doe - (365 * yoe + yoe / 4 - yoe / 100);               // [0, 365]
			const u32 mp = (5 * doy + 2) / 153;                                  // [0, 11]
			out_d = doy - (153 * mp + 2) / 5 + 1;                                  // [1, 31]
			out_m = mp < 10 ? mp + 3 : mp - 9;                                   // [1, 12]
			out_y = y + (out_m <= 2);
		}
		updateDate.day = out_d;
		updateDate.month = out_m;
		updateDate.year = out_y;
	}
	INFO_LOG(Log::sceNet, "%s: %d/%d/%d %d:%d:%d %d", header, updateDate.month, updateDate.day, updateDate.year, updateDate.hour, updateDate.minute, updateDate.second, updateDate.microsecond);
}

void print_SceNpUserInfo2(const SceNpUserInfo2* user)
{
	INFO_LOG(Log::sceNet, "SceNpUserInfo2:");
	INFO_LOG(Log::sceNet, "npid: %s", user->npId.ToString().c_str());
	INFO_LOG(Log::sceNet, "onlineName: *0x%x(%s)", user->onlineName, user->onlineName.IsValid() ? static_cast<const char*>(user->onlineName->data) : "");
	INFO_LOG(Log::sceNet, "avatarUrl: *0x%x(%s)", user->avatarUrl, user->avatarUrl.IsValid() ? static_cast<const char*>(user->avatarUrl->data) : "");
}

void print_SceNpMatching2SignalingOptParam(const SceNpMatching2SignalingOptions* opt)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2SignalingOptParam:");
	INFO_LOG(Log::sceNet, "type: %d", opt->type);
	INFO_LOG(Log::sceNet, "flag: %d", opt->flag);
	INFO_LOG(Log::sceNet, "hubMemberId: %d", opt->hubMemberId);
}

void print_int_attr(const SceNpMatching2IntAttr* attr)
{
	INFO_LOG(Log::sceNet, "Id: 0x%x, num:%d(0x%x)", attr->id, attr->num, attr->num);
}

void print_SceNpMatching2BinAttr(const SceNpMatching2BinAttr* bin)
{
	const auto ptr = bin->ptr;
	const u32 size = bin->size;

	INFO_LOG(Log::sceNet, "Id: %d, Size: %d, ptr: *0x%x", bin->id, size, bin->ptr.ptr);
	if (bin->ptr.IsValid() && size)
	{
		INFO_HEXLOG(Log::sceNet, "Data:", reinterpret_cast<const u8*>(&*bin->ptr), size, 386);
	}
}

void print_SceNpMatching2BinAttr_internal(const SceNpMatching2RoomBinAttrInternal* bin)
{
	print_ScePspDateTime("updateDate", bin->updateDate.tick);
	INFO_LOG(Log::sceNet, "updateMemberId: %d", bin->updateMemberId);
	print_SceNpMatching2BinAttr(&bin->data);
}

void print_member_bin_attr_internal(const SceNpMatching2RoomMemberBinAttrInternal* bin)
{
	print_ScePspDateTime("updateDate", bin->updateDate.tick);
	print_SceNpMatching2BinAttr(&bin->data);
}

void print_SceNpMatching2PresenceOptionData(const SceNpMatching2PresenceOptionData* opt)
{
	INFO_HEXLOG(Log::sceNet, "Data:", reinterpret_cast<const u8*>(&*opt->data), sizeof(u8) * opt->length, 386);
}

void print_range(const SceNpMatching2Range* range)
{
	INFO_LOG(Log::sceNet, "startIndex: %d", range->startIndex);
	INFO_LOG(Log::sceNet, "total: %d", range->total);
	INFO_LOG(Log::sceNet, "size: %d", range->size);
}

void print_SceNpMatching2RangeFilter(const SceNpMatching2RangeFilter* filt)
{
	INFO_LOG(Log::sceNet, "startIndex: %d", filt->startIndex);
	INFO_LOG(Log::sceNet, "max: %d", filt->max);
}

void print_int_search_filter(const SceNpMatching2IntSearchFilter* filt)
{
	INFO_LOG(Log::sceNet, "searchOperator: %u", filt->searchOperator);
	print_int_attr(&filt->attr);
}

void print_bin_search_filter(const SceNpMatching2BinSearchFilter* filt)
{
	INFO_LOG(Log::sceNet, "searchOperator: %u", filt->searchOperator);
	print_SceNpMatching2BinAttr(&filt->attr);
}

// Verified against np_matching2.prx (OFW 6.60): flagFilter and flagAttr share the
// ROOM_FLAG_ATTR bit domain. The firmware serializer (FUN_0000bc40) sends them
// paired to the server - filter selects which bits to change, attr their values -
// and omits the block entirely when filter == 0.
void print_SceNpMatching2FlagAttr(const SceNpMatching2FlagAttr flagAttr, const char *label) {
	std::vector<std::string> flags;
	if (flagAttr == 0)
		flags.push_back("NONE | ");
	else {
		if (flagAttr & SCE_NP_MATCHING2_ROOM_FLAG_ATTR_OWNER_AUTO_GRANT)
			flags.push_back("OWNER_AUTO_GRANT | ");
		if (flagAttr & SCE_NP_MATCHING2_ROOM_FLAG_ATTR_CLOSED)
			flags.push_back("CLOSED | ");
		if (flagAttr & SCE_NP_MATCHING2_ROOM_FLAG_ATTR_FULL)
			flags.push_back("FULL | ");
		if (flagAttr & SCE_NP_MATCHING2_ROOM_FLAG_ATTR_HIDDEN)
			flags.push_back("HIDDEN | ");
		if (flagAttr & SCE_NP_MATCHING2_ROOM_FLAG_ATTR_NAT_TYPE_RESTRICTION)
			flags.push_back("NAT_TYPE_RESTRICTION | ");
		if (flagAttr & SCE_NP_MATCHING2_ROOM_FLAG_ATTR_PROHIBITIVE_MODE)
			flags.push_back("PROHIBITIVE_MODE | ");
	}
	std::string _flags = std::accumulate(flags.begin(), flags.end(), std::string(""));
	INFO_LOG(Log::sceNet, "%s: 0x%x => %s", label, flagAttr, _flags.substr(0, _flags.length() - 3).c_str());
}

void print_SceNpMatching2CreateJoinRoomRequest(const SceNpMatching2CreateJoinRoomRequest* req)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2CreateJoinRoomRequest:");
	INFO_LOG(Log::sceNet, "worldId: %d", req->worldId);
	INFO_LOG(Log::sceNet, "lobbyId: %d", req->lobbyId);
	INFO_LOG(Log::sceNet, "maxSlot: %d", req->maxSlot);

	print_SceNpMatching2FlagAttr(req->flagAttr);

	INFO_LOG(Log::sceNet, "roomBinAttrInternal: *0x%x", req->roomBinAttrInternal.ptr);
	INFO_LOG(Log::sceNet, "roomBinAttrInternalNum: %d", req->roomBinAttrInternalNum);

	for (u32 i = 0; i < req->roomBinAttrInternalNum && req->roomBinAttrInternal.IsValid(); i++)
		print_SceNpMatching2BinAttr(req->roomBinAttrInternal + i);

	INFO_LOG(Log::sceNet, "roomSearchableIntAttrExternal: *0x%x", req->roomSearchableIntAttrExternal.ptr);
	INFO_LOG(Log::sceNet, "roomSearchableIntAttrExternalNum: %d", req->roomSearchableIntAttrExternalNum);

	for (u32 i = 0; i < req->roomSearchableIntAttrExternalNum && req->roomSearchableIntAttrExternal.IsValid(); i++)
		print_int_attr(req->roomSearchableIntAttrExternal + i);

	INFO_LOG(Log::sceNet, "roomSearchableBinAttrExternal: *0x%x", req->roomSearchableBinAttrExternal.ptr);
	INFO_LOG(Log::sceNet, "roomSearchableBinAttrExternalNum: %d", req->roomSearchableBinAttrExternalNum);

	for (u32 i = 0; i < req->roomSearchableBinAttrExternalNum && req->roomSearchableBinAttrExternal.IsValid(); i++)
		print_SceNpMatching2BinAttr(req->roomSearchableBinAttrExternal + i);

	INFO_LOG(Log::sceNet, "roomBinAttrExternal: *0x%x", req->roomBinAttrExternal.ptr);
	INFO_LOG(Log::sceNet, "roomBinAttrExternalNum: %d", req->roomBinAttrExternalNum);

	for (u32 i = 0; i < req->roomBinAttrExternalNum && req->roomBinAttrExternal.IsValid(); i++)
		print_SceNpMatching2BinAttr(req->roomBinAttrExternal + i);

	INFO_LOG(Log::sceNet, "roomPassword: *0x%x", req->roomPassword.ptr);

	if (req->roomPassword.IsValid())
		INFO_HEXLOG(Log::sceNet, "data:", reinterpret_cast<const u8*>(&*req->roomPassword->data), sizeof(u8) * 8, 386);

	INFO_LOG(Log::sceNet, "groupConfig: *0x%x", req->groupConfig);
	INFO_LOG(Log::sceNet, "groupConfigNum: %d", req->groupConfigNum);
	INFO_LOG(Log::sceNet, "passwordSlotMask: *0x%x, value: 0x%x", req->passwordSlotMask.ptr, req->passwordSlotMask.IsValid() ? static_cast<u64>(*req->passwordSlotMask) : 0ull);
	INFO_LOG(Log::sceNet, "allowedUser: *0x%x", req->allowedUser);
	INFO_LOG(Log::sceNet, "allowedUserNum: %d", req->allowedUserNum);
	INFO_LOG(Log::sceNet, "blockedUser: *0x%x", req->blockedUser);
	INFO_LOG(Log::sceNet, "blockedUserNum: %d", req->blockedUserNum);
	INFO_LOG(Log::sceNet, "joinRoomGroupLabel: *0x%x", req->joinRoomGroupLabel);
	INFO_LOG(Log::sceNet, "roomMemberBinAttrInternal: *0x%x", req->roomMemberBinAttrInternal);
	INFO_LOG(Log::sceNet, "roomMemberBinAttrInternalNum: %d", req->roomMemberBinAttrInternalNum);

	for (u32 i = 0; i < req->roomMemberBinAttrInternalNum && req->roomMemberBinAttrInternal.IsValid(); i++)
		print_SceNpMatching2BinAttr(req->roomMemberBinAttrInternal + i);

	INFO_LOG(Log::sceNet, "teamId: %d", req->teamId);
	INFO_LOG(Log::sceNet, "sigOptParam: *0x%x", req->sigOptions.ptr);

	if (req->sigOptions.IsValid())
		print_SceNpMatching2SignalingOptParam(req->sigOptions);
}

void print_SceNpMatching2JoinRoomRequest(const SceNpMatching2JoinRoomRequest* req)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2JoinRoomRequest:");
	INFO_LOG(Log::sceNet, "roomId: %d", req->roomId);
	INFO_LOG(Log::sceNet, "roomPassword: *0x%x", req->roomPassword.ptr);
	INFO_LOG(Log::sceNet, "joinRoomGroupLabel: *0x%x", req->joinRoomGroupLabel.ptr);
	INFO_LOG(Log::sceNet, "roomMemberBinAttrInternal: *0x%x", req->roomMemberBinAttrInternal.ptr);
	INFO_LOG(Log::sceNet, "roomMemberBinAttrInternalNum: %d", req->roomMemberBinAttrInternalNum);
	print_SceNpMatching2PresenceOptionData(&req->optData);
	INFO_LOG(Log::sceNet, "teamId: %d", req->teamId);

	for (u32 i = 0; i < req->roomMemberBinAttrInternalNum && req->roomMemberBinAttrInternal.IsValid(); i++)
		print_SceNpMatching2BinAttr(req->roomMemberBinAttrInternal + i);
}

void print_SceNpMatching2SearchRoomRequest(const SceNpMatching2SearchRoomRequest* req)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2SearchRoomRequest:");
	INFO_LOG(Log::sceNet, "option: 0x%x", req->option);
	INFO_LOG(Log::sceNet, "worldId: %d", req->worldId);
	INFO_LOG(Log::sceNet, "lobbyId: %lld", req->lobbyId);
	print_SceNpMatching2RangeFilter(&req->rangeFilter);
	INFO_LOG(Log::sceNet, "flagFilter: 0x%x", req->flagFilter);

	print_SceNpMatching2FlagAttr(req->flagAttr);

	INFO_LOG(Log::sceNet, "intFilter: *0x%x", req->intFilter.ptr);
	INFO_LOG(Log::sceNet, "intFilterNum: %d", req->intFilterNum);
	for (u32 i = 0; i < req->intFilterNum && req->intFilter.IsValid(); i++)
		print_int_search_filter(&req->intFilter[i]);
	INFO_LOG(Log::sceNet, "binFilter: *0x%x", req->binFilter.ptr);
	INFO_LOG(Log::sceNet, "binFilterNum: %d", req->binFilterNum);
	for (u32 i = 0; i < req->binFilterNum && req->binFilter.IsValid(); i++)
		print_bin_search_filter(&req->binFilter[i]);
	INFO_LOG(Log::sceNet, "attrId: *0x%x", req->attrId.ptr);
	INFO_LOG(Log::sceNet, "attrIdNum: %d", req->attrIdNum);
	for (u32 i = 0; i < req->attrIdNum && req->attrId.IsValid(); i++)
		INFO_LOG(Log::sceNet, "attrId[%d] = 0x%x", i, req->attrId[i]);
}

void print_SceNpMatching2SearchRoomResponse(const SceNpMatching2SearchRoomResponse* resp)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2SearchRoomResponse:");
	print_range(&resp->range);

	const SceNpMatching2RoomDataExternal* room_ptr = resp->roomDataExternal;
	for (u32 i = 0; i < resp->range.total; i++)
	{
		INFO_LOG(Log::sceNet, "SceNpMatching2SearchRoomResponse[%d]:", i);
		print_SceNpMatching2RoomDataExternal(room_ptr);
		room_ptr = room_ptr->next;
	}
}

void print_SceNpMatching2RoomMemberDataInternal(const SceNpMatching2RoomMemberDataInternal* member)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2RoomMemberDataInternal:");
	INFO_LOG(Log::sceNet, "next: *0x%x", member->next.ptr);
	INFO_LOG(Log::sceNet, "npId: %s", member->userInfo.npId.ToString().c_str());
	INFO_LOG(Log::sceNet, "onlineName: %s", member->userInfo.onlineName.IsValid() ? member->userInfo.onlineName->data : "");
	INFO_LOG(Log::sceNet, "avatarUrl: %s", member->userInfo.avatarUrl.IsValid() ? member->userInfo.avatarUrl->data : "");
	//INFO_LOG(Log::sceNet, "joinDate: %lld", member->joinDate.tick);
	print_ScePspDateTime("joinDate", member->joinDate.tick);
	INFO_LOG(Log::sceNet, "memberId: %d", member->memberId);
	INFO_LOG(Log::sceNet, "teamId: %d", member->teamId);
	INFO_LOG(Log::sceNet, "roomGroup: *0x%x", member->roomGroup.ptr);
	INFO_LOG(Log::sceNet, "natType: %d", member->natType);

	std::vector<std::string> flags;
	if (member->flagAttr == 0)
		flags.push_back("NONE | ");
	else {
		if (member->flagAttr & SCE_NP_MATCHING2_LOBBYMEMBER_FLAG_ATTR_OWNER)
			flags.push_back("LOBBY_OWNER | ");
		if (member->flagAttr & SCE_NP_MATCHING2_ROOMMEMBER_FLAG_ATTR_OWNER)
			flags.push_back("ROOM_OWNER | ");
	}
	std::string _flags = std::accumulate(flags.begin(), flags.end(), std::string(""));
	INFO_LOG(Log::sceNet, "flagAttr: 0x%x => %s", member->flagAttr, _flags.substr(0, _flags.length() - 3).c_str());

	INFO_LOG(Log::sceNet, "roomMemberBinAttrInternal: *0x%x", member->roomMemberBinAttrInternal.ptr);
	INFO_LOG(Log::sceNet, "roomMemberBinAttrInternalNum: %d", member->roomMemberBinAttrInternalNum);
	for (u32 i = 0; i < member->roomMemberBinAttrInternalNum && member->roomMemberBinAttrInternal.IsValid(); i++)
		print_member_bin_attr_internal(&member->roomMemberBinAttrInternal[i]);
}

void print_SceNpMatching2RoomDataInternal(const SceNpMatching2RoomDataInternal* room)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2RoomDataInternal:");
	INFO_LOG(Log::sceNet, "serverId: %d", room->serverId);
	INFO_LOG(Log::sceNet, "worldId: %d", room->worldId);
	INFO_LOG(Log::sceNet, "lobbyId: %lld", room->lobbyId);
	INFO_LOG(Log::sceNet, "roomId: %lld", room->roomId);
	INFO_LOG(Log::sceNet, "passwordSlotMask: 0x%x", room->passwordSlotMask);
	INFO_LOG(Log::sceNet, "maxSlot: %d", room->maxSlot);

	INFO_LOG(Log::sceNet, "members: *0x%x", room->memberList.members.ptr);
	auto cur_member = room->memberList.members;
	while (cur_member.IsValid())
	{
		print_SceNpMatching2RoomMemberDataInternal(cur_member);
		cur_member = cur_member->next;
	}
	INFO_LOG(Log::sceNet, "membersNum: %d", room->memberList.membersNum);
	INFO_LOG(Log::sceNet, "me: *0x%x", room->memberList.me.ptr);
	INFO_LOG(Log::sceNet, "owner: *0x%x", room->memberList.owner.ptr);

	INFO_LOG(Log::sceNet, "roomGroup: *0x%x", room->roomGroup.ptr);
	INFO_LOG(Log::sceNet, "roomGroupNum: %d", room->roomGroupNum);

	print_SceNpMatching2FlagAttr(room->flagAttr);

	INFO_LOG(Log::sceNet, "roomBinAttrInternal: *0x%x", room->roomBinAttrInternal.ptr);
	INFO_LOG(Log::sceNet, "roomBinAttrInternalNum: %d", room->roomBinAttrInternalNum);
	for (u32 i = 0; i < room->roomBinAttrInternalNum && room->roomBinAttrInternal.IsValid(); i++)
		print_SceNpMatching2BinAttr_internal(room->roomBinAttrInternal + i);
}

void print_SceNpMatching2RoomDataExternal(const SceNpMatching2RoomDataExternal* room)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2RoomDataExternal:");
	INFO_LOG(Log::sceNet, "next: *0x%x", room->next.ptr);
	INFO_LOG(Log::sceNet, "serverId: %d", room->serverId);
	INFO_LOG(Log::sceNet, "worldId: %d", room->worldId);
	INFO_LOG(Log::sceNet, "publicSlotNum: %d", room->publicSlotNum);
	INFO_LOG(Log::sceNet, "privateSlotNum: %d", room->privateSlotNum);
	INFO_LOG(Log::sceNet, "lobbyId: %d", room->lobbyId);
	INFO_LOG(Log::sceNet, "roomId: %d", room->roomId);
	//INFO_LOG(Log::sceNet, "openPublicSlotNum: %d", room->openPublicSlotNum);
	INFO_LOG(Log::sceNet, "maxSlot: %d", room->maxSlot);
	//INFO_LOG(Log::sceNet, "openPrivateSlotNum: %d", room->openPrivateSlotNum);
	INFO_LOG(Log::sceNet, "curMemberNum: %d", room->curMemberNum);
	INFO_LOG(Log::sceNet, "SceNpMatching2RoomPasswordSlotMask: 0x%x", room->passwordSlotMask);
	INFO_LOG(Log::sceNet, "owner: *0x%x", room->owner.ptr);

	if (room->owner.IsValid())
		print_SceNpUserInfo2(room->owner);

	INFO_LOG(Log::sceNet, "roomGroup: *0x%x", room->roomGroup.ptr);
	// TODO: print roomGroup
	INFO_LOG(Log::sceNet, "roomGroupNum: %d", room->roomGroupNum);

	print_SceNpMatching2FlagAttr(room->flagAttr);

	INFO_LOG(Log::sceNet, "roomSearchableIntAttrExternal: *0x%x", room->roomSearchableIntAttrExternal.ptr);
	INFO_LOG(Log::sceNet, "roomSearchableIntAttrExternalNum: %d", room->roomSearchableIntAttrExternalNum);

	for (u32 i = 0; i < room->roomSearchableIntAttrExternalNum && room->roomSearchableIntAttrExternal.IsValid(); i++)
		print_int_attr(&room->roomSearchableIntAttrExternal[i]);

	INFO_LOG(Log::sceNet, "roomSearchableBinAttrExternal: *0x%x", room->roomSearchableBinAttrExternal.ptr);
	INFO_LOG(Log::sceNet, "roomSearchableBinAttrExternalNum: %d", room->roomSearchableBinAttrExternalNum);

	for (u32 i = 0; i < room->roomSearchableBinAttrExternalNum && room->roomSearchableBinAttrExternal.IsValid(); i++)
		print_SceNpMatching2BinAttr(room->roomSearchableBinAttrExternal + i);

	INFO_LOG(Log::sceNet, "roomBinAttrExternal: *0x%x", room->roomBinAttrExternal.ptr);
	INFO_LOG(Log::sceNet, "roomBinAttrExternalNum: %d", room->roomBinAttrExternalNum);

	for (u32 i = 0; i < room->roomBinAttrExternalNum && room->roomBinAttrExternal.IsValid(); i++)
		print_SceNpMatching2BinAttr(room->roomBinAttrExternal + i);
}

void print_SceNpMatching2CreateJoinRoomResponse(const SceNpMatching2CreateJoinRoomResponse* resp)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2CreateJoinRoomResponse:");
	INFO_LOG(Log::sceNet, "roomDataInternal: *0x%x", resp->roomDataInternal.ptr);
	if (resp->roomDataInternal.IsValid())
		print_SceNpMatching2RoomDataInternal(resp->roomDataInternal);
}

void print_SceNpMatching2SetRoomDataExternalRequest(const SceNpMatching2SetRoomDataExternalRequest* req)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2SetRoomDataExternalRequest:");
	INFO_LOG(Log::sceNet, "roomId: %d", req->roomId);
	INFO_LOG(Log::sceNet, "roomSearchableIntAttrExternal: *0x%x", req->roomSearchableIntAttrExternal.ptr);
	INFO_LOG(Log::sceNet, "roomSearchableIntAttrExternalNum: %d", req->roomSearchableIntAttrExternalNum);

	for (u32 i = 0; i < req->roomSearchableIntAttrExternalNum && req->roomSearchableIntAttrExternal.IsValid(); i++)
		print_int_attr(&req->roomSearchableIntAttrExternal[i]);

	INFO_LOG(Log::sceNet, "roomSearchableBinAttrExternal: *0x%x", req->roomSearchableBinAttrExternal.ptr);
	INFO_LOG(Log::sceNet, "roomSearchableBinAttrExternalNum: %d", req->roomSearchableBinAttrExternalNum);

	for (u32 i = 0; i < req->roomSearchableBinAttrExternalNum && req->roomSearchableBinAttrExternal.IsValid(); i++)
		print_SceNpMatching2BinAttr(req->roomSearchableBinAttrExternal + i);

	INFO_LOG(Log::sceNet, "roomBinAttrExternal: *0x%x", req->roomBinAttrExternal.ptr);
	INFO_LOG(Log::sceNet, "roomBinAttrExternalNum: %d", req->roomBinAttrExternalNum);

	for (u32 i = 0; i < req->roomBinAttrExternalNum && req->roomBinAttrExternal.IsValid(); i++)
		print_SceNpMatching2BinAttr(req->roomBinAttrExternal + i);
}

void print_SceNpMatching2SetRoomDataInternalRequest(const SceNpMatching2SetRoomDataInternalRequest* req)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2SetRoomDataInternalRequest:");
	INFO_LOG(Log::sceNet, "roomId: %d", req->roomId);
	print_SceNpMatching2FlagAttr(req->flagFilter, "flagFilter");
	print_SceNpMatching2FlagAttr(req->flagAttr);

	INFO_LOG(Log::sceNet, "roomBinAttrInternal: *0x%x", req->roomBinAttrInternal.ptr);
	INFO_LOG(Log::sceNet, "roomBinAttrInternalNum: %d", req->roomBinAttrInternalNum);

	for (u32 i = 0; i < req->roomBinAttrInternalNum && req->roomBinAttrInternal.IsValid(); i++)
		print_SceNpMatching2BinAttr(req->roomBinAttrInternal + i);

	INFO_LOG(Log::sceNet, "passwordConfig: *0x%x", req->passwordConfig.ptr);
	INFO_LOG(Log::sceNet, "passwordConfigNum: %d", req->passwordConfigNum);
	INFO_LOG(Log::sceNet, "passwordSlotMask: *0x%x", req->passwordSlotMask.ptr);
	INFO_LOG(Log::sceNet, "ownerPrivilegeRank: *0x%x", req->ownerPrivilegeRank.ptr);
	INFO_LOG(Log::sceNet, "ownerPrivilegeRankNum: %d", req->ownerPrivilegeRankNum);
}

void print_SceNpMatching2GetRoomMemberDataInternalRequest(const SceNpMatching2GetRoomMemberDataInternalRequest* req)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2GetRoomMemberDataInternalRequest:");
	INFO_LOG(Log::sceNet, "roomId: %d", req->roomId);
	INFO_LOG(Log::sceNet, "memberId: %d", req->memberId);
	INFO_LOG(Log::sceNet, "attrId: *0x%x", req->attrId.ptr);
	INFO_LOG(Log::sceNet, "attrIdNum: %d", req->attrIdNum);
	for (u32 i = 0; i < req->attrIdNum && req->attrId.IsValid(); i++)
	{
		INFO_LOG(Log::sceNet, "attrId[%d] = %d", i, req->attrId[i]);
	}
}

void print_SceNpMatching2SetRoomMemberDataInternalRequest(const SceNpMatching2SetRoomMemberDataInternalRequest* req)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2SetRoomMemberDataInternalRequest:");
	INFO_LOG(Log::sceNet, "roomId: %d", req->roomId);
	INFO_LOG(Log::sceNet, "memberId: %d", req->memberId);
	INFO_LOG(Log::sceNet, "teamId: %d", req->teamId);
	print_SceNpMatching2FlagAttr(req->flagFilter, "flagFilter");
	print_SceNpMatching2FlagAttr(req->flagAttr);

	INFO_LOG(Log::sceNet, "roomMemberBinAttrInternal: *0x%x", req->roomMemberBinAttrInternal.ptr);
	INFO_LOG(Log::sceNet, "roomMemberBinAttrInternalNum: %d", req->roomMemberBinAttrInternalNum);
	for (u32 i = 0; i < req->roomMemberBinAttrInternalNum && req->roomMemberBinAttrInternal.IsValid(); i++)
		print_SceNpMatching2BinAttr(req->roomMemberBinAttrInternal + i);
}

void print_SceNpMatching2GetRoomDataExternalListRequest(const SceNpMatching2GetRoomDataExternalListRequest* req)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2GetRoomDataExternalListRequest:");
	INFO_LOG(Log::sceNet, "roomId: *0x%x", req->roomId.ptr);
	INFO_LOG(Log::sceNet, "roomIdNum: %d", req->roomIdNum);
	for (u32 i = 0; i < req->roomIdNum && req->roomId.IsValid(); i++)
	{
		INFO_LOG(Log::sceNet, "RoomId[%d] = %d", i, req->roomId[i]);
	}
	INFO_LOG(Log::sceNet, "attrId: *0x%x", req->attrId.ptr);
	INFO_LOG(Log::sceNet, "attrIdNum: %d", req->attrIdNum);
	for (u32 i = 0; i < req->attrIdNum && req->attrId.IsValid(); i++)
	{
		INFO_LOG(Log::sceNet, "attrId[%d] = %d", i, req->attrId[i]);
	}
}

void print_SceNpMatching2GetRoomDataExternalListResponse(const SceNpMatching2GetRoomDataExternalListResponse* resp)
{
	INFO_LOG(Log::sceNet, "SceNpMatching2GetRoomDataExternalListResponse:");
	INFO_LOG(Log::sceNet, "roomDataExternal: *0x%x", resp->roomDataExternal.ptr);
	INFO_LOG(Log::sceNet, "roomDataExternalNum: %d", resp->roomDataExternalNum);

	auto cur_room = resp->roomDataExternal;

	for (u32 i = 0; i < resp->roomDataExternalNum && cur_room.IsValid(); i++)
	{
		INFO_LOG(Log::sceNet, "SceNpMatching2GetRoomDataExternalListResponse[%d]:", i);
		print_SceNpMatching2RoomDataExternal(cur_room);
		cur_room = cur_room->next;
	}
}

//void print_SceNpMatching2GetLobbyInfoListRequest(const SceNpMatching2GetLobbyInfoListRequest* resp)
//{
//	INFO_LOG(Log::sceNet, "SceNpMatching2GetLobbyInfoListRequest:");
//	INFO_LOG(Log::sceNet, "worldId: %d", resp->worldId);
//	print_SceNpMatching2RangeFilter(&resp->rangeFilter);
//	INFO_LOG(Log::sceNet, "attrIdNum: %d", resp->attrIdNum);
//	INFO_LOG(Log::sceNet, "attrId: *0x%x", resp->attrId.ptr);
//
//	if (resp->attrId.IsValid())
//	{
//		for (u32 i = 0; i < resp->attrIdNum; i++)
//		{
//			INFO_LOG(Log::sceNet, "attrId[%d] = %d", i, resp->attrId[i]);
//		}
//	}
//}

//void print_SceNpBasicAttachmentData(const SceNpBasicAttachmentData* data)
//{
//	INFO_LOG(Log::sceNet, "SceNpBasicAttachmentData:");
//	INFO_LOG(Log::sceNet, "id: 0x%x", data->id);
//	INFO_LOG(Log::sceNet, "size: %d", data->size);
//}
//
//void print_SceNpBasicExtendedAttachmentData(const SceNpBasicExtendedAttachmentData* data)
//{
//	INFO_LOG(Log::sceNet, "SceNpBasicExtendedAttachmentData:");
//
//	INFO_LOG(Log::sceNet, "flags: 0x%x", data->flags);
//	INFO_LOG(Log::sceNet, "msgId: %d", data->msgId);
//	INFO_LOG(Log::sceNet, "SceNpBasicAttachmentData.id: %d", data->data.id);
//	INFO_LOG(Log::sceNet, "SceNpBasicAttachmentData.size: %d", data->data.size);
//	INFO_LOG(Log::sceNet, "userAction: %d", data->userAction);
//	INFO_LOG(Log::sceNet, "markedAsUsed: %d", data->markedAsUsed);
//}
//
//void print_SceNpScoreRankData(const SceNpScoreRankData* data)
//{
//	INFO_LOG(Log::sceNet, "sceNpScoreRankData:");
//	INFO_LOG(Log::sceNet, "npId: %s", static_cast<const char*>(data->npId.handle.data));
//	INFO_LOG(Log::sceNet, "onlineName: %s", static_cast<const char*>(data->onlineName.data));
//	INFO_LOG(Log::sceNet, "pcId: %d", data->pcId);
//	INFO_LOG(Log::sceNet, "serialRank: %d", data->serialRank);
//	INFO_LOG(Log::sceNet, "rank: %d", data->rank);
//	INFO_LOG(Log::sceNet, "highestRank: %d", data->highestRank);
//	INFO_LOG(Log::sceNet, "scoreValue: %d", data->scoreValue);
//	INFO_LOG(Log::sceNet, "hasGameData: %d", data->hasGameData);
//	INFO_LOG(Log::sceNet, "recordDate: %d", data->recordDate.tick);
//}
//
//void print_SceNpScoreRankData_deprecated(const SceNpScoreRankData_deprecated* data)
//{
//	INFO_LOG(Log::sceNet, "sceNpScoreRankData_deprecated:");
//	INFO_LOG(Log::sceNet, "npId: %s", static_cast<const char*>(data->npId.handle.data));
//	INFO_LOG(Log::sceNet, "onlineName: %s", static_cast<const char*>(data->onlineName.data));
//	INFO_LOG(Log::sceNet, "serialRank: %d", data->serialRank);
//	INFO_LOG(Log::sceNet, "rank: %d", data->rank);
//	INFO_LOG(Log::sceNet, "highestRank: %d", data->highestRank);
//	INFO_LOG(Log::sceNet, "scoreValue: %d", data->scoreValue);
//	INFO_LOG(Log::sceNet, "hasGameData: %d", data->hasGameData);
//	INFO_LOG(Log::sceNet, "recordDate: %d", data->recordDate.tick);
//}
//
//void print_SceNpMatchingAttr(const SceNpMatchingAttr* data)
//{
//	INFO_LOG(Log::sceNet, "SceNpMatchingAttr:");
//	INFO_LOG(Log::sceNet, "next: 0x%x", data->next);
//	INFO_LOG(Log::sceNet, "type: %d", data->type);
//	INFO_LOG(Log::sceNet, "id: %d", data->id);
//
//	if (data->type == SCE_NP_MATCHING_ATTR_TYPE_BASIC_BIN || data->type == SCE_NP_MATCHING_ATTR_TYPE_GAME_BIN)
//	{
//		INFO_LOG(Log::sceNet, "ptr: *0x%x", data->value.data.ptr);
//		INFO_LOG(Log::sceNet, "size: %d", data->value.data.size);
//		INFO_LOG(Log::sceNet, "data:\n%s", fmt::buf_to_hexstring(static_cast<u8*>(data->value.data.ptr.get_ptr()), data->value.data.size));
//	}
//	else
//	{
//		INFO_LOG(Log::sceNet, "num: %d(0x%x)", data->value.num, data->value.num);
//	}
//}
//
//void print_SceNpMatchingSearchCondition(const SceNpMatchingSearchCondition* data)
//{
//	INFO_LOG(Log::sceNet, "SceNpMatchingSearchCondition:");
//	INFO_LOG(Log::sceNet, "target_attr_type: %d", data->target_attr_type);
//	INFO_LOG(Log::sceNet, "target_attr_id: %d", data->target_attr_id);
//	INFO_LOG(Log::sceNet, "comp_type: %d", data->comp_type);
//	INFO_LOG(Log::sceNet, "comp_op: %d", data->comp_op);
//	INFO_LOG(Log::sceNet, "next: 0x%x", data->next);
//	print_SceNpMatchingAttr(&data->compared);
//}
//
//void print_SceNpMatchingRoom(const SceNpMatchingRoom* data)
//{
//	INFO_LOG(Log::sceNet, "SceNpMatchingRoom:");
//	INFO_LOG(Log::sceNet, "next: 0x%x", data->next);
//	print_SceNpRoomId(data->id);
//
//	for (auto it = data->attr; it; it = it->next)
//	{
//		print_SceNpMatchingAttr(it.get_ptr());
//	}
//}
//
//void print_SceNpMatchingRoomList(const SceNpMatchingRoomList* data)
//{
//	INFO_LOG(Log::sceNet, "SceNpMatchingRoomList:");
//	INFO_LOG(Log::sceNet, "lobbyid.opt: %s", fmt::buf_to_hexstring(data->lobbyid.opt, sizeof(data->lobbyid.opt), sizeof(data->lobbyid.opt)));
//	INFO_LOG(Log::sceNet, "start: %d", data->range.start);
//	INFO_LOG(Log::sceNet, "results: %d", data->range.results);
//	INFO_LOG(Log::sceNet, "total: %d", data->range.total);
//
//	for (auto it = data->head; it; it = it->next)
//	{
//		print_SceNpMatchingRoom(it.get_ptr());
//	}
//}
//
//void print_SceNpUserInfo(const SceNpUserInfo* data)
//{
//	INFO_LOG(Log::sceNet, "userId: %s", data->userId.handle.data);
//	INFO_LOG(Log::sceNet, "name: %s", data->name.data);
//	INFO_LOG(Log::sceNet, "icon: %s", data->icon.data);
//}
//
//void print_SceNpRoomId(const SceNpRoomId& room_id)
//{
//	INFO_LOG(Log::sceNet, "room_id: %s", fmt::buf_to_hexstring(room_id.opt, sizeof(room_id.opt), sizeof(room_id.opt)));
//}
//
//void print_SceNpMatchingRoomMember(const SceNpMatchingRoomMember* data)
//{
//	INFO_LOG(Log::sceNet, "SceNpMatchingRoomMember:");
//	INFO_LOG(Log::sceNet, "next: 0x%x", data->next);
//	INFO_LOG(Log::sceNet, "owner: %d", data->owner);
//	print_SceNpUserInfo(&data->user_info);
//}
//
//void print_SceNpMatchingRoomStatus(const SceNpMatchingRoomStatus* data)
//{
//	INFO_LOG(Log::sceNet, "SceNpMatchingRoomStatus:");
//	print_SceNpRoomId(data->id);
//	INFO_LOG(Log::sceNet, "members: 0x%x", data->members);
//	INFO_LOG(Log::sceNet, "num: %d", data->num);
//
//	for (auto it = data->members; it; it = it->next)
//	{
//		print_SceNpMatchingRoomMember(it.get_ptr());
//	}
//
//	INFO_LOG(Log::sceNet, "kick_actor: 0x%x", data->kick_actor);
//
//	if (data->kick_actor)
//	{
//		INFO_LOG(Log::sceNet, "kick_actor: %s", data->kick_actor->handle.data);
//	}
//
//	INFO_LOG(Log::sceNet, "opt: 0x%x", data->kick_actor);
//	INFO_LOG(Log::sceNet, "opt_len: %d", data->opt_len);
//}
//
//void print_SceNpMatchingJoinedRoomInfo(const SceNpMatchingJoinedRoomInfo* data)
//{
//	INFO_LOG(Log::sceNet, "SceNpMatchingJoinedRoomInfo:");
//	INFO_LOG(Log::sceNet, "lobbyid.opt: %s", fmt::buf_to_hexstring(data->lobbyid.opt, sizeof(data->lobbyid.opt), sizeof(data->lobbyid.opt)));
//	print_SceNpMatchingRoomStatus(&data->room_status);
//}
//
//void print_SceNpMatchingSearchJoinRoomInfo(const SceNpMatchingSearchJoinRoomInfo* data)
//{
//	INFO_LOG(Log::sceNet, "SceNpMatchingSearchJoinRoomInfo:");
//	INFO_LOG(Log::sceNet, "lobbyid.opt: %s", fmt::buf_to_hexstring(data->lobbyid.opt, sizeof(data->lobbyid.opt), sizeof(data->lobbyid.opt)));
//	print_SceNpMatchingRoomStatus(&data->room_status);
//	for (auto it = data->attr; it; it = it->next)
//	{
//		print_SceNpMatchingAttr(it.get_ptr());
//	}
//}
