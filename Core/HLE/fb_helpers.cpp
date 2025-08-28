//#include "stdafx.h"
//#include "Emu/Cell/lv2/sys_process.h"
#include "fb_helpers.h"
#include <Log.h>
#include <Core/MemMapHelpers.h>

namespace np
{
	void BinAttr_to_SceNpMatching2BinAttr(BlockAllocator& edata, const BinAttr* bin_attr, SceNpMatching2BinAttr* binattr_info)
	{
		NOTICE_LOG(Log::sceNet, "BinAttr_to_SceNpMatching2BinAttr()");
		binattr_info->id = bin_attr->id();
		binattr_info->size = bin_attr->data()->size();
		//auto* ptr = edata.allocate<u8>(binattr_info->size, binattr_info->ptr);
		auto ptr = PSPPointer<u8>::Create(edata.Alloc(binattr_info->size));
		binattr_info->ptr = ptr;
		for (flatbuffers::uoffset_t i = 0; i < bin_attr->data()->size(); i++)
		{
			ptr[i] = bin_attr->data()->Get(i);
		}
	}

	void BinAttrs_to_SceNpMatching2BinAttrs(BlockAllocator& edata, const flatbuffers::Vector<flatbuffers::Offset<BinAttr>>* fb_attr, PSPPointer<SceNpMatching2BinAttr> binattr_info)
	{
		NOTICE_LOG(Log::sceNet, "BinAttrs_to_SceNpMatching2BinAttrs()");
		for (flatbuffers::uoffset_t i = 0; i < fb_attr->size(); i++)
		{
			auto cur_fb_attr = fb_attr->Get(i);
			auto cur_binattr = binattr_info + i;

			BinAttr_to_SceNpMatching2BinAttr(edata, cur_fb_attr, cur_binattr);
		}
	}

	void RoomMemberBinAttrInternal_to_SceNpMatching2RoomMemberBinAttrInternal(BlockAllocator& edata, const RoomMemberBinAttrInternal* fb_attr, PSPPointer<SceNpMatching2RoomMemberBinAttrInternal> binattr_info)
	{
		NOTICE_LOG(Log::sceNet, "RoomMemberBinAttrInternal_to_SceNpMatching2RoomMemberBinAttrInternal()");
		binattr_info->updateDate.tick = fb_attr->updateDate();
		BinAttr_to_SceNpMatching2BinAttr(edata, fb_attr->data(), &binattr_info->data);
	}

	void RoomBinAttrInternal_to_SceNpMatching2RoomBinAttrInternal(BlockAllocator& edata, const BinAttrInternal* fb_attr, PSPPointer<SceNpMatching2RoomBinAttrInternal> binattr_info)
	{
		NOTICE_LOG(Log::sceNet, "RoomBinAttrInternal_to_SceNpMatching2RoomBinAttrInternal()");
		binattr_info->updateDate.tick = fb_attr->updateDate();
		binattr_info->updateMemberId = fb_attr->updateMemberId();
		BinAttr_to_SceNpMatching2BinAttr(edata, fb_attr->data(), &binattr_info->data);
	}

	void RoomGroup_to_SceNpMatching2RoomGroup(const RoomGroup* fb_group, PSPPointer<SceNpMatching2RoomGroup> sce_group)
	{
		NOTICE_LOG(Log::sceNet, "RoomGroup_to_SceNpMatching2RoomGroup(group: %d)", sce_group->groupId);
		sce_group->groupId = fb_group->groupId();
		sce_group->withPassword = fb_group->withPassword();
		sce_group->withLabel = fb_group->label() ? 1 : 0;
		if (fb_group->label())
		{
			for (flatbuffers::uoffset_t l_index = 0; l_index < fb_group->label()->size(); l_index++)
			{
				sce_group->label.data[l_index] = fb_group->label()->Get(l_index);
			}
		}
		sce_group->slotNum = fb_group->slotNum();
		sce_group->curGroupMemberNum = fb_group->curGroupMemberNum();
	}

	void RoomGroups_to_SceNpMatching2RoomGroups(const flatbuffers::Vector<flatbuffers::Offset<RoomGroup>>* fb_groups, PSPPointer<SceNpMatching2RoomGroup> sce_groups)
	{
		NOTICE_LOG(Log::sceNet, "RoomGroups_to_SceNpMatching2RoomGroups(groups: %d)", fb_groups->size());
		for (flatbuffers::uoffset_t i = 0; i < fb_groups->size(); i++)
		{
			const auto* fb_group = fb_groups->Get(i);
			PSPPointer<SceNpMatching2RoomGroup> sce_group = sce_groups + i;
			RoomGroup_to_SceNpMatching2RoomGroup(fb_group, sce_group);
		}
	}

	void UserInfo_to_SceNpUserInfo(const UserInfo* user, PSPPointer<SceNpUserInfo> user_info)
	{
		NOTICE_LOG(Log::sceNet, "UserInfo_to_SceNpUserInfo()");
		if (const auto npid = user->npId(); npid)
		{
			std::memcpy(user_info->userId.handle.data, npid->c_str(), std::min<std::size_t>(16, npid->size()));
		}

		if (const auto online_name = user->onlineName(); online_name)
		{
			std::memcpy(user_info->name.data, online_name->c_str(), std::min<std::size_t>(48, online_name->size()));
		}

		if (const auto avatar_url = user->avatarUrl(); avatar_url)
		{
			std::memcpy(user_info->icon.data, avatar_url->c_str(), std::min<std::size_t>(127, avatar_url->size()));
		}
	}

	void UserInfo_to_SceNpUserInfo2(BlockAllocator& edata, const UserInfo* user, SceNpUserInfo2* user_info, bool include_onlinename, bool include_avatarurl)
	{
		NOTICE_LOG(Log::sceNet, "UserInfo_to_SceNpUserInfo2()");
		if (user->npId())
			std::memcpy(user_info->npId.handle.data, user->npId()->c_str(), std::min<std::size_t>(16, user->npId()->size()));

		if (include_onlinename && user->onlineName())
		{
			u32 alloc = sizeof(SceNpOnlineName);
			auto ptr = PSPPointer<SceNpOnlineName>::Create(edata.Alloc(alloc));
			user_info->onlineName = ptr;
			std::memcpy(ptr->data, user->onlineName()->c_str(), std::min<std::size_t>(48, user->onlineName()->size()));
		}
		if (include_avatarurl && user->avatarUrl())
		{
			u32 alloc = sizeof(SceNpAvatarUrl);
			auto ptr = PSPPointer<SceNpAvatarUrl>::Create(edata.Alloc(alloc));
			user_info->avatarUrl = ptr;
			std::memcpy(ptr->data, user->avatarUrl()->c_str(), std::min<std::size_t>(127, user->avatarUrl()->size()));
		}
	}

	void RoomDataExternal_to_SceNpMatching2RoomDataExternal(BlockAllocator& edata, const RoomDataExternal* room, PSPPointer<SceNpMatching2RoomDataExternal> room_info, bool include_onlinename, bool include_avatarurl)
	{
		NOTICE_LOG(Log::sceNet, "RoomDataExternal_to_SceNpMatching2RoomDataExternal()");
		room_info->serverId = room->serverId();
		room_info->worldId = room->worldId();
		room_info->lobbyId = room->lobbyId();
		room_info->roomId = room->roomId();
		room_info->maxSlot = room->maxSlot();
		room_info->curMemberNum = room->curMemberNum();
		room_info->passwordSlotMask = room->passwordSlotMask();

		// PS3 version control for compatibility
		//s32 sdk_ver;
		//process_get_sdk_version(process_getpid(), sdk_ver);

		//// Structure changed in sdk 3.3.0
		//if (sdk_ver >= 0x330000)
		//{
		//	room_info->publicSlotNum = room->publicSlotNum();
		//	room_info->privateSlotNum = room->privateSlotNum();
		//	room_info->openPublicSlotNum = room->openPublicSlotNum();
		//	room_info->openPrivateSlotNum = room->openPrivateSlotNum();
		//}
		//else
		//{
		//	room_info->publicSlotNum = 0;
		//	room_info->privateSlotNum = 0;
		//	room_info->openPublicSlotNum = 0;
		//	room_info->openPrivateSlotNum = 0;
		//}
		room_info->publicSlotNum = 0;
		room_info->privateSlotNum = 0;
		room_info->openPublicSlotNum = 0;
		room_info->openPrivateSlotNum = 0;

		if (auto owner = room->owner())
		{
			//auto* ptr_owner = edata.allocate<SceNpUserInfo2>(sizeof(SceNpUserInfo2), room_info->owner);
			u32 alloc = sizeof(SceNpUserInfo2);
			auto ptr_owner = PSPPointer<SceNpUserInfo2>::Create(edata.Alloc(alloc));
			room_info->owner = ptr_owner;
			UserInfo_to_SceNpUserInfo2(edata, owner, ptr_owner, include_onlinename, include_avatarurl);
		}

		if (room->roomGroup() && room->roomGroup()->size() != 0)
		{
			room_info->roomGroupNum = room->roomGroup()->size();
			//auto* ptr_groups = edata.allocate<SceNpMatching2RoomGroup>(sizeof(SceNpMatching2RoomGroup) * room_info->roomGroupNum, room_info->roomGroup);
			u32 alloc = sizeof(SceNpMatching2RoomGroup) * room_info->roomGroupNum;
			auto ptr_groups = PSPPointer<SceNpMatching2RoomGroup>::Create(edata.Alloc(alloc));
			room_info->roomGroup = ptr_groups;
			RoomGroups_to_SceNpMatching2RoomGroups(room->roomGroup(), ptr_groups);
		}

		room_info->flagAttr = room->flagAttr();

		if (room->roomSearchableIntAttrExternal() && room->roomSearchableIntAttrExternal()->size() != 0)
		{
			room_info->roomSearchableIntAttrExternalNum = room->roomSearchableIntAttrExternal()->size();
			//auto* ptr_int_attr = edata.allocate<SceNpMatching2IntAttr>(sizeof(SceNpMatching2IntAttr) * room_info->roomSearchableIntAttrExternalNum, room_info->roomSearchableIntAttrExternal);
			u32 alloc = sizeof(SceNpMatching2IntAttr) * room_info->roomSearchableIntAttrExternalNum;
			auto ptr_int_attr = PSPPointer<SceNpMatching2IntAttr>::Create(edata.Alloc(alloc));
			room_info->roomSearchableIntAttrExternal = ptr_int_attr;
			for (flatbuffers::uoffset_t a_index = 0; a_index < room->roomSearchableIntAttrExternal()->size(); a_index++)
			{
				auto fb_int_attr = room->roomSearchableIntAttrExternal()->Get(a_index);
				ptr_int_attr[a_index].id = fb_int_attr->id();
				ptr_int_attr[a_index].num = fb_int_attr->num();
			}
		}

		if (room->roomSearchableBinAttrExternal() && room->roomSearchableBinAttrExternal()->size() != 0)
		{
			room_info->roomSearchableBinAttrExternalNum = room->roomSearchableBinAttrExternal()->size();
			//auto* ptr_bin_attr = edata.allocate<SceNpMatching2BinAttr>(sizeof(SceNpMatching2BinAttr) * room_info->roomSearchableBinAttrExternalNum, room_info->roomSearchableBinAttrExternal);
			u32 alloc = sizeof(SceNpMatching2BinAttr) * room_info->roomSearchableBinAttrExternalNum;
			auto ptr_bin_attr = PSPPointer<SceNpMatching2BinAttr>::Create(edata.Alloc(alloc));
			room_info->roomSearchableBinAttrExternal = ptr_bin_attr;
			BinAttrs_to_SceNpMatching2BinAttrs(edata, room->roomSearchableBinAttrExternal(), ptr_bin_attr);
		}

		if (room->roomBinAttrExternal() && room->roomBinAttrExternal()->size() != 0)
		{
			room_info->roomBinAttrExternalNum = room->roomBinAttrExternal()->size();
			//auto* ptr_bin_attr = edata.allocate<SceNpMatching2BinAttr>(sizeof(SceNpMatching2BinAttr) * room_info->roomBinAttrExternalNum, room_info->roomBinAttrExternal);
			u32 alloc = sizeof(SceNpMatching2BinAttr) * room_info->roomBinAttrExternalNum;
			auto ptr_bin_attr = PSPPointer<SceNpMatching2BinAttr>::Create(edata.Alloc(alloc));
			room_info->roomBinAttrExternal = ptr_bin_attr;
			BinAttrs_to_SceNpMatching2BinAttrs(edata, room->roomBinAttrExternal(), ptr_bin_attr);
		}
	}

	void SearchRoomResponse_to_SceNpMatching2SearchRoomResponse(BlockAllocator& edata, const SearchRoomResponse* resp, PSPPointer<SceNpMatching2SearchRoomResponse> search_resp)
	{
		NOTICE_LOG(Log::sceNet, "SearchRoomResponse_to_SceNpMatching2SearchRoomResponse()");
		search_resp->range.size = resp->rooms() ? resp->rooms()->size() : 0;
		search_resp->range.startIndex = resp->startIndex();
		search_resp->range.total = resp->total();

		SceNpMatching2RoomDataExternal* prev_room = nullptr;
		for (flatbuffers::uoffset_t i = 0; i < search_resp->range.size; i++)
		{
			auto* fb_room = resp->rooms()->Get(i);
			PSPPointer<SceNpMatching2RoomDataExternal> cur_room;
			//cur_room = edata.allocate<SceNpMatching2RoomDataExternal>(sizeof(SceNpMatching2RoomDataExternal), (i > 0) ? prev_room->next : search_resp->roomDataExternal);
			u32 alloc = sizeof(SceNpMatching2RoomDataExternal);
			cur_room = PSPPointer<SceNpMatching2RoomDataExternal>::Create(edata.Alloc(alloc));
			if (i > 0)
				prev_room->next = cur_room;
			else
				search_resp->roomDataExternal = cur_room;
			RoomDataExternal_to_SceNpMatching2RoomDataExternal(edata, fb_room, cur_room, true, true);
			prev_room = cur_room;
		}
	}

	void GetRoomDataExternalListResponse_to_SceNpMatching2GetRoomDataExternalListResponse(BlockAllocator& edata, const GetRoomDataExternalListResponse* resp, PSPPointer<SceNpMatching2GetRoomDataExternalListResponse> get_resp, bool include_onlinename, bool include_avatarurl)
	{
		NOTICE_LOG(Log::sceNet, "GetRoomDataExternalListResponse_to_SceNpMatching2GetRoomDataExternalListResponse()");
		get_resp->roomDataExternalNum = resp->rooms() ? resp->rooms()->size() : 0;

		SceNpMatching2RoomDataExternal* prev_room = nullptr;
		for (flatbuffers::uoffset_t i = 0; i < get_resp->roomDataExternalNum; i++)
		{
			auto* fb_room = resp->rooms()->Get(i);
			PSPPointer<SceNpMatching2RoomDataExternal> cur_room;

			//cur_room = edata.allocate<SceNpMatching2RoomDataExternal>(sizeof(SceNpMatching2RoomDataExternal), (i > 0) ? prev_room->next : get_resp->roomDataExternal);
			u32 alloc = sizeof(SceNpMatching2RoomDataExternal);
			cur_room = PSPPointer<SceNpMatching2RoomDataExternal>::Create(edata.Alloc(alloc));
			if (i > 0)
				prev_room->next = cur_room;
			else
				get_resp->roomDataExternal = cur_room;

			RoomDataExternal_to_SceNpMatching2RoomDataExternal(edata, fb_room, cur_room, include_onlinename, include_avatarurl);
			prev_room = cur_room;
		}
	}

	u16 RoomDataInternal_to_SceNpMatching2RoomDataInternal(BlockAllocator& edata, const RoomDataInternal* resp, PSPPointer<SceNpMatching2RoomDataInternal> room_info, const SceNpId& npid, bool include_onlinename, bool include_avatarurl)
	{
		NOTICE_LOG(Log::sceNet, "RoomDataInternal_to_SceNpMatching2RoomDataInternal(server: %d, world: %d, lobby: %d, room: %d)", resp->serverId(), resp->worldId(), resp->lobbyId(), resp->roomId());
		u16 member_id = 0;
		room_info->serverId = resp->serverId();
		room_info->worldId = resp->worldId();
		room_info->lobbyId = resp->lobbyId();
		room_info->roomId = resp->roomId();
		room_info->passwordSlotMask = resp->passwordSlotMask();
		room_info->maxSlot = resp->maxSlot();

		NOTICE_LOG(Log::sceNet, " - adding %d room groups", (resp->roomGroup() ? resp->roomGroup()->size() : 0));
		if (resp->roomGroup() && resp->roomGroup()->size() != 0)
		{
			room_info->roomGroupNum = resp->roomGroup()->size();
			//auto* ptr_groups = edata.allocate<SceNpMatching2RoomGroup>(sizeof(SceNpMatching2RoomGroup) * room_info->roomGroupNum, room_info->roomGroup);
			u32 alloc = sizeof(SceNpMatching2RoomGroup) * room_info->roomGroupNum;
			auto ptr_groups = PSPPointer<SceNpMatching2RoomGroup>::Create(edata.Alloc(alloc));
			room_info->roomGroup = ptr_groups;
			RoomGroups_to_SceNpMatching2RoomGroups(resp->roomGroup(), ptr_groups);
		}

		NOTICE_LOG(Log::sceNet, " - processing %d members", resp->memberList()->size());
		room_info->memberList.membersNum = static_cast<u32>(resp->memberList()->size());
		//edata.allocate<SceNpMatching2RoomMemberDataInternal>(sizeof(SceNpMatching2RoomMemberDataInternal) * room_info->memberList.membersNum, room_info->memberList.members);
		u32 alloc = sizeof(SceNpMatching2RoomMemberDataInternal) * room_info->memberList.membersNum;
		room_info->memberList.members = PSPPointer<SceNpMatching2RoomMemberDataInternal>::Create(edata.Alloc(alloc));

		for (flatbuffers::uoffset_t i = 0; i < resp->memberList()->size(); i++)
		{
			auto fb_member = resp->memberList()->Get(i);
			PSPPointer<SceNpMatching2RoomMemberDataInternal> sce_member = room_info->memberList.members + i;

			if (i < (resp->memberList()->size() - 1))
			{
				sce_member->next = room_info->memberList.members + i + 1;
				//edata.add_relocation<SceNpMatching2RoomMemberDataInternal>(sce_member->next);
				edata.add_relocation(sce_member->next.ptr);
			}

			RoomMemberDataInternal_to_SceNpMatching2RoomMemberDataInternal(edata, fb_member, room_info, sce_member, include_onlinename, include_avatarurl);
		}

		u32 self = 0;
		for (u32 i = 0; i < room_info->memberList.membersNum; i++)
		{
			SceNpMatching2RoomMemberDataInternal* sce_member = &room_info->memberList.members[i];
			if (strcmp(sce_member->userInfo.npId.handle.data, npid.handle.data) == 0)
			{
				NOTICE_LOG(Log::sceNet, " - Member[%d] is Self", i);
				//room_info->memberList.me = room_info->memberList.members + i;
				//room_info->memberList.me = PSPPointer<SceNpMatching2RoomMemberDataInternal>::Create(room_info->memberList.members.ptr + i * sizeof(SceNpMatching2RoomMemberDataInternal));
				room_info->memberList.me = PSPPointer<SceNpMatching2RoomMemberDataInternal>::Create((room_info->memberList.members + i).ptr);
				self = room_info->memberList.me.ptr;
				NOTICE_LOG(Log::sceNet, " - Self at %08x", room_info->memberList.me.ptr);
				//edata.add_relocation<SceNpMatching2RoomMemberDataInternal>(room_info->memberList.me);
				member_id = sce_member->memberId;
				break;
			}
		}

		for (u32 i = 0; i < room_info->memberList.membersNum; i++)
		{
			SceNpMatching2RoomMemberDataInternal* sce_member = &room_info->memberList.members[i];
			if (sce_member->memberId == resp->ownerId())
			{
				NOTICE_LOG(Log::sceNet, " - Member[%d] is Owner", i);
				//room_info->memberList.owner = room_info->memberList.members + i;
				//room_info->memberList.owner = PSPPointer<SceNpMatching2RoomMemberDataInternal>::Create(room_info->memberList.members.ptr + i * sizeof(SceNpMatching2RoomMemberDataInternal));
				room_info->memberList.owner = PSPPointer<SceNpMatching2RoomMemberDataInternal>::Create((room_info->memberList.members + i).ptr);
				NOTICE_LOG(Log::sceNet, " - Owner at %08x", room_info->memberList.owner.ptr);
				//edata.add_relocation<SceNpMatching2RoomMemberDataInternal>(room_info->memberList.owner);
				break;
			}
		}

		room_info->flagAttr = resp->flagAttr();

		if (resp->roomBinAttrInternal() && resp->roomBinAttrInternal()->size() != 0)
		{
			room_info->roomBinAttrInternalNum = resp->roomBinAttrInternal()->size();
			//auto* ptr_bin_attr = edata.allocate<SceNpMatching2RoomBinAttrInternal>(sizeof(SceNpMatching2RoomBinAttrInternal) * room_info->roomBinAttrInternalNum, room_info->roomBinAttrInternal);

			u32 alloc = sizeof(SceNpMatching2RoomBinAttrInternal) * room_info->roomBinAttrInternalNum;
			auto ptr_bin_attr = PSPPointer<SceNpMatching2RoomBinAttrInternal>::Create(edata.Alloc(alloc));
			room_info->roomBinAttrInternal = ptr_bin_attr;

			for (u32 b_index = 0; b_index < room_info->roomBinAttrInternalNum; b_index++)
			{
				auto fb_bin_attr = resp->roomBinAttrInternal()->Get(b_index);
				ptr_bin_attr[b_index].updateDate.tick = fb_bin_attr->updateDate();
				ptr_bin_attr[b_index].updateMemberId = fb_bin_attr->updateMemberId();

				ptr_bin_attr[b_index].data.id = fb_bin_attr->data()->id();
				ptr_bin_attr[b_index].data.size = fb_bin_attr->data()->data()->size();
				//auto* ptr_bin_attr_data = edata.allocate<u8>(ptr_bin_attr[b_index].data.size, ptr_bin_attr[b_index].data.ptr);
				if (ptr_bin_attr[b_index].data.size > 0) {
					auto ptr_bin_attr_data = PSPPointer<u8>::Create(edata.Alloc(ptr_bin_attr[b_index].data.size));
					for (flatbuffers::uoffset_t tmp_index = 0; tmp_index < ptr_bin_attr[b_index].data.size; tmp_index++)
					{
						ptr_bin_attr_data[tmp_index] = fb_bin_attr->data()->data()->Get(tmp_index);
					}
				}
			}
		}

		return member_id;
	}

	void RoomMemberDataInternal_to_SceNpMatching2RoomMemberDataInternal(BlockAllocator& edata, const RoomMemberDataInternal* member_data, const PSPPointer<SceNpMatching2RoomDataInternal> room_info, PSPPointer<SceNpMatching2RoomMemberDataInternal> sce_member_data, bool include_onlinename, bool include_avatarurl)
	{
		NOTICE_LOG(Log::sceNet, "RoomMemberDataInternal_to_SceNpMatching2RoomMemberDataInternal(member: %d)", sce_member_data->memberId);
		UserInfo_to_SceNpUserInfo2(edata, member_data->userInfo(), &sce_member_data->userInfo, include_onlinename, include_avatarurl);
		sce_member_data->joinDate.tick = member_data->joinDate();
		sce_member_data->memberId = member_data->memberId();
		sce_member_data->teamId = member_data->teamId();

		if (const auto* fb_roomgroup = member_data->roomGroup())
		{
			if (room_info)
			{
				// If we have SceNpMatching2RoomDataInternal available we point the pointers to the group there
				sce_member_data->roomGroup = PSPPointer<SceNpMatching2RoomGroup>::Create((room_info->roomGroup + (fb_roomgroup->groupId() - 1)).ptr);
				//sce_member_data->roomGroup = room_info->roomGroup + (fb_roomgroup->groupId() - 1);
				//edata.add_relocation<SceNpMatching2RoomGroup>(sce_member_data->roomGroup);
			}
			else
			{
				// Otherwise we allocate for it
				//auto* ptr_group = edata.allocate<SceNpMatching2RoomGroup>(sizeof(SceNpMatching2RoomGroup), sce_member_data->roomGroup);
				u32 alloc = sizeof(SceNpMatching2RoomGroup);
				auto ptr_group = PSPPointer<SceNpMatching2RoomGroup>::Create(edata.Alloc(alloc));
				sce_member_data->roomGroup = ptr_group;
				RoomGroup_to_SceNpMatching2RoomGroup(fb_roomgroup, ptr_group);
			}
		}

		sce_member_data->natType = member_data->natType();
		sce_member_data->flagAttr = member_data->flagAttr();

		if (member_data->roomMemberBinAttrInternal() && member_data->roomMemberBinAttrInternal()->size() != 0)
		{
			sce_member_data->roomMemberBinAttrInternalNum = member_data->roomMemberBinAttrInternal()->size();
			//auto* sce_binattrs = edata.allocate<SceNpMatching2RoomMemberBinAttrInternal>(sizeof(SceNpMatching2RoomMemberBinAttrInternal) * sce_member_data->roomMemberBinAttrInternalNum, sce_member_data->roomMemberBinAttrInternal);
			u32 alloc = sizeof(SceNpMatching2RoomMemberBinAttrInternal) * sce_member_data->roomMemberBinAttrInternalNum;
			auto sce_binattrs = PSPPointer<SceNpMatching2RoomMemberBinAttrInternal>::Create(edata.Alloc(alloc));
			sce_member_data->roomMemberBinAttrInternal = sce_binattrs;
			for (u32 b_index = 0; b_index < sce_member_data->roomMemberBinAttrInternalNum; b_index++)
			{
				const auto fb_battr = member_data->roomMemberBinAttrInternal()->Get(b_index);
				sce_binattrs[b_index].updateDate.tick = fb_battr->updateDate();

				sce_binattrs[b_index].data.id = fb_battr->data()->id();
				sce_binattrs[b_index].data.size = fb_battr->data()->data()->size();
				//auto* sce_binattr_data = edata.allocate<u8>(sce_binattrs[b_index].data.size, sce_binattrs[b_index].data.ptr);
				if (sce_binattrs[b_index].data.size > 0) {
					auto sce_binattr_data = PSPPointer<u8>::Create(edata.Alloc(sce_binattrs[b_index].data.size));
					for (flatbuffers::uoffset_t tmp_index = 0; tmp_index < sce_binattrs[b_index].data.size; tmp_index++)
					{
						sce_binattr_data[tmp_index] = fb_battr->data()->data()->Get(tmp_index);
					}
				}
			}
		}
	}

	void RoomMemberUpdateInfo_to_SceNpMatching2RoomMemberUpdateInfo(BlockAllocator& edata, const RoomMemberUpdateInfo* update_info, PSPPointer<SceNpMatching2RoomMemberUpdateInfo> sce_update_info, bool include_onlinename, bool include_avatarurl)
	{
		NOTICE_LOG(Log::sceNet, "RoomMemberUpdateInfo_to_SceNpMatching2RoomMemberUpdateInfo()");
		sce_update_info->eventCause = 0;
		if (update_info->optData())
		{
			sce_update_info->optData.length = update_info->optData()->data()->size();
			for (flatbuffers::uoffset_t i = 0; i < 16; i++)
			{
				sce_update_info->optData.data[i] = update_info->optData()->data()->Get(i);
			}
		}

		if (update_info->roomMemberDataInternal())
		{
			auto fb_member = update_info->roomMemberDataInternal();
			//auto* ptr_roomemberinternal = edata.allocate<SceNpMatching2RoomMemberDataInternal>(sizeof(SceNpMatching2RoomMemberDataInternal), sce_update_info->roomMemberDataInternal);
			u32 alloc = sizeof(SceNpMatching2RoomMemberDataInternal);
			auto ptr_roomemberinternal = PSPPointer<SceNpMatching2RoomMemberDataInternal>::Create(edata.Alloc(alloc));
			sce_update_info->roomMemberDataInternal = ptr_roomemberinternal;

			// TODO: Pass room_info
			RoomMemberDataInternal_to_SceNpMatching2RoomMemberDataInternal(edata, fb_member, PSPPointer<SceNpMatching2RoomDataInternal>(), ptr_roomemberinternal, include_onlinename, include_avatarurl);
		}
	}

	void RoomUpdateInfo_to_SceNpMatching2RoomUpdateInfo(const RoomUpdateInfo* update_info, PSPPointer<SceNpMatching2RoomUpdateInfo> sce_update_info)
	{
		NOTICE_LOG(Log::sceNet, "RoomUpdateInfo_to_SceNpMatching2RoomUpdateInfo()");
		sce_update_info->errorCode = 0;
		sce_update_info->eventCause = 0;
		if (update_info->optData())
		{
			sce_update_info->optData.length = update_info->optData()->data()->size();
			for (flatbuffers::uoffset_t i = 0; i < 16; i++)
			{
				sce_update_info->optData.data[i] = update_info->optData()->data()->Get(i);
			}
		}
	}

	void RoomDataInternalUpdateInfo_to_SceNpMatching2RoomDataInternalUpdateInfo(BlockAllocator& edata, const RoomDataInternalUpdateInfo* update_info, PSPPointer<SceNpMatching2RoomDataInternalUpdateInfo> sce_update_info, const SceNpId& npid, bool include_onlinename, bool include_avatarurl)
	{
		NOTICE_LOG(Log::sceNet, "RoomDataInternalUpdateInfo_to_SceNpMatching2RoomDataInternalUpdateInfo()");
		//auto* sce_room_data = edata.allocate<SceNpMatching2RoomDataInternal>(sizeof(SceNpMatching2RoomDataInternal), sce_update_info->newRoomDataInternal);
		u32 alloc = sizeof(SceNpMatching2RoomDataInternal);
		auto sce_room_data = PSPPointer<SceNpMatching2RoomDataInternal>::Create(edata.Alloc(alloc));
		sce_update_info->newRoomDataInternal = sce_room_data;
		RoomDataInternal_to_SceNpMatching2RoomDataInternal(edata, update_info->newRoomDataInternal(), sce_room_data, npid, include_onlinename, include_avatarurl);

		if (sce_room_data->flagAttr != update_info->prevFlagAttr())
		{
			/*sce_update_info->newFlagAttr = sce_update_info->newRoomDataInternal.ptr(&SceNpMatching2RoomDataInternal::flagAttr);
			edata.add_relocation<u32>(sce_update_info->newFlagAttr);
			auto* ptr_sce_prevflag = edata.allocate<SceNpMatching2FlagAttr>(sizeof(SceNpMatching2FlagAttr), sce_update_info->prevFlagAttr);
			*ptr_sce_prevflag = update_info->prevFlagAttr();*/

			//sce_update_info->newFlagAttr.ptr = sce_update_info->newRoomDataInternal.ptr(&SceNpMatching2RoomDataInternal::flagAttr);
			sce_update_info->newFlagAttr.ptr = sce_update_info->newRoomDataInternal.ptr + offsetof(SceNpMatching2RoomDataInternal, flagAttr);
			u32 alloc = sizeof(SceNpMatching2FlagAttr);
			auto ptr_sce_prevflag = PSPPointer<SceNpMatching2FlagAttr>::Create(edata.Alloc(alloc));
			sce_update_info->prevFlagAttr = ptr_sce_prevflag;
			*ptr_sce_prevflag = update_info->prevFlagAttr();
		}

		if (sce_room_data->passwordSlotMask != update_info->prevRoomPasswordSlotMask())
		{
			//sce_update_info->newRoomPasswordSlotMask = sce_update_info->newRoomDataInternal.ptr(&SceNpMatching2RoomDataInternal::passwordSlotMask);
			sce_update_info->newRoomPasswordSlotMask.ptr = sce_update_info->newRoomDataInternal.ptr + offsetof(SceNpMatching2RoomDataInternal, passwordSlotMask);
			//edata.add_relocation<u64>(sce_update_info->newRoomPasswordSlotMask);
			//auto* ptr_sce_prevpass = edata.allocate<SceNpMatching2RoomPasswordSlotMask>(sizeof(SceNpMatching2RoomPasswordSlotMask), sce_update_info->prevRoomPasswordSlotMask);
			u32 alloc = sizeof(SceNpMatching2RoomPasswordSlotMask);
			auto ptr_sce_prevpass = PSPPointer<SceNpMatching2RoomPasswordSlotMask>::Create(edata.Alloc(alloc));
			sce_update_info->prevRoomPasswordSlotMask = ptr_sce_prevpass;
			*ptr_sce_prevpass = update_info->prevRoomPasswordSlotMask();
		}

		if (update_info->newRoomGroup() && update_info->newRoomGroup()->size() != 0)
		{
			//rpcn_log.todo("RoomDataInternalUpdateInfo::newRoomGroup");
			// TODO
			// sce_update_info->newRoomGroupNum = update_info->newRoomGroup()->size();
			// vm::ptr<SceNpMatching2RoomGroup> group_info(allocate(sizeof(SceNpMatching2RoomGroup) * sce_update_info->newRoomGroupNum));
			// RoomGroups_to_SceNpMatching2RoomGroup(update_info->newRoomGroup(), group_info);
			// sce_update_info->newRoomGroup = group_info;
		}

		if (update_info->newRoomBinAttrInternal() && update_info->newRoomBinAttrInternal()->size() != 0)
		{
			const auto get_ptr_for_binattr = [&](u16 binattr_id) -> PSPPointer<SceNpMatching2RoomBinAttrInternal>
			{
				PSPPointer<SceNpMatching2RoomBinAttrInternal> ret_ptr = sce_room_data->roomBinAttrInternal;
				for (u32 i = 0; i < sce_room_data->roomBinAttrInternalNum; i++)
				{
					if (ret_ptr->data.id == binattr_id)
						return ret_ptr;

					ret_ptr++;
				}
				//rpcn_log.fatal("RoomDataInternalUpdateInfo_to_SceNpMatching2RoomDataInternalUpdateInfo: Couldn't find matching roomBinAttrInternal!");
				return PSPPointer<SceNpMatching2RoomBinAttrInternal>();
			};

			sce_update_info->newRoomBinAttrInternalNum = update_info->newRoomBinAttrInternal()->size();
			//edata.allocate_ptr_array<SceNpMatching2RoomBinAttrInternal>(sce_update_info->newRoomBinAttrInternalNum, sce_update_info->newRoomBinAttrInternal);
			sce_update_info->newRoomBinAttrInternal = PSPPointer<SceNpMatching2RoomBinAttrInternal>::Create(edata.Alloc(sce_update_info->newRoomBinAttrInternalNum));
			for (u32 i = 0; i < sce_update_info->newRoomBinAttrInternalNum; i++)
			{
				sce_update_info->newRoomBinAttrInternal[i] = *get_ptr_for_binattr(update_info->newRoomBinAttrInternal()->Get(i));
			}
		}
	}

	void RoomMemberDataInternalUpdateInfo_to_SceNpMatching2RoomMemberDataInternalUpdateInfo(BlockAllocator& edata, const RoomMemberDataInternalUpdateInfo* update_info, PSPPointer<SceNpMatching2RoomMemberDataInternalUpdateInfo> sce_update_info, bool include_onlinename, bool include_avatarurl)
	{
		NOTICE_LOG(Log::sceNet, "RoomMemberDataInternalUpdateInfo_to_SceNpMatching2RoomMemberDataInternalUpdateInfo()");
		//auto* sce_room_member_data = edata.allocate<SceNpMatching2RoomMemberDataInternal>(sizeof(SceNpMatching2RoomMemberDataInternal), sce_update_info->newRoomMemberDataInternal);
		u32 alloc = sizeof(SceNpMatching2RoomMemberDataInternal);
		auto sce_room_member_data = PSPPointer<SceNpMatching2RoomMemberDataInternal>::Create(edata.Alloc(alloc));
		sce_update_info->newRoomMemberDataInternal = sce_room_member_data;
		RoomMemberDataInternal_to_SceNpMatching2RoomMemberDataInternal(edata, update_info->newRoomMemberDataInternal(), PSPPointer<SceNpMatching2RoomDataInternal>(), sce_room_member_data, include_onlinename, include_avatarurl);

		if (sce_update_info->newRoomMemberDataInternal->flagAttr != update_info->prevFlagAttr())
		{
			//sce_update_info->newFlagAttr = sce_update_info->newRoomMemberDataInternal.ptr(&SceNpMatching2RoomMemberDataInternal::flagAttr);
			edata.add_relocation(sce_update_info->newFlagAttr.ptr);
			//sce_update_info->newFlagAttr = sce_update_info->newRoomMemberDataInternal->flagAttr;
			//edata.add_relocation<u32>(sce_update_info->newFlagAttr);
			//auto* ptr_sce_prevflag = edata.allocate<SceNpMatching2FlagAttr>(sizeof(SceNpMatching2FlagAttr), sce_update_info->prevFlagAttr);
			u32 alloc = sizeof(SceNpMatching2FlagAttr);
			auto ptr_sce_prevflag = PSPPointer<SceNpMatching2FlagAttr>::Create(edata.Alloc(alloc));
			sce_update_info->prevFlagAttr = ptr_sce_prevflag;
			*ptr_sce_prevflag = update_info->prevFlagAttr();
		}

		if (sce_update_info->newRoomMemberDataInternal->teamId != update_info->prevTeamId())
		{
			//sce_update_info->newTeamId = sce_update_info->newRoomMemberDataInternal.ptr(&SceNpMatching2RoomMemberDataInternal::teamId);
			sce_update_info->newTeamId = sce_update_info->newRoomMemberDataInternal->teamId;
			//edata.add_relocation<u8>(sce_update_info->newTeamId);
		}

		if (update_info->newRoomMemberBinAttrInternal() && update_info->newRoomMemberBinAttrInternal()->size() != 0)
		{
			const auto get_ptr_for_binattr = [&](u16 binattr_id) -> PSPPointer<SceNpMatching2RoomMemberBinAttrInternal>
			{
				PSPPointer<SceNpMatching2RoomMemberBinAttrInternal> ret_ptr = sce_room_member_data->roomMemberBinAttrInternal;
				for (u32 i = 0; i < sce_room_member_data->roomMemberBinAttrInternalNum; i++)
				{
					if (ret_ptr->data.id == binattr_id)
						return ret_ptr;

					ret_ptr++;
				}
				//rpcn_log.fatal("RoomMemberDataInternalUpdateInfo_to_SceNpMatching2RoomMemberDataInternalUpdateInfo: Couldn't find matching roomMemberBinAttrInternal!");
				return PSPPointer<SceNpMatching2RoomMemberBinAttrInternal>();
			};

			sce_update_info->newRoomMemberBinAttrInternalNum = update_info->newRoomMemberBinAttrInternal()->size();
			//edata.allocate_ptr_array<SceNpMatching2RoomMemberBinAttrInternal>(sce_update_info->newRoomMemberBinAttrInternalNum, sce_update_info->newRoomMemberBinAttrInternal);
			for (u32 i = 0; i < sce_update_info->newRoomMemberBinAttrInternalNum; i++)
			{
				sce_update_info->newRoomMemberBinAttrInternal[i] = *get_ptr_for_binattr(update_info->newRoomMemberBinAttrInternal()->Get(i));
			}
		}
	}

	void GetPingInfoResponse_to_SceNpMatching2SignalingGetPingInfoResponse(const GetPingInfoResponse* resp, PSPPointer<SceNpMatching2SignalingGetPingInfoResponse> sce_resp)
	{
		NOTICE_LOG(Log::sceNet, "GetPingInfoResponse_to_SceNpMatching2SignalingGetPingInfoResponse()");
		sce_resp->serverId = resp->serverId();
		sce_resp->worldId = resp->worldId();
		sce_resp->roomId = resp->roomId();
		sce_resp->rtt = resp->rtt();
	}

	void RoomMessageInfo_to_SceNpMatching2RoomMessageInfo(BlockAllocator& edata, const RoomMessageInfo* mi, PSPPointer<SceNpMatching2RoomMessageInfo> sce_mi, bool include_onlinename, bool include_avatarurl)
	{
		NOTICE_LOG(Log::sceNet, "RoomMessageInfo_to_SceNpMatching2RoomMessageInfo()");
		sce_mi->filtered = mi->filtered();
		sce_mi->castType = mi->castType();

		if (sce_mi->castType != SCE_NP_MATCHING2_CASTTYPE_BROADCAST)
		{
			//edata.allocate<SceNpMatching2RoomMessageDestination>(sizeof(SceNpMatching2RoomMessageDestination), sce_mi->dst);
			u32 alloc = sizeof(SceNpMatching2RoomMessageDestination);
			sce_mi->dst = PSPPointer<SceNpMatching2RoomMessageDestination>::Create(edata.Alloc(alloc));
		}

		switch (sce_mi->castType)
		{
		case SCE_NP_MATCHING2_CASTTYPE_BROADCAST: break;
		case SCE_NP_MATCHING2_CASTTYPE_UNICAST: sce_mi->dst->unicastTarget = mi->dst()->Get(0); break;
		case SCE_NP_MATCHING2_CASTTYPE_MULTICAST:
		{
			sce_mi->dst->multicastTarget.memberIdNum = mi->dst()->size();
			//edata.allocate<u16>(sizeof(u16) * mi->dst()->size(), sce_mi->dst->multicastTarget.memberId);
			u32 alloc = sizeof(u16) * mi->dst()->size();
			sce_mi->dst->multicastTarget.memberId = PSPPointer<u16>::Create(edata.Alloc(alloc));
			for (u32 i = 0; i < mi->dst()->size(); i++)
			{
				sce_mi->dst->multicastTarget.memberId[i] = mi->dst()->Get(i);
			}
			break;
		}
		case SCE_NP_MATCHING2_CASTTYPE_MULTICAST_TEAM: sce_mi->dst->multicastTargetTeamId = (SceNpMatching2TeamId)(mi->dst()->Get(0)); break;
		default:
			//ensure(false);
			assert(false);
		}

		if (auto src_member = mi->srcMember())
		{
			//auto* ptr_sce_userinfo = edata.allocate<SceNpUserInfo2>(sizeof(SceNpUserInfo2), sce_mi->srcMember);
			u32 alloc = sizeof(SceNpUserInfo2);
			auto ptr_sce_userinfo = PSPPointer<SceNpUserInfo2>::Create(edata.Alloc(alloc));
			sce_mi->srcMember = ptr_sce_userinfo;
			UserInfo_to_SceNpUserInfo2(edata, src_member, sce_mi->srcMember, include_onlinename, include_avatarurl);
		}

		if (auto msg = mi->msg())
		{
			sce_mi->msgLen = msg->size();
			//auto* ptr_msg_data = static_cast<u8*>(edata.allocate<void>(msg->size(), sce_mi->msg));
			u32 alloc = msg->size();
			auto ptr_msg_data = PSPPointer<u8>::Create(edata.Alloc(alloc));
			sce_mi->msg = ptr_msg_data;
			for (u32 i = 0; i < msg->size(); i++)
			{
				ptr_msg_data[i] = msg->Get(i);
			}
		}
	}

	//void MatchingRoomStatus_to_SceNpMatchingRoomStatus(BlockAllocator& edata, const MatchingRoomStatus* resp, SceNpMatchingRoomStatus* room_status)
	//{
	//	const auto* vec_id = resp->id();
	//	ensure(vec_id && vec_id->size() == 28, "Invalid room id in MatchingRoomStatus");

	//	for (flatbuffers::uoffset_t i = 0; i < 28; i++)
	//	{
	//		room_status->id.opt[i] = vec_id->Get(i);
	//	}

	//	// In some events the member list can be empty
	//	if (const auto* members = resp->members(); members && members->size())
	//	{
	//		room_status->num = members->size();
	//		SceNpMatchingRoomMember* prev_member{};

	//		for (flatbuffers::uoffset_t i = 0; i < members->size(); i++)
	//		{
	//			auto* cur_member = edata.allocate<SceNpMatchingRoomMember>(sizeof(SceNpMatchingRoomMember), (i > 0) ? prev_member->next : room_status->members);
	//			const auto* member = members->Get(i);
	//			ensure(member && member->info(), "Invalid member in MatchingRoomStatus list");

	//			cur_member->owner = member->owner() ? 1 : 0;
	//			UserInfo_to_SceNpUserInfo(member->info(), &cur_member->user_info);

	//			prev_member = cur_member;
	//		}
	//	}

	//	if (const auto* kick_npid = resp->kick_actor(); kick_npid)
	//	{
	//		auto* npid = edata.allocate<SceNpId>(sizeof(SceNpId), room_status->kick_actor);
	//		std::memcpy(npid->handle.data, kick_npid->c_str(), std::min<std::size_t>(16, kick_npid->size()));
	//	}

	//	if (const auto* opt = resp->opt(); opt && opt->size())
	//	{
	//		room_status->opt_len = opt->size();
	//		u8* opt_data = static_cast<u8*>(edata.allocate<void>(opt->size(), room_status->opt));

	//		for (flatbuffers::uoffset_t i = 0; i < opt->size(); i++)
	//		{
	//			opt_data[i] = opt->Get(i);
	//		}
	//	}
	//}

	//void MatchingRoomStatus_to_SceNpMatchingJoinedRoomInfo(BlockAllocator& edata, const MatchingRoomStatus* resp, SceNpMatchingJoinedRoomInfo* room_info)
	//{
	//	// The use of SceNpLobbyId is unclear as it is never specified by the client except in further operations, so we always set it to a series of 0 and a 1
	//	room_info->lobbyid.opt[27] = 1;
	//	MatchingRoomStatus_to_SceNpMatchingRoomStatus(edata, resp, &room_info->room_status);
	//}

	//void MatchingAttr_to_SceNpMatchingAttr(BlockAllocator& edata, const flatbuffers::Vector<flatbuffers::Offset<MatchingAttr>>* attr_list, vm::bptr<SceNpMatchingAttr>& first_attr)
	//{
	//	if (attr_list)
	//	{
	//		SceNpMatchingAttr* cur_attr = nullptr;

	//		for (flatbuffers::uoffset_t i_attr = 0; i_attr < attr_list->size(); i_attr++)
	//		{
	//			const auto* attr = attr_list->Get(i_attr);
	//			cur_attr = edata.allocate<SceNpMatchingAttr>(sizeof(SceNpMatchingAttr), cur_attr ? cur_attr->next : first_attr);

	//			ensure(attr);
	//			cur_attr->type = attr->attr_type();
	//			cur_attr->id = attr->attr_id();
	//			if (attr->data())
	//			{
	//				if (attr->data()->size())
	//				{
	//					cur_attr->value.data.size = attr->data()->size();
	//					u8* data_ptr = static_cast<u8*>(edata.allocate<void>(attr->data()->size(), cur_attr->value.data.ptr));
	//					memcpy(data_ptr, attr->data()->data(), attr->data()->size());
	//				}
	//			}
	//			else
	//			{
	//				cur_attr->value.num = attr->num();
	//			}
	//		}
	//	}
	//}

	//void MatchingRoom_to_SceNpMatchingRoom(BlockAllocator& edata, const MatchingRoom* resp, SceNpMatchingRoom* room)
	//{
	//	ensure(room && resp->id() && resp->id()->size() == sizeof(SceNpRoomId::opt));
	//	memcpy(room->id.opt, resp->id()->data(), sizeof(SceNpRoomId::opt));
	//	MatchingAttr_to_SceNpMatchingAttr(edata, resp->attr(), room->attr);
	//}

	//void MatchingRoomList_to_SceNpMatchingRoomList(BlockAllocator& edata, const MatchingRoomList* resp, SceNpMatchingRoomList* room_list)
	//{
	//	// The use of SceNpLobbyId is unclear as it is never specified by the client except in further operations, so we always set it to a series of 0 and a 1
	//	room_list->lobbyid.opt[27] = 1;
	//	room_list->range.start = resp->start();
	//	room_list->range.total = resp->total();

	//	if (auto rooms = resp->rooms(); rooms)
	//	{
	//		room_list->range.results = rooms->size();

	//		SceNpMatchingRoom* cur_room = nullptr;

	//		for (flatbuffers::uoffset_t i = 0; i < rooms->size(); i++)
	//		{
	//			const auto* room = rooms->Get(i);
	//			cur_room = edata.allocate<SceNpMatchingRoom>(sizeof(SceNpMatchingRoom), cur_room ? cur_room->next : room_list->head);
	//			MatchingRoom_to_SceNpMatchingRoom(edata, room, cur_room);
	//		}
	//	}
	//}

	//void MatchingSearchJoinRoomInfo_to_SceNpMatchingSearchJoinRoomInfo(BlockAllocator& edata, const MatchingSearchJoinRoomInfo* resp, SceNpMatchingSearchJoinRoomInfo* room_info)
	//{
	//	ensure(resp->room());
	//	room_info->lobbyid.opt[27] = 1;
	//	MatchingRoomStatus_to_SceNpMatchingRoomStatus(edata, resp->room(), &room_info->room_status);
	//	MatchingAttr_to_SceNpMatchingAttr(edata, resp->attr(), room_info->attr);
	//}

} // namespace np
