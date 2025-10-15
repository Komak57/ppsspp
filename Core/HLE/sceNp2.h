// Copyright (c) 2022- PPSSPP Project.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0 or later versions.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License 2.0 for more details.

// A copy of the GPL 2.0 should have been included with the program.
// If not, see http://www.gnu.org/licenses/

// Official git repository and contact information can be found at
// https://github.com/hrydgard/ppsspp and http://www.ppsspp.org/.

#pragma once
#include <sstream>
#include <string>
#include <iomanip>
#include <cstdint>
#include <Swap.h>
#include <mutex>
#include "Core/HLE/Np2Types.h"
#include <Core/Util/BlockAllocator.h>

extern std::recursive_mutex npMatching2EvtMtx;
extern BlockAllocator np_memory;

/*sceNpMatching2RequestCallback = (
	SceNpMatching2ContextId ctxId,
	SceNpMatching2RequestId reqId,
	SceNpMatching2Event event,
	SceNpMatching2EventKey eventKey,
	s32 errorCode,
	u32 dataPtr,
	PSPPointer<u8> arg);
*/

SceNpMatching2RequestId GenerateRequestId(SceNpMatching2RequestId app_req);
SceNpMatching2RequestId RegisterNpMatching2Handler(SceNpMatching2ContextId ctxId, SceNpMatching2RequestOptParam optParam, u32 assignedReqId, SceNpMatching2EventType event_type);
int notifyRequestHandler(SceNpMatching2RequestId reqId, SceNpMatching2Event event, s32 errorCode, u32 dataPtr);
int notifyRoomMessageHandler(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId, RPCNMatching2RequestEvent requestEvent, u32 dataPtr);
int notifyRoomEventHandler(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId, SceNpMatching2Event event, u32 dataPtr);
int notifySignalingHandler(SceNpMatching2RoomId room_id, u32 conn_id, u32 unknown, SceNpMatching2RoomMemberId roomMemberId, SceNpMatching2Event event, s32 errorCode);
int abortNpMatching2Handlers();
bool NpMatching2ProcessEvents();

void __Np2Init();
void __Np2Shutdown();

void Register_sceNpMatching2();
