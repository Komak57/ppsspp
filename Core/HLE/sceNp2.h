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

struct NpMatching2Handler {
	SceNpMatching2ContextId ctx_id;
	/*std::variant<
		PSPPointer<SceNpMatching2RequestCallback>,
		PSPPointer<SceNpMatching2RoomEventCallback>,
		PSPPointer<SceNpMatching2RoomMessageCallback>,
		PSPPointer<SceNpMatching2LobbyEventCallback>,
		PSPPointer<SceNpMatching2LobbyMessageCallback>,
		PSPPointer<SceNpMatching2SignalingCallback>,
		PSPPointer<SceNpMatching2ContextCallback>,
	> cb;*/
	PSPPointer<SceNpMatching2RequestCallback> cb;
	PSPPointer<u8> cb_arg;
	SceNpMatching2EventType event_type;
};

// Arg1 and Arg2 seems to be a pair and predefined: 0x0001 with 0x1001, 0x0002 with 0x1008, 0x0003 with 0x1006, 0x0004 with 0x1007, 
//		0x0005 with 0x1206, 0x0006 with 0x1207, 0x0007 with 0x1208, 0x0101 with 0x1209, 0x0102 with 0x1209, 0x0103 with 0x3202,
//		0x0104 with 0x3210, 0x0105 with 0x3211, 0x0106 with 2 possibilities (0x1200 and 0x120c), 0x0107 with 0x3208, 0x0108 with 0x320a,
//		0x0109 with 0x3204, 0x010a with 0x3205, 0x010b with 0x3206, 0x010c with 0x3207, 0x010d with 0x3203, 0x010e with 0x3204,
//		0xa102 with 0x120b.
// Arg5 seems to be boolean (0/1), mostly 0, conditional when Arg1=0x0001
// Arg7 seems to be integer/state? (0..2), mostly 0, conditional when Arg1=0x0108 (0 on SendRoomMessage, 2 on others), 1 when Arg1=0xa102

// Contains all relevant information for a callback event
struct NpMatching2Args {
	// Now allows for optional arguments to be omitted in the sending process.
	static const size_t MAX_ARGS = 11;
	NpMatching2Handler handler;
	SceNpMatching2RequestId request_id; // Only REQUEST_EVENT tracks request id's
	SceNpMatching2EventType event_type; // Everything has a matching Event code
	//u32 cbFunc;
	size_t argc = 0;
	u32_le args[MAX_ARGS]; // 7 elements (excluding optional data)? or may be 11 elements (including optional data)?
	// May be followed by optional data? since these Args usually created on the stack

	// DefaultOpt Arguments
	NpMatching2Args(NpMatching2Handler handler, size_t argc, u32_le args[], SceNpMatching2EventType event_type) {
		this->handler = handler;
		this->request_id = 0;
		this->event_type = event_type;
		this->argc = (argc > MAX_ARGS) ? MAX_ARGS : argc;
		for (size_t i = 0; i < this->argc; ++i)
			this->args[i] = args[i];
	}
	// Request Event Arguments
	NpMatching2Args(NpMatching2Handler handler, SceNpMatching2RequestId request_id, size_t argc, u32_le args[], SceNpMatching2EventType event_type) {
		this->handler = handler;
		this->request_id = request_id;
		this->event_type = event_type;
		this->argc = (argc > MAX_ARGS) ? MAX_ARGS : argc;
		for (size_t i = 0; i < this->argc; ++i)
			this->args[i] = args[i];
	}
	std::string ToString() {
		std::ostringstream oss;
		oss << "";

		for (size_t i = 0; i < argc; ++i) {
			if (i > 0) oss << ",";

			oss << std::setw(8) << std::setfill('0') << std::hex << args[i];
		}
		return oss.str();
	}

};
#define DEFAULT_CONTEXT 0
#define CONTEXT_MAX_ID 7
class NpMatching2Context {
public:
	NpMatching2Context() {};
	NpMatching2Context(SceNpCommunicationId communicationId, SceNpCommunicationPassphrase passphrase, s32 optionFlags)
		: communicationId(communicationId), passphrase(passphrase), include_onlinename(optionFlags& SCE_NP_MATCHING2_CONTEXT_OPTION_USE_ONLINENAME), include_avatarurl(optionFlags& SCE_NP_MATCHING2_CONTEXT_OPTION_USE_AVATARURL)
	{
	}

	std::atomic<u32> started = 0;

	SceNpCommunicationId communicationId{};
	SceNpCommunicationPassphrase passphrase{};
	bool include_onlinename = false, include_avatarurl = false;

	std::atomic<SceNpMatching2RequestId> match2_request_cnt = 1;
};
extern std::map<SceNpMatching2ContextId, std::unique_ptr<NpMatching2Context>> ctx;
extern std::map<SceNpMatching2EventType, NpMatching2Handler> defaultOptParams;
// Maintains Request ID's for Default Context events
extern std::atomic<u16> match2_event_cnt;


int sceNpMatching2SetDefaultRequestOptParam(int ctxId, u32 optParamPtr);
int sceNpMatching2SetDefaultRoomEventOptParam(int ctxId, u32 optParamPtr);
int sceNpMatching2SetDefaultRoomMessageOptParam(int ctxId, u32 optParamPtr);
int sceNpMatching2SetSignalingOptParam(int ctxId, u32 optParamPtr);

SceNpMatching2RequestId GenerateRequestId(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId app_req);
SceNpMatching2RequestId RegisterNpMatching2Handler(SceNpMatching2ContextId ctxId, SceNpMatching2RequestOptParam optParam, u32 assignedReqId, SceNpMatching2EventType event_type);
int notifyRequestHandler(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2Event event, s32 errorCode, u32 dataPtr);
int notifyRoomMessageHandler(SceNpMatching2ContextId ctxId, SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId, RPCNMatching2RequestEvent requestEvent, u32 dataPtr);
int notifyRoomEventHandler(SceNpMatching2ContextId ctxId, SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId, SceNpMatching2Event event, u32 dataPtr);
int notifySignalingHandler(SceNpMatching2ContextId ctxId, SceNpMatching2RoomId room_id, u32 conn_id, u32 conn_state, SceNpMatching2RoomMemberId roomMemberId, SceNpMatching2Event event, s32 errorCode);
bool NpMatching2ProcessEvents();

void __Np2Init();
void __Np2Shutdown();

void Register_sceNpMatching2();
