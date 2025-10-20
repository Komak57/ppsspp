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

#include <mutex>
#include <deque>
#include <StringUtils.h>
#include <future>
#include "Core/Config.h"
#include "Core/MemMapHelpers.h"
#include "Core/CoreTiming.h"
#include "Core/HLE/HLE.h"
#include "Core/HLE/ErrorCodes.h"
#include "Core/HLE/FunctionWrappers.h"
#include "Core/HLE/sceNp.h"
#include "Core/HLE/sceNp2.h"
#include "Core/HLE/sceNetResolver.h"
#include <Core/Net/NPAgent.h>
#include "Core/Net/SignalingHandler.h"
#include "Core/HLE/sceKernelMemory.h"
#include "Core/Net/fb_helpers.h"
#include "Core/HLE/proAdhoc.h" // For Local IP
//#include "NpMatchingContext.h"
//#include "Np2SignalingHandler.h"

bool npMatching2Inited = false;
std::recursive_mutex npMatching2EvtMtx;
SceNpAuthMemoryStat npMatching2MemStat = {};
u32 npPoolAddr = 0;
BlockAllocator np_memory;
SceNpMatching2ContextId signaling_ctxId = 0;

std::map<SceNpMatching2ContextId, std::unique_ptr<NpMatching2Context>> ctx;
std::deque<NpMatching2Args> npMatching2Events;
std::map<SceNpMatching2ContextId, NpMatching2Handler> npMatching2Handlers;
std::map<SceNpMatching2EventType, NpMatching2Handler> defaultOptParams;
//std::recursive_mutex npMatching2SigMtx;
//NpMatching2Handler npSignalingCallback;
//std::unordered_map<u32, NpMatching2Handler> npSignalingHandlers;
//std::map<int, NpMatching2Context> npMatching2Contexts;
//u16 tServer;

//std::map<u16, std::unique_ptr<net::NPAgent>> servers;
std::unique_ptr<net::NPAgent> npServer = nullptr;
signaling_handler g_signaling;

// RPCN Signaling
int np2RPCNState = NP_SIGNIN_STATUS_NONE;
static int np2RPCNStateEvent = -1;
static int actionAfterRPCNMipsCall;
// P2P Signaling
int np2P2PState = NP_SIGNIN_STATUS_NONE;
static int np2P2PStateEvent = -1;
static int actionAfterP2PMipsCall;

static void __RPCNState(u64 userdata, int cyclesLate) {
	SceUID threadID = userdata >> 32;
	int uid = (int)(userdata & 0xFFFFFFFF);
	int event = uid - 1;

	s64 result = 0;
	u32 error = 0;

	SceUID waitID = __KernelGetWaitID(threadID, WAITTYPE_NET, error);
	if (waitID == 0 || error != 0) {
		WARN_LOG(Log::sceNet, "sceNp2 State WaitID(%i) on Thread(%i) already woken up? (error: %08x)", uid, threadID, error);
		return;
	}

	u32 waitVal = __KernelGetWaitValue(threadID, error);
	if (error == 0) {
		np2RPCNState = waitVal;
	}

	__KernelResumeThreadFromWait(threadID, result);
	WARN_LOG(Log::sceNet, "Returning (WaitID: %d, error: %08x) Result (%08x) of sceNp2 - Event: %d, State: %d", waitID, error, (int)result, event, np2RPCNState);
}

int ScheduleRPCNState(int event, int newState, int usec, const char* reason) {
	int uid = event + 1;

	u64 param = ((u64)__KernelGetCurThread()) << 32 | uid;
	CoreTiming::ScheduleEvent(usToCycles(usec), np2RPCNStateEvent, param);
	__KernelWaitCurThread(WAITTYPE_NET, uid, newState, 0, false, reason);

	return 0;
}

static void __P2PState(u64 userdata, int cyclesLate) {
	SceUID threadID = userdata >> 32;
	int uid = (int)(userdata & 0xFFFFFFFF);
	int event = uid - 1;

	s64 result = 0;
	u32 error = 0;

	SceUID waitID = __KernelGetWaitID(threadID, WAITTYPE_NET, error);
	if (waitID == 0 || error != 0) {
		WARN_LOG(Log::sceNet, "sceNp2 State WaitID(%i) on Thread(%i) already woken up? (error: %08x)", uid, threadID, error);
		return;
	}

	u32 waitVal = __KernelGetWaitValue(threadID, error);
	if (error == 0) {
		np2P2PState = waitVal;
	}

	__KernelResumeThreadFromWait(threadID, result);
	WARN_LOG(Log::sceNet, "Returning (WaitID: %d, error: %08x) Result (%08x) of sceNp2 - Event: %d, State: %d", waitID, error, (int)result, event, np2P2PState);
}

int ScheduleP2PState(int event, int newState, int usec, const char* reason) {
	int uid = event + 1;

	u64 param = ((u64)__KernelGetCurThread()) << 32 | uid;
	CoreTiming::ScheduleEvent(usToCycles(usec), np2P2PStateEvent, param);
	__KernelWaitCurThread(WAITTYPE_NET, uid, newState, 0, false, reason);

	return 0;
}

void __Np2Init() {
	npMatching2Inited = false;

	np2RPCNState = NP_SIGNIN_STATUS_NONE;
	np2P2PState = NP_SIGNIN_STATUS_NONE;
	np2RPCNStateEvent = CoreTiming::RegisterEvent("__RPCNState", __RPCNState);
	np2P2PStateEvent = CoreTiming::RegisterEvent("__P2PState", __P2PState);

	np2RPCNThreadHackAddr = __CreateHLELoop(np2RPCNThreadCode, "sceNpMatching2", "__Np2SignalingGetRPCNResponses", "np2RPCNThreadHack");
	np2P2PThreadHackAddr = __CreateHLELoop(np2P2PThreadCode, "sceNpMatching2", "__Np2SignalingGetP2PResponses", "np2P2PThreadHack");
	//np2SignalingThreadHackAddr = __CreateHLELoop(np2SignalingThreadCode, "sceNpMatching2", "__NpMatching2GetResponses", "np2SignalingThreadHack");

	//actionAfterMatching2MipsCall = __KernelRegisterActionType(AfterMatching2MipsCall::Create);
	//actionAfter2SignalingMipsCall = __KernelRegisterActionType(AfterMatching2MipsCall::Create);
}

void __Np2Shutdown() {
	if (npServer && npServer->IsConnected()) {
		g_signaling.stop("NpMatching2 Shutdown");
		npServer->Disconnect();
	}

	// Stop fake PSP Thread
	if (np2RPCNThreadID != 0) {
		__KernelStopThread(np2RPCNThreadID, SCE_KERNEL_ERROR_THREAD_TERMINATED, "RPCN Thread stopped");
	}
	if (np2P2PThreadID != 0) {
		__KernelStopThread(np2P2PThreadID, SCE_KERNEL_ERROR_THREAD_TERMINATED, "P2P Thread stopped");
	}
}

void __Np2SignalingGetRPCNResponses()
{
	hleSkipDeadbeef();
	int newState = SCE_NP_MATCHING2_STATE_NONE;
	int delayus = 1000000;
	if (npServer) {
		newState = SCE_NP_MATCHING2_STATE_INIT;
		delayus = 1000000;
		if (npServer->IsConnected()) {
			newState = SCE_NP_MATCHING2_STATE_CONNECTED;
			delayus = npServer->HandleResponses().count();
		}
	}
	//ScheduleRPCNState(1, newState, delayus, "RPCN Wait State");
	DEBUG_LOG(Log::sceNet, "RPCN Waiting %d ms", (delayus / 1000));
	//int r = hleDelayResult(0, "RPCN Wait State", delayus);
	hleCall(ThreadManForUser, int, sceKernelDelayThread, delayus);
	hleNoLogVoid();
}

void __Np2SignalingGetP2PResponses()
{
	hleSkipDeadbeef();

	int newState = SCE_NP_MATCHING2_STATE_NONE;
	int delayus = 1000000;
	if (npMatching2Inited) {
		newState = SCE_NP_MATCHING2_STATE_INIT;
		//g_signaling.get_wait_time_ns();
		delayus = g_signaling.HandleResponses().count();
	}

	//ScheduleP2PState(3, newState, delayus, "P2P Wait State");
	DEBUG_LOG(Log::sceNet, "P2P Waiting %d ms", (delayus / 1000));
	//int r = hleDelayResult(0, "P2P Wait State", delayus);
	hleCall(ThreadManForUser, int, sceKernelDelayThread, delayus);
	hleNoLogVoid();
}

/* Generate a Unique Request Id for various callbacks
 * @param app_req value derrived from AppRequestID
 * @return u32 System RequestID
 */
SceNpMatching2RequestId GenerateRequestId(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId app_req) {
	auto context = ctx.find(ctxId);
	// Matching context
	if (context != ctx.end())
		return context->second->match2_request_cnt.fetch_add(1);

	// No matching context
	SceNpMatching2RequestId request_id = app_req + 1;
	while (request_id == 0 || npMatching2Handlers.find(request_id) != npMatching2Handlers.end())
		request_id++;
	return request_id;
}

//template <typename T>
//void Write_Struct(const T& object, const u32 address, const char* tag, size_t taglen) {
//	Memory::Memcpy(address, &object, sizeof(T), tag, taglen);
//}

void SetDefaultParams(SceNpMatching2ContextId ctxId, u32 callbackFunctionAddr, u32 callbackArgument, SceNpMatching2EventType event_type) {
	NpMatching2Handler optParam{};
	optParam.ctx_id = ctxId;
	optParam.cb = callbackFunctionAddr;
	optParam.cb_arg = callbackArgument;
	optParam.event_type = event_type;
	defaultOptParams[event_type] = optParam;
}

/* Generate a callback handler for async processing returns
 * @param optParamPtr pointer to SceNpMatching2RequestOptParam
 * @param assignedReqIdPtr pointer to AppRequestID
 * @param event_type PS3Matching2RequestEvent Event
 * @return u32 System RequestID
 */
SceNpMatching2RequestId RegisterNpMatching2Handler(SceNpMatching2ContextId ctxId, SceNpMatching2RequestOptParam optParam, u32 assignedReqId, SceNpMatching2EventType event_type) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %d) at %08x", __FUNCTION__, ctxId, optParam.cbFunc.ptr, optParam.cbFuncArg.ptr, event_type, currentMIPS->pc);

	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);
	auto req_id = GenerateRequestId(ctxId, assignedReqId);

	//if (!Memory::IsValidAddress(optParam.cbFunc.ptr)) {
	//	req_id = 0; // PSP2i crashes if this isn't set to abort
	//}
	NpMatching2Handler handler{};

	handler.ctx_id = ctxId; // double handle
	handler.cb = optParam.cbFunc.ptr;
	handler.cb_arg = optParam.cbFuncArg.ptr;
	handler.event_type = event_type;

	// 0 defines an Aborted Request
	npMatching2Handlers[req_id] = handler;
	if (Memory::IsValidAddress(optParam.cbFunc.ptr))
		NOTICE_LOG(Log::sceNet, "%s(count: %d) - Added Callback FUN_%08x(%08x) for %s", __FUNCTION__, npMatching2Handlers.size(), handler.cb, handler.cb_arg, EventToString(event_type).c_str());
	else
		NOTICE_LOG(Log::sceNet, "%s(count: %d) - Added Abort to Empty Callback for %s", __FUNCTION__, npMatching2Handlers.size(), EventToString(event_type).c_str());
	return req_id;
}

/* Thread-safe Event Processor for Request Callback. Relevant arguments will be replaced.
 * @param event_code Related System Request Type, matches the Handler
 * @param argc Count of the number of arguments
 * @param args Variable length of arguments, MAX_ARGS = 11
 * @note If there are any problems writing to np_memory, it may be prudent to run a thread-sanitized environment instead
 */
int notifyRequestHandler(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2Event event, s32 errorCode, u32 dataPtr) {
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	u32 args[6];
	//args[0] = ctxId	// ContextID
	args[1] = reqId;	// RequestId || 0 indicates aborted request
	args[2] = event;	// Event
	args[3] = errorCode;// ErrorCode || 0 is OK
	args[4] = dataPtr;	// Response struct
	//args[5] = argsPtr	// Request Arguments

	npMatching2Events.push_back(NpMatching2Args(ctxId, reqId, 6, args, SCE_NP_MATCHING2_REQUEST_EVENT));

	return 0;
}

/* Thread-safe Event Processor for related Callback. Relevant arguments will be replaced.
 * @param event_code Related System Request Type, matches the Handler
 * @param argc Count of the number of arguments
 * @param args Variable length of arguments, MAX_ARGS = 11
 * @note If there are any problems writing to np_memory, it may be prudent to run a thread-sanitized environment instead
 */
int notifyRoomMessageHandler(SceNpMatching2ContextId ctxId, SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId, RPCNMatching2RequestEvent requestEvent, u32 dataPtr) {
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	u32 args[8];
	//args[0] = ctxId	// ContextID
	args[1] = roomId;	// RoomID
	args[2] = 0;		// ConnId? Ignored by PSP2i
	args[3] = ctx[ctxId]->match2_event_cnt.fetch_add(1); // param_4? Ingored by PSP2i
	args[4] = memberId;	// MemberID
	args[5] = requestEvent;// Event [SCE_NP_MATCHING2_ROOM_MSG_EVENT_ChatMessage / SCE_NP_MATCHING2_ROOM_MSG_EVENT_Message]
	args[6] = dataPtr;	// Message
	//args[7] = argsPtr	// Request Arguments

	npMatching2Events.push_back(NpMatching2Args(ctxId, 8, args, SCE_NP_MATCHING2_ROOM_MSG_EVENT));

	return 0;
}

/* Thread-safe Event Processor for related Callback. Relevant arguments will be replaced.
 * @param event_code Related System Request Type, matches the Handler
 * @param argc Count of the number of arguments
 * @param args Variable length of arguments, MAX_ARGS = 11
 * @note If there are any problems writing to np_memory, it may be prudent to run a thread-sanitized environment instead
 */
int notifyRoomEventHandler(SceNpMatching2ContextId ctxId, SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId, SceNpMatching2Event event, u32 dataPtr) {
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	u32 args[7];
	//args[0] = ctxId	// ContextID
	args[1] = roomId;	// RoomID
	args[2] = ctx[ctxId]->match2_event_cnt.fetch_add(1); // ConnectionID?
	args[3] = memberId;	// MemberID?
	args[4] = event;	// Event
	args[5] = dataPtr;	// ErrorCode
	//args[6] = argsPtr	// Request Arguments

	npMatching2Events.push_back(NpMatching2Args(ctxId, 7, args, SCE_NP_MATCHING2_ROOM_EVENT));

	return 0;
}

/* Thread-safe Event Processor for related Callback. Relevant arguments will be replaced.
 * @param event_code Related System Request Type, matches the Handler
 * @param argc Count of the number of arguments
 * @param args Variable length of arguments, MAX_ARGS = 11
 * @note If there are any problems writing to np_memory, it may be prudent to run a thread-sanitized environment instead
 */
int notifySignalingHandler(SceNpMatching2ContextId ctxId, SceNpMatching2RoomId room_id, u32 conn_id, u32 unknown, SceNpMatching2RoomMemberId roomMemberId, SceNpMatching2Event event, s32 errorCode) {
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	// FIXME: Need confirmation on arguments for conn_id, room_id
	u32 args[8];
	//args[0] = ctxId;		// ContextID
	args[1] = room_id;		// room_id?
	args[2] = conn_id;		// conn_id?
	args[3] = unknown;		// unknown?
	args[4] = roomMemberId;	// roomMemberId
	args[5] = event;		// EventCode
	args[6] = errorCode;	// ErrorCode
	//args[7] = 0;			// cbArgs

	npMatching2Events.push_back(NpMatching2Args(ctxId, 8, args, SCE_NP_MATCHING2_SIGNALING_EVENT));

	return 0;
}

//int trynotifySignalingHandler() {
//	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);
//
//	u32 args[8];
//	//args[0] = 1;	// ContextID
//	args[1] = 2;	// param_2
//	args[2] = 3;	// param_3
//	args[3] = 4;	// param_4
//	args[4] = 5;	// roomMemberId
//	args[5] = SCE_NP_MATCHING2_SIGNALING_EVENT_Established;	// event
//	args[6] = 7;	// errorCode
//	//args[7] = 0;	// cbArgs
//
//	npMatching2Events.push_back(NpMatching2Args(SCE_NP_MATCHING2_SIGNALING_EVENT, 8, args));
//
//	return 0;
//}
/* Event Processor
 * @note The arguments are suppose to be combined here?
 */
bool NpMatching2ProcessEvents() {
	if (npMatching2Events.empty()) {
		return false;
	}

	// Consume latest event
	auto& event = npMatching2Events.front();
	npMatching2Events.pop_front();

	NpMatching2Handler* optParam = nullptr;
	if (event.context_id == 0) {
		WARN_LOG(Log::sceNet, "NpMatching2ProcessEvents - Using Default Opt Params");
		if (auto def = defaultOptParams.find(event.event_type); def != defaultOptParams.end())
			optParam = &def->second;
	} else if (auto it = npMatching2Handlers.find(event.request_id); it != npMatching2Handlers.end()) {
		//optParam = &it->second;
		optParam = new NpMatching2Handler(std::move(it->second));  // Save and erase?
		npMatching2Handlers.erase(it);
	}
	else {
		ERROR_LOG(Log::sceNet, "NpMatching2ProcessEvents - No Handler Found for Event %s", EventToString(event.event_type).c_str());
		return false;
	}

	if (optParam != nullptr) {
		if (!Memory::IsValidAddress(optParam->cb.ptr)) {
			WARN_LOG(Log::sceNet, "NpMatching2ProcessEvents - Nothing to Callback to for %s", EventToString(event.event_type).c_str());
			return NpMatching2ProcessEvents();
		}
		switch (optParam->event_type) {
			// combine the callback parameters with the request based on the event type
		case SCE_NP_MATCHING2_REQUEST_EVENT:
			event.args[0] = optParam->ctx_id;
			event.args[5] = optParam->cb_arg.ptr;

			NOTICE_LOG(Log::sceNet, "SceNpMatching2RequestCallback - %s_%08x(ctxId: %d, reqId: %d, event: %d, error: %08x, dataPtr: %08x, cbArgPtr: %08x)", EventToString(event.event_type).c_str(), optParam->cb.ptr,
				event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5]);
			break;
		case SCE_NP_MATCHING2_ROOM_EVENT:
			event.args[0] = optParam->ctx_id;
			event.args[6] = optParam->cb_arg.ptr;

			NOTICE_LOG(Log::sceNet, "SceNpMatching2RoomEventCallback - %s_%08x(ctxId: %d, roomId: %d, connId?: %08x, memberId: %d, requestEvent: %08x, dataPtr: %08x, argPtr: %08x)", EventToString(event.event_type).c_str(), optParam->cb.ptr,
				event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5], event.args[6]);
			break;
		case SCE_NP_MATCHING2_ROOM_MSG_EVENT:
			event.args[0] = optParam->ctx_id;
			event.args[7] = optParam->cb_arg.ptr;
			_dbg_assert_(Memory::IsValidAddress(event.args[7]));

			NOTICE_LOG(Log::sceNet, "SceNpMatching2RoomMessageCallback - %s_%08x(ctxId: %d, roomId: %d, memberId: %d, param_4: %08x, param_5: %08x, event: %08x, dataPtr: %08x, argPtr: %08x)", EventToString(event.event_type).c_str(), optParam->cb.ptr,
				event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5], event.args[6], event.args[7]);
			break;
		case SCE_NP_MATCHING2_LOBBY_EVENT:
			event.args[0] = optParam->ctx_id;

			ERROR_LOG(Log::sceNet, "UNIMPLEMENTED SceNpMatching2LobbyEventCallback - %s_%08x(ctxId: %d)", EventToString(event.event_type).c_str(), optParam->cb.ptr, event.args[0]);
			return false;
		case SCE_NP_MATCHING2_LOBBY_MSG_EVENT:
			event.args[0] = optParam->ctx_id;

			ERROR_LOG(Log::sceNet, "UNIMPLEMENTED SceNpMatching2LobbyMessageCallback - %s_%08x(ctxId: %d)", EventToString(event.event_type).c_str(), optParam->cb.ptr, event.args[0]);
			return false;
		case SCE_NP_MATCHING2_SIGNALING_EVENT:
			event.args[0] = optParam->ctx_id;
			event.args[7] = optParam->cb_arg.ptr;

			NOTICE_LOG(Log::sceNet, "SceNpMatching2SignalingCallback - %s_%08x(param_1: %d, param_2: %d, param_3: %d, param_4: %d, param_5: %d, param_6: %d, param_7: %d, param_8: %08x)", EventToString(event.event_type).c_str(), optParam->cb.ptr,
				event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5], event.args[6], event.args[7]);
			break;
		default:
			NOTICE_LOG(Log::sceNet, "UNHANDLED Callback Type %d - FUN_%08x(ctxId: %d)", event.event_type, optParam->cb.ptr, event.args[0]);
			_dbg_assert_(false);
			return false;
		}
		//DEBUG_LOG(Log::sceNet, "NpMatching2Callback [HandlerID=%i][EventID=%04x][State=%04x][ArgsPtr=%08x]", it->first, event, stat, optParam->argument);
		if (Memory::IsValidAddress(optParam->cb.ptr))
			hleEnqueueCall(optParam->cb.ptr, event.argc, event.args);
		return true;
	}
	return false;
}

static inline u32 AllocUser(u32 size, bool fromTop, const char* name) {
	u32 addr = userMemory.Alloc(size, fromTop, name);
	if (addr == -1)
		return 0;
	return addr;
}

static inline void FreeUser(u32& addr) {
	if (addr != 0)
		userMemory.Free(addr);
	addr = 0;
}

static int sceNpMatching2Init(int poolSize, int threadPriority, int cpuAffinityMask, int threadStackSize)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %d, %d, %d) at %08x", __FUNCTION__, poolSize, threadPriority, cpuAffinityMask, threadStackSize, currentMIPS->pc);
	if (npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_ALREADY_INITIALIZED);

	if (poolSize == 0) {
		return hleLogError(Log::sceNet, SCE_KERNEL_ERROR_ILLEGAL_MEMSIZE, "invalid pool size");
	}
	else if (threadPriority < 0x08 || threadPriority > 0x77) {
		return hleLogError(Log::sceNet, SCE_KERNEL_ERROR_ILLEGAL_PRIORITY, "invalid init thread priority");
	}

	npPoolAddr = AllocUser(poolSize, false, "np2pool");
	if (npPoolAddr == 0) {
		return hleLogError(Log::sceNet, SCE_KERNEL_ERROR_NO_MEMORY, "unable to allocate pool");
	}
	if (np2RPCNThreadID > 0) {
		__KernelStartThread(np2RPCNThreadID, 0, 0);
	}
	/*if (np2P2PThreadID > 0) {
		__KernelStartThread(np2P2PThreadID, 0, 0);
	}*/
	np_memory.Init(npPoolAddr, poolSize, false);

	npMatching2MemStat.npMemSize = poolSize - 0x20;
	npMatching2MemStat.npMaxMemSize = 0x4050; // Dummy maximum foot print
	npMatching2MemStat.npFreeMemSize = npMatching2MemStat.npMemSize;

	npMatching2Handlers.clear();
	npMatching2Events.clear();
	npMatching2Inited = true;

	// We don't need the auth agent after this.
	if (npAuthServer && npAuthServer->IsConnected())
		npAuthServer->Disconnect();

	npServer = npAuthServer->CreateAgent();

	// Just in case the NPAgent is hosted on a different physical server
	if (!npServer->Resolve()) {
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_AVAILABLE, "Unable to find Server.");
	}

	std::string npid = net::RPCNAuthAgent::generate_npid();
	if (!npServer->Connect()) {
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE, "Could not connect.");
	}

	std::string* creds = NpGetLogin();
	int ret = npServer->Login(creds[0].c_str(), creds[2].c_str(), creds[1].c_str());
	if (ret != 0) {
		switch ((ErrorType)ret) {
		case ErrorType::LoginError:
			return hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_BUSY, "Login Error");
		case ErrorType::LoginAlreadyLoggedIn:
			return hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_ALREADY_JOINED, "User is already signed in");
		case ErrorType::LoginInvalidUsername:
			return hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_USER, "Invalid Login Credentials");
		case ErrorType::LoginInvalidPassword:
			return hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_PASSWORD_MISMATCH, "Invalid Login Credentials");
		case ErrorType::LoginInvalidToken:
			return hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_INVALID_TICKET, "Invalid Token");
		default:
			return hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_BUSY, "Unable to Log In (%d)", ret);
		}
	}

	// FIXME: This thread runs even when you trigger break
	// RPCS3 has only 1 connection perpetually active
	//  As such, it has additional functions in sceNp that
	//  trigger signaling to start, and P2P connect requests
	if (g_signaling.create_connection())
		g_signaling.set_self_sig_info(*NpGetNpId());
	else
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_ABORTED, "Signaling Loop could not be started");
	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2Term()
{
	WARN_LOG(Log::sceNet, "UNTESTED %s() at %08x", __FUNCTION__, currentMIPS->pc);

	if (npServer && npServer->IsConnected()) {
		g_signaling.stop("NpMatching2 Terminating");
		npServer->Disconnect();
	}

	npMatching2Inited = false;
	npMatching2Handlers.clear();
	npMatching2Events.clear();

	FreeUser(npPoolAddr);

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2CreateContext(u32 communicationIdPtr, u32 passPhrasePtr, u32 ctxIdPtr, s32 optionFlags)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%08x[%s], %08x[%08x], %08x[%hu], %08x) at %08x", __FUNCTION__, communicationIdPtr, safe_string(Memory::GetCharPointer(communicationIdPtr)), passPhrasePtr, Memory::Read_U32(passPhrasePtr), ctxIdPtr, Memory::Read_U16(ctxIdPtr), optionFlags, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (!Memory::IsValidAddress(communicationIdPtr) || !Memory::IsValidAddress(passPhrasePtr) || !Memory::IsValidAddress(ctxIdPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_MAX);

	// FIXME: It seems Context are mapped to TitleID? may return 0x80550C05 or 0x80550C06 when finding an existing context
	SceNpCommunicationId* titleid = (SceNpCommunicationId*)Memory::GetCharPointer(communicationIdPtr);
	memcpy(&npTitleId, titleid, sizeof(SceNpCommunicationId));

	SceNpCommunicationPassphrase* passph = (SceNpCommunicationPassphrase*)Memory::GetCharPointer(passPhrasePtr);
	npServer->UpdateOptions(optionFlags);

	INFO_LOG(Log::sceNet, "%s - Title ID: %s", __FUNCTION__, npTitleId.data);
	INFO_LOG(Log::sceNet, "%s - Title NUM: %d", __FUNCTION__, npTitleId.num);
	//INFO_LOG(Log::sceNet, "%s - Online ID: %s", __FUNCTION__, npid->handle.data);
	INFO_LOG(Log::sceNet, "%s - User ID: %d", __FUNCTION__, npServer->GetUserID());
	INFO_LOG(Log::sceNet, "%s - Login ID: %s", __FUNCTION__, g_Config.infraNpId.c_str());
	INFO_LOG(Log::sceNet, "%s - Use Online ID: %s", __FUNCTION__, (npServer->IncludeOnlineName() ? "YES" : "NO"));
	INFO_LOG(Log::sceNet, "%s - Online ID: %s", __FUNCTION__, npServer->GetOnlineName().c_str());
	INFO_LOG(Log::sceNet, "%s - Use Avatar: %s", __FUNCTION__, (npServer->IncludeAvatarUrl() ? "YES" : "NO"));
	INFO_LOG(Log::sceNet, "%s - Avatar URL: %s", __FUNCTION__, npServer->GetAvatarURL().c_str());
	std::string datahex;
	/*DataToHexString(npid->opt, sizeof(npid->opt), &datahex);
	INFO_LOG(Log::sceNet, "%s - Options?: %s", __FUNCTION__, datahex.c_str());
	datahex.clear();*/
	DataToHexString(10, 0, passph->data, sizeof(passph->data), &datahex);
	INFO_LOG(Log::sceNet, "%s - Passphrase: \n%s", __FUNCTION__, datahex.c_str());

	SceNpMatching2ContextId ctxId = 1;
	for (ctxId = 1; ctxId <= CONTEXT_MAX_ID; ctxId++) {
		if (ctx.find(ctxId) != ctx.end())
			continue;
		break;
	}

	if (ctxId > CONTEXT_MAX_ID)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_MAX, "Max Contexts Reached");

	//ctx[ctxId] = NpMatching2Context(*titleid, *passph, optionFlags);
	/*ctx.emplace(std::piecewise_construct,
		std::forward_as_tuple(ctxId),
		std::forward_as_tuple(std::make_unique<NpMatching2Context>(*titleid, *passph, optionFlags)));*/

	ctx.emplace(ctxId, std::make_unique<NpMatching2Context>(*titleid, *passph, optionFlags));
	//ctx[ctxId] = std::move(NpMatching2Context(*titleid, *passph, optionFlags));
	// TODO: Allocate & zeroed a memory of 68 bytes where npId (36 bytes) is copied to offset 8, offset 44 = 0x00026808, offset 48 = 0

	// Returning dummy Id, a 16-bit variable according to JPCSP
	// FIXME: It seems ctxId need to be in the range of 1 to 7 to be valid ?
	Memory::Write_U16(ctxId, ctxIdPtr);
	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2ContextStart(int ctxId)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d) at %08x", __FUNCTION__, ctxId, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto ctx_it = ctx.find(ctxId);
	if (ctx_it == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND); //SCE_NP_MATCHING2_ERROR_INVALID_CONTEXT_ID

	if (ctx_it->second->started.load())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_ALREADY_STARTED);

	// TODO: use sceNpGetUserProfile and check server availability using sceNpService_76867C01
	ctx_it->second->started.store(1, std::memory_order_release);

	if (!npServer || !npServer->IsConnected())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE);

	int ret = npServer->GetServers(npTitleId);

	hleEatMicro(1000000);
	// Returning 0x805508A6 (error code inherited from sceNpService_76867C01 which check server availability) if can't check server availability (ie. Fat Princess (US) through http://static-resource.np.community.playstation.net/np/resource/psp-title/NPWR00670_00/matching/NPWR00670_00-matching.xml using User-Agent: "PS3Community-agent/1.0.0 libhttp/1.0.0")
	if (ret != 0)
		return hleLogError(Log::sceNet, ret, "Unable to retrieve Server list");
	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2ContextStop(int ctxId)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d) at %08x", __FUNCTION__, ctxId, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND); //SCE_NP_MATCHING2_ERROR_INVALID_CONTEXT_ID

	if (!ctx[ctxId]->started.load())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_STARTED);

	//TODO: Stop any in-progress HTTPClient communication used on sceNpMatching2ContextStart
	ctx[ctxId]->started.store(false);

	// Delete all tasks
	{
		std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);
		npMatching2Handlers.clear();
		defaultOptParams.clear();
		npMatching2Events.clear();
	}

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2DestroyContext(int ctxId)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d) at %08x", __FUNCTION__, ctxId, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto it = ctx.find(ctxId);
	if (it == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND); //SCE_NP_MATCHING2_ERROR_INVALID_CONTEXT_ID

	ctx.erase(it);

	ERROR_LOG(Log::sceNet, "%s: Invalid Context ID %d", __FUNCTION__, ctxId);

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2GetMemoryStat(u32 memStatPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%08x) at %08x", __FUNCTION__, memStatPtr, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto memStat = PSPPointer<SceNpAuthMemoryStat>::Create(memStatPtr);
	if (!memStat.IsValid())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	*memStat = npMatching2MemStat;
	memStat.NotifyWrite("NpMatching2GetMemoryStat");

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2RegisterSignalingCallback(int ctxId, u32 callbackFunctionAddr, u32 callbackArgument)
{
	ERROR_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x) at %08x", __FUNCTION__, ctxId, callbackFunctionAddr, callbackArgument, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (callbackFunctionAddr == 0 || !Memory::IsValidAddress(callbackFunctionAddr)) {
		return hleLogError(Log::sceNet, SCE_NP_ERROR_INVALID_CALLBACK, "%s - Invalid Callback %08x", __FUNCTION__, callbackFunctionAddr);
	}

	signaling_ctxId = ctxId;
	SetDefaultParams(ctxId, callbackFunctionAddr, callbackArgument, SCE_NP_MATCHING2_SIGNALING_EVENT);

	return SCE_NP_MATCHING2_OKAY; // error returns 0x80550004
}

// PSP2i assigns unknown 0x10, 0x0c, or 0x14
static int sceNpMatching2SignalingGetConnectionStatus(int ctxId, u32 unknown, u32 roomId, u32 status, u32 peerMemberId, u32 connInfoPtr, u32 ipAddrPtr, u32 portPtr) {
	WARN_LOG(Log::sceNet, "UNIMPL %s(%d, %08X, %d, %08X, %d, 0x%08X, 0x%08X, 0x%08X) at %08x", __FUNCTION__, ctxId, unknown, roomId, status, peerMemberId, connInfoPtr, ipAddrPtr, portPtr, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	SceNpMatching2ConnectionInfo* statusInfo = (SceNpMatching2ConnectionInfo*)&status;
	NOTICE_LOG(Log::sceNet, " - Service State: %d", statusInfo->status1);
	NOTICE_LOG(Log::sceNet, " - NPPort Status: %d", statusInfo->status2);
	NOTICE_LOG(Log::sceNet, " - UPnP State: %d", statusInfo->status3);
	NOTICE_LOG(Log::sceNet, " - NAT Type: %d", statusInfo->NatType);
	/*statusInfo->status1 = SCE_NP_SERVICE_STATE_UNKNOWN;
	statusInfo->status2 = SCE_NP_SIGNALING_NETINFO_NPPORT_STATUS_CLOSED;
	statusInfo->status3 = SCE_NP_SIGNALING_NETINFO_UPNP_STATUS_UNKNOWN;
	statusInfo->NatType = SCE_NP_SIGNALING_NETINFO_NAT_STATUS_UNKNOWN;*/

	if (connInfoPtr == 0 || !Memory::IsValidAddress(connInfoPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT, "connInfoPtr is an invalid pointer");

	//auto connStatus = PSPPointer<SceNpMatching2ServerStatus>::Create(connInfoPtr);
	//connStatus = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;
	Memory::Write_U32(SCE_NP_SIGNALING_CONN_STATUS_INACTIVE, connInfoPtr);

	auto member = npServer->cache.GetMember(peerMemberId);
	if (!member) {
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_ROOM_MEMBER_NOT_FOUND, "Member not found");
	}

	/*if (strncmp(NpGetNpId()->handle.data, member->userInfo.npId.handle.data, 16) == 0) {
		connInfo->status = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;
		return hleLogError(Log::sceNet, SCE_NP_SIGNALING_ERROR_OWN_NP_ID, "Member is Self");
	}*/
	auto connID = g_signaling.get_conn_id_from_npid(member->userInfo.npId);
	if (!connID) {
		return hleLogError(Log::sceNet, SCE_NP_SIGNALING_ERROR_CONN_NOT_FOUND, "Connection not found");
	}

	auto si = g_signaling.get_sig_infos(*connID);
	if (!si) {
		return hleLogError(Log::sceNet, SCE_NP_SIGNALING_ERROR_CONN_NOT_FOUND, "Not Connected");
	}
	
	// Write Connection Status
	//connStatus = si->conn_status;
	Memory::Write_U32(si->conn_status, connInfoPtr);

	if (ipAddrPtr == 0 || !Memory::IsValidAddress(ipAddrPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT, "ipAddrPtr is an invalid pointer");

	u32 addr = si->addr;
	Memory::Write_U32(addr, ipAddrPtr);
	NOTICE_LOG(Log::sceNet, " - IP Addr: %s", ip2str(Memory::Read_U32(ipAddrPtr)).c_str());

	if (portPtr == 0 || !Memory::IsValidAddress(portPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT, "portPtr is an invalid pointer");

	u16 port = 3658;
	//if (port == SCE_NP_PORT)
		//port = 3658;
	Memory::Write_U16(htons(port), portPtr);
	NOTICE_LOG(Log::sceNet, " - Port: %d", ntohs(Memory::Read_U16(portPtr)));

	// Write IPAddress
	/*connInfo->conn.sa_len = ip2str(si->addr).length();
	memcpy(connInfo->conn.sa_data, ip2str(si->addr).c_str(), connInfo->conn.sa_len);
	connInfo->conn.sa_family = 0x02;*/

	return hleLogWarning(Log::sceNet, SCE_NP_MATCHING2_OKAY, "- %d", Memory::Read_U32(connInfoPtr));
}

/* Allocates the list of server Id's to memory
 * @param serverIdsPtr Pointer to where the servers should be written
 * @param maxServerIds maximum number of servers the client can receive
 * @return Number of servers we allocated
 * @note PSP has been observed writing these in decremental order
 */
static int sceNpMatching2GetServerIdListLocal(int ctxId, u32 serverIdsPtr, u32 maxServerIds)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %d) at %08x", __FUNCTION__, ctxId, serverIdsPtr, maxServerIds, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(serverIdsPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	if (npServer->servers.size() == 0)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND);

	auto servers = PSPPointer<SceNpMatching2ServerId>::Create(serverIdsPtr);


	u32 num_servs = std::min(static_cast<u32>(npServer->servers.size()), maxServerIds);

	NOTICE_LOG(Log::sceNet, " - Server Count: %d", num_servs);
	if (servers.IsValid()) {
		for (u32 i = 0; i < num_servs; i++)
		{
			NOTICE_LOG(Log::sceNet, " - Server[%d] ID: %d", i, npServer->servers[i].id);
			servers[i] = npServer->servers[i].id;
		}
	}

	// Return the number of servers allocated to memory
	return num_servs;
}

/* Produces information about a target server
 * @param serverIdPtr Pointer to the target Server ID
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Server will respond with relevant information and trigger the related callback
 * @note PSP2i calls this once witha reqId 0, and then once for each server allocated in sceNpMatching2GetServerIdListLocal
 */
static int sceNpMatching2GetServerInfo(int ctxId, u32 serverIdPtr, u32 optParamPtr, u32 assignedReqIdPtr) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x[%d], %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, serverIdPtr, Memory::Read_U16(serverIdPtr), optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(assignedReqIdPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetServerInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (!Memory::IsValidAddress(serverIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetServerInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_SERVER_ID), 0);
	// Server ID is a 16-bit variable according to JPCSP
	SceNpMatching2ServerId serverId = Memory::Read_U16(serverIdPtr);

	// Check server status
	//servers[serverId]->Resolve();

	SceNpMatching2ServerInfo serverInfo = npServer->GetServerInfo(serverId);

	u32 respSize = sizeof(SceNpMatching2GetServerInfoResponse);
	auto serv_info_ptr = np_memory.Alloc(respSize);
	if (serv_info_ptr == 0)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetServerInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY), 0);
	auto serv_info = PSPPointer<SceNpMatching2GetServerInfoResponse>::Create(serv_info_ptr);

	serv_info->server.id = serverInfo.id;
	serv_info->server.status = serverInfo.status;
		
	NOTICE_LOG(Log::sceNet, " - Server ID: %d", serverInfo.id);
	NOTICE_LOG(Log::sceNet, " - Server Status: %d", serverInfo.status);

	return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetServerInfo, SCE_NP_MATCHING2_OKAY, serv_info.ptr);
}

/* Allocates a list of SceNpMatching2World for information about the lobbies, parties, and existing player counts
 * @param serverIdPtr Pointer to the target Server ID
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Server will respond with relevant information and trigger the related callback
 * @note This function occurs immediately after a server has been selected
 */
static int sceNpMatching2GetWorldInfoList(int ctxId, u32 serverIdPtr, u32 optParamPtr, u32 assignedReqIdPtr) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x[%d], %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, serverIdPtr, Memory::Read_U16(serverIdPtr), optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (!Memory::IsValidAddress(serverIdPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	// Server ID is a 16-bit variable according to JPCSP
	SceNpMatching2ServerId serverId = Memory::Read_U16(serverIdPtr);
	if (serverId == 0 || !npServer->SelectServer(serverId))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_SERVER_ID), 0);

	auto err = npServer->GetWorldInfo(ctxId, request_id, serverId, npTitleId);

	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Searches for all Lobbies/Parties
 * @param reqParamPtr SceNpMatching2SearchRoomRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SearchRoom(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	const PSPPointer<SceNpMatching2SearchRoomRequest> req = PSPPointer<SceNpMatching2SearchRoomRequest>::Create(reqParamPtr);

	INFO_LOG(Log::sceNet, "SceNpMatching2SearchRoomRequest(%08X)", req.ptr);
	INFO_LOG(Log::sceNet, " - option:       %d", req->option);
	INFO_LOG(Log::sceNet, " - worldIndex:   %d", req->worldIndex);
	INFO_LOG(Log::sceNet, " - lobbyId:      %d", req->lobbyId);
	INFO_LOG(Log::sceNet, " - rangeFilter:  %d", req->rangeFilter);
	INFO_LOG(Log::sceNet, " - flagFilter:   %d", req->flagFilter);
	INFO_LOG(Log::sceNet, " - flagAttr:     %d", req->flagAttr);
	INFO_LOG(Log::sceNet, " - intFilterNum: %d", req->intFilterNum);
	INFO_LOG(Log::sceNet, " - binFilterNum: %d", req->binFilterNum);
	INFO_LOG(Log::sceNet, " - attrIdNum:    %d", req->attrIdNum);
	if (!npServer->cache.GetWorldFromIndex(req->worldIndex)) {
		ERROR_LOG(Log::sceNet, " - Invalid World ID");
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM), 0);
	}

	// WARNING! This is a constant, and thus read-only
	const SearchRoomResponse* roomResp;

	int ret = npServer->SearchRoom(ctxId, request_id, req);

	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Hosts a Lobby/Party
 * @param reqParamPtr SceNpMatching2CreateJoinRoomRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param roomEventCbPtr Pointer to Callback Address for future Room Events (optional)
 * @param roomMessageCbPtr Pointer to Callback Address for future Room Messages (optional) 
 * @param assignedReqIdPtr Pointer to a pre-specified request id
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2CreateJoinRoom(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 roomEventCbPtr, u32 roomMessageCbPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, roomEventCbPtr, roomMessageCbPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	if (Memory::IsValidAddress(roomEventCbPtr)) {
		u32 roomEventCb = Memory::Read_U32(roomEventCbPtr);
		if (Memory::IsValidAddress(roomEventCb))
			SetDefaultParams(ctxId, roomEventCb, optParam->cbFuncArg.ptr, SCE_NP_MATCHING2_ROOM_EVENT);
	}

	if (Memory::IsValidAddress(roomMessageCbPtr)) {
		u32 roomMessageCb = Memory::Read_U32(roomMessageCbPtr);
		if (Memory::IsValidAddress(roomMessageCb))
			SetDefaultParams(ctxId, roomMessageCb, optParam->cbFuncArg.ptr, SCE_NP_MATCHING2_ROOM_MSG_EVENT);
	}

	auto req = PSPPointer<SceNpMatching2CreateJoinRoomRequest>::Create(reqParamPtr);
	//Memory::Memcpy(&req, reqParamPtr, sizeof(req));
	auto world = npServer->cache.GetWorldFromIndex(req->worldIndex);
	INFO_LOG(Log::sceNet, "SceNpMatching2CreateJoinRoomRequest(%08X)", req.ptr);
	INFO_LOG(Log::sceNet, " - worldId:          %d", world? world->worldId : -1);
	INFO_LOG(Log::sceNet, " - worldIndex:       %d", req->worldIndex);
	INFO_LOG(Log::sceNet, " - lobbyId:          %d", req->lobbyId);
	INFO_LOG(Log::sceNet, " - maxSlot:          %d", req->maxSlot);
	INFO_LOG(Log::sceNet, " - flagAttr:         %08X", req->flagAttr);
	INFO_LOG(Log::sceNet, " - roomBinAttrInternalNum: %d", req->roomBinAttrInternalNum);
	INFO_LOG(Log::sceNet, " - roomSearchableIntAttrExternalNum: %d", req->roomSearchableIntAttrExternalNum);
	INFO_LOG(Log::sceNet, " - roomSearchableBinAttrExternalNum: %d", req->roomSearchableBinAttrExternalNum);
	INFO_LOG(Log::sceNet, " - roomBinAttrExternalNum: %d", req->roomBinAttrExternalNum);
	//INFO_LOG(Log::sceNet, " - roomPassword:     %s", req->roomPassword->data);
	INFO_LOG(Log::sceNet, " - groupConfigNum:   %d", req->groupConfigNum);
	INFO_LOG(Log::sceNet, " - passwordSlotMask: %llx", (req->passwordSlotMask.IsValid() ? *req->passwordSlotMask : 0));
	char* pwd = "EMPTY";
	if (req->roomPassword.IsValid()) {
		pwd = reinterpret_cast<char*>(req->roomPassword->data);
	}

	INFO_LOG(Log::sceNet, " - roomPassword:		%s", pwd);
	INFO_LOG(Log::sceNet, " - allowedUserNum:   %d", req->allowedUserNum);
	INFO_LOG(Log::sceNet, " - blockedUserNum:   %d", req->blockedUserNum);
	INFO_LOG(Log::sceNet, " - roomMemberBinAttrInternalNum: %d", req->roomMemberBinAttrInternalNum);
	INFO_LOG(Log::sceNet, " - teamId:           %d", req->teamId);
	// Patapon 3 requests WorldID 0. Is this suppose to be the first available world?
	//if (req->worldId == 0)
		//req->worldId = servers[tServer]->worlds.begin()->first;
	if (!world) {
		ERROR_LOG(Log::sceNet, " - Invalid worldId");
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ROOM_ID), 0);
	}

	int ret = npServer->CreateJoinRoom(ctxId, request_id, req);

	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Joins an existing Lobby/Party
 * @param reqParamPtr ?
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2JoinRoom(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 roomEventCbPtr, u32 roomMessageCbPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, roomEventCbPtr, roomMessageCbPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	if (Memory::IsValidAddress(roomEventCbPtr))
		SetDefaultParams(ctxId, Memory::Read_U32(roomEventCbPtr), optParam->cbFuncArg.ptr, SCE_NP_MATCHING2_ROOM_EVENT);

	if (Memory::IsValidAddress(roomMessageCbPtr))
		SetDefaultParams(ctxId, Memory::Read_U32(roomMessageCbPtr), optParam->cbFuncArg.ptr, SCE_NP_MATCHING2_ROOM_MSG_EVENT);

	auto req = PSPPointer<SceNpMatching2JoinRoomRequest>::Create(reqParamPtr);

	if (np2P2PThreadID)
		__KernelStartThread(np2P2PThreadID, 0, 0);
	// FIXME: Get roomData from PSN
	int ret = npServer->JoinRoom(ctxId, request_id, req);


	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Leaves the current Lobby/Party
 * @param reqParamPtr ?
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 * PSP2i fails to create a party at 08ca57d8 when DAT_08ed59d4 is set to 2
 */
static int sceNpMatching2LeaveRoom(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	auto req = PSPPointer<SceNpMatching2LeaveRoomRequest>::Create(reqParamPtr);
	int ret = npServer->LeaveRoom(ctxId, request_id, req);

	// Execute signaling callback to update users
	g_signaling.DisconnectUsers(req->roomId);
	if (np2P2PThreadID)
		__KernelStopThread(np2P2PThreadID, 0, "User Left Room");

	// After returning, Fat Princess will loop for 64 times (increasing the address by 288 bytes on each loop) or until found a zero status byte (0x08BD4860 + 0x10), looking for empty/available entry to set?
	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Requests attributes of a specific Lobby/Party
 * @param reqParamPtr SceNpMatching2GetRoomDataInternalRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2GetRoomDataInternal(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);


	auto req = PSPPointer<SceNpMatching2GetRoomDataInternalRequest>::Create(reqParamPtr);
	//Memory::Memcpy(&req, reqParamPtr, sizeof(req));

	INFO_LOG(Log::sceNet, "SceNpMatching2GetRoomDataInternalRequest(%08X)", req.ptr);
	INFO_LOG(Log::sceNet, " - roomId:     %d", req->roomId);
	INFO_LOG(Log::sceNet, " - attrIdNum:  %d", req->attrIdNum);

	int ret = npServer->GetRoomDataInternal(ctxId, request_id, req);

	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Unconfirmed. Similar to sceNpMatching2SetRoomDataInternal
 * @param reqParamPtr SceNpMatching2SetRoomDataExternalRequest containing External room information?
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SetRoomDataExternal(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(reqParamPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	auto req = PSPPointer<SceNpMatching2SetRoomDataExternalRequest>::Create(reqParamPtr);

	INFO_LOG(Log::sceNet, " - roomId:     %d", req->roomId);

	int ret = npServer->SetRoomDataExternal(ctxId, request_id, req);

	// After returning, Fat Princess will loop for 64 times (increasing the address by 288 bytes on each loop) or until found a zero status byte (0x08BD4860 + 0x10), looking for empty/available entry to set?
	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Sets attributes of a specific Lobby/Party
 * @param reqParamPtr SceNpMatching2GetRoomDataInternalRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SetRoomDataInternal(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	auto req = PSPPointer<SceNpMatching2SetRoomDataInternalRequest>::Create(reqParamPtr);

	INFO_LOG(Log::sceNet, " - roomId:     %d", req->roomId);

	int ret = npServer->SetRoomDataInternal(ctxId, request_id, req);

	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Sends a Chat Message to relevant players?
 * @param reqParamPtr ? Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SendRoomChatMessage(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, SCE_NP_MATCHING2_OKAY, 0);
}

static int sceNpMatching2SetDefaultRequestOptParam(int ctxId, u32 optParam)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x) at %08x", __FUNCTION__, ctxId, optParam, currentMIPS->pc);

	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(optParam) || !Memory::IsValidAddress(optParam))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	SetDefaultParams(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2SetUserInfo(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	auto req = PSPPointer<SceNpMatching2SetUserInfoRequest>::Create(reqParamPtr);

	int ret = npServer->SetUserInfo(ctxId, request_id, req);

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2GetUserInfoList(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	// FIXME: Actually get the User Info
	return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_OKAY, "UNIMPLEMENTED"), 0);
}

static int sceNpMatching2AbortRequest(int ctxId, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x) at %08x", __FUNCTION__, ctxId, assignedReqIdPtr, currentMIPS->pc);

	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	auto request_id = Memory::Read_U32(assignedReqIdPtr);
	// Find the handler matching the request_id
	auto it = npMatching2Handlers.find(request_id);
	if (it == npMatching2Handlers.end())
		return SCE_NP_MATCHING2_ERROR_REQUEST_NOT_FOUND;

	// FIXME: Context needs to know exactly what event it should match
	// Assign an event with reqId 0 to matching handler
	//notifyRequestHandler(ctxId, 0, it->second.event_type, SCE_NP_MATCHING2_ERROR_ABORTED, 0);


	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2SetSignalingOptParam(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SetDefaultParams(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_SIGNALING_EVENT);

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2GetSignalingOptParamLocal(int ctxId, u32 roomId, u32 optParamPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, optParamPtr, currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(roomId) || !Memory::IsValidAddress(optParamPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	auto optPtr = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);

	if (defaultOptParams.find(SCE_NP_MATCHING2_SIGNALING_EVENT) == defaultOptParams.end())
		return SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND;
	auto sigParam = defaultOptParams[SCE_NP_MATCHING2_SIGNALING_EVENT];
	optPtr->cbFunc = sigParam.cb;
	optPtr->cbFuncArg = sigParam.cb_arg;

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2SignalingGetLocalNetInfo(u32 netInfoPtr)
{
	ERROR_LOG(Log::sceNet, "UNTESTED %s(%08x) at %08x", __FUNCTION__, netInfoPtr, currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED, "Not Initialized");

	if (!Memory::IsValidAddress(netInfoPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT, "Invalid Argument");

	
	auto netInfo = PSPPointer<SceNpMatching2SignalingNetInfo>::Create(netInfoPtr);

	// FIXME: Use npServer->local_addr_sig
	netInfo->localAddr = npServer->GetLocalAddr();	// Local  IP
	netInfo->mappedAddr = npServer->GetSigAddr();	// Public IP
	// Pure speculation
	//si->conn_status
	netInfo->natStatus = SCE_NP_SIGNALING_NETINFO_NAT_STATUS_TYPE2;
	// Unverified extra data?
	netInfo->UPnPStatus = (g_Config.bEnableUPnP ? SCE_NP_SIGNALING_NETINFO_UPNP_STATUS_VALID : SCE_NP_SIGNALING_NETINFO_UPNP_STATUS_INVALID);
	netInfo->portStatus = SCE_NP_SIGNALING_NETINFO_NPPORT_STATUS_OPEN;
	netInfo->port = htons(npServer->GetSigPort());

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2SignalingGetPeerNetInfo(int ctxId, u32 roomId, u32 roomMemberId, u32 netInfoPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, roomMemberId, netInfoPtr, currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(netInfoPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	auto netInfo = PSPPointer<SceNpMatching2SignalingNetInfo>::Create(netInfoPtr);
	auto room = npServer->cache.GetRoom(roomId);
	if (!room)
		return SCE_NP_MATCHING2_ERROR_ROOM_NOT_FOUND;
	auto member = npServer->cache.GetMember(roomMemberId);
	if (!member)
		return SCE_NP_MATCHING2_ERROR_ROOM_MEMBER_NOT_FOUND;
	auto connId = g_signaling.get_conn_id_from_npid(member->userInfo.npId);
	if (!connId)
		return SCE_NP_MATCHING2_SIGNALING_ERROR_CONNID_NOT_AVAILABLE;
	auto si = g_signaling.get_sig_infos(*connId);
	if (!si)
		return SCE_NP_MATCHING2_SIGNALING_ERROR_NETINFO_NOT_AVAILABLE;

	// FIXME: Use npServer->local_addr_sig
	netInfo->localAddr = si->addr;
	netInfo->mappedAddr = si->mapped_addr;	// PublicIP
	// Pure speculation
	//si->conn_status
	netInfo->natStatus = SCE_NP_SIGNALING_NETINFO_NAT_STATUS_TYPE2;
	// Unverified extra data?
	netInfo->UPnPStatus = SCE_NP_SIGNALING_NETINFO_UPNP_STATUS_VALID;
	netInfo->portStatus = SCE_NP_SIGNALING_NETINFO_NPPORT_STATUS_OPEN;
	netInfo->port = htons(si->port);

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2SignalingGetPeerNetInfoResult(int ctxId, u32 signalingReqIdPtr, u32 netInfoPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x[%08x], %08x) at %08x", __FUNCTION__, ctxId, signalingReqIdPtr, Memory::Read_U32(signalingReqIdPtr), netInfoPtr, currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(signalingReqIdPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2SignalingCancelPeerNetInfo(int ctxId, u32 signalingReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x[%08x]) at %08x", __FUNCTION__, ctxId, signalingReqIdPtr, Memory::Read_U32(signalingReqIdPtr), currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (!Memory::IsValidAddress(signalingReqIdPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2SignalingGetConnectionInfo(int ctxId, u32 roomId, u32 memberId, u32 code, u32 connInfoPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, memberId, code, connInfoPtr, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (connInfoPtr == 0 || !Memory::IsValidAddress(connInfoPtr))
		return SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT;

	auto connInfo = PSPPointer<SceNpSignalingConnectionInfo>::Create(connInfoPtr);

	auto member = npServer->cache.GetMember(memberId);

	if (!member)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_ROOM_MEMBER_NOT_FOUND, "Member Not Found");

	if (strncmp(NpGetNpId()->handle.data, member->userInfo.npId.handle.data, 16) == 0) {
		return hleLogError(Log::sceNet, SCE_NP_SIGNALING_ERROR_OWN_NP_ID, "Member is Self");
	}

	auto conn_id = g_signaling.get_always_conn_id(member->userInfo.npId);

	auto si = g_signaling.get_sig_infos(conn_id);
	if (!si) {
		return hleLogError(Log::sceNet, SCE_NP_SIGNALING_ERROR_CONN_NOT_FOUND, "Not Connected");
	}

	switch (code) {
	case SCE_NP_SIGNALING_CONN_INFO_RTT:
		connInfo->rtt = si->rtt;
		WARN_LOG(Log::sceNet, "Returning a RTT of %d microseconds", connInfo->rtt);
		break;
	case SCE_NP_SIGNALING_CONN_INFO_BANDWIDTH:
		connInfo->bandwidth = 100'000'000; // 100 MBPS HACK
		break;
	case SCE_NP_SIGNALING_CONN_INFO_PEER_NPID:
		connInfo->npId = si->npid;
		break;
	case SCE_NP_SIGNALING_CONN_INFO_PEER_ADDRESS:
		connInfo->address.port = (u16)si->port;
		connInfo->address.addr.np_s_addr = si->addr;
		break;
	case SCE_NP_SIGNALING_CONN_INFO_MAPPED_ADDRESS:
		connInfo->address.port = (u16)si->mapped_port;
		connInfo->address.addr.np_s_addr = si->mapped_addr;
		break;
	case SCE_NP_SIGNALING_CONN_INFO_PACKET_LOSS:
		connInfo->packet_loss = 0; // HACK
		break;
	default:
		return SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT;
	}

	return SCE_NP_MATCHING2_OKAY;
}


static int sceNpMatching2GetRoomDataExternalList(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	auto req = PSPPointer<SceNpMatching2GetRoomDataExternalListRequest>::Create(reqParamPtr);
	int ret = npServer->GetRoomDataExternalList(ctxId, request_id, req);

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2GetRoomPasswordLocal(int ctxId, u32 roomIdPtr, u32 withPasswordPtr, u32 roomPasswordPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomIdPtr, withPasswordPtr, roomPasswordPtr, currentMIPS->pc);

	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (ctx.find(ctxId) == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (Memory::IsValidAddress(roomIdPtr) || Memory::IsValidAddress(withPasswordPtr) || !Memory::IsValidAddress(roomPasswordPtr))
		return SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT;

	auto roomId = PSPPointer<SceNpMatching2RoomId>::Create(roomIdPtr);
	auto withPassword = PSPPointer<u8>::Create(withPasswordPtr);
	auto roomPassword = PSPPointer<SceNpMatching2SessionPassword>::Create(roomPasswordPtr);

	// get Password from cache
	bool cache_withPassword = false;
	auto cache_Password = new SceNpMatching2SessionPassword();

	if (cache_withPassword) {
		withPassword = true;
		Memory::Memcpy(roomPassword.ptr, &*cache_Password, sizeof(SceNpMatching2SessionPassword));
	}
	else {
		withPassword = false;
	}

	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Sends a Room Message to relevant players?
 * @param reqParamPtr PSPPointer<SceNpMatching2SendRoomMessageRequest> Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Sends the message to the NPAgent, and receives a reply via Notification
 * @note PSP2i doesn't provide a callback, they should be optional
 */
static int sceNpMatching2SendRoomMessage(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	auto req = PSPPointer<SceNpMatching2SendRoomMessageRequest>::Create(reqParamPtr);

	INFO_LOG(Log::sceNet, " - roomId:     %d", req->roomId);
	INFO_LOG(Log::sceNet, " - castType:   %d", req->castType);
	INFO_LOG(Log::sceNet, " - msgLen:     %d", req->msgLen);

	auto roomData = npServer->cache.GetRoom(req->roomId);
	if (!roomData)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM, "Room doesn't exist"), 0);

	int ret = npServer->SendRoomMessage(ctxId, request_id, req);

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2GrantRoomOwner(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner, SCE_NP_MATCHING2_OKAY, 0);
}

static int sceNpMatching2GetRoomMemberIdListLocal(int ctxId, u32 roomId, u32 sortMethod, u32 memberId, u32 memberIdNum)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, sortMethod, memberId, memberIdNum, currentMIPS->pc);

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2SetRoomMemberDataInternal(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_OKAY, "UNIMPLEMENTED"), 0);
}

static int sceNpMatching2GetRoomMemberDataInternalLocal(int ctxId, u32 roomId, u32 memberId, u32 attrId, u32 attrIdNum, u32 memberPtr, u32 bufPtr, u32 bufLen)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x, %08x, %08x, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, memberId, attrId, attrIdNum, memberPtr, bufPtr, bufLen, currentMIPS->pc);

	return SCE_NP_MATCHING2_OKAY;
}

static int sceNpMatching2GetRoomMemberDataInternal(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_OKAY, "UNIMPLEMENTED"), 0);
}

static int sceNpMatching2GetRoomMemberDataExternalList(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_OKAY, "UNIMPLEMENTED"), 0);
}

static int sceNpMatching2KickoutRoomMember(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_KickoutRoomMember, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	if (ctx.find(ctxId) == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_KickoutRoomMember, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_KickoutRoomMember, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_KickoutRoomMember, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_KickoutRoomMember, hleLogError(Log::sceNet, SCE_NP_MATCHING2_OKAY, "UNIMPLEMENTED"), 0);
}






const HLEFunction sceNpMatching2[] = {
	{0xF47342FC, &WrapI_IUU<sceNpMatching2GetServerIdListLocal>,			"sceNpMatching2GetServerIdListLocal",			'i', "ixx"    },
	{0x4EE3A8EC, &WrapI_IUUU<sceNpMatching2GetServerInfo>,					"sceNpMatching2GetServerInfo",					'i', "ixxx"   },
	{0xA53E7C69, &WrapI_IUUU<sceNpMatching2GetWorldInfoList>,				"sceNpMatching2GetWorldInfoList",				'i', "ixxx"   },
	{0x631682CC, &WrapI_IU<sceNpMatching2SetDefaultRequestOptParam>,		"sceNpMatching2SetDefaultRequestOptParam",		'i', "ix"     },
	{0x22F38DAF, &WrapI_U<sceNpMatching2GetMemoryStat>,						"sceNpMatching2GetMemoryStat",					'i', "x"      },
	{0x7D1D5F5E, &WrapI_IUUU<sceNpMatching2SetUserInfo>,					"sceNpMatching2SetUserInfo",					'i', "ixxx"   },
	{0xC8FC5D41, &WrapI_IUUU<sceNpMatching2GetUserInfoList>,				"sceNpMatching2GetUserInfoList",				'i', "ixxx"   },
	{0xFADBA9DB, &WrapI_IU<sceNpMatching2AbortRequest>,						"sceNpMatching2AbortRequest",					'i', "ix"     },

	{0xA3C298D1, &WrapI_IUU<sceNpMatching2RegisterSignalingCallback>,		"sceNpMatching2RegisterSignalingCallback",		'i', "ixx"    },
	{0x9A67F5D0, &WrapI_IUUU<sceNpMatching2SetSignalingOptParam>,			"sceNpMatching2SetSignalingOptParam",			'i', "ixxx"   },
	{0xC7E72EC5, &WrapI_IUU<sceNpMatching2GetSignalingOptParamLocal>,		"sceNpMatching2GetSignalingOptParamLocal",		'i', "ixx"    },
	{0xFF32EA05, &WrapI_U<sceNpMatching2SignalingGetLocalNetInfo>,			"sceNpMatching2SignalingGetLocalNetInfo",		'i', "x"      },
	{0x8CD109E7, &WrapI_IUUU<sceNpMatching2SignalingGetPeerNetInfo>,		"sceNpMatching2SignalingGetPeerNetInfo",		'i', "ixxx"   },
	{0xDFEDB642, &WrapI_IUU<sceNpMatching2SignalingGetPeerNetInfoResult>,	"sceNpMatching2SignalingGetPeerNetInfoResult",	'i', "ixx"    },
	{0x9462C05A, &WrapI_IU<sceNpMatching2SignalingCancelPeerNetInfo>,		"sceNpMatching2SignalingCancelPeerNetInfo",		'i', "ix"     },
	{0x3892E9A6, &WrapI_IUUUU<sceNpMatching2SignalingGetConnectionInfo>,	"sceNpMatching2SignalingGetConnectionInfo",		'i', "ixxxx"  },
	{0x6D6D0C75, &WrapI_IUUUUUUU<sceNpMatching2SignalingGetConnectionStatus>,	"sceNpMatching2SignalingGetConnectionStatus",	'i', "ixxxxxxx" },

	{0x2E61F6E1, &WrapI_IIII<sceNpMatching2Init>,							"sceNpMatching2Init",							'i', "iiii"   },
	{0x8BF37D8C, &WrapI_V<sceNpMatching2Term>,								"sceNpMatching2Term",							'i', ""       },
	{0x5030CC53, &WrapI_UUUS<sceNpMatching2CreateContext>,					"sceNpMatching2CreateContext",					'i', "xxxx"   },
	{0x3DE70241, &WrapI_I<sceNpMatching2DestroyContext>,					"sceNpMatching2DestroyContext",					'i', "i"      },
	{0x190FF903, &WrapI_I<sceNpMatching2ContextStart>,						"sceNpMatching2ContextStart",					'i', "i"      },
	{0x2B3892FC, &WrapI_I<sceNpMatching2ContextStop>,						"sceNpMatching2ContextStop",					'i', "i"      },

	{0x1421514B, nullptr,													"sceNpMatching2SetDefaultRoomEventOptParam",	'i', ""       },
	{0xD13491AB, nullptr,													"sceNpMatching2SetDefaultRoomMessageOptParam",	'i', ""       },
	{0xE6C93DBD, &WrapI_IUUU<sceNpMatching2SetRoomDataInternal>,			"sceNpMatching2SetRoomDataInternal",			'i', "ixxx"   },
	{0xE313E586, &WrapI_IUUU<sceNpMatching2GetRoomDataInternal>,			"sceNpMatching2GetRoomDataInternal",			'i', "ixxx"   },
	{0xEF683F4F, nullptr,													"sceNpMatching2GetRoomDataInternalLocal",		'i', ""       },
	{0xD7D4AEB2, &WrapI_IUUU<sceNpMatching2SetRoomDataExternal>,			"sceNpMatching2SetRoomDataExternal",			'i', "ixxx"   },
	{0x12C5A111, &WrapI_IUUU<sceNpMatching2GetRoomDataExternalList>,		"sceNpMatching2GetRoomDataExternalList",		'i', "ixxx"   },
	{0xF739BE92, &WrapI_IUUU<sceNpMatching2GetRoomPasswordLocal>,			"sceNpMatching2GetRoomPasswordLocal",			'i', "ixxx"   },

	{0xAAD0946A, &WrapI_IUUUUU<sceNpMatching2CreateJoinRoom>,				"sceNpMatching2CreateJoinRoom",					'i', "ixxxxx" },
	{0x7BBFC427, &WrapI_IUUUUU<sceNpMatching2JoinRoom>,						"sceNpMatching2JoinRoom",						'i', "ixxxxx" },
	{0xC870535A, &WrapI_IUUU<sceNpMatching2LeaveRoom>,						"sceNpMatching2LeaveRoom",						'i', "ixxx"   },
	{0x81C13E6D, &WrapI_IUUU<sceNpMatching2SearchRoom>,						"sceNpMatching2SearchRoom",						'i', "ixxx"   },
	{0xF940D9AD, &WrapI_IUUU<sceNpMatching2SendRoomMessage>,				"sceNpMatching2SendRoomMessage",				'i', "ixxx"   },
	{0x55F7837F, &WrapI_IUUU<sceNpMatching2SendRoomChatMessage>,			"sceNpMatching2SendRoomChatMessage",			'i', "ixxx"   },
	{0x495E97BD, &WrapI_IUUU<sceNpMatching2GrantRoomOwner>,					"sceNpMatching2GrantRoomOwner",					'i', "ixxx"   },

	{0x80F61558, &WrapI_IUUUU<sceNpMatching2GetRoomMemberIdListLocal>,		"sceNpMatching2GetRoomMemberIdListLocal",		'i', "ixxxx"  },
	{0x7DAA8A90, &WrapI_IUUU<sceNpMatching2SetRoomMemberDataInternal>,		"sceNpMatching2SetRoomMemberDataInternal",		'i', "ixxx"   },
	{0xF22C7ADC, &WrapI_IUUUUUUU<sceNpMatching2GetRoomMemberDataInternalLocal>,	"sceNpMatching2GetRoomMemberDataInternalLocal",	'i', "ixxxxxxx"   },
	{0xA5775DBF, &WrapI_IUUU<sceNpMatching2GetRoomMemberDataInternal>,		"sceNpMatching2GetRoomMemberDataInternal",		'i', "ixxx"   },
	{0x5C7DB6A4, nullptr,													"sceNpMatching2GetRoomMemberDataInternalList",	'i', ""       },
	{0xFBF494C0, &WrapI_IUUU<sceNpMatching2GetRoomMemberDataExternalList>,	"sceNpMatching2GetRoomMemberDataExternalList",	'i', "ixxx"   },
	{0x97529ECC, &WrapI_IUUU<sceNpMatching2KickoutRoomMember>,				"sceNpMatching2KickoutRoomMember",				'i', "ixxx"   },
	// Fake function for PPSSPP's use.
	{0X756E6F1C, &WrapV_V<__Np2SignalingGetRPCNResponses>,					"__Np2SignalingGetRPCNResponses",					'v', ""		  },
	{0X756E6F28, &WrapV_V<__Np2SignalingGetP2PResponses>,					"__Np2SignalingGetP2PResponses",					'v', ""		  },
};

void Register_sceNpMatching2()
{
	RegisterHLEModule("sceNpMatching2", ARRAY_SIZE(sceNpMatching2), sceNpMatching2);
}
