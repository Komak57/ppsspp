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

// Definitions:
// Internal - Data scoped to members in the session
// External - Data accessible by all
// Local - Cached Data

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
#include <Core/Util/PortManager.h>
//#include "NpMatchingContext.h"
//#include "Np2SignalingHandler.h"

bool npMatching2Inited = false;
std::recursive_mutex npMatching2EvtMtx;
SceNpAuthMemoryStat npMatching2MemStat = {};
u32 npPoolAddr = 0;
BlockAllocator np_memory;

std::map<SceNpMatching2ContextId, std::unique_ptr<NpMatching2Context>> ctx;
std::deque<NpMatching2Args> npMatching2Events;
std::map<SceNpMatching2RequestId, NpMatching2Handler> npMatching2Handlers;
std::map<SceNpMatching2EventType, NpMatching2Handler> defaultOptParams;
std::atomic<u16> match2_event_cnt = 1;
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

/*
* This function is added as a placeholder for FakePSN Savestates to
*   handle RPCN IP/Port information for the client
*/
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

/*
* This function is added as a placeholder for FakePSN Savestates to
*   handle P2P communications, fake or otherwise
*/
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

/* We register the HLE Loop functions when initializing the emulator here.
*    This is safe enough, as the functions are small, clean, and do not auto-start
*    But, these should be registered when the module is loaded instead.
*/ 
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

/* 
*   Signaling is made of 3 parts. This is Part 1, which handles the STUN based public/local IP information
*/
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

/*
*   Signaling is made of 3 parts. This is Part 2, which handles the Internal P2P connections.
*   Part 3 is System P2P communications, and is officially on SCE_SIGN_PORT 3658.
*   TODO: Intercept communications on port 3658, handle as RPCN or InternalP2P, and
*       pass all unmatched packets to System.
*   Reason: We're forced to man-handle the port numbers. This can require the use of
*       Port Forwarding to function as intended, but so far has not.
*/
void __Np2SignalingGetP2PResponses()
{
	hleSkipDeadbeef();

	int newState = SCE_NP_MATCHING2_STATE_NONE;
	int delayus = 1000000;
	if (npMatching2Inited) {
		newState = SCE_NP_MATCHING2_STATE_INIT;
		//g_signaling.get_wait_time_ns();
		delayus = g_signaling.HandleP2PResponses().count();
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
 * @note Request ID's can never be recycled, or the game can interpret it as already handled
 * @note Request ID of 0 is handled as an aborted request
 * @note app_req should be overwritten whenever supplied
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

/* Temporary Context Grabber
*  - Functions that need this should probably use the relavant System Call
*/ 
std::optional<std::map<SceNpMatching2ContextId, std::unique_ptr<NpMatching2Context>>::iterator> GetDefaultContext(SceNpMatching2EventType event_type) {
	auto def = defaultOptParams.find(event_type);
	if (def == defaultOptParams.end()) {
		ERROR_LOG(Log::sceNet, "Default event handler not Found");
		return std::nullopt;
	}
	auto _context = ctx.find(def->second.ctx_id);
	if (_context == ctx.end()) {
		ERROR_LOG(Log::sceNet, "Matching Context not Found for Event");
		return std::nullopt;
	}
	return _context;
}

/* Generate a request_id based callback handler for async processing returns
 * @param optParam Contains Callback / Args to be supplied to matching notifications
 * @param assignedReqIdPtr Default Request_Id used when registration errors
 * @param event_type PS3Matching2RequestEvent Event
 * @return u32 System Generated RequestID
 * @note This WILL advance the request_id if it doesn't fail
 */
SceNpMatching2RequestId RegisterNpMatching2Handler(SceNpMatching2ContextId ctxId, SceNpMatching2RequestOptParam optParam, u32 assignedReqId, SceNpMatching2EventType event_type) {
	NOTICE_LOG(Log::sceNet, "%s(ctx: %d, cb: %08x, cb_args: %08x, event_type: %d) at %08x", __FUNCTION__, ctxId, optParam.cbFunc.ptr, optParam.cbFuncArg.ptr, event_type, currentMIPS->pc);

	// If empty callback, check for a default callback of the same type
	if (!Memory::IsValidAddress(optParam.cbFunc.ptr)) {
		return RegisterNpMatching2DefaultHandler(ctxId, assignedReqId, event_type);
	}

	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);
	SceNpMatching2RequestId req_id = GenerateRequestId(ctxId, assignedReqId);

	//if (!Memory::IsValidAddress(optParam.cbFunc.ptr)) {
	//	req_id = 0; // PSP2i crashes if this isn't set to abort
	//}
	NpMatching2Handler handler{};

	handler.ctx_id = ctxId; // double handle
	handler.cb.ptr = optParam.cbFunc.ptr;
	handler.cb_arg.ptr = optParam.cbFuncArg.ptr;
	handler.event_type = event_type;


	// 0 defines an Aborted Request
	npMatching2Handlers[req_id] = handler;
	NOTICE_LOG(Log::sceNet, "%s(count: %d) - Added Callback FUN_%08x(%d, %d, %08x) for %s", __FUNCTION__, npMatching2Handlers.size(), handler.cb.ptr, ctxId, req_id, handler.cb_arg.ptr, EventToString(event_type).c_str());

	return req_id;
}

/* Generate a default request_id based callback handler for async processing returns
 * @param ctxId Replaced with the defaultOptParam's context id
 * @param assignedReqId Default ID to return if the request fails
 * @param event_type PS3Matching2RequestEvent Event
 * @return u32 System RequestID
 * @note This WILL advance the request_id if it doesn't fail
 */
SceNpMatching2RequestId RegisterNpMatching2DefaultHandler(SceNpMatching2ContextId& ctxId, SceNpMatching2RequestId assignedReqId, SceNpMatching2EventType event_type) {
	// Check if defaultOptParams contains this eventType
	auto it = defaultOptParams.find(event_type);
	if (it == defaultOptParams.end()) {
		WARN_LOG(Log::sceNet, "%s - No Default Callback for %s(%d, %d)", __FUNCTION__, EventToString(event_type).c_str(), ctxId, assignedReqId);
		return assignedReqId;
	}
	if (!Memory::IsValidAddress(it->second.cb.ptr)) {
		WARN_LOG(Log::sceNet, "%s - Invalid Default Callback for %s(%d, %d)", __FUNCTION__, EventToString(event_type).c_str(), ctxId, assignedReqId);
		return assignedReqId;
	}
	WARN_LOG(Log::sceNet, "%s - Using Default Opt Params", __FUNCTION__);

	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	//if (!Memory::IsValidAddress(optParam.cbFunc.ptr)) {
	//	req_id = 0; // PSP2i crashes if this isn't set to abort
	//}
	NpMatching2Handler handler = it->second;
	ctxId = it->second.ctx_id;
	// Match ctxId to the default handler's context
	SceNpMatching2RequestId req_id = GenerateRequestId(ctxId, assignedReqId);

	// 0 defines an Aborted Request
	npMatching2Handlers[req_id] = handler;
	NOTICE_LOG(Log::sceNet, "%s(count: %d) - Added Callback FUN_%08x(%d, %d, %08x) for %s", __FUNCTION__, npMatching2Handlers.size(), handler.cb, ctxId, req_id, handler.cb_arg, EventToString(event_type).c_str());

	return req_id;
}

/* Thread-safe Event Processor for System Requests. Relevant arguments will be replaced.
 * @param ctxId Relevant Context to notify
 * @param reqId Matching Request ID
 * @param event u16 value to notify the system what event occurred
 * @param errorCode u32 value indicating what errors occurred
 * @param dataPtr u32 pointer to the data struct we pass back to the system
 * @note If there are any problems writing to np_memory, it may be prudent to run a thread-sanitized environment instead
 * @note errorCode 0 or SCE_NP_MATCHING2_OKAY is a clean request
 */
int notifyRequestHandler(SceNpMatching2ContextId ctxId, SceNpMatching2RequestId reqId, SceNpMatching2Event event, s32 errorCode, u32 dataPtr) {
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	NpMatching2Handler* handler = nullptr;
	// Check for registered handler
	if (auto it = npMatching2Handlers.find(reqId); it != npMatching2Handlers.end()) {
		//handler = &it->second;
		handler = new NpMatching2Handler(std::move(it->second));
		npMatching2Handlers.erase(it);
	}
	else
	{
		// Check for default handler
		if (auto def = defaultOptParams.find(SCE_NP_MATCHING2_REQUEST_EVENT); def != defaultOptParams.end())
			handler = &def->second;
	}

	
	u32 args[6];
	args[0] = ctxId;	// ContextID
	args[1] = reqId;	// RequestId || 0 indicates aborted request
	args[2] = event;	// Event
	args[3] = errorCode;// ErrorCode || 0 is OK
	args[4] = dataPtr;	// Response struct
	args[5] = 0;		// Request Arguments

	// Consume if the event handler has no callback
	if (handler == nullptr) {
		NOTICE_LOG(Log::sceNet, "notifyRequestHandler - Destroying %s_EMPTY(ctxId: %d, reqId: %d, event: 0x%08x, error: 0x%08x, dataPtr: 0x%08x, cbArgPtr: 0x%08x)", EventToString(SCE_NP_MATCHING2_REQUEST_EVENT).c_str(),
			ctxId, args[1], args[2], args[3], args[4], args[5]);
		return 0;
	}
	args[0] = handler->ctx_id;
	args[5] = handler->cb_arg.ptr;
	npMatching2Events.push_back(NpMatching2Args(*handler, reqId, 6, args, SCE_NP_MATCHING2_REQUEST_EVENT));

	NOTICE_LOG(Log::sceNet, "notifyRequestHandler - %s_%08x(ctxId: %d, reqId: %d, event: 0x%08x, error: 0x%08x, dataPtr: 0x%08x, cbArgPtr: 0x%08x)", EventToString(SCE_NP_MATCHING2_REQUEST_EVENT).c_str(), handler->cb.ptr,
		args[0], args[1], args[2], args[3], args[4], args[5]);
	return 0;
}

/* Thread-safe Event Processor for Room Messages. Incomplete, but functional.
 * @param roomId What room the notification triggered for
 * @param memberId The relevant source, or target of the event
 * @param event u16 value to notify the system what event occurred
 * @param dataPtr u32 pointer to the data struct we pass back to the system
 * @note If there are any problems writing to np_memory, it may be prudent to run a thread-sanitized environment instead
 */
int notifyRoomMessageHandler(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId, u32 conn_id, RPCNMatching2RequestEvent requestEvent, u32 dataPtr) {
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	NpMatching2Handler* handler = nullptr;

	// Check for default handler
	if (auto def = defaultOptParams.find(SCE_NP_MATCHING2_ROOM_MSG_EVENT); def != defaultOptParams.end())
		handler = &def->second;

	u32 args[8];
	args[0] = 0;		// ContextID
	args[1] = roomId;	// RoomID
	args[2] = conn_id;	// ConnId? Ignored by PSP2i
	args[3] = 0;		// param_4? Ingored by PSP2i
	args[4] = memberId;	// MemberID
	args[5] = requestEvent;// Event [SCE_NP_MATCHING2_ROOM_MSG_EVENT_ChatMessage / SCE_NP_MATCHING2_ROOM_MSG_EVENT_Message]
	args[6] = dataPtr;	// Message
	args[7] = 0;		// Request Arguments

	// Consume if the event handler has no callback
	if (handler == nullptr) {
		NOTICE_LOG(Log::sceNet, "notifyRoomMessageHandler - Destroying %s_EMPTY(ctxId: %d, roomId: %d, memberId: %d, dataPtr: %08x, cbArgPtr: %08x)", EventToString(SCE_NP_MATCHING2_ROOM_MSG_EVENT).c_str(),
			args[0], args[1], args[2], args[6], 0);
		return 0;
	}
	args[0] = handler->ctx_id;
	args[7] = handler->cb_arg.ptr;

	npMatching2Events.push_back(NpMatching2Args(*handler, 8, args, SCE_NP_MATCHING2_ROOM_MSG_EVENT));

	NOTICE_LOG(Log::sceNet, "notifyRoomMessageHandler - %s_%08x(ctxId: %d, roomId: %d, memberId: %d, param_4: %d, param_5: %d, dataPtr: %08x, cbArgPtr: %08x)", EventToString(SCE_NP_MATCHING2_ROOM_MSG_EVENT).c_str(), handler->cb.ptr,
		args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
	return 0;
}

/* Thread-safe Event Processor for Room Events. Incomplete, but functional.
 * @param roomId What room the notification triggered for
 * @param memberId The relevant source, or target of the event
 * @param event u16 value to notify the system what event occurred
 * @param dataPtr u32 pointer to the data struct we pass back to the system
 * @note If there are any problems writing to np_memory, it may be prudent to run a thread-sanitized environment instead
 * @note This function seems to return a ConnectionID. This is optional, and replaces the requirement of room/member
 */
int notifyRoomEventHandler(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId, u32 conn_id, SceNpMatching2Event event, u32 dataPtr) {
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	NpMatching2Handler* handler = nullptr;

	// Check for default handler
	if (auto def = defaultOptParams.find(SCE_NP_MATCHING2_ROOM_EVENT); def != defaultOptParams.end())
		handler = &def->second;

	u32 args[7];
	args[0] = 0;	// ContextID
	args[1] = roomId;	// RoomID
	args[2] = conn_id;  // ConnectionID?
	args[3] = memberId;	// MemberID?
	args[4] = event;	// Event
	args[5] = dataPtr;	// ErrorCode
	args[6] = 0;		// Request Arguments

	// Consume if the event handler has no callback
	if (handler == nullptr) {
		NOTICE_LOG(Log::sceNet, "notifyRoomEventHandler - Destroying %s_EMPTY(ctxId: %d, roomId: %d, memberId: %d, dataPtr: %08x, cbArgPtr: %08x)", EventToString(SCE_NP_MATCHING2_ROOM_EVENT).c_str(),
			args[0], args[1], args[3], args[4], 0);
		return 0;
	}

	args[0] = handler->ctx_id;
	args[6] = handler->cb_arg.ptr;

	npMatching2Events.push_back(NpMatching2Args(*handler, 7, args, SCE_NP_MATCHING2_ROOM_EVENT));

	NOTICE_LOG(Log::sceNet, "notifyRoomEventHandler - %s_%08x(ctxId: %d, roomId: %d, param_3: %d, memberId: %d, event: %d, dataPtr: %08x, cbArgPtr: %08x)", EventToString(SCE_NP_MATCHING2_ROOM_EVENT).c_str(), handler->cb.ptr,
		args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
	return 0;
}

/* Thread-safe Event Processor for Room Events. Incomplete, but functional.
 * @param roomId What room the notification triggered for
 * @param conn_id A key matching a room/member combination, usually ignored or set to 0 
 * @param memberId The relevant source, or target of the event
 * @param event u16 value to notify the system what event occurred
 * @param errorCode u32 value indicating what system error occurred
 * @note If there are any problems writing to np_memory, it may be prudent to run a thread-sanitized environment instead
 * @note This function seems to return a ConnectionID. This is optional, and replaces the requirement of room/member
 */
int notifySignalingHandler(SceNpMatching2RoomId room_id, SceNpMatching2RoomMemberId memberId, u32 conn_id, u32 conn_state, SceNpMatching2Event event, s32 errorCode) {
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	NpMatching2Handler* handler = nullptr;

	// Check for default handler
	if (auto def = defaultOptParams.find(SCE_NP_MATCHING2_SIGNALING_EVENT); def != defaultOptParams.end())
		handler = &def->second;

	// FIXME: Need confirmation on arguments for conn_id, room_id
	u32 args[8];
	args[0] = 0;		// ContextID
	args[1] = room_id;		// room_id?
	args[2] = conn_id;		// conn_id?
	args[3] = conn_state;	// unknown?
	args[4] = memberId;		// roomMemberId
	args[5] = event;		// EventCode
	args[6] = errorCode;	// ErrorCode
	args[7] = 0;			// cbArgs

	// Consume if the event handler has no callback
	if (handler == nullptr) {
		NOTICE_LOG(Log::sceNet, "notifySignalingHandler - Destroying %s_EMPTY(ctxId: %d, roomId: %d, connId: %d, connState: %d, memberId: %d, event: 0x%04x, errorCode: 0x%08x, cbArgPtr: 0x%08x)", EventToString(SCE_NP_MATCHING2_SIGNALING_EVENT).c_str(),
			args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
		return 0;
	}

	args[0] = handler->ctx_id;
	args[7] = handler->cb_arg.ptr;

	npMatching2Events.push_back(NpMatching2Args(*handler, 8, args, SCE_NP_MATCHING2_SIGNALING_EVENT));

	NOTICE_LOG(Log::sceNet, "notifySignalingHandler - %s_%08x(ctxId: %d, roomId: %d, connId: %d, connState: %d, memberId: %d, event: 0x%04x, errorCode: 0x%08x, cbArgPtr: 0x%08x)", EventToString(SCE_NP_MATCHING2_SIGNALING_EVENT).c_str(), handler->cb.ptr,
		args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);

	return 0;
}

/* Event Processor
 * @note There is some complex logging in here, but it just validates the callback address and executes
 * @note This is triggered from sceNet
 */
bool NpMatching2ProcessEvents() {
	if (npMatching2Events.empty()) {
		return false;
	}

	// Consume latest event
	auto& event = npMatching2Events.front();
	npMatching2Events.pop_front();


	if (!Memory::IsValidAddress(event.handler.cb.ptr)) {
		WARN_LOG(Log::sceNet, "NpMatching2ProcessEvents - Nothing to Callback to for %s", EventToString(event.event_type).c_str());
		return false;
	}
	switch (event.handler.event_type) {
		// combine the callback parameters with the request based on the event type
	case SCE_NP_MATCHING2_REQUEST_EVENT:
		NOTICE_LOG(Log::sceNet, "SceNpMatching2RequestCallback - %s_%08x(ctxId: %d, reqId: %d, event: %d, error: %08x, dataPtr: %08x, cbArgPtr: %08x)", EventToString(event.event_type).c_str(), event.handler.cb.ptr,
			event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5]);
		break;
	case SCE_NP_MATCHING2_ROOM_EVENT:
		NOTICE_LOG(Log::sceNet, "SceNpMatching2RoomEventCallback - %s_%08x(ctxId: %d, roomId: %d, connId?: %08x, memberId: %d, requestEvent: %08x, dataPtr: %08x, argPtr: %08x)", EventToString(event.event_type).c_str(), event.handler.cb.ptr,
			event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5], event.args[6]);
		break;
	case SCE_NP_MATCHING2_ROOM_MSG_EVENT:
		NOTICE_LOG(Log::sceNet, "SceNpMatching2RoomMessageCallback - %s_%08x(ctxId: %d, roomId: %d, memberId: %d, param_4: %d, param_5: %d, event: %d, dataPtr: %08x, argPtr: %08x)", EventToString(event.event_type).c_str(), event.handler.cb.ptr,
			event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5], event.args[6], event.args[7]);
		break;
	case SCE_NP_MATCHING2_LOBBY_EVENT:
		ERROR_LOG(Log::sceNet, "UNIMPLEMENTED SceNpMatching2LobbyEventCallback - %s_%08x(ctxId: %d)", EventToString(event.event_type).c_str(), event.handler.cb.ptr, event.args[0]);
		return false;
	case SCE_NP_MATCHING2_LOBBY_MSG_EVENT:
		ERROR_LOG(Log::sceNet, "UNIMPLEMENTED SceNpMatching2LobbyMessageCallback - %s_%08x(ctxId: %d)", EventToString(event.event_type).c_str(), event.handler.cb.ptr, event.args[0]);
		return false;
	case SCE_NP_MATCHING2_SIGNALING_EVENT:
		NOTICE_LOG(Log::sceNet, "SceNpMatching2SignalingCallback - %s_%08x(param_1: %d, param_2: %d, param_3: %d, param_4: %d, param_5: %d, param_6: %d, param_7: %d, param_8: %08x)", EventToString(event.event_type).c_str(), event.handler.cb.ptr,
			event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5], event.args[6], event.args[7]);
		break;
	default:
		NOTICE_LOG(Log::sceNet, "UNHANDLED Callback Type %d - FUN_%08x(ctxId: %d)", event.event_type, event.handler.cb.ptr, event.args[0]);
		_dbg_assert_(false);
		return false;
	}
	//DEBUG_LOG(Log::sceNet, "NpMatching2Callback [HandlerID=%i][EventID=%04x][State=%04x][ArgsPtr=%08x]", it->first, event, stat, event.handler.argument);
	if (Memory::IsValidAddress(event.handler.cb.ptr))
		hleEnqueueCall(event.handler.cb.ptr, event.argc, event.args);
	return true;
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

/* Initialization
 * @note This is triggered when any game requires the functions from NpMatching2
 */
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

	// We can't sign into the RPCN NPAgent if the AuthAgent is still connected
	if (npAuthServer->GetAuthType() == net::NPAgentType::RPCN && npAuthServer && npAuthServer->IsConnected())
		npAuthServer->Disconnect();

	npServer = npAuthServer->CreateAgent();

	// We only sign-in here if we're on RPCN
	if (npAuthServer->GetAuthType() == net::NPAgentType::PSN)
		return SCE_NP_MATCHING2_OKAY;

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
	if (ret != SCE_NP_MATCHING2_OKAY)
		return hleLogError(Log::sceNet, ret);

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

/* Initialization
 * @note This is triggered when any game no longer requires this module or it's functions
 */
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

/* Create Context
 * @param communicationIdPtr Pointer to a SceNpCommunicationId containing the PSN Title and Number
 * @param passPhrasePtr Some crypto key used for communicating with the NP Matching Servers?
 * @param ctxIdPtr A pointer containing the Unique Context ID generated by this request
 * @param optionFlags Flags indicating if the OnlineName or Avatar are used by the game
 * @note Some hints suggest this usually only supports 1-7 contexts at a time, but most games only request 1 context
 */
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

	// It seems ctxId need to be in the range of 1 to 7 to be valid ?
	SceNpMatching2ContextId ctxId = 1;
	for (ctxId = 1; ctxId <= CONTEXT_MAX_ID; ctxId++) {
		if (ctx.find(ctxId) != ctx.end())
			continue;
		ctx.emplace(ctxId, std::make_unique<NpMatching2Context>(*titleid, *passph, optionFlags));

		INFO_LOG(Log::sceNet, "%s - Context ID: %d", __FUNCTION__, ctxId);
		INFO_LOG(Log::sceNet, "%s - Title ID: %s", __FUNCTION__, npTitleId.data);
		INFO_LOG(Log::sceNet, "%s - Title NUM: %d", __FUNCTION__, npTitleId.num);
		//INFO_LOG(Log::sceNet, "%s - Online ID: %s", __FUNCTION__, npid->handle.data);
		INFO_LOG(Log::sceNet, "%s - User ID: %d", __FUNCTION__, user_id.load());
		INFO_LOG(Log::sceNet, "%s - Login ID: %s", __FUNCTION__, g_Config.sInfraNpId.c_str());
		INFO_LOG(Log::sceNet, "%s - Use Online ID: %s", __FUNCTION__, (ctx[ctxId]->include_onlinename ? "YES" : "NO"));
		INFO_LOG(Log::sceNet, "%s - Online ID: %s", __FUNCTION__, online_name);
		INFO_LOG(Log::sceNet, "%s - Use Avatar: %s", __FUNCTION__, (ctx[ctxId]->include_avatarurl ? "YES" : "NO"));
		INFO_LOG(Log::sceNet, "%s - Avatar URL: %s", __FUNCTION__, avatar_url.data);
		std::string datahex;
		/*DataToHexString(npid->opt, sizeof(npid->opt), &datahex);
		INFO_LOG(Log::sceNet, "%s - Options?: %s", __FUNCTION__, datahex.c_str());
		datahex.clear();*/
		DataToHexString(10, 0, passph->data, sizeof(passph->data), &datahex);
		INFO_LOG(Log::sceNet, "%s - Passphrase: \n%s", __FUNCTION__, datahex.c_str());

		Memory::Write_U16(ctxId, ctxIdPtr);
		// TODO: Allocate & zeroed a memory of 68 bytes where npId (36 bytes) is copied to offset 8, offset 44 = 0x00026808, offset 48 = 0
		return SCE_NP_MATCHING2_OKAY;
	}

	return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_MAX, "Max Contexts Reached");
}

/* Start Context
 * @param ctxId Related Context to start
 * @note Some hints suggest the PSP caches the server list here
 */
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

	// PSN Calls this from a static URL, RPCN needs to be logged in
	if (!npAuthServer && !npServer)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE);

	int ret = SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE;
	if (npAuthServer->GetAuthType() == net::NPAgentType::PSN || (npAuthServer->GetAuthType() == net::NPAgentType::RPCN && npServer->IsConnected()))
		ret = npServer->GetServers(npTitleId);

	//hleEatMicro(1000000);
	// Returning 0x805508A6 (error code inherited from sceNpService_76867C01 which check server availability) if can't check server availability (ie. Fat Princess (US) through http://static-resource.np.community.playstation.net/np/resource/psp-title/NPWR00670_00/matching/NPWR00670_00-matching.xml using User-Agent: "PS3Community-agent/1.0.0 libhttp/1.0.0")
	if (ret != 0)
		return hleLogError(Log::sceNet, ret, "Unable to retrieve Server list");
	return SCE_NP_MATCHING2_OKAY;
}

/* Stop Context
 * @param ctxId Related Context to stop
 */
static int sceNpMatching2ContextStop(int ctxId)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d) at %08x", __FUNCTION__, ctxId, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

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

/* Destroy Context
 * @param ctxId Related Context to destroy
 * @note The context is still technically valid until this is called
 */
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

	return hleLogWarning(Log::sceNet, SCE_NP_MATCHING2_OKAY);
}

/* Register Signaling Callback
 * @param ctxId Related Context that signaling should run on
 * @param cbFuncPtr a u32 pointer to the address the game uses to handle the response
 * @param cbArgsPtr a u32 pointer to the global struct the game uses in memory
 * @note This should register and start the SignalingHandler
 */
static int sceNpMatching2RegisterSignalingCallback(int ctxId, u32 cbFuncPtr, u32 cbArgsPtr)
{
	ERROR_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x) at %08x", __FUNCTION__, ctxId, cbFuncPtr, cbArgsPtr, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (cbFuncPtr == 0 || !Memory::IsValidAddress(cbFuncPtr))
		return hleLogError(Log::sceNet, SCE_NP_ERROR_INVALID_CALLBACK, "%s - Invalid Callback %08x", __FUNCTION__, cbFuncPtr);

	u32 alloc_size = sizeof(SceNpMatching2SignalingOptParam);
	auto signalingOptParam = PSPPointer<SceNpMatching2SignalingOptParam>::Create(np_memory.Alloc(alloc_size));
	signalingOptParam->cbFunc.ptr = cbFuncPtr;
	signalingOptParam->cbFuncArg.ptr = cbArgsPtr;

	hleCall(sceNpMatching2, int, sceNpMatching2SetSignalingOptParam, ctxId, signalingOptParam.ptr);

	// This is normally started 
	if (np2P2PThreadID > 0) {
		__KernelStartThread(np2P2PThreadID, 0, 0);
	}
	// We should probably move most of the signaling calls to SignalingHandler
	// And, you know, rename it to sceNpMatching2Signaling

	return SCE_NP_MATCHING2_OKAY; // error returns 0x80550004
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

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(serverIdsPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	if (!npServer || npServer->servers.size() == 0)
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
 * @param optParamPtr Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Server will respond with relevant information and trigger the related callback
 * @note PSP2i calls this once witha reqId 0, and then once for each server allocated in sceNpMatching2GetServerIdListLocal
 */
static int sceNpMatching2GetServerInfo(int ctxId, u32 serverIdPtr, u32 optParamPtr, u32 assignedReqIdPtr) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x[%d], %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, serverIdPtr, Memory::Read_U16(serverIdPtr), optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
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
	// PSP2i says this is a 16-bit request struct where only the 16-bit server id is allocated
	auto serverReq = PSPPointer<SceNpMatching2GetServerInfoRequest>::Create(serverIdPtr);
	//SceNpMatching2ServerId serverId = Memory::Read_U16(serverIdPtr);

	// Check server status
	//servers[serverId]->Resolve();

	SceNpMatching2ServerInfo serverInfo = npServer->GetServerInfo(serverReq);

	u32 respSize = sizeof(SceNpMatching2GetServerInfoResponse);
	auto serv_info_ptr = np_memory.Alloc(respSize);
	if (serv_info_ptr == 0)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetServerInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY), 0);
	auto serv_info = PSPPointer<SceNpMatching2GetServerInfoResponse>::Create(serv_info_ptr);

	serv_info->server.id = serverInfo.id;
	serv_info->server.status = serverInfo.status;

	NOTICE_LOG(Log::sceNet, " - Server Id: %d", serverInfo.id);
	switch (serverInfo.status) {
	case SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE: NOTICE_LOG(Log::sceNet, " - Server Status: Available"); break;
	case SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE: ERROR_LOG(Log::sceNet, " - Server Status: Unavailable"); break;
	case SCE_NP_MATCHING2_SERVER_STATUS_BUSY: ERROR_LOG(Log::sceNet, " - Server Status: Busy"); break;
	case SCE_NP_MATCHING2_SERVER_STATUS_MAINTENANCE: ERROR_LOG(Log::sceNet, " - Server Status: Maintenance"); break;
	}

	return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetServerInfo, SCE_NP_MATCHING2_OKAY, serv_info.ptr);
}

/* Allocates a list of SceNpMatching2World for information about the lobbies, parties, and existing player counts
 * @param serverIdPtr Pointer to the target Server ID
 * @param optParamPtr Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Server will respond with relevant information and trigger the related callback
 * @note This function occurs immediately after a server has been selected
 */
static int sceNpMatching2GetWorldInfoList(int ctxId, u32 serverIdPtr, u32 optParamPtr, u32 assignedReqIdPtr) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x[%d], %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, serverIdPtr, Memory::Read_U16(serverIdPtr), optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
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

	INFO_LOG(Log::sceNet, " - Selected Server ID %d", serverId);
	auto err = npServer->GetWorldInfo(ctxId, request_id, serverId, npTitleId);

	return SCE_NP_MATCHING2_OKAY;
}

/* Searches for all Lobbies/Parties
 * @param reqParamPtr SceNpMatching2SearchRoomRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note If the room is in an incomplete state, the client may be unable to select it for auto matching
 */
static int sceNpMatching2SearchRoom(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
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
	INFO_HEXLOG(Log::sceNet, "SearchRoom Request: ", reinterpret_cast<const u8*>(&*req), sizeof(SceNpMatching2SearchRoomRequest), 386);

	INFO_LOG(Log::sceNet, " - option:       %d", req->option);
	INFO_LOG(Log::sceNet, " - worldId:      %d", req->worldId);
	INFO_LOG(Log::sceNet, " - lobbyId:      %d", req->lobbyId);
	INFO_LOG(Log::sceNet, " - rangeFilter:  %d", req->rangeFilter);
	INFO_LOG(Log::sceNet, " - flagFilter:   %d", req->flagFilter);
	INFO_LOG(Log::sceNet, " - flagAttr:     %d", req->flagAttr);
	for (int i = 0; i < req->intFilterNum; i++) {
		auto data = req->intFilter + i;

		INFO_LOG(Log::sceNet, " - intFilter[%d]", i);
		INFO_LOG(Log::sceNet, " - - searchOp:     %d", data->searchOperator);
		INFO_LOG(Log::sceNet, " - - attr.id:      %d", data->attr.id);
		INFO_LOG(Log::sceNet, " - - attr.num:     %d", data->attr.num);
	}
	INFO_LOG(Log::sceNet, " - intFilterNum: %d", req->intFilterNum);
	
	for (int i = 0; i < req->binFilterNum; i++) {
		auto data = req->binFilter + i;

		INFO_LOG(Log::sceNet, " - binFilter[%d]", i);
		INFO_LOG(Log::sceNet, " - - searchOp:     %d", data->searchOperator);
		INFO_LOG(Log::sceNet, " - - attr:");
		INFO_LOG(Log::sceNet, " - - - id:         %d", data->attr.id);
		INFO_HEXLOG(Log::sceNet, "- - - binFilter: ", reinterpret_cast<const u8*>(&*data->attr.ptr), data->attr.size, 386);
		INFO_LOG(Log::sceNet, " - - - size:       %d", data->attr.size);
	}
	INFO_LOG(Log::sceNet, " - binFilterNum: %d", req->binFilterNum);
	
	for (int i = 0; i < req->attrIdNum; i++) {
		auto data = Memory::Read_U32(req->attrId.ptr + i * 4);
		INFO_LOG(Log::sceNet, " - attrId[%d]", i);
		INFO_LOG(Log::sceNet, " - - id:         %d", i, data);
	}
	INFO_LOG(Log::sceNet, " - attrIdNum:    %d", req->attrIdNum);

	INFO_LOG(Log::sceNet, "End of Request", req.ptr);

	if (!npServer->cache.Exists(req->worldId)) {
		ERROR_LOG(Log::sceNet, " - Invalid World ID");
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM), 0);
	}

	int ret = npServer->SearchRoom(ctxId, request_id, req);

	return SCE_NP_MATCHING2_OKAY;
}

/* Hosts a Lobby/Party
 * @param reqParamPtr SceNpMatching2CreateJoinRoomRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param roomEventCbPtr Pointer to Callback Address for future Room Events (optional)
 * @param roomMessageCbPtr Pointer to Callback Address for future Room Messages (optional) 
 * @param assignedReqIdPtr Pointer to a pre-specified request id to be overwritten
 * @return 0; System Errors are entirely ignored
 * @note This will officially start self-signaling
 */
static int sceNpMatching2CreateJoinRoom(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 roomEventCbPtr, u32 roomMessageCbPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x, %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, roomEventCbPtr, roomMessageCbPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
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

	if (Memory::IsValidAddress(roomEventCbPtr))
		hleCall(sceNpMatching2, int, sceNpMatching2SetDefaultRoomEventOptParam, ctxId, roomEventCbPtr);

	if (Memory::IsValidAddress(roomMessageCbPtr))
		hleCall(sceNpMatching2, int, sceNpMatching2SetDefaultRoomMessageOptParam, ctxId, roomMessageCbPtr);

	auto req = PSPPointer<SceNpMatching2CreateJoinRoomRequest>::Create(reqParamPtr);
	//Memory::Memcpy(&req, reqParamPtr, sizeof(req));
	auto world_exists = npServer->cache.Exists(req->worldId);
	INFO_LOG(Log::sceNet, "SceNpMatching2CreateJoinRoomRequest(%08X)", req.ptr);
	if (world_exists) {
		INFO_LOG(Log::sceNet, " - worldId:          %d", req->worldId);
	}
	else {
		ERROR_LOG(Log::sceNet, " - worldId:         NONE");
	}
	INFO_LOG(Log::sceNet, " - lobbyId:          %d", req->lobbyId);
	INFO_LOG(Log::sceNet, " - maxSlot:          %d", req->maxSlot);
	INFO_LOG(Log::sceNet, " - flagAttr:         %lx", req->flagAttr);

	for (int i = 0; i < req->roomBinAttrInternalNum; i++) {
		auto data = req->roomBinAttrInternal + i;
		INFO_LOG(Log::sceNet, " - roomBinAttrInternal[%d]:", i);
		INFO_LOG(Log::sceNet, " - - id:         %d", data->id);
		if (data->ptr.IsValid())
			INFO_HEXLOG(Log::sceNet, " - - ptr:", reinterpret_cast<const u8*>(&*data->ptr), sizeof(u8) * data->size, 386);
		else
			INFO_LOG(Log::sceNet, " - - ptr:         0x%08x", 0);
		INFO_LOG(Log::sceNet, " - - size:       %d", data->size);
	}
	INFO_LOG(Log::sceNet, " - roomBinAttrInternalNum:         %d", req->roomBinAttrInternalNum);

	for (int i = 0; i < req->roomSearchableIntAttrExternalNum; i++) {
		auto data = PSPPointer<SceNpMatching2IntAttr>::Create(req->roomSearchableIntAttrExternal.ptr + i * sizeof(SceNpMatching2IntAttr));
		INFO_LOG(Log::sceNet, " - roomSearchableIntAttrExternal[%d]:", i);
		INFO_LOG(Log::sceNet, " - - Id:   %d", data->id);
		INFO_LOG(Log::sceNet, " - - Num:  %04x", data->num);
	}
	INFO_LOG(Log::sceNet, " - roomSearchableIntAttrExternalNum: %d", req->roomSearchableIntAttrExternalNum);

	for (int i = 0; i < req->roomSearchableBinAttrExternalNum; i++) {
		auto data = req->roomSearchableBinAttrExternal + i;
		INFO_LOG(Log::sceNet, " - roomSearchableBinAttrExternal[%d]:", i);
		INFO_LOG(Log::sceNet, " - - id:         %d", data->id);
		if (data->ptr.IsValid())
			INFO_HEXLOG(Log::sceNet, " - - ptr:", reinterpret_cast<const u8*>(&*data->ptr), sizeof(u8) * data->size, 386);
		else
			INFO_LOG(Log::sceNet, " - - ptr:         0x%08x", 0);
		INFO_LOG(Log::sceNet, " - - size:       %d", data->size);
	}
	INFO_LOG(Log::sceNet, " - roomSearchableBinAttrExternalNum: %d", req->roomSearchableBinAttrExternalNum);

	for (int i = 0; i < req->roomBinAttrExternalNum; i++) {
		auto data = req->roomBinAttrExternal + i;
		INFO_LOG(Log::sceNet, " - roomBinAttrExternal[%d]:", i);
		INFO_LOG(Log::sceNet, " - - id:         %d", data->id);
		if (data->ptr.IsValid())
			INFO_HEXLOG(Log::sceNet, " - - ptr:", reinterpret_cast<const u8*>(&*data->ptr), sizeof(u8) * data->size, 386);
		else
			INFO_LOG(Log::sceNet, " - - ptr:         0x%08x", 0);
		INFO_LOG(Log::sceNet, " - - size:       %d", data->size);
	}
	INFO_LOG(Log::sceNet, " - roomBinAttrExternalNum:         %d", req->roomBinAttrExternalNum);

	char* pwd = "EMPTY";
	if (req->roomPassword.IsValid()) {
		npServer->cache.SetPassword(*req->roomPassword);
		pwd = reinterpret_cast<char*>(req->roomPassword->data);
	}
	INFO_LOG(Log::sceNet, " - roomPassword:		'%s'", pwd);

	for (int i = 0; i < req->groupConfigNum; i++) {
		auto data = req->groupConfig + i;
		INFO_HEXLOG(Log::sceNet, "groupConfig: ", reinterpret_cast<const u8*>(&data), sizeof(SceNpMatching2RoomGroupConfig), 386);
	}
	INFO_LOG(Log::sceNet, " - groupConfigNum:   %d", req->groupConfigNum);

	INFO_LOG(Log::sceNet, " - passwordSlotMask: %llx", (req->passwordSlotMask.IsValid() ? *req->passwordSlotMask : 0));

	if (req->joinRoomGroupLabel.IsValid())
		INFO_HEXLOG(Log::sceNet, "joinRoomGroupLabel: ", reinterpret_cast<const u8*>(&*req->joinRoomGroupLabel), sizeof(SceNpMatching2GroupLabel), 386);

	if (req->allowedUser.IsValid())
		INFO_HEXLOG(Log::sceNet, "allowedUser: ", reinterpret_cast<const u8*>(&*req->allowedUser), sizeof(SceNpId) * req->allowedUserNum, 386);
	INFO_LOG(Log::sceNet, " - allowedUserNum:   %d", req->allowedUserNum);

	if (req->blockedUser.IsValid())
		INFO_HEXLOG(Log::sceNet, "blockedUser: ", reinterpret_cast<const u8*>(&*req->blockedUser), sizeof(SceNpId) * req->blockedUserNum, 386);
	INFO_LOG(Log::sceNet, " - blockedUserNum:   %d", req->blockedUserNum);

	for (int i = 0; i < req->roomMemberBinAttrInternalNum; i++) {
		auto data = req->roomMemberBinAttrInternal + i;
		INFO_LOG(Log::sceNet, " - roomMemberBinAttrInternal[%d]:", i);
		INFO_LOG(Log::sceNet, " - - id:         %d", data->id);
		if (data->ptr.IsValid())
			INFO_HEXLOG(Log::sceNet, " - - ptr:", reinterpret_cast<const u8*>(&*data->ptr), sizeof(u8) * data->size, 386);
		else
			INFO_LOG(Log::sceNet, " - - ptr:         0x%08x", 0);
		INFO_LOG(Log::sceNet, " - - size:       %d", data->size);
	}
	INFO_LOG(Log::sceNet, " - roomMemberBinAttrInternalNum:         %d", req->roomMemberBinAttrInternalNum);

	INFO_LOG(Log::sceNet, " - teamId:           %d", req->teamId);

	INFO_LOG(Log::sceNet, " - sigOptions:       0x%08x", req->sigOptions.ptr);
	if (req->sigOptions.IsValid()) {
		INFO_LOG(Log::sceNet, " - - type:           %d", req->sigOptions->type);
		INFO_LOG(Log::sceNet, " - - flag:           %01x", req->sigOptions->flag);
		INFO_LOG(Log::sceNet, " - - memberId:       %d", req->sigOptions->hubMemberId);
		INFO_LOG(Log::sceNet, " - - reserved:       %01x%01x%01x%01x", req->sigOptions->reserved2[0], req->sigOptions->reserved2[1], req->sigOptions->reserved2[2], req->sigOptions->reserved2[3]);
	}

	// When a game requests world_id 0, it implies an error occurred in the game's logic
	if (!world_exists) {
		ERROR_LOG(Log::sceNet, " - Invalid worldId");
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ROOM_ID), 0);
	}

	// Password Slot Masks
	// 00 00 00 00 00 00 00 00 -> No Password
	// 00 00 00 00 00 00 00 c0 -> Password Locked
	// 00 00 00 00 00 00 00 80 -> Default Password? (Fat Princess)
	
	// Phantasy Star will set a c0 mask with a password, or nullptr for none
	// Dynasty Warriors uses the 00 Mask with a password for private games
	// Fat Princess uses 80 without a password with no option to set a password

	int ret = npServer->CreateJoinRoom(ctxId, request_id, req);

	return SCE_NP_MATCHING2_OKAY;
}

/* Joins an existing Lobby/Party
 * @param reqParamPtr SceNpMatching2JoinRoomRequest containing relavant information required for the join process
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to a pre-specified request id to be overwritten
 * @return 0; System Errors are entirely ignored
 * @note This will officially start self-signaling
 */
static int sceNpMatching2JoinRoom(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 roomEventCbPtr, u32 roomMessageCbPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x, %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, roomEventCbPtr, roomMessageCbPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	if (Memory::IsValidAddress(roomEventCbPtr))
		hleCall(sceNpMatching2, int, sceNpMatching2SetDefaultRoomEventOptParam, ctxId, roomEventCbPtr);

	if (Memory::IsValidAddress(roomMessageCbPtr))
		hleCall(sceNpMatching2, int, sceNpMatching2SetDefaultRoomMessageOptParam, ctxId, roomMessageCbPtr);

	auto req = PSPPointer<SceNpMatching2JoinRoomRequest>::Create(reqParamPtr);

	INFO_HEXLOG(Log::sceNet, "JoinRoom Request: ", reinterpret_cast<const u8*>(&*req), sizeof(SceNpMatching2JoinRoomRequest), 386);

	INFO_LOG(Log::sceNet, " - roomId:		%ll", req->roomId);
	if (req->roomPassword.IsValid())
		INFO_HEXLOG(Log::sceNet, "roomPassword: ", reinterpret_cast<const u8*>(&*req->roomPassword), sizeof(SceNpMatching2SessionPassword), 386);

	if (req->joinRoomGroupLabel.IsValid())
		INFO_HEXLOG(Log::sceNet, "joinRoomGroupLabel: ", reinterpret_cast<const u8*>(&*req->joinRoomGroupLabel), sizeof(SceNpMatching2GroupLabel), 386);

	for (int i = 0; i < req->roomMemberBinAttrInternalNum; i++) {
		auto data = req->roomMemberBinAttrInternal + i;
		INFO_LOG(Log::sceNet, " - roomMemberBinAttrInternal[%d]:", i);
		INFO_LOG(Log::sceNet, " - - id:         %d", data->id);
		if (data->ptr.IsValid())
			INFO_HEXLOG(Log::sceNet, " - - ptr:", reinterpret_cast<const u8*>(&*data->ptr), sizeof(u8) * data->size, 386);
		else
			INFO_LOG(Log::sceNet, " - - ptr:         0x%08x", 0);
		INFO_LOG(Log::sceNet, " - - size:       %d", data->size);
	}
	INFO_LOG(Log::sceNet, " - roomMemberBinAttrInternalNum:		%d", req->roomMemberBinAttrInternalNum);
	INFO_HEXLOG(Log::sceNet, " - optData:", reinterpret_cast<const u8*>(&*req->optData.data), sizeof(u8) * req->optData.length, 386);
	INFO_LOG(Log::sceNet, " - teamId:		%d", req->teamId);

	if (np2P2PThreadID)
		__KernelStartThread(np2P2PThreadID, 0, 0);
	// FIXME: Get roomData from PSN
	int ret = npServer->JoinRoom(ctxId, request_id, req);


	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Leaves the current Lobby/Party
 * @param reqParamPtr ?
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to a pre-specified request id to be overwritten
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 * PSP2i fails to create a party at 08ca57d8 when DAT_08ed59d4 is set to 2
 */
static int sceNpMatching2LeaveRoom(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	auto req = PSPPointer<SceNpMatching2LeaveRoomRequest>::Create(reqParamPtr);
	int ret = npServer->LeaveRoom(ctxId, request_id, req);

	hleEatCycles(30000);
	// After returning, Fat Princess will loop for 64 times (increasing the address by 288 bytes on each loop) or until found a zero status byte (0x08BD4860 + 0x10), looking for empty/available entry to set?
	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Requests attributes of a specific Lobby/Party
 * @param reqParamPtr SceNpMatching2GetRoomDataInternalRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to a pre-specified request id to be overwritten
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2GetRoomDataInternal(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
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

// Placeholder until args are found
// FIXME: Return RoomDataInternal from Cache
static int sceNpMatching2GetRoomDataInternalLocal(int ctxId) {
	ERROR_LOG(Log::sceNet, "UNIMPLEMENTED %s(%d) at %08x", __FUNCTION__, ctxId, currentMIPS->pc);
	return -1;
}

/* Similar to sceNpMatching2SetRoomDataInternal, but stores the information externally
 * @param reqParamPtr SceNpMatching2SetRoomDataExternalRequest containing External room information?
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to a pre-specified request id to be overwritten
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SetRoomDataExternal(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	auto req = PSPPointer<SceNpMatching2SetRoomDataExternalRequest>::Create(reqParamPtr);

	INFO_LOG(Log::sceNet, " - roomId:             %d", req->roomId);

	for (int i = 0; i < req->roomSearchableIntAttrExternalNum; i++) {
		auto data = req->roomSearchableIntAttrExternal + i;
		INFO_LOG(Log::sceNet, " - roomSearchableIntAttrExternal[%d]:", i);
		INFO_LOG(Log::sceNet, " - - id:               %d", data->id);
		INFO_LOG(Log::sceNet, " - - num:              %d", data->num);
	}
	INFO_LOG(Log::sceNet, " - roomSearchableIntAttrExternalNum:		%d", req->roomSearchableIntAttrExternalNum);

	for (int i = 0; i < req->roomSearchableBinAttrExternalNum; i++) {
		auto data = req->roomSearchableBinAttrExternal + i;
		INFO_LOG(Log::sceNet, " - roomSearchableBinAttrExternal[%d]:", i);
		INFO_LOG(Log::sceNet, " - - id:               %d", data->id);
		if (data->ptr.IsValid())
			INFO_HEXLOG(Log::sceNet, " - - ptr:              %d", reinterpret_cast<const u8*>(&*data->ptr), sizeof(u8) * data->size, 386);
		else
			INFO_LOG(Log::sceNet, " - - ptr:              0x00000000");
		INFO_LOG(Log::sceNet, " - - size:             %d", data->size);
	}
	INFO_LOG(Log::sceNet, " - roomSearchableBinAttrExternalNum:		%d", req->roomSearchableBinAttrExternalNum);

	for (int i = 0; i < req->roomBinAttrExternalNum; i++) {
		auto data = req->roomBinAttrExternal + i;
		INFO_LOG(Log::sceNet, " - roomBinAttrExternal[%d]:", i);
		INFO_LOG(Log::sceNet, " - - id:               %d", data->id);
		if (data->ptr.IsValid())
			INFO_HEXLOG(Log::sceNet, " - - ptr:              %d", reinterpret_cast<const u8*>(&*data->ptr), sizeof(u8) * data->size, 386);
		else
			INFO_LOG(Log::sceNet, " - - ptr:              0x00000000");
		INFO_LOG(Log::sceNet, " - - size:             %d", data->size);
	}
	INFO_LOG(Log::sceNet, " - roomBinAttrExternalNum:		%d", req->roomBinAttrExternalNum);

	int ret = npServer->SetRoomDataExternal(ctxId, request_id, req);

	// After returning, Fat Princess will loop for 64 times (increasing the address by 288 bytes on each loop) or until found a zero status byte (0x08BD4860 + 0x10), looking for empty/available entry to set?
	return SCE_NP_MATCHING2_OKAY;
}

/* Sets attributes of a specific Lobby/Party
 * @param reqParamPtr SceNpMatching2SetRoomDataInternalRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to a pre-specified request id to be overwritten
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SetRoomDataInternal(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(reqParamPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	auto req = PSPPointer<SceNpMatching2SetRoomDataInternalRequest>::Create(reqParamPtr);

	INFO_HEXLOG(Log::sceNet, "SetRoomDataInternal Request: ", reinterpret_cast<const u8*>(&*req), sizeof(SceNpMatching2SetRoomDataInternalRequest), 386);

	INFO_LOG(Log::sceNet, " - roomId:         %d", req->roomId);
	INFO_LOG(Log::sceNet, " - flagFilter:     %04x", req->flagFilter);
	INFO_LOG(Log::sceNet, " - flagAttr:       %04x", req->flagAttr);

	for (int i = 0; i < req->roomBinAttrInternalNum; i++) {
		auto data = req->roomBinAttrInternal + i;
		INFO_LOG(Log::sceNet, " - roomSearchableBinAttrExternal[%d]:", i);
		INFO_LOG(Log::sceNet, " - - id:               %d", data->id);
		if (data->ptr.IsValid())
			INFO_HEXLOG(Log::sceNet, " - - ptr:              %d", reinterpret_cast<const u8*>(&*data->ptr), sizeof(u8) * data->size, 386);
		else
			INFO_LOG(Log::sceNet, " - - ptr:              0x00000000");
		INFO_LOG(Log::sceNet, " - - size:             %d", data->size);
	}
	INFO_LOG(Log::sceNet, " - roomBinAttrInternalNum:		%d", req->roomBinAttrInternalNum);

	if (req->passwordConfig.ptr != 0)
		INFO_HEXLOG(Log::sceNet, "passwordConfig: ", reinterpret_cast<const u8*>(&*req->passwordConfig), sizeof(SceNpMatching2RoomGroupPasswordConfig) * req->passwordConfigNum, 386);
	INFO_LOG(Log::sceNet, " - passwordConfigNum:          %d", req->passwordConfigNum);

	if (req->passwordSlotMask.ptr != 0)
		INFO_HEXLOG(Log::sceNet, "passwordSlotMask: ", reinterpret_cast<const u8*>(&*req->passwordSlotMask), sizeof(SceNpMatching2RoomPasswordSlotMask), 386);
	else
		INFO_LOG(Log::sceNet, " - passwordSlotMask:           NONE");

	if (req->ownerPrivilegeRank.ptr != 0)
		INFO_LOG(Log::sceNet, " - ownerPrivilegeRankNum:      %d", req->ownerPrivilegeRank);

	for (int i = 0; i < req->ownerPrivilegeRankNum; i++) {
		auto data = req->ownerPrivilegeRank + i;
		INFO_LOG(Log::sceNet, " - ownerPrivilegeRank[%d]: %d", i, data);
	}
	INFO_LOG(Log::sceNet, " - ownerPrivilegeRankNum:      %d", req->ownerPrivilegeRankNum);

	//return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal, SCE_NP_MATCHING2_OKAY, 0);
	int ret = npServer->SetRoomDataInternal(ctxId, request_id, req);

	return SCE_NP_MATCHING2_OKAY;
}

/* Sends a Chat Message to relevant players?
 * @param reqParamPtr ? Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to a pre-specified request id to be overwritten
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SendRoomChatMessage(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, SCE_NP_MATCHING2_OKAY, 0);
}

/* Sets the Default Callback function for System Requests to be used when the functions optParam isn't provided
 * @param optParamPtr Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @return 0; or System Error
 * @note Few games use this, and normally rely on the optParamPtr argument for said functions instead
 */
static int sceNpMatching2SetDefaultRequestOptParam(int ctxId, u32 optParamPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x) at %08x", __FUNCTION__, ctxId, optParamPtr, currentMIPS->pc);

	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(optParamPtr) || !Memory::IsValidAddress(optParamPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	auto requestOptParams = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	NpMatching2Handler optParam{};
	optParam.ctx_id = ctxId;
	optParam.cb = requestOptParams->cbFunc.ptr;
	optParam.cb_arg = requestOptParams->cbFuncArg.ptr;
	optParam.event_type = SCE_NP_MATCHING2_REQUEST_EVENT;
	defaultOptParams[SCE_NP_MATCHING2_REQUEST_EVENT] = optParam;

	return SCE_NP_MATCHING2_OKAY;
}

/* Appears to set user-specific attributes, but is rarely used
 * @param reqParamPtr SceNpMatching2SetUserInfoRequest containing the new attributes
 * @param optParamPtr Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 */
static int sceNpMatching2SetUserInfo(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(reqParamPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	auto req = PSPPointer<SceNpMatching2SetUserInfoRequest>::Create(reqParamPtr);

	int ret = npServer->SetUserInfo(ctxId, request_id, req);

	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Appears to get user-specific attributes, but is rarely used
 * @param reqParamPtr SceNpMatching2GetUserInfoListRequest containing relevant information of a player?
 * @param optParamPtr Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 */
static int sceNpMatching2GetUserInfoList(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(reqParamPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	auto req = PSPPointer<SceNpMatching2GetUserInfoListRequest>::Create(reqParamPtr);

	// FIXME: GetUserInfoList does not yet exist in RPCN, or is otherwise unimplemented
	//int ret = npServer->GetUserInfo(ctxId, request_id, req);
	return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_OKAY, "UNIMPLEMENTED"), 0);
}

/* Incomplete - When a request is aborted, it should use request_id 0
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; or System Error
 * @note Not used under normal circumstances.
 */
static int sceNpMatching2AbortRequest(int ctxId, u32 reqId)
{
	ERROR_LOG(Log::sceNet, "UNTESTED %s(%d, %d) at %08x", __FUNCTION__, ctxId, reqId, currentMIPS->pc);

	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	// Find the handler matching the request_id
	auto it = npMatching2Handlers.find(reqId);
	if (it == npMatching2Handlers.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CANNOT_ABORT, "Request already completed");

	// Assign an event with reqId 0 to matching handler
	notifyRequestHandler(it->second.ctx_id, it->first, it->second.event_type, SCE_NP_MATCHING2_ERROR_ABORTED, 0);
	npMatching2Handlers.erase(it);

	return SCE_NP_MATCHING2_OKAY;
}

/* Sets or Changes the registered Signaling Callback information
 * @param optParamPtr Pointer to SceNpMatching2SignalingOptParam containing Callback information
 * @return 0; or System Error
 * @note This should set the information in SignalingHandler for cleaner separation
 */
static int sceNpMatching2SetSignalingOptParam(int ctxId, u32 optParamPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x) at %08x", __FUNCTION__, ctxId, optParamPtr, currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(optParamPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	auto signalingOptParam = PSPPointer<SceNpMatching2SignalingOptParam>::Create(optParamPtr);
	NpMatching2Handler optParam{};
	optParam.ctx_id = ctxId;
	optParam.cb.ptr = signalingOptParam->cbFunc.ptr;
	optParam.cb_arg.ptr = signalingOptParam->cbFuncArg.ptr;
	optParam.event_type = SCE_NP_MATCHING2_SIGNALING_EVENT;
	defaultOptParams[SCE_NP_MATCHING2_SIGNALING_EVENT] = optParam;

	return SCE_NP_MATCHING2_OKAY;
}

/* Gets the registered Signaling Callback information
 * @param roomId SceNpMatching2RoomId as the primary key for signaling
 * @param optParamPtr Pointer to SceNpMatching2SignalingOptParam containing Callback information
 * @return 0; or System Error
 * @note room_id is the primary key for default parameters, not context
 */
static int sceNpMatching2GetSignalingOptParamLocal(int ctxId, u32 roomId, u32 optParamPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, optParamPtr, currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(roomId) || !Memory::IsValidAddress(optParamPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	auto optPtr = PSPPointer<SceNpMatching2SignalingOptParam>::Create(optParamPtr);

	if (defaultOptParams.find(SCE_NP_MATCHING2_SIGNALING_EVENT) == defaultOptParams.end())
		return SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND;
	auto sigParam = defaultOptParams[SCE_NP_MATCHING2_SIGNALING_EVENT];
	optPtr->cbFunc = sigParam.cb.ptr;
	optPtr->cbFuncArg = sigParam.cb_arg;

	return SCE_NP_MATCHING2_OKAY;
}

/* Sets or Changes the registered Room Event Callback information
 * @param optParamPtr Pointer to SceNpMatching2RoomEventOptParam containing Callback information
 * @return 0; or System Error
 * @note This channel handles Create/Join/Leave events
 */
static int sceNpMatching2SetDefaultRoomEventOptParam(int ctxId, u32 optParamPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x) at %08x", __FUNCTION__, ctxId, optParamPtr, currentMIPS->pc);

	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (optParamPtr == 0 || !Memory::IsValidAddress(optParamPtr)) {
		return hleLogError(Log::sceNet, SCE_NP_ERROR_INVALID_CALLBACK, "%s - Invalid Callback %08x", __FUNCTION__, optParamPtr);
	}

	auto roomEvtOptParams = PSPPointer<SceNpMatching2RoomEventOptParam>::Create(optParamPtr);
	NpMatching2Handler optParam{};
	optParam.ctx_id = ctxId;
	optParam.cb = roomEvtOptParams->cbFunc.ptr;
	optParam.cb_arg = roomEvtOptParams->cbFuncArg.ptr;
	optParam.event_type = SCE_NP_MATCHING2_ROOM_EVENT;
	defaultOptParams[SCE_NP_MATCHING2_ROOM_EVENT] = optParam;

	return SCE_NP_MATCHING2_OKAY;
}

/* Sets or Changes the registered Room Message Event Callback information
 * @param optParamPtr Pointer to SceNpMatching2RoomMessageOptParam containing Callback information
 * @return 0; or System Error
 * @note This channel handles optional extra details about the room conditions and flags
 */
static int sceNpMatching2SetDefaultRoomMessageOptParam(int ctxId, u32 optParamPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x) at %08x", __FUNCTION__, ctxId, optParamPtr, currentMIPS->pc);

	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (optParamPtr == 0 || !Memory::IsValidAddress(optParamPtr)) {
		return hleLogError(Log::sceNet, SCE_NP_ERROR_INVALID_CALLBACK, "%s - Invalid Callback %08x", __FUNCTION__, optParamPtr);
	}

	auto roomEvtOptParams = PSPPointer<SceNpMatching2RoomMessageOptParam>::Create(optParamPtr);
	NpMatching2Handler optParam{};
	optParam.ctx_id = ctxId;
	optParam.cb = roomEvtOptParams->cbFunc.ptr;
	optParam.cb_arg = roomEvtOptParams->cbFuncArg.ptr;
	optParam.event_type = SCE_NP_MATCHING2_ROOM_MSG_EVENT;
	defaultOptParams[SCE_NP_MATCHING2_ROOM_MSG_EVENT] = optParam;

	return SCE_NP_MATCHING2_OKAY;
}

/* Gets the local IP, Port, NAT Type, and other flags
 * @param netInfoPtr Pointer to SceNpMatching2SignalingNetInfo to be provided requested information
 * @return 0; or System Error
 * @note This channel handles optional extra details about the room conditions and flags
 */
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
	netInfo->localAddr = g_signaling.GetLocalAddr();	// Local  IP
	netInfo->mappedAddr = g_signaling.GetSigAddr();		// Public IP
	// Pure speculation
	//si->conn_status
	netInfo->natStatus = g_signaling.nat_type.load();
	// Unverified extra data?
	netInfo->UPnPStatus = (g_PortManager.GetInitState() == UPNP_INITSTATE_DONE ? SCE_NP_SIGNALING_NETINFO_UPNP_STATUS_VALID : SCE_NP_SIGNALING_NETINFO_UPNP_STATUS_INVALID);
	netInfo->portStatus = SCE_NP_SIGNALING_NETINFO_NPPORT_STATUS_OPEN;
	netInfo->port = htons(g_signaling.GetSigPort());

	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Gets the target Peer's IP, Port, NAT Type, and other flags
 * @param roomId The keyed room_id to search for player
 * @param roomMemberId The target players ID to provide in the system request
 * @param netInfoPtr Pointer to SceNpMatching2SignalingNetInfo to be provided requested information
 * @return 0; or System Error
 * @note This might request the information from the target player, rather than providing what it knows
 */
static int sceNpMatching2SignalingGetPeerNetInfo(int ctxId, u32 roomId, u32 roomMemberId, u32 netInfoPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, roomMemberId, netInfoPtr, currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(netInfoPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	auto netInfo = PSPPointer<SceNpMatching2SignalingNetInfo>::Create(netInfoPtr);

	auto member_exists = npServer->cache.Exists(roomId, roomMemberId);
	if (!member_exists)
		return SCE_NP_MATCHING2_ERROR_ROOM_MEMBER_NOT_FOUND;
	auto connId = g_signaling.get_conn_id_from_npid(npServer->cache.GetNpId(roomId, roomMemberId));
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
	netInfo->natStatus = si->nat_type;
	// Unverified extra data?
	netInfo->UPnPStatus = SCE_NP_SIGNALING_NETINFO_UPNP_STATUS_VALID;
	netInfo->portStatus = SCE_NP_SIGNALING_NETINFO_NPPORT_STATUS_OPEN;
	netInfo->port = htons(si->mapped_port);

	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Might handle the response from the PeerNetInfo request?
 * @param signalingReqIdPtr ?
 * @param netInfoPtr Pointer to SceNpMatching2SignalingNetInfo to be provided requested information
 * @return 0; or System Error
 */
static int sceNpMatching2SignalingGetPeerNetInfoResult(int ctxId, u32 signalingReqIdPtr, u32 netInfoPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x[%08x], %08x) at %08x", __FUNCTION__, ctxId, signalingReqIdPtr, Memory::Read_U32(signalingReqIdPtr), netInfoPtr, currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(signalingReqIdPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Might cancel the request from the PeerNetInfo request?
 * @param signalingReqIdPtr ?
 * @return 0; or System Error
 */
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

/* Provides known Connection Status, IP, and Port between 2 members
 * @param connId Optionally replaces RoomId / MemberId
 * @param roomId Keyed Room where the member is a part of
 * @param memberId Source member to check connection
 * @param peerMemberId Target member to retrieve information about
 * @param connInfoPtr Peer CONNECT_STATUS
 * @param ipAddrPtr Peer IP Address
 * @param portPtr Peer Port
 * @return 0; or System Error
 * @note It looks like 0 is used for "self"
 * @note Fat Princess assigns a local connId? here when requesting information, and then proceeds to call GetConnectionInfo
 */
static int sceNpMatching2SignalingGetConnectionStatus(int ctxId, u32 connId, u32 roomId, u32 memberId, u32 peerMemberId, u32 connInfoPtr, u32 ipAddrPtr, u32 portPtr) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %d, %d, %d, %d, 0x%08X, 0x%08X, 0x%08X) at %08x", __FUNCTION__, ctxId, connId, roomId, memberId, peerMemberId, connInfoPtr, ipAddrPtr, portPtr, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (connInfoPtr == 0 || !Memory::IsValidAddress(connInfoPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT, "connInfoPtr is an invalid pointer");

	if (ipAddrPtr == 0 || !Memory::IsValidAddress(ipAddrPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT, "ipAddrPtr is an invalid pointer");

	if (portPtr == 0 || !Memory::IsValidAddress(portPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT, "portPtr is an invalid pointer");

	//auto connStatus = PSPPointer<SceNpMatching2ServerStatus>::Create(connInfoPtr);
	//connStatus = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;
	Memory::Write_U32(SCE_NP_SIGNALING_CONN_STATUS_INACTIVE, connInfoPtr);

	u32 sig_addr = 0;
	u16 sig_port = 0;
	u32 conn_status = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;

	std::optional<u32> conn_id = std::nullopt;
	if (connId != 0) {
		conn_id = connId;

		auto si = g_signaling.get_sig_infos(conn_id.value());
		if (!si) {
			// PSP2i uses peerMemberId as the connId instead of an actual connId at 08cb4f38
			WARN_LOG(Log::sceNet, "Invalid Connection ID. Trying Member ID instead.");

			if (!npServer->cache.Exists((SceNpMatching2RoomId)roomId))
				return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_ROOM_NOT_FOUND, "Room not found");

			if (!npServer->cache.Exists(roomId, peerMemberId))
				return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_ROOM_MEMBER_NOT_FOUND, "Member not found");

			conn_id = g_signaling.get_conn_id_from_npid(npServer->cache.GetNpId(roomId, peerMemberId));
		}
	}
	else {
		if (!npServer->cache.Exists((SceNpMatching2RoomId)roomId))
			return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_ROOM_NOT_FOUND, "Room not found");

		if (!npServer->cache.Exists(roomId, peerMemberId))
			return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_ROOM_MEMBER_NOT_FOUND, "Member not found");

		conn_id = g_signaling.get_conn_id_from_npid(npServer->cache.GetNpId(roomId, peerMemberId));
	}
	// FIXME: This can technically call for p2p info between other members, but should call sceNpMatching2SignalingGetPeerNetInfo instead?
	if (!conn_id) {
		return hleLogError(Log::sceNet, SCE_NP_SIGNALING_ERROR_CONN_NOT_FOUND, "Connection not found");
	}

	auto si = g_signaling.get_sig_infos(conn_id.value());
	if (!si) {
		return hleLogError(Log::sceNet, SCE_NP_SIGNALING_ERROR_CONN_NOT_FOUND, "Not Connected");
	}

	sig_addr = si->addr;
	sig_port = htons(si->port);
	conn_status = si->conn_status;
	//else {
	//	// TODO: Use p2p siginfo for self?
	//	if (memberId == 0)
	//		sig_addr = g_signaling.GetLocalAddr();
	//	else
	//		sig_addr = g_signaling.GetSigAddr();
	//	member_exists = true;
	//	sig_port = htons(g_signaling.GetSigPort());
	//	conn_status = SCE_NP_SIGNALING_CONN_STATUS_ACTIVE;
	//}

	// Write Connection Status
	Memory::Write_U32(conn_status, connInfoPtr);

	switch (conn_status) {
	case SCE_NP_SIGNALING_CONN_STATUS_INACTIVE:
		NOTICE_LOG(Log::sceNet, " - INACTIVE"); break;
	case SCE_NP_SIGNALING_CONN_STATUS_PENDING:
		NOTICE_LOG(Log::sceNet, " - PENDING"); break;
	case SCE_NP_SIGNALING_CONN_STATUS_ACTIVE:
		NOTICE_LOG(Log::sceNet, " - ACTIVE"); break;
	}

	Memory::Write_U32(sig_addr, ipAddrPtr);
	NOTICE_LOG(Log::sceNet, " - IP Addr: %s", ip2str(sig_addr).c_str());

	Memory::Write_U16(sig_port, portPtr);
	NOTICE_LOG(Log::sceNet, " - Port: %d", ntohs(sig_port));

	return hleLogInfo(Log::sceNet, SCE_NP_MATCHING2_OKAY);
}

/* Provides more detailed information, and specific between 2 members
 * @param connId Optionally replaces RoomId / MemberId
 * @param roomId Keyed Room where the member is a part of
 * @param memberId Source member to check connection, or 0 for self
 * @param peerMemberId Target member to retrieve information about
 * @param code Enum Type of information requested
 * @param connInfoPtr SceNpSignalingConnectionInfo containing response information
 * @return 0; or System Error
 * @note Fat Princess assigns a connId of 0 when connStatus == 2
 * @note Most games appear to adhere to this rule of thumb, and rely on roomId/memberId for assigning connection details
 * @note This returns a UNION, not a struct, meaning only specific parts of the struct will be returned
 */
static int sceNpMatching2SignalingGetConnectionInfo(int ctxId, u32 connId, u32 roomId, u32 memberId, u32 peerMemberId, u32 code, u32 connInfoPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %d, %d, %d, %d, %d, %08x) at %08x", __FUNCTION__, ctxId, connId, roomId, memberId, peerMemberId, code, connInfoPtr, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (connInfoPtr == 0 || !Memory::IsValidAddress(connInfoPtr))
		return SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT;
	// Fat Princess marks this as 0x24
	auto connInfo = PSPPointer<SceNpSignalingConnectionInfo>::Create(connInfoPtr);

	if (!npServer->cache.Exists(roomId, peerMemberId))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_ROOM_MEMBER_NOT_FOUND, "Member Not Found");

	// FIXME: Do a memberId check instead?
	if (strncmp(NpGetNpId()->handle.data, npServer->cache.GetNpId(roomId, peerMemberId).handle.data, 16) == 0) {
		return hleLogError(Log::sceNet, SCE_NP_SIGNALING_ERROR_OWN_NP_ID, "Member is Self");
	}

	auto conn_id = g_signaling.get_always_conn_id(npServer->cache.GetNpId(roomId, peerMemberId));

	auto si = g_signaling.get_sig_infos(conn_id);
	if (!si) {
		return hleLogError(Log::sceNet, SCE_NP_SIGNALING_ERROR_CONN_NOT_FOUND, "Not Connected");
	}

	// This is a union. Only the value modified will be passed to the game
	switch (code) {
	case SCE_NP_SIGNALING_CONN_INFO_RTT:
		connInfo->rtt = si->rtt;
		NOTICE_LOG(Log::sceNet, " - SCE_NP_SIGNALING_CONN_INFO_RTT:");
		NOTICE_LOG(Log::sceNet, " - RTT: %d microseconds", connInfo->rtt);
		break;
	case SCE_NP_SIGNALING_CONN_INFO_BANDWIDTH:
		connInfo->bandwidth = 100'000'000; // 100 MBPS HACK
		NOTICE_LOG(Log::sceNet, " - SCE_NP_SIGNALING_CONN_INFO_BANDWIDTH:");
		NOTICE_LOG(Log::sceNet, " - Bandwidth: %d", connInfo->bandwidth);
		break;
	case SCE_NP_SIGNALING_CONN_INFO_PEER_NPID:
		connInfo->npId = si->npid;
		NOTICE_LOG(Log::sceNet, " - SCE_NP_SIGNALING_CONN_INFO_PEER_NPID:");
		NOTICE_LOG(Log::sceNet, " - NpId: %s", connInfo->npId.handle.data);
		break;
	case SCE_NP_SIGNALING_CONN_INFO_PEER_ADDRESS:
		connInfo->address.port = htons(si->port);
		connInfo->address.addr.np_s_addr = si->addr;
		NOTICE_LOG(Log::sceNet, " - SCE_NP_SIGNALING_CONN_INFO_PEER_ADDRESS:");
		NOTICE_LOG(Log::sceNet, " - IP Addr: %s", ip2str(connInfo->address.addr.np_s_addr).c_str());
		NOTICE_LOG(Log::sceNet, " - Port: %d", ntohs(connInfo->address.port));
		break;
	case SCE_NP_SIGNALING_CONN_INFO_MAPPED_ADDRESS:
		connInfo->address.port = htons(si->mapped_port);
		connInfo->address.addr.np_s_addr = si->mapped_addr;
		NOTICE_LOG(Log::sceNet, " - SCE_NP_SIGNALING_CONN_INFO_MAPPED_ADDRESS:");
		NOTICE_LOG(Log::sceNet, " - IP Addr: %s", ip2str(connInfo->address.addr.np_s_addr).c_str());
		NOTICE_LOG(Log::sceNet, " - Port: %d", connInfo->address.port);
		break;
	case SCE_NP_SIGNALING_CONN_INFO_PACKET_LOSS:
		connInfo->packet_loss = 0; // HACK
		NOTICE_LOG(Log::sceNet, " - SCE_NP_SIGNALING_CONN_INFO_PACKET_LOSS:");
		NOTICE_LOG(Log::sceNet, " - Packet Loss: %d", connInfo->packet_loss);
		break;
	default:
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT, "Unrecognized Code %d", code);
	}

	return SCE_NP_MATCHING2_OKAY;
}

/* Requests RoomData from an external source
 * @param reqParamPtr 
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to a pre-specified request id to be overwritten
 * @return 0; or System Error
 */
static int sceNpMatching2GetRoomDataExternalList(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND), 0);

	if (!Memory::IsValidAddress(reqParamPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	auto req = PSPPointer<SceNpMatching2GetRoomDataExternalListRequest>::Create(reqParamPtr);
	int ret = npServer->GetRoomDataExternalList(ctxId, request_id, req);

	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Requests Room Password Information from cache
 * @param roomIdPtr Relevant cached room to request information about
 * @param withPasswordPtr Boolean validating the condition of the room password
 * @param roomPasswordPtr SceNpMatching2SessionPassword containing the password
 * @return 0; or System Error
 * @note None of our test games support this system call
 * @note Fat Princess uses a default password of some sort, and PSP2i uses an optional user generated password
 */
static int sceNpMatching2GetRoomPasswordLocal(int ctxId, u32 roomIdPtr, u32 withPasswordPtr, u32 roomPasswordPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomIdPtr, withPasswordPtr, roomPasswordPtr, currentMIPS->pc);

	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (Memory::IsValidAddress(roomIdPtr) || Memory::IsValidAddress(withPasswordPtr) || !Memory::IsValidAddress(roomPasswordPtr))
		return SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT;

	auto roomId = PSPPointer<SceNpMatching2RoomId>::Create(roomIdPtr);
	auto withPassword = PSPPointer<u8>::Create(withPasswordPtr);
	auto roomPassword = PSPPointer<SceNpMatching2SessionPassword>::Create(roomPasswordPtr);

	withPassword = false;

	if (!npServer->cache.Exists(*roomId)) {
		return SCE_NP_MATCHING2_SERVER_ERROR_NO_PASSWORD;
	}

	// get Password from cache
	bool cache_withPassword = npServer->cache.HasPassword(*roomId);
	if (!cache_withPassword) {
		return SCE_NP_MATCHING2_SERVER_ERROR_NO_PASSWORD;
	}

	if (cache_withPassword) {
		withPassword = true;
		auto room_pwd = npServer->cache.GetRoomPassword(*roomId);
		Memory::Memcpy(roomPassword.ptr, &room_pwd, sizeof(SceNpMatching2SessionPassword));
	}

	return SCE_NP_MATCHING2_OKAY;
}

/* Sends a Room Message to relevant players
 * @param reqParamPtr PSPPointer<SceNpMatching2SendRoomMessageRequest> Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Sends the message to the NPAgent, and receives a reply via Notification
 * @note PSP2i doesn't provide a callback, and waits for the related notification to send a ROOM_MSG_EVENT
 * @note PSP2i sends character level/equipment over this channel, but not player position
 */
static int sceNpMatching2SendRoomMessage(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%d]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	if (!Memory::IsValidAddress(optParam->cbFunc.ptr))
		request_id = 0;
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	auto req = PSPPointer<SceNpMatching2SendRoomMessageRequest>::Create(reqParamPtr);

	INFO_LOG(Log::sceNet, " - roomId:     %d", req->roomId);
	INFO_LOG(Log::sceNet, " - castType:   %d", req->castType);
	INFO_LOG(Log::sceNet, " - msgLen:     %d", req->msgLen);

	if (!npServer->cache.Exists(req->roomId))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM, "Room doesn't exist"), 0);

	int ret = npServer->SendRoomMessage(ctxId, request_id, req);

	return SCE_NP_MATCHING2_OKAY;
}

/* Incomplete - Promotes a member of the party to Host?
 * @param reqParamPtr ?
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to a pre-specified request id to be overwritten
 * @return 0; or System Error
 */
static int sceNpMatching2GrantRoomOwner(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner, SCE_NP_MATCHING2_OKAY, 0);
}

/* Incomplete - Requests the cached list of member_id's in a room
 * @param roomId ?
 * @param sortMethod ?
 * @param memberId ?
 * @param memberIdNum ?
 * @return 0; or System Error
 */
static int sceNpMatching2GetRoomMemberIdListLocal(int ctxId, u32 roomId, u32 sortMethod, u32 memberId, u32 memberIdNum)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, sortMethod, memberId, memberIdNum, currentMIPS->pc);

	_dbg_assert_msg_(false, "FoxLovesYou is looking for more information about this system call!");
	return SCE_NP_MATCHING2_OKAY;
}

/* Changes or Sets Room Member updates
 * @param reqParamPtr SceNpMatching2SetRoomMemberDataInternalRequest
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to a pre-specified request id to be overwritten
 * @return 0; or System Error
 */
static int sceNpMatching2SetRoomMemberDataInternal(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	auto req = PSPPointer<SceNpMatching2SetRoomMemberDataInternalRequest>::Create(reqParamPtr);

	INFO_LOG(Log::sceNet, " - roomId:             %d", req->roomId);
	INFO_LOG(Log::sceNet, " - memberId:           %d", req->memberId);
	INFO_LOG(Log::sceNet, " - teamId:             %d", req->teamId);
	INFO_LOG(Log::sceNet, " - flagFilter:         %d", req->flagFilter);
	INFO_LOG(Log::sceNet, " - flagAttr:           %d", req->flagAttr);

	for (int i = 0; i < req->roomMemberBinAttrInternalNum; i++) {
		auto data = req->roomMemberBinAttrInternal + i;
		INFO_LOG(Log::sceNet, " - roomMemberBinAttrInternal[%d]:", i);
		INFO_LOG(Log::sceNet, " - - id:               %d", data->id);
		if (data->ptr.IsValid())
			INFO_HEXLOG(Log::sceNet, " - - ptr:", reinterpret_cast<const u8*>(&*data->ptr), sizeof(u8) * data->size, 386);
		else
			INFO_LOG(Log::sceNet, " - - ptr:              0x00000000");
		INFO_LOG(Log::sceNet, " - - size:             %d", data->size);
	}
	INFO_LOG(Log::sceNet, " - roomMemberBinAttrInternalNum:		%d", req->roomMemberBinAttrInternalNum);

	npServer->SetRoomMemberDataInternal(ctxId, request_id, req);

	return hleLogWarning(Log::sceNet, SCE_NP_MATCHING2_OKAY, "UNTESTED");
}

/* Incomplete - Gets extra cached information about all room members
 * @param roomId ?
 * @param memberId ?
 * @param attrId ?
 * @param attrIdNum ?
 * @param memberPtr ?
 * @param bufPtr ?
 * @param bufLen ?
 * @return 0; or System Error
 */
static int sceNpMatching2GetRoomMemberDataInternalLocal(int ctxId, u32 roomId, u32 memberId, u32 attrId, u32 attrIdNum, u32 memberPtr, u32 bufPtr, u32 bufLen)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x, %08x, %08x, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, memberId, attrId, attrIdNum, memberPtr, bufPtr, bufLen, currentMIPS->pc);

	_dbg_assert_msg_(false, "FoxLovesYou is looking for more information about this system call!");
	return SCE_NP_MATCHING2_OKAY;
}

/* Gets a members data from an Internal source
 * @param reqParamPtr SceNpMatching2GetRoomMemberDataInternalRequest
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to a pre-specified request id to be overwritten
 * @return 0; or System Error
 */
static int sceNpMatching2GetRoomMemberDataInternal(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	auto req = PSPPointer<SceNpMatching2GetRoomMemberDataInternalRequest>::Create(reqParamPtr);
	npServer->GetRoomMemberDataInternal(ctxId, request_id, req);

	return hleLogWarning(Log::sceNet, SCE_NP_MATCHING2_OKAY, "UNTESTED");
}

/* Incomplete - Requests a list of extended information about members in a room
 * @param Parameters are unknown!
 * @return 0; or System Error
 * @note Placeholder until args are identified
 */
static int sceNpMatching2GetRoomMemberDataInternalList(int ctxId)
{
	ERROR_LOG(Log::sceNet, "UNIMPLEMENTED %s(%d) at %08x", __FUNCTION__, ctxId, currentMIPS->pc);
	_dbg_assert_msg_(false, "FoxLovesYou is looking for more information about this system call!");
	return -1;
}

/* Incomplete - Requests an extended list of information from an external source
 * @param reqParamPtr ?
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to a pre-specified request id to be overwritten
 * @return 0; or System Error
 */
static int sceNpMatching2GetRoomMemberDataExternalList(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

	if (!npServer)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

	return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_OKAY, "UNIMPLEMENTED"), 0);
}

/* Incomplete - Ejects a member from the party
 * @param reqParamPtr ?
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to a pre-specified request id to be overwritten
 * @return 0; or System Error
 */
static int sceNpMatching2KickoutRoomMember(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto optParam = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParamPtr);
	SceNpMatching2RequestId assignedReqId = Memory::Read_U32(assignedReqIdPtr);
	SceNpMatching2RequestId request_id = RegisterNpMatching2Handler(ctxId, *optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT);
	Memory::Write_U32(request_id, assignedReqIdPtr);

	if (!npMatching2Inited)
		return notifyRequestHandler(ctxId, request_id, SCE_NP_MATCHING2_REQUEST_EVENT_KickoutRoomMember, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

	auto _context = ctx.find(ctxId);
	if (_context == ctx.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND);

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
	{0x9A67F5D0, &WrapI_IU<sceNpMatching2SetSignalingOptParam>,				"sceNpMatching2SetSignalingOptParam",			'i', "ix"     },
	{0xC7E72EC5, &WrapI_IUU<sceNpMatching2GetSignalingOptParamLocal>,		"sceNpMatching2GetSignalingOptParamLocal",		'i', "ixx"    },
	{0xFF32EA05, &WrapI_U<sceNpMatching2SignalingGetLocalNetInfo>,			"sceNpMatching2SignalingGetLocalNetInfo",		'i', "x"      },
	{0x8CD109E7, &WrapI_IUUU<sceNpMatching2SignalingGetPeerNetInfo>,		"sceNpMatching2SignalingGetPeerNetInfo",		'i', "ixxx"   },
	{0xDFEDB642, &WrapI_IUU<sceNpMatching2SignalingGetPeerNetInfoResult>,	"sceNpMatching2SignalingGetPeerNetInfoResult",	'i', "ixx"    },
	{0x9462C05A, &WrapI_IU<sceNpMatching2SignalingCancelPeerNetInfo>,		"sceNpMatching2SignalingCancelPeerNetInfo",		'i', "ix"     },
	{0x3892E9A6, &WrapI_IUUUUUU<sceNpMatching2SignalingGetConnectionInfo>,	"sceNpMatching2SignalingGetConnectionInfo",		'i', "ixxxxxx"},
	{0x6D6D0C75, &WrapI_IUUUUUUU<sceNpMatching2SignalingGetConnectionStatus>,	"sceNpMatching2SignalingGetConnectionStatus",	'i', "ixxxxxxx" },

	{0x2E61F6E1, &WrapI_IIII<sceNpMatching2Init>,							"sceNpMatching2Init",							'i', "iiii"   },
	{0x8BF37D8C, &WrapI_V<sceNpMatching2Term>,								"sceNpMatching2Term",							'i', ""       },
	{0x5030CC53, &WrapI_UUUS<sceNpMatching2CreateContext>,					"sceNpMatching2CreateContext",					'i', "xxxx"   },
	{0x3DE70241, &WrapI_I<sceNpMatching2DestroyContext>,					"sceNpMatching2DestroyContext",					'i', "i"      },
	{0x190FF903, &WrapI_I<sceNpMatching2ContextStart>,						"sceNpMatching2ContextStart",					'i', "i"      },
	{0x2B3892FC, &WrapI_I<sceNpMatching2ContextStop>,						"sceNpMatching2ContextStop",					'i', "i"      },

	{0x1421514B, &WrapI_IU<sceNpMatching2SetDefaultRoomEventOptParam>,		"sceNpMatching2SetDefaultRoomEventOptParam",	'i', "ix"    },
	{0xD13491AB, &WrapI_IU<sceNpMatching2SetDefaultRoomMessageOptParam>,	"sceNpMatching2SetDefaultRoomMessageOptParam",	'i', "ix"    },
	{0xE6C93DBD, &WrapI_IUUU<sceNpMatching2SetRoomDataInternal>,			"sceNpMatching2SetRoomDataInternal",			'i', "ixxx"   },
	{0xE313E586, &WrapI_IUUU<sceNpMatching2GetRoomDataInternal>,			"sceNpMatching2GetRoomDataInternal",			'i', "ixxx"   },
	{0xEF683F4F, &WrapI_I<sceNpMatching2GetRoomDataInternalLocal>,			"sceNpMatching2GetRoomDataInternalLocal",		'i', ""       },
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
	{0x5C7DB6A4, &WrapI_I<sceNpMatching2GetRoomMemberDataInternalList>,		"sceNpMatching2GetRoomMemberDataInternalList",	'i', ""       },
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
