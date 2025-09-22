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
#include "Core/HLE/proAdhoc.h"
//#include "NpMatchingContext.h"
//#include "Np2SignalingHandler.h"

bool npMatching2Inited = false;
SceNpAuthMemoryStat npMatching2MemStat = {};
u32 npPoolAddr = 0;
BlockAllocator np_memory;

std::recursive_mutex npMatching2EvtMtx;
std::deque<NpMatching2Args> npMatching2Events;
std::map<u32, NpMatching2Handler> npMatching2Handlers;

//std::recursive_mutex npMatching2SigMtx;
//NpMatching2Handler npSignalingCallback;
//std::unordered_map<u32, NpMatching2Handler> npSignalingHandlers;
//std::map<int, NpMatching2Context> npMatching2Contexts;
//u16 tServer;

//std::map<u16, std::unique_ptr<net::NPAgent>> servers;
std::unique_ptr<net::NPAgent> npServer = nullptr;
std::map<u16, std::future<int>> tasks;
signaling_handler g_signaling;


void __Np2Init() {
	npMatching2Inited = false;
}

void __Np2Shutdown() {
	if (npServer && npServer->IsConnected()) {
		g_signaling.stop();
		npServer->Disconnect();
	}
}
/* Generate a Request Id for various callbacks
 * @param assignedReqIdPtr pointer to AppRequestID
 * @return u32 System RequestID
 */
u32 GenerateRequestId(u32 assignedReqIdPtr) {
	if (!Memory::IsValidAddress(assignedReqIdPtr)) {
		ERROR_LOG(Log::sceNet, "%s - Invalid assignedReqIdPtr %08x", __FUNCTION__, assignedReqIdPtr);
		return 0; // 0 => aborted
	}

	// PPSSPP uses LE memory; value returned is host-endian u32.
	u32 reqId = Memory::Read_U32(assignedReqIdPtr) + 1;
	return reqId;
}

//template <typename T>
//void Write_Struct(const T& object, const u32 address, const char* tag, size_t taglen) {
//	Memory::Memcpy(address, &object, sizeof(T), tag, taglen);
//}

/* Generate a callback handler for async processing returns
 * @param optParamPtr pointer to SceNpMatching2RequestOptParam
 * @param assignedReqIdPtr pointer to AppRequestID
 * @param event_type PS3Matching2RequestEvent Event
 * @return u32 System RequestID
 */
bool RegisterNpMatching2Handler(int ctxId, u32 callbackPtr, u32 argPtr, SceNpMatching2EventType event_type) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %d) at %08x", __FUNCTION__, ctxId, callbackPtr, argPtr, event_type, currentMIPS->pc);

	INFO_LOG(Log::sceNet, "%s - optParam[%08x, %08x]", __FUNCTION__, callbackPtr, argPtr);

	if (!Memory::IsValidAddress(callbackPtr)) {
		ERROR_LOG(Log::sceNet, "%s - Invalid Callback FUN_%08x(%08x) for Event (%d)", __FUNCTION__, callbackPtr, argPtr, event_type);
		return false;
	}
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	NpMatching2Handler handler{};

	handler.ctx_id = ctxId; // double handle
	handler.cb = callbackPtr;
	handler.cb_arg = argPtr;
	handler.event_type = event_type;

	// 0 defines an Aborted Request
	npMatching2Handlers[event_type] = handler;
	std::string event_name = "UNKNOWN";
	switch (event_type) {
	case SCE_NP_MATCHING2_REQUEST_EVENT: event_name = "REQUEST_EVENT"; break;
	case SCE_NP_MATCHING2_ROOM_EVENT: event_name = "ROOM_EVENT"; break;
	case SCE_NP_MATCHING2_ROOM_MSG_EVENT: event_name = "ROOM_MSG_EVENT"; break;
	case SCE_NP_MATCHING2_LOBBY_EVENT: event_name = "LOBBY_EVENT"; break;
	case SCE_NP_MATCHING2_LOBBY_MSG_EVENT: event_name = "LOBBY_MSG_EVENT"; break;
	case SCE_NP_MATCHING2_SIGNALING_EVENT: event_name = "SIGNALING_EVENT"; break;
	default: event_name = "UNHANDLED"; break;
	}
	NOTICE_LOG(Log::sceNet, "%s - Added Callback FUN_%08x(%08x) for %s", __FUNCTION__, handler.cb, handler.cb_arg, event_name.c_str());
	return true;
}

/* Thread-safe Abort Return for all Callback threads
 * @return u32 System Error Code (SCE_NP_MATCHING2_ERROR_ABORTED)
 * @note The tasks aren't stopped, they still process in the background. But, without the handler, they'll simply fail.
 */
int abortNpMatching2Handlers() {

	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);
	for (std::map<u32, NpMatching2Handler>::iterator it = npMatching2Handlers.begin(); it != npMatching2Handlers.end(); ++it) {

		u32_le args[6];
		args[0] = it->second.ctx_id;			// ContextID
		args[1] = 0;							// RequestId || 0 indicates aborted request
		args[2] = it->second.event_type;		// Event
		args[3] = SCE_NP_MATCHING2_ERROR_ABORTED;// ErrorCode || 0 is OK
		args[4] = 0;							// Response struct
		args[5] = it->second.cb_arg.ptr;		// Request Arguments?

		// Call the function immediately
		hleEnqueueCall(it->second.cb.ptr, 6, args);
	}

	return SCE_NP_MATCHING2_ERROR_ABORTED;
}

/* Thread-safe Event Processor for Request Callback. Relevant arguments will be replaced.
 * @param event_code Related System Request Type, matches the Handler
 * @param argc Count of the number of arguments
 * @param args Variable length of arguments, MAX_ARGS = 11
 * @note If there are any problems writing to np_memory, it may be prudent to run a thread-sanitized environment instead
 */
int notifyRequestHandler(SceNpMatching2RequestId reqId, SceNpMatching2Event event, s32 errorCode, u32 dataPtr) {
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	u32 args[6];
	//args[0] = ctxId	// ContextID
	args[1] = reqId;	// RequestId || 0 indicates aborted request
	args[2] = event;	// Event
	args[3] = errorCode;// ErrorCode || 0 is OK
	args[4] = dataPtr;	// Response struct
	//args[5] = argsPtr	// Request Arguments

	npMatching2Events.push_back(NpMatching2Args(reqId, SCE_NP_MATCHING2_REQUEST_EVENT, 6, args));

	return 0;
}

/* Thread-safe Event Processor for related Callback. Relevant arguments will be replaced.
 * @param event_code Related System Request Type, matches the Handler
 * @param argc Count of the number of arguments
 * @param args Variable length of arguments, MAX_ARGS = 11
 * @note If there are any problems writing to np_memory, it may be prudent to run a thread-sanitized environment instead
 */
int notifyRoomMessageHandler(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId, SceNpMatching2Event event, u32 dataPtr) {
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	u32 args[8];
	//args[0] = ctxId	// ContextID
	args[1] = roomId;	// RoomID
	args[2] = 2;		// ConnId?
	args[3] = 3;		// param_4 - EventKey?
	args[4] = memberId;	// MemberID
	args[5] = event;	// Event
	args[6] = dataPtr;	// Message
	//args[7] = argsPtr	// Request Arguments

	npMatching2Events.push_back(NpMatching2Args(SCE_NP_MATCHING2_ROOM_MSG_EVENT, 8, args));

	return 0;
}

/* Thread-safe Event Processor for related Callback. Relevant arguments will be replaced.
 * @param event_code Related System Request Type, matches the Handler
 * @param argc Count of the number of arguments
 * @param args Variable length of arguments, MAX_ARGS = 11
 * @note If there are any problems writing to np_memory, it may be prudent to run a thread-sanitized environment instead
 */
int notifyRoomEventHandler(SceNpMatching2RoomId roomId, SceNpMatching2RoomMemberId memberId, SceNpMatching2Event event, u32 dataPtr) {
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	u32 args[7];
	//args[0] = ctxId	// ContextID
	args[1] = roomId;	// RoomID
	args[2] = 2;		// ConnectionID?
	args[3] = memberId;	// MemberID?
	args[4] = event;	// Event
	args[5] = dataPtr;	// ErrorCode
	//args[6] = argsPtr	// Request Arguments

	npMatching2Events.push_back(NpMatching2Args(SCE_NP_MATCHING2_ROOM_EVENT, 7, args));

	return 0;
}

/* Thread-safe Event Processor for related Callback. Relevant arguments will be replaced.
 * @param event_code Related System Request Type, matches the Handler
 * @param argc Count of the number of arguments
 * @param args Variable length of arguments, MAX_ARGS = 11
 * @note If there are any problems writing to np_memory, it may be prudent to run a thread-sanitized environment instead
 */
int notifySignalingHandler(u32 room_id, u32 conn_id, u32 unknown, u32 roomMemberId, u32 eventCode, u32 errorCode) {
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	// FIXME: Need confirmation on arguments for conn_id, room_id
	u32 args[8];
	//args[0] = ctxId;		// ContextID
	args[1] = room_id;		// room_id?
	args[2] = conn_id;		// conn_id?
	args[3] = unknown;		// unknown?
	args[4] = roomMemberId;	// roomMemberId
	args[5] = eventCode;	// EventCode
	args[6] = errorCode;	// ErrorCode
	//args[7] = 0;			// cbArgs

	npMatching2Events.push_back(NpMatching2Args(SCE_NP_MATCHING2_SIGNALING_EVENT, 8, args));

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

	// Process matching Event_Code
	for (std::map<u32, NpMatching2Handler>::iterator it = npMatching2Handlers.begin(); it != npMatching2Handlers.end(); ++it) {
		if (it->first == event.event_code)
		{
			switch (it->second.event_type) {
			// RequestCallback
			case SCE_NP_MATCHING2_REQUEST_EVENT:
				event.args[0] = it->second.ctx_id;
				event.args[5] = it->second.cb_arg.ptr;

				NOTICE_LOG(Log::sceNet, "SceNpMatching2RequestCallback - FUN_%08x(ctxId: %d, reqId: %d, event: %d, error: %08x, dataPtr: %08x, cbArgPtr: %08x)", it->second.cb.ptr,
					event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5]);
				break;
			case SCE_NP_MATCHING2_ROOM_EVENT:
				event.args[0] = it->second.ctx_id;
				event.args[6] = it->second.cb_arg.ptr;

				NOTICE_LOG(Log::sceNet, "SceNpMatching2RoomEventCallback - FUN_%08x(ctxId: %d, roomId: %d, param_3: %08x, memberId: %d, event: %08x, dataPtr: %08x, argPtr: %08x)", it->second.cb.ptr,
					event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5], event.args[6]);
				break;
			case SCE_NP_MATCHING2_ROOM_MSG_EVENT:
				event.args[0] = it->second.ctx_id;
				event.args[7] = it->second.cb_arg.ptr;

				NOTICE_LOG(Log::sceNet, "SceNpMatching2RoomMessageCallback - FUN_%08x(ctxId: %d, roomId: %d, memberId: %d, param_4: %08x, param_5: %08x, event: %08x, dataPtr: %08x, argPtr: %08x)", it->second.cb.ptr,
					event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5], event.args[6], event.args[7]);
				break;
			case SCE_NP_MATCHING2_LOBBY_EVENT:
				event.args[0] = it->second.ctx_id;

				ERROR_LOG(Log::sceNet, "UNIMPLEMENTED SceNpMatching2LobbyEventCallback - FUN_%08x(ctxId: %d)", it->second.cb.ptr, event.args[0]);
				return false;
			case SCE_NP_MATCHING2_LOBBY_MSG_EVENT:
				event.args[0] = it->second.ctx_id;

				ERROR_LOG(Log::sceNet, "UNIMPLEMENTED SceNpMatching2LobbyMessageCallback - FUN_%08x(ctxId: %d)", it->second.cb.ptr, event.args[0]);
				return false;
			case SCE_NP_MATCHING2_SIGNALING_EVENT:
				event.args[0] = it->second.ctx_id;
				event.args[7] = it->second.cb_arg.ptr;

				NOTICE_LOG(Log::sceNet, "SceNpMatching2SignalingCallback - FUN_%08x(param_1: %d, param_2: %d, param_3: %d, param_4: %d, param_5: %d, param_6: %d, param_7: %d, param_8: %08x)", it->second.cb.ptr,
					event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5], event.args[6], event.args[7]);
				break;
			default:
				NOTICE_LOG(Log::sceNet, "UNHANDLED Callback Type %d - FUN_%08x(ctxId: %d)", event.event_code, it->second.cb.ptr, event.args[0]);
				return false;
			}
			//DEBUG_LOG(Log::sceNet, "NpMatching2Callback [HandlerID=%i][EventID=%04x][State=%04x][ArgsPtr=%08x]", it->first, event, stat, it->second.argument);

			hleEnqueueCall(it->second.cb.ptr, event.argc, event.args);
			return true;
		}
	}
	ERROR_LOG(Log::sceNet, "%s - No Handler Found for Event %d", __FUNCTION__, event.event_code);
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
	//if (npMatching2Inited)
	//	return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_ALREADY_INITIALIZED);

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
	np_memory.Init(npPoolAddr, poolSize, false);

	npMatching2MemStat.npMemSize = poolSize - 0x20;
	npMatching2MemStat.npMaxMemSize = 0x4050; // Dummy maximum foot print
	npMatching2MemStat.npFreeMemSize = npMatching2MemStat.npMemSize;

	npMatching2Handlers.clear();
	npMatching2Events.clear();
	npMatching2Inited = true;
	return 0;
}

static int sceNpMatching2Term()
{
	WARN_LOG(Log::sceNet, "UNTESTED %s() at %08x", __FUNCTION__, currentMIPS->pc);

	npMatching2Inited = false;
	npMatching2Handlers.clear();
	npMatching2Events.clear();

	FreeUser(npPoolAddr);

	return 0;
}

static int sceNpMatching2CreateContext(u32 communicationIdPtr, u32 passPhrasePtr, u32 ctxIdPtr, int unknown)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%08x[%s], %08x[%08x], %08x[%hu], %i) at %08x", __FUNCTION__, communicationIdPtr, safe_string(Memory::GetCharPointer(communicationIdPtr)), passPhrasePtr, Memory::Read_U32(passPhrasePtr), ctxIdPtr, Memory::Read_U16(ctxIdPtr), unknown, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (!Memory::IsValidAddress(communicationIdPtr) || !Memory::IsValidAddress(passPhrasePtr) || !Memory::IsValidAddress(ctxIdPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_MAX);

	// FIXME: It seems Context are mapped to TitleID? may return 0x80550C05 or 0x80550C06 when finding an existing context
	SceNpCommunicationId* titleid = (SceNpCommunicationId*)Memory::GetCharPointer(communicationIdPtr);
	memcpy(&npTitleId, titleid, sizeof(SceNpCommunicationId));

	SceNpCommunicationPassphrase* passph = (SceNpCommunicationPassphrase*)Memory::GetCharPointer(passPhrasePtr);

	// TODO: Get NPID from RPCN - login(nous),password,token(from email) - RPCS3 @GalCiv
	/*SceNpId* npid = NpGetNpId();
	if (!npid)
		return hleLogError(Log::sceNet, SCE_NP_MANAGER_ERROR_ID_NOT_AVAIL);*/

	INFO_LOG(Log::sceNet, "%s - Title ID: %s", __FUNCTION__, npTitleId.data);
	INFO_LOG(Log::sceNet, "%s - Title NUM: %d", __FUNCTION__, npTitleId.num);
	//INFO_LOG(Log::sceNet, "%s - Online ID: %s", __FUNCTION__, npid->handle.data);
	INFO_LOG(Log::sceNet, "%s - User ID: %d", __FUNCTION__, npAuthServer->GetUserID());
	INFO_LOG(Log::sceNet, "%s - Login ID: %s", __FUNCTION__, g_Config.sPSNNPID.c_str());
	INFO_LOG(Log::sceNet, "%s - Online ID: %s", __FUNCTION__, npAuthServer->GetOnlineName().c_str());
	INFO_LOG(Log::sceNet, "%s - Avatar URL: %s", __FUNCTION__, npAuthServer->GetAvatarURL().c_str());
	std::string datahex;
	/*DataToHexString(npid->opt, sizeof(npid->opt), &datahex);
	INFO_LOG(Log::sceNet, "%s - Options?: %s", __FUNCTION__, datahex.c_str());
	datahex.clear();*/
	DataToHexString(10, 0, passph->data, sizeof(passph->data), &datahex);
	INFO_LOG(Log::sceNet, "%s - Passphrase: \n%s", __FUNCTION__, datahex.c_str());

	// TODO: Allocate & zeroed a memory of 68 bytes where npId (36 bytes) is copied to offset 8, offset 44 = 0x00026808, offset 48 = 0

	// Returning dummy Id, a 16-bit variable according to JPCSP
	// FIXME: It seems ctxId need to be in the range of 1 to 7 to be valid ?
	Memory::Write_U16(1, ctxIdPtr);
	return 0;
}

static int sceNpMatching2ContextStart(int ctxId)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d) at %08x", __FUNCTION__, ctxId, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	//if (!npMatching2Ctx)
	//	return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND); //SCE_NP_MATCHING2_ERROR_INVALID_CONTEXT_ID

	//if (npMatching2Ctx.started)
	//	return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_ALREADY_STARTED);

	// TODO: use sceNpGetUserProfile and check server availability using sceNpService_76867C01
	//npMatching2Ctx.started = true;
	npServer = nullptr;
	//net::PSNAuthAgent::GetServers(&ProcessHostnameWithInfraDNS, npTitleId, &servers);
	//net::RPCNAuthAgent::GetServers(npTitleId, &servers);
	npAuthServer->GetServers(npTitleId);
	// We don't need the auth agent after this.
	npAuthServer->Disconnect();

	// Just in case the NPAgent is hosted on a different physical server
	npServer->Resolve();
	std::string npid = net::RPCNAuthAgent::generate_npid();
	bool connected = npServer->Connect();
	if (!connected) {
		ERROR_LOG(Log::sceNet, "Could not connect.");
		return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_SERVICE_UNAVAILABLE), 0);
	}

	int ret;

	std::string* creds = NpGetLogin();
	ret = npServer->Login(creds[0].c_str(), creds[2].c_str(), creds[1].c_str());
	if (ret != 0) {
		ERROR_LOG(Log::sceNet, "Unable to Log In");
		return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, hleLogError(Log::sceNet, ret), 0);
	}

	////signaling_handler::print_interfaces();
	//if (g_signaling.connect("fe80::be24:11ff:fed8:39c4", 3657, 21)) {
	//	NOTICE_LOG(Log::sceNet, "Connected to Signaling Server!");
	//}
	//else {
	//	ERROR_LOG(Log::sceNet, "Failed to connect to Signaling Server!");
	//	//return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_SIGNALING_ERROR_CONN_NOT_FOUND));
	//}

	hleEatMicro(1000000);
	// Returning 0x805508A6 (error code inherited from sceNpService_76867C01 which check server availability) if can't check server availability (ie. Fat Princess (US) through http://static-resource.np.community.playstation.net/np/resource/psp-title/NPWR00670_00/matching/NPWR00670_00-matching.xml using User-Agent: "PS3Community-agent/1.0.0 libhttp/1.0.0")
	return 0;
}

static int sceNpMatching2ContextStop(int ctxId)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d) at %08x", __FUNCTION__, ctxId, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	//if (!npMatching2Ctx)
	//	return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND); //SCE_NP_MATCHING2_ERROR_INVALID_CONTEXT_ID

	//if (!npMatching2Ctx.started)
	//	return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_STARTED);

	//TODO: Stop any in-progress HTTPClient communication used on sceNpMatching2ContextStart
	//npMatching2Ctx.started = false;
	// 
	//TODO: Cancel all async tasks and return SCE_NP_MATCHING2_ERROR_ABORTED for each.
	//abortNpMatching2Handlers();


	if (npServer != 0 && npServer->IsConnected()) {
		g_signaling.stop();
		npServer->Disconnect();
	}

	// Delete all tasks
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);
	npMatching2Handlers.clear();

	return 0;
}

static int sceNpMatching2DestroyContext(int ctxId)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d) at %08x", __FUNCTION__, ctxId, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	//if (!npMatching2Ctx)
	//	return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND); //SCE_NP_MATCHING2_ERROR_INVALID_CONTEXT_ID

	// Remove callback handler
	int handlerID = ctxId - 1;
	if (npMatching2Handlers.find(handlerID) != npMatching2Handlers.end()) {
		npMatching2Handlers.erase(handlerID);
		WARN_LOG(Log::sceNet, "%s: Deleted handler %d", __FUNCTION__, handlerID);
	}
	else {
		ERROR_LOG(Log::sceNet, "%s: Invalid Context ID %d", __FUNCTION__, ctxId);
	}

	return 0;
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

	return 0;
}

static int sceNpMatching2RegisterSignalingCallback(int ctxId, u32 callbackFunctionAddr, u32 callbackArgument)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x) at %08x", __FUNCTION__, ctxId, callbackFunctionAddr, callbackArgument, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (ctxId <= 0)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_CONTEXT_ID);

	if (callbackFunctionAddr == 0 || !Memory::IsValidAddress(callbackFunctionAddr)) {
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT, "%s - Invalid Callback %08x", __FUNCTION__, callbackFunctionAddr);
	}

	/*auto ctx = get_match2_context(ctxId);

	if (!ctx)
	{
		return SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND;
	}
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	std::lock_guard lock(ctx->mutex);
	ctx->signaling_cb = callbackFunctionAddr;
	ctx->signaling_cb_arg = callbackArgument;*/

	//auto& sigh = g_fxo->get<named_thread<signaling_handler>>();
	//sigh.add_match2_ctx(ctxId);


	RegisterNpMatching2Handler(ctxId, callbackFunctionAddr, callbackArgument, SCE_NP_MATCHING2_SIGNALING_EVENT);

	// FIXME: This thread runs even when you trigger break
	// RPCS3 has only 1 connection perpetually active
	// As such, it has additional functions in sceNp that
	//  trigger signaling to start, and P2P connect requests
	if (g_signaling.create_connection())
		npServer->StartSignalingThread();
	else
		ERROR_LOG(Log::sceNet, "Signaling Loop could not be started.");

	//notifySignalingHandler(0, 0, 0, 0, SCE_NP_MATCHING2_SIGNALING_EVENT_Established, SCE_NP_MATCHING2_SIGNALING_EVENT);

	/*ContextState ctx = {
		(u32)ctxId,
		callbackFunctionAddr,
		callbackArgument,
		0
	};
	g_signaling.add_match2_ctx(ctx);*/

	//struct NpMatching2Handler handler;
	//npSignalingCallback = {};

	//npSignalingCallback.ctx_id = ctxId; // double handle
	//npSignalingCallback.cb = callbackFunctionAddr;
	//npSignalingCallback.cb_arg = callbackArgument;

	//npMatching2Handlers[0] = handler;
	//NOTICE_LOG(Log::sceNet, "%s - Added SignalingCallback FUN_%08x(%08x)", __FUNCTION__, callbackFunctionAddr, callbackArgument);
	/*if (npMatching2Handlers.find(ctxId) == npMatching2Handlers.end()) {
		npMatching2Handlers[ctxId] = handler;
		WARN_LOG(Log::sceNet, "%s - Added handler(%08x, %08x) : %d", __FUNCTION__, handler.cb, handler.cb_arg, ctxId);
		return ctxId;
	}
	else {
		ERROR_LOG(Log::sceNet, "%s - Same handler(%08x, %08x) already exists", __FUNCTION__, handler.cb, handler.cb_arg);
	}*/
	//u32 dataLength = 4097; 
	//notifyNpMatching2Handlers(retval, dataLength, handler.argument);

	// callback struct have 57 * u32? where [0]=0, [40]=flags, [55]=callbackFunc, and [56]=callbackArgs?
	//hleEnqueueCall(callbackFunctionAddr, 7, (u32*)Memory::GetPointer(callbackArgument), nullptr); // 7 args? since the callback handler is trying to use t2 register
	return 0; // error returns 0x80550004
}

// roomId may be a struct containing room info?
static int sceNpMatching2SignalingGetConnectionStatus(int ctxId, u32 unknown, u32 roomId, u32 unknown1, u32 memberId, u32 connInfoPtr) {
	ERROR_LOG(Log::sceNet, "UNIMPL %s(ctx: %d, %08X, roomId: %d, %08X, memberId: %d, connInfoPtr: 0x%08X) at %08x", __FUNCTION__, ctxId, unknown, roomId, unknown1, memberId, connInfoPtr, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (connInfoPtr == 0 || !Memory::IsValidAddress(connInfoPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT, "unkPtr is an invalid pointer");

	auto connInfo = PSPPointer<ScenpMatching2SignalingInfo>::Create(connInfoPtr);

	auto member = npServer->cache.GetMember(memberId);
	if (!member) {
		connInfo->status = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_ROOM_MEMBER_NOT_FOUND, "Member not found");
	}

	if (strncmp(NpGetNpId()->handle.data, member->userInfo.npId.handle.data, 16) == 0) {
		connInfo->status = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;
		return hleLogError(Log::sceNet, SCE_NP_SIGNALING_ERROR_OWN_NP_ID, "Member is Self");
	}
	auto connID = g_signaling.get_conn_id_from_npid(member->userInfo.npId);


	auto si = g_signaling.get_sig_infos(*connID);
	if (!si) {
		connInfo->status = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;
		return hleLogError(Log::sceNet, SCE_NP_SIGNALING_ERROR_CONN_NOT_FOUND, "Not Connected");
	}
	
	// Write Connection Status
	connInfo->status = SCE_NP_SIGNALING_CONN_STATUS_ACTIVE;
	// Write IPAddress
	connInfo->ipaddr.np_s_addr = si->addr;
	// Write Port
	connInfo->port = si->port;

	return hleLogError(Log::sceNet, SCE_NP_MATCHING2_OKAY, "Assigned Address for %s to %s:%d", member->userInfo.npId.handle.data, ip2str(si->addr).c_str(), si->port);
}

/* Allocates the list of server Id's to memory
 * @param serverIdsPtr Pointer to where the servers should be written
 * @param maxServerIds maximum number of servers the client can receive
 * @return Number of servers we allocated
 * @note PSP has been observed writing these in decremental order
 */
static int sceNpMatching2GetServerIdListLocal(int ctxId, u32 serverIdsPtr, int maxServerIds)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %d) at %08x", __FUNCTION__, ctxId, serverIdsPtr, maxServerIds, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (!Memory::IsValidAddress(serverIdsPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	if (npServer->servers.size() == 0)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND);

	std::vector<u16> server_list;
	for (auto it = npServer->servers.begin(); it != npServer->servers.end() && server_list.size() < maxServerIds; ++it) {
		server_list.push_back(it->first);
	}

	int ofs = 0;
	for (auto rit = server_list.rbegin(); rit != server_list.rend(); ++rit, ofs+=2) {
		Memory::Write_U16(*rit, serverIdsPtr + ofs);
	}
	/*for (auto it = servers.rbegin(); it != servers.rend() && count < maxServerIds; ++it, ++count) {
		Memory::Write_U16(it->first, serverIdsPtr + ofs);
		ofs += 2;
	}*/

	// Return the number of servers allocated to memory
	return server_list.size();
}

/* Produces information about a target server
 * @param serverIdPtr Pointer to the target Server ID
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 * @note PSP2i calls this once witha reqId 0, and then once for each server allocated in sceNpMatching2GetServerIdListLocal
 */
static int sceNpMatching2GetServerInfo(int ctxId, u32 serverIdPtr, u32 optParam, u32 assignedReqIdPtr) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x[%d], %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, serverIdPtr, Memory::Read_U16(serverIdPtr), optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetServerInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(serverIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetServerInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		// Server ID is a 16-bit variable according to JPCSP
		u16 serverId;
		if ((serverId = Memory::Read_U16(serverIdPtr)) == 0)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetServerInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_SERVER_ID), 0);

		// Check server status
		//servers[serverId]->Resolve();

		u32 infoSize = sizeof(SceNpMatching2ServerInfo);
		SceNpMatching2ServerInfo serverInfo = npServer->GetServerInfo(serverId);

		// Allocate space, and write value into the pool
		u32 serverInfoPtr = np_memory.Alloc(infoSize);
		Memory::Write_Struct(serverInfo, serverInfoPtr, "SceNpMatching2ServerInfo", 25);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetServerInfo, SCE_NP_MATCHING2_OKAY, serverInfoPtr);
	}); // ThreadEnd
	tasks.emplace(request_id, std::move(task));
	return 0;
}

/* Produces information about the lobbies, parties, and existing player counts
 * @param serverIdPtr Pointer to the target Server ID
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 * @note This function occurs immediately after a server has been selected
 */
static int sceNpMatching2GetWorldInfoList(int ctxId, u32 serverIdPtr, u32 optParam, u32 assignedReqIdPtr) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x[%d], %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, serverIdPtr, Memory::Read_U16(serverIdPtr), optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(serverIdPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		// Server ID is a 16-bit variable according to JPCSP
		u16 serverId;
		if ((serverId = Memory::Read_U16(serverIdPtr)) == 0)
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_SERVER_ID), 0);

		npServer->SelectServer(serverId);
		std::vector<SceNpMatching2World> worldArray;
		int worldNum = npServer->GetWorldInfo(serverId, npTitleId, &worldArray);
		if (worldNum < 0) {
			ERROR_LOG(Log::sceNet, "Error requesting WorldInfo: %08X", worldNum);
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);
		}
		// First attempts for new games won't contain a world.
		if (worldNum == 0) {
			ERROR_LOG(Log::sceNet, "No Worlds Returned");
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_WORLD), 0);
		}

		// Allocate space for all worlds
		u32 worldsSize = sizeof(SceNpMatching2World) * worldNum;
		// We have a maximum size
		if (worldsSize > SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetWorldInfoList)
			worldsSize = SCE_NP_MATCHING2_EVENT_DATA_MAX_SIZE_GetWorldInfoList;
		auto worlds = PSPPointer<SceNpMatching2World>::Create(np_memory.Alloc(worldsSize));
		// Transfer WorldID
		NOTICE_LOG(Log::sceNet, "Received %d worlds", worldNum);
		for (int i = 0; i < worldsSize / sizeof(SceNpMatching2World); i++)
		{
			NOTICE_LOG(Log::sceNet, " - World %d => WorldId: %d", i, worldArray[i].worldId);
			worlds[i].worldId = worldArray[i].worldId;
			npServer->cache.AddWorld(worldArray[i]);
		}

		u32 alloc = sizeof(SceNpMatching2GetWorldInfoListResponse);
		auto resp = PSPPointer<SceNpMatching2GetWorldInfoListResponse>::Create(np_memory.Alloc(alloc));
		resp->worldNum = worldNum;
		resp->world = worlds;

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList, SCE_NP_MATCHING2_OKAY, resp.ptr);
	}); // ThreadEnd
	tasks.emplace(request_id, std::move(task));
	return 0;
}

/* Incomplete - Searches for all Lobbies/Parties
 * @param reqParamPtr SceNpMatching2SearchRoomRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SearchRoom(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
		return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		const PSPPointer<SceNpMatching2SearchRoomRequest> req = PSPPointer<SceNpMatching2SearchRoomRequest>::Create(reqParamPtr);

		INFO_LOG(Log::sceNet, "SceNpMatching2SearchRoomRequest(%08X)", req.ptr);
		INFO_LOG(Log::sceNet, " - option:       %d", req->option);
		INFO_LOG(Log::sceNet, " - worldId:      %d", req->worldId);
		INFO_LOG(Log::sceNet, " - lobbyId:      %d", req->lobbyId);
		INFO_LOG(Log::sceNet, " - rangeFilter:  %d", req->rangeFilter);
		INFO_LOG(Log::sceNet, " - flagFilter:   %d", req->flagFilter);
		INFO_LOG(Log::sceNet, " - flagAttr:     %d", req->flagAttr);
		INFO_LOG(Log::sceNet, " - intFilterNum: %d", req->intFilterNum);
		INFO_LOG(Log::sceNet, " - binFilterNum: %d", req->binFilterNum);
		INFO_LOG(Log::sceNet, " - attrIdNum:    %d", req->attrIdNum);
		if (!npServer->cache.GetWorld(req->worldId)) {
			ERROR_LOG(Log::sceNet, " - Invalid World ID");
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM), 0);
		}
			
		// WARNING! This is a constant, and thus read-only
		const SearchRoomResponse* roomResp;

		int ret = npServer->SearchRoom(req, roomResp);

		if (ret != 0) {
			ERROR_LOG(Log::sceNet, "Unable to retrieve Room Info");
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, hleLogError(Log::sceNet, ret), 0);
		}

		uint32_t room_count = roomResp->rooms() ? roomResp->rooms()->size() : 0;
		uint32_t start_index = roomResp->startIndex();
		uint32_t total_rooms = roomResp->total();

		INFO_LOG(Log::sceNet, " - Start Index: %d", start_index);
		INFO_LOG(Log::sceNet, " - Total:       %d", total_rooms);
		INFO_LOG(Log::sceNet, " - Rooms:       %d", room_count);

		u32 respSize = sizeof(SceNpMatching2SearchRoomResponse);
		u32 respPtr = np_memory.Alloc(respSize);
		auto respData = PSPPointer<SceNpMatching2SearchRoomResponse>::Create(respPtr);
		np::SearchRoomResponse_to_SceNpMatching2SearchRoomResponse(np_memory, roomResp, respData);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom, SCE_NP_MATCHING2_OKAY, respPtr);
	});
	tasks.emplace(request_id, std::move(task));

	return 0;
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
static int sceNpMatching2CreateJoinRoom(int ctxId, u32 reqParamPtr, u32 optParam, u32 roomEventCbPtr, u32 roomMessageCbPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, roomEventCbPtr, roomMessageCbPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		if (Memory::IsValidAddress(roomEventCbPtr)) {
			u32 roomEventCb = Memory::Read_U32(roomEventCbPtr);
			if (Memory::IsValidAddress(roomEventCb))
				RegisterNpMatching2Handler(ctxId, roomEventCb, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_ROOM_EVENT);
		}

		if (Memory::IsValidAddress(roomMessageCbPtr)) {
			u32 roomMessageCb = Memory::Read_U32(roomMessageCbPtr);
			if (Memory::IsValidAddress(roomMessageCb))
			RegisterNpMatching2Handler(ctxId, roomMessageCb, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_ROOM_MSG_EVENT);
		}

		auto req = PSPPointer<SceNpMatching2CreateJoinRoomRequest>::Create(reqParamPtr);
		//Memory::Memcpy(&req, reqParamPtr, sizeof(req));

		INFO_LOG(Log::sceNet, "SceNpMatching2CreateJoinRoomRequest(%08X)", req.ptr);
		INFO_LOG(Log::sceNet, " - worldId:          %d", req->worldId);
		INFO_LOG(Log::sceNet, " - lobbyId:          %d", req->lobbyId);
		INFO_LOG(Log::sceNet, " - maxSlot:          %d", req->maxSlot);
		INFO_LOG(Log::sceNet, " - flagAttr:         %08X", req->flagAttr);
		INFO_LOG(Log::sceNet, " - roomBinAttrInternalNum: %d", req->roomBinAttrInternalNum);
		INFO_LOG(Log::sceNet, " - roomSearchableIntAttrExternalNum: %d", req->roomSearchableIntAttrExternalNum);
		INFO_LOG(Log::sceNet, " - roomSearchableBinAttrExternalNum: %d", req->roomSearchableBinAttrExternalNum);
		INFO_LOG(Log::sceNet, " - roomBinAttrExternalNum: %d", req->roomBinAttrExternalNum);
		//INFO_LOG(Log::sceNet, " - roomPassword:     %s", req->roomPassword->data);
		INFO_LOG(Log::sceNet, " - groupConfigNum:   %d", req->groupConfigNum);
		INFO_LOG(Log::sceNet, " - passwordSlotMask: %d", req->passwordSlotMask);
		INFO_LOG(Log::sceNet, " - allowedUserNum:   %d", req->allowedUserNum);
		INFO_LOG(Log::sceNet, " - blockedUserNum:   %d", req->blockedUserNum);
		INFO_LOG(Log::sceNet, " - roomMemberBinAttrInternalNum: %d", req->roomMemberBinAttrInternalNum);
		INFO_LOG(Log::sceNet, " - teamId:           %d", req->teamId);
		// Patapon 3 requests WorldID 0. Is this suppose to be the first available world?
		//if (req->worldId == 0)
			//req->worldId = servers[tServer]->worlds.begin()->first;
		if (!npServer->cache.GetWorld(req->worldId)) {
			ERROR_LOG(Log::sceNet, " - Invalid worldId");
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ROOM_ID), 0);
		}
		// FIXME: Populate all relevant data from req into memory as required
		const RoomDataInternal* resp;

		// FIXME: Get roomData from PSN
		int ret = npServer->CreateJoinRoom(req, resp);
		if (ret != 0) {
			ERROR_LOG(Log::sceNet, "Unable to Create Room: %08X", ret);
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::sceNet, ret), 0);
		}

		u32 infoSize = sizeof(SceNpMatching2RoomDataInternal);
		u32 roomDataPtr = np_memory.Alloc(infoSize);

		if (!Memory::IsValidAddress(roomDataPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomDataExternal");
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY), 0);
		}
		auto room_info = PSPPointer<SceNpMatching2RoomDataInternal>::Create(roomDataPtr);
		SceNpId* npId = NpGetNpId();
		np::RoomDataInternal_to_SceNpMatching2RoomDataInternal(np_memory, resp, room_info, npId, true, false);

		// Cache Rooms
		//rooms.push_back(roomData);
		SceNpMatching2CreateJoinRoomResponse respData{};
		respData.roomDataInternal = room_info;

		u32 respSize = sizeof(respData);
		u32 respPtr = np_memory.Alloc(respSize);

		if (!Memory::IsValidAddress(respPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomResponse");
			return notifyRequestHandler(0, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY), 0);
		}
		Memory::Write_Struct(respData, respPtr, "SceNpMatching2CreateJoinRoomResponse", 37);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom, SCE_NP_MATCHING2_OKAY, respPtr);
	});
	tasks.emplace(request_id, std::move(task));

	return 0;
}

/* Incomplete - Joins an existing Lobby/Party
 * @param reqParamPtr ?
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2JoinRoom(int ctxId, u32 reqParamPtr, u32 optParam, u32 roomEventCbPtr, u32 roomMessageCbPtr, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, roomEventCbPtr, roomMessageCbPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		if (Memory::IsValidAddress(roomEventCbPtr))
			RegisterNpMatching2Handler(ctxId, Memory::Read_U32(roomEventCbPtr), opt->cbFuncArg.ptr, SCE_NP_MATCHING2_ROOM_EVENT);

		if (Memory::IsValidAddress(roomMessageCbPtr))
			RegisterNpMatching2Handler(ctxId, Memory::Read_U32(roomMessageCbPtr), opt->cbFuncArg.ptr, SCE_NP_MATCHING2_ROOM_MSG_EVENT);

		auto req = PSPPointer<SceNpMatching2JoinRoomRequest>::Create(reqParamPtr);
		const JoinRoomResponse* resp;

		// FIXME: Get roomData from PSN
		int ret = npServer->JoinRoom(req, resp);

		u32 sizeof_room_resp = sizeof(SceNpMatching2JoinRoomResponse);
		u32 roomRespPtr = np_memory.Alloc(sizeof_room_resp);
		auto room_resp = PSPPointer<SceNpMatching2JoinRoomResponse>::Create(roomRespPtr);

		u32 sizeof_room_info = sizeof(SceNpMatching2RoomDataInternal);
		u32 roomInfoPtr = np_memory.Alloc(sizeof_room_info);
		auto room_info = PSPPointer<SceNpMatching2RoomDataInternal>::Create(roomInfoPtr);

		room_resp->roomDataInternal = room_info;

		SceNpId* npId = NpGetNpId();
		np::RoomDataInternal_to_SceNpMatching2RoomDataInternal(np_memory, resp->room_data(), room_info, npId, false, false);
		// Cache room_info
		npServer->cache.AddRoom(*room_info);

		// We initiate signaling if necessary
		if (const auto* signaling_data = resp->signaling_data())
		{
			const u64 room_id = resp->room_data()->roomId();

			for (unsigned int i = 0; i < signaling_data->size(); i++)
			{
				const auto* signaling_info = signaling_data->Get(i);
				//ensure(signaling_info->addr());

				const u32 sig_ip = static_cast<u32>(signaling_info->addr()->ip()->Get(0)) << 24 | static_cast<u32>(signaling_info->addr()->ip()->Get(1)) << 16 |
					static_cast<u32>(signaling_info->addr()->ip()->Get(2)) << 8 | static_cast<u32>(signaling_info->addr()->ip()->Get(3));

				const u32 addr_p2p = htonl(sig_ip);
				const u16 port_p2p = signaling_info->addr()->port();

				const u16 member_id = signaling_info->member_id();

				auto member = npServer->cache.GetMember(member_id);

				if (!member)
					continue;

				NOTICE_LOG(Log::sceNet, "JoinRoomResult told to connect to member(%d=%s) of room(%d): %s:%d", member_id, reinterpret_cast<const char*>(member->userInfo.npId.handle.data), room_id, ip2str(addr_p2p).c_str(), port_p2p);

				// Attempt Signaling
				const u32 conn_id = g_signaling.init_sig(member->userInfo.npId, room_id, member_id);
				g_signaling.connect(conn_id, addr_p2p, port_p2p);
			}
		}

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom, SCE_NP_MATCHING2_OKAY, roomRespPtr);
	});
	tasks.emplace(request_id, std::move(task));

	return 0;
}

/* Incomplete - Leaves the current Lobby/Party
 * @param reqParamPtr ?
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2LeaveRoom(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);
	
	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		auto req = PSPPointer<SceNpMatching2LeaveRoomRequest>::Create(reqParamPtr);
		u64 roomId = req->roomId;
		int ret = npServer->LeaveRoom(req, &roomId);

		// Execute signaling callback to update users
		g_signaling.DisconnectUsers(roomId);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom, SCE_NP_MATCHING2_OKAY, 0);
	});
	tasks.emplace(request_id, std::move(task));

	// After returning, Fat Princess will loop for 64 times (increasing the address by 288 bytes on each loop) or until found a zero status byte (0x08BD4860 + 0x10), looking for empty/available entry to set?
	return 0;
}

/* Incomplete - Requests attributes of a specific Lobby/Party
 * @param reqParamPtr SceNpMatching2GetRoomDataInternalRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2GetRoomDataInternal(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);


		auto req = PSPPointer<SceNpMatching2GetRoomDataInternalRequest>::Create(reqParamPtr);
		//Memory::Memcpy(&req, reqParamPtr, sizeof(req));

		INFO_LOG(Log::sceNet, "SceNpMatching2GetRoomDataInternalRequest(%08X)", req.ptr);
		INFO_LOG(Log::sceNet, " - roomId:     %d", req->roomId);
		INFO_LOG(Log::sceNet, " - attrIdNum:  %d", req->attrIdNum);

		/*auto roomData = &npServer->cache.GetRoom(req->roomId);
		if (!roomData) {
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ROOM_ID), 0);
		}*/
		const RoomDataInternal* resp;
		int ret;
		if ((ret = npServer->GetRoomDataInternal(req, resp)) != 0)
		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::sceNet, ret), 0);
		
		u32 alloc = sizeof(SceNpMatching2RoomDataInternal);
		u32 roomInfoPtr = np_memory.Alloc(alloc);
		if (!Memory::IsValidAddress(roomInfoPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomData");
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY), 0);
		}
		auto room_info = PSPPointer<SceNpMatching2RoomDataInternal>::Create(roomInfoPtr);
		np::RoomDataInternal_to_SceNpMatching2RoomDataInternal(np_memory, resp, room_info, NpGetNpId(), false, false);
		// Cache the new Room Info
		npServer->cache.AddRoom(*room_info);

		alloc = sizeof(SceNpMatching2GetRoomDataInternalResponse);
		u32 roomRespPtr = np_memory.Alloc(alloc);
		if (!Memory::IsValidAddress(roomRespPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomResponse");
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY), 0);
		}
		auto room_resp = PSPPointer<SceNpMatching2GetRoomDataInternalResponse>::Create(roomRespPtr);
		room_resp->roomDataInternal = room_info;

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal, SCE_NP_MATCHING2_OKAY, room_resp.ptr);
	});
	tasks.emplace(request_id, std::move(task));

	return 0;
}

/* Incomplete - Unconfirmed. Similar to sceNpMatching2SetRoomDataInternal
 * @param reqParamPtr SceNpMatching2SetRoomDataExternalRequest containing External room information?
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SetRoomDataExternal(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);
	
	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		auto req = PSPPointer<SceNpMatching2SetRoomDataExternalRequest>::Create(reqParamPtr);

		INFO_LOG(Log::sceNet, " - roomId:     %d", req->roomId);

		npServer->SetRoomDataExternal(req);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, SCE_NP_MATCHING2_OKAY, 0);
	});
	tasks.emplace(request_id, std::move(task));

	// After returning, Fat Princess will loop for 64 times (increasing the address by 288 bytes on each loop) or until found a zero status byte (0x08BD4860 + 0x10), looking for empty/available entry to set?
	return 0;
}

/* Incomplete - Sets attributes of a specific Lobby/Party
 * @param reqParamPtr SceNpMatching2GetRoomDataInternalRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SetRoomDataInternal(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		auto req = PSPPointer<SceNpMatching2SetRoomDataInternalRequest>::Create(reqParamPtr);

		INFO_LOG(Log::sceNet, " - roomId:     %d", req->roomId);
		
		int ret;
		if ((ret = npServer->SetRoomDataInternal(req)) != 0)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, hleLogError(Log::sceNet, ret), 0);

		/*auto [r, self] = npServer->GetSelf(req->roomId);
		if (r == 0)
			g_signaling.init_sig(self->userInfo.npId);*/

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal, SCE_NP_MATCHING2_OKAY, 0);
	});
	tasks.emplace(request_id, std::move(task));

	return 0;
}

/* Incomplete - Sends a Chat Message to relevant players?
 * @param reqParamPtr ? Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SendRoomChatMessage(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage, SCE_NP_MATCHING2_OKAY, 0);
	});
	tasks.emplace(request_id, std::move(task));

	// After returning, Fat Princess will loop for 64 times (increasing the address by 288 bytes on each loop) or until found a zero status byte (0x08BD4860 + 0x10), looking for empty/available entry to set?
	return 0;
}

static int sceNpMatching2SetDefaultRequestOptParam(int ctxId, u32 optParam)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x) at %08x", __FUNCTION__, ctxId, optParam, currentMIPS->pc);

	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (!Memory::IsValidAddress(optParam) || !Memory::IsValidAddress(optParam))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);

	return 0;
}

static int sceNpMatching2SetUserInfo(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		auto req = PSPPointer<SceNpMatching2SetUserInfoRequest>::Create(reqParamPtr);

		int ret = npServer->SetUserInfo(req);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo, ret, 0);
	});
	tasks.emplace(request_id, std::move(task));

	return 0;
}

static int sceNpMatching2GetUserInfoList(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList, SCE_NP_MATCHING2_OKAY, 0);
	});
	tasks.emplace(request_id, std::move(task));

	return 0;
}

static int sceNpMatching2AbortRequest(int ctxId, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x) at %08x", __FUNCTION__, ctxId, assignedReqIdPtr, currentMIPS->pc);

	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	auto request_id = Memory::Read_U32(assignedReqIdPtr);

	// Process matching Event_Code
	for (std::deque<NpMatching2Args>::iterator it = npMatching2Events.begin(); it != npMatching2Events.end(); ++it) {
		if (it->event_code != SCE_NP_MATCHING2_REQUEST_EVENT)
			continue; // Only REQUEST_EVENT tracks Request IDs
		if (it->request_id == request_id) {
			npMatching2Events.erase(it);
			return 0;
		}
	}
	return SCE_NP_MATCHING2_ERROR_REQUEST_NOT_FOUND;
}

static int sceNpMatching2SetSignalingOptParam(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_SIGNALING_EVENT);

	return 0;
}

static int sceNpMatching2GetSignalingOptParamLocal(int ctxId, u32 roomId, u32 optParam)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, optParam, currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (!Memory::IsValidAddress(roomId) || !Memory::IsValidAddress(optParam))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);

	for (std::map<u32, NpMatching2Handler>::iterator it = npMatching2Handlers.begin(); it != npMatching2Handlers.end(); ++it) {
		if (it->first != SCE_NP_MATCHING2_SIGNALING_EVENT)
			continue; // Only REQUEST_EVENT tracks Request IDs
		opt->cbFunc = it->second.cb;
		opt->cbFuncArg = it->second.cb_arg;
		return 0;
	}

	return SCE_NP_MATCHING2_ERROR_CONTEXT_NOT_FOUND;
}

static int sceNpMatching2SignalingGetLocalNetInfo(u32 netInfoPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%08x) at %08x", __FUNCTION__, netInfoPtr, currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (!Memory::IsValidAddress(netInfoPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	auto netInfo = PSPPointer<SceNpMatching2SignalingNetInfo>::Create(netInfoPtr);

	sockaddr_in sockAddr{};
	netInfo->localAddr = getLocalIp(&sockAddr);	// LocalIP
	// FIXME: Get PublicIP from RPCN's Signaling server or PSN's STUN server
	netInfo->mappedAddr = 0;	// PublicIP
	netInfo->natStatus = SCE_NP_SIGNALING_NETINFO_NAT_STATUS_TYPE2;
	return 0;
}

static int sceNpMatching2SignalingGetPeerNetInfo(int ctxId, u32 roomId, u32 roomMemberId, u32 signalingReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, roomId, roomMemberId, signalingReqIdPtr, Memory::Read_U32(signalingReqIdPtr), currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (!Memory::IsValidAddress(signalingReqIdPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	return 0;
}

static int sceNpMatching2SignalingGetPeerNetInfoResult(int ctxId, u32 signalingReqIdPtr, u32 netInfoPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x[%08x], %08x) at %08x", __FUNCTION__, ctxId, signalingReqIdPtr, Memory::Read_U32(signalingReqIdPtr), netInfoPtr, currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (!Memory::IsValidAddress(signalingReqIdPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	return 0;
}

static int sceNpMatching2SignalingCancelPeerNetInfo(int ctxId, u32 signalingReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x[%08x]) at %08x", __FUNCTION__, ctxId, signalingReqIdPtr, Memory::Read_U32(signalingReqIdPtr), currentMIPS->pc);

	// ThreadStart
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (!Memory::IsValidAddress(signalingReqIdPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	return 0;
}

static int sceNpMatching2SignalingGetConnectionInfo(int ctxId, u32 roomId, u32 memberId, u32 code, u32 connInfoPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, memberId, code, connInfoPtr, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

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


static int sceNpMatching2GetRoomDataExternalList(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		auto req = PSPPointer<SceNpMatching2GetRoomDataExternalListRequest>::Create(reqParamPtr);
		const GetRoomDataExternalListResponse* resp;
		npServer->GetRoomDataExternalList(req, resp);

		bool include_onlinename = true, include_avatarurl = false;

		u32 alloc = sizeof(SceNpMatching2GetRoomDataExternalListResponse);
		auto sce_get_room_ext_resp = PSPPointer<SceNpMatching2GetRoomDataExternalListResponse>::Create(np_memory.Alloc(alloc));
		np::GetRoomDataExternalListResponse_to_SceNpMatching2GetRoomDataExternalListResponse(np_memory, resp, sce_get_room_ext_resp, include_onlinename, include_avatarurl);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList, SCE_NP_MATCHING2_OKAY, 0);
	});
	tasks.emplace(request_id, std::move(task));

	return 0;
}

static int sceNpMatching2GetRoomPasswordLocal(int ctxId, u32 roomIdPtr, u32 withPasswordPtr, u32 roomPasswordPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomIdPtr, withPasswordPtr, roomPasswordPtr, currentMIPS->pc);

	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

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

	return 0;
}

/* Incomplete - Sends a Room Message to relevant players?
 * @param reqParamPtr PSPPointer<SceNpMatching2SendRoomMessageRequest> Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqIdPtr Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Sends the message to the NPAgent, and receives a reply via Notification
 */
static int sceNpMatching2SendRoomMessage(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	if (!npMatching2Inited)
		return SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED;

	if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
		return SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT;

	if (!npServer)
		return SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND;

	auto req = PSPPointer<SceNpMatching2SendRoomMessageRequest>::Create(reqParamPtr);

	INFO_LOG(Log::sceNet, " - roomId:     %d", req->roomId);
	INFO_LOG(Log::sceNet, " - castType:   %d", req->castType);
	INFO_LOG(Log::sceNet, " - msgLen:     %d", req->msgLen);

	auto roomData = &npServer->cache.GetRoom(req->roomId);
	if (!roomData)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_SERVER_ERROR_NO_SUCH_ROOM);

	int ret;
	if ((ret = npServer->SendRoomMessage(req)) != 0)
		return hleLogError(Log::sceNet, ret);

	return 0;
}

static int sceNpMatching2GrantRoomOwner(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner, SCE_NP_MATCHING2_OKAY, 0);
	});
	tasks.emplace(request_id, std::move(task));

	return 0;
}

static int sceNpMatching2GetRoomMemberIdListLocal(int ctxId, u32 roomId, u32 sortMethod, u32 memberId, u32 memberIdNum)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, sortMethod, memberId, memberIdNum, currentMIPS->pc);

	return 0;
}

static int sceNpMatching2SetRoomMemberDataInternal(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal, SCE_NP_MATCHING2_OKAY, 0);
	});
	tasks.emplace(request_id, std::move(task));

	return 0;
}

static int sceNpMatching2GetRoomMemberDataInternalLocal(int ctxId, u32 roomId, u32 memberId, u32 attrId, u32 attrIdNum, u32 memberPtr, u32 bufPtr, u32 bufLen)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x, %08x, %08x, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, memberId, attrId, attrIdNum, memberPtr, bufPtr, bufLen, currentMIPS->pc);

	return 0;
}

static int sceNpMatching2GetRoomMemberDataInternal(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal, SCE_NP_MATCHING2_OKAY, 0);
	});
	tasks.emplace(request_id, std::move(task));

	return 0;
}

static int sceNpMatching2GetRoomMemberDataExternalList(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList, SCE_NP_MATCHING2_OKAY, 0);
	});
	tasks.emplace(request_id, std::move(task));

	return 0;
}

static int sceNpMatching2KickoutRoomMember(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	auto opt = PSPPointer<SceNpMatching2RequestOptParam>::Create(optParam);
	RegisterNpMatching2Handler(ctxId, opt->cbFunc.ptr, opt->cbFuncArg.ptr, SCE_NP_MATCHING2_REQUEST_EVENT);
	auto request_id = GenerateRequestId(assignedReqIdPtr);
	// ThreadStart
	std::future<int> task = std::async(std::launch::async, [=]() -> int {
		if (!npMatching2Inited)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_KickoutRoomMember, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED), 0);

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_KickoutRoomMember, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT), 0);

		if (!npServer)
			return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_KickoutRoomMember, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND), 0);

		return notifyRequestHandler(request_id, SCE_NP_MATCHING2_REQUEST_EVENT_KickoutRoomMember, SCE_NP_MATCHING2_OKAY, 0);
	});
	tasks.emplace(request_id, std::move(task));

	return 0;
}






const HLEFunction sceNpMatching2[] = {
	{0xF47342FC, &WrapI_IUI<sceNpMatching2GetServerIdListLocal>,			"sceNpMatching2GetServerIdListLocal",			'i', "ixi"    },
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
	{0x6D6D0C75, &WrapI_IUUUUU<sceNpMatching2SignalingGetConnectionStatus>,	"sceNpMatching2SignalingGetConnectionStatus",	'i', "ixxxxx" },

	{0x2E61F6E1, &WrapI_IIII<sceNpMatching2Init>,							"sceNpMatching2Init",							'i', "iiii"   },
	{0x8BF37D8C, &WrapI_V<sceNpMatching2Term>,								"sceNpMatching2Term",							'i', ""       },
	{0x5030CC53, &WrapI_UUUI<sceNpMatching2CreateContext>,					"sceNpMatching2CreateContext",					'i', "xxxi"   },
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
};

void Register_sceNpMatching2()
{
	RegisterHLEModule("sceNpMatching2", ARRAY_SIZE(sceNpMatching2), sceNpMatching2);
}
