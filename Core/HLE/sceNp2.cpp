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
#include "Core/MemMapHelpers.h"
#include "Core/CoreTiming.h"
#include "Core/HLE/HLE.h"
#include "Core/HLE/FunctionWrappers.h"
#include "Core/HLE/sceNp2.h"
#include <Core\Util\NPAgent.h>
#include "sceNetResolver.cpp"
#include <future>

bool npMatching2Inited = false;
SceNpAuthMemoryStat npMatching2MemStat = {};
u32 npPoolAddr = 0;
BlockAllocator np_memory;

std::recursive_mutex npMatching2EvtMtx;
std::deque<NpMatching2Args> npMatching2Events;
std::map<u32, NpMatching2Handler> npMatching2Handlers;
//std::map<int, NpMatching2Context> npMatching2Contexts;
u16 tServer;
std::map<u16, std::unique_ptr<net::NPAgent>> servers;
SceNpMatching2Data npData;

template <typename T>
void Write_Struct(const T& object, const u32 address, const char* tag, size_t taglen) {
	Memory::Memcpy(address, &object, sizeof(T), tag, taglen);
}

/* Generate a callback handler for async processing returns
 * @param optParamPtr pointer to SceNpMatching2RequestOptParam
 * @param assignedReqIdPtr pointer to AppRequestID
 * @param event_type PS3Matching2RequestEvent Event
 * @return u32 System RequestID
 */
static u32 GenerateCallbackInfo(int ctxId, u32 optParamPtr, u32 assignedReqIdPtr, PS3Matching2RequestEvent event_type) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %d) at %08x", __FUNCTION__, ctxId, optParamPtr, assignedReqIdPtr, event_type, currentMIPS->pc);

	if (!Memory::IsValidAddress(optParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr)) {
		ERROR_LOG(Log::sceNet, "%s - Invalid Arguments", __FUNCTION__);
		return 0; // Abort Request
	}

	SceNpMatching2RequestOptParam req{};
	Memory::Memcpy(&req, optParamPtr, sizeof(req));
	INFO_LOG(Log::sceNet, "%s - optParam[%08x, %08x]", __FUNCTION__, req.cbFunc, req.cbFuncArg);

	if (req.cbFunc == 0 || !Memory::IsValidAddress(req.cbFunc)) {
		ERROR_LOG(Log::sceNet, "%s - Invalid Callback FUN_%08x(%08x) for appReqId(%d)", __FUNCTION__, req.cbFunc, req.cbFuncArg, event_type);
		return 0; // Abort Request
	}
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	NpMatching2Handler handler{};

	handler.ctx_id = ctxId; // double handle
	handler.cb = req.cbFunc;
	handler.cb_arg = req.cbFuncArg;
	handler.event_type = event_type;

	// 0 defines an Aborted Request
	u32 reqId = Memory::Read_U32(assignedReqIdPtr)+1;
	npMatching2Handlers[reqId] = handler;
	NOTICE_LOG(Log::sceNet, "%s - Added Callback FUN_%08x(%08x, %d) with appReqId(%d)", __FUNCTION__, handler.cb, handler.cb_arg, event_type, reqId);
	return reqId;
}

/* Thread-safe Notify Return for related Callback
 * @param appReqId Related System Request ID
 * @param dataPtr Pointer to a Struct generated for the request
 * @param errorCode System Error Code
 * @return u32 System Error Code (unused)
 * @note If there are any problems writing to np_memory, it may be prudent to run a thread-sanitized environment instead
 */
static int notifyNpMatching2Handlers(u32 appReqId, u32 dataPtr, u32 errorCode = SCE_NP_MATCHING2_OKAY) {
	if (npMatching2Handlers.find(appReqId) == npMatching2Handlers.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_CONTEXT_ID, "%s - No Handler Found for appReqId %d", __FUNCTION__, appReqId);

	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);
	//NOTICE_LOG(Log::sceNet, "%s - Matching Handler for appReqId(%d)", __FUNCTION__, appReqId);

	auto handler = npMatching2Handlers[appReqId];

	u32_le args[6];
	args[0] = handler.ctx_id;				// ContextID
	args[1] = appReqId;						// RequestId || 0 indicates aborted request
	args[2] = handler.event_type;			// Event
	args[3] = errorCode;					// ErrorCode || 0 is OK
	args[4] = dataPtr;						// Response struct
	args[5] = handler.cb_arg;				// Request Arguments?

	npMatching2Events.push_back(NpMatching2Args(appReqId, 6, args));
	if (appReqId == 0)
		return SCE_NP_MATCHING2_ERROR_ABORTED;
	return errorCode;
}

/* Event Processor
 * @note The arguments are suppose to be combined here?
 */
bool NpMatching2ProcessEvents() {
	if (npMatching2Events.empty()) {
		return false;
	}

	auto& event = npMatching2Events.front();
	/*auto& event = args.data[0];
	auto& stat = args.data[1];
	auto& serverIdPtr = args.data[2];
	auto& inStructPtr = args.data[3];
	auto& newStat = args.data[5];*/
	npMatching2Events.pop_front();

	// Process matching ctxId
	for (std::map<u32, NpMatching2Handler>::iterator it = npMatching2Handlers.begin(); it != npMatching2Handlers.end(); ++it) {
		if (it->first == event.reqId)
		{
			//DEBUG_LOG(Log::sceNet, "NpMatching2Callback [HandlerID=%i][EventID=%04x][State=%04x][ArgsPtr=%08x]", it->first, event, stat, it->second.argument);
			NOTICE_LOG(Log::sceNet, "%s - FUN_%08x(ctxId: %d, reqId: %d, event: %d, error: %08x, dataPtr: %08x, cbArgPtr: %08x)", __FUNCTION__, it->second.cb,
				event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5]);
			hleEnqueueCall(it->second.cb, event.argc, event.args);
			return true;
		}
	}
	ERROR_LOG(Log::sceNet, "%s - No Handler Found for CtxId %d", __FUNCTION__, event.reqId);
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
	memcpy(npTitleId.data, titleid->data, sizeof(npTitleId));

	SceNpCommunicationPassphrase* passph = (SceNpCommunicationPassphrase*)Memory::GetCharPointer(passPhrasePtr);

	// TODO: Get NPID from RPCN - login(nous),password,token(from email) - RPCS3 @GalCiv
	SceNpId npid{};
	int retval = NpGetNpId(&npid);
	if (retval < 0)
		return hleLogError(Log::sceNet, retval);

	INFO_LOG(Log::sceNet, "%s - Title ID: %s", __FUNCTION__, titleid->data);
	INFO_LOG(Log::sceNet, "%s - Online ID: %s", __FUNCTION__, npid.handle.data);
	std::string datahex;
	DataToHexString(npid.opt, sizeof(npid.opt), &datahex);
	INFO_LOG(Log::sceNet, "%s - Options?: %s", __FUNCTION__, datahex.c_str());
	datahex.clear();
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

	servers.clear();
	//net::PSNAgent::GetServers(npTitleId, &servers);
	net::RPCNAuthAgent::GetServers(npTitleId, &servers);

	npData = {};
	npData.worlds.clear();
	npData.rooms.clear();
	
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

	//TODO: Cancel all async tasks and return SCE_NP_MATCHING2_ERROR_ABORTED for each.

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
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	struct NpMatching2Handler handler;
	memset(&handler, 0, sizeof(handler));

	handler.ctx_id = ctxId; // double handle
	handler.cb = callbackFunctionAddr;
	handler.cb_arg = callbackArgument;

	npMatching2Handlers[0] = handler;
	NOTICE_LOG(Log::sceNet, "%s - Added SignalingCallback FUN_%08x(%08x) with appReqId(%d)", __FUNCTION__, handler.cb, handler.cb_arg, 0);
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
	return 0;
}

static int sceNpMatching2SignalingGetConnectionStatus(int unk) {
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d) at %08x", __FUNCTION__, unk, currentMIPS->pc);
	return 0;
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

	std::vector<u16> server_list;
	for (auto it = servers.begin(); it != servers.end() && server_list.size() < maxServerIds; ++it) {
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
 * @param assignedReqId Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 * @note PSP2i calls this once witha reqId 0, and then once for each server allocated in sceNpMatching2GetServerIdListLocal
 */
static int sceNpMatching2GetServerInfo(int ctxId, u32 serverIdPtr, u32 optParam, u32 assignedReqId) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x[%d], %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, serverIdPtr, Memory::Read_U16(serverIdPtr), optParam, assignedReqId, Memory::Read_U32(assignedReqId), currentMIPS->pc);
	u32 request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetServerInfo);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(serverIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		// Server ID is a 16-bit variable according to JPCSP
		u16 serverId;
		if ((serverId = Memory::Read_U16(serverIdPtr)) == 0)
			return notifyNpMatching2Handlers(request_id, 0, SCE_NP_MATCHING2_ERROR_INVALID_SERVER_ID);

		// Check server status
		servers[serverId]->Resolve();

		u32 infoSize = sizeof(SceNpMatching2ServerInfo);
		SceNpMatching2ServerInfo serverInfo = servers[serverId]->GetServerInfo();

		// Allocate space, and write value into the pool
		u32 serverInfoPtr = np_memory.Alloc(infoSize);
		Write_Struct(serverInfo, serverInfoPtr, "SceNpMatching2ServerInfo", 25);

		return notifyNpMatching2Handlers(request_id, serverInfoPtr);
	}); // ThreadEnd
	return 0;
}

/* Produces information about the lobbies, parties, and existing player counts
 * @param serverIdPtr Pointer to the target Server ID
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqId Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 * @note This function occurs immediately after a server has been selected
 */
static int sceNpMatching2GetWorldInfoList(int ctxId, u32 serverIdPtr, u32 optParam, u32 assignedReqId) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x[%d], %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, serverIdPtr, Memory::Read_U16(serverIdPtr), optParam, assignedReqId, Memory::Read_U32(assignedReqId), currentMIPS->pc);
	u32 request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqId, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(serverIdPtr) || !Memory::IsValidAddress(assignedReqId))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		// Server ID is a 16-bit variable according to JPCSP
		u16 serverId;
		if ((serverId = Memory::Read_U16(serverIdPtr)) == 0)
			return notifyNpMatching2Handlers(request_id, 0, SCE_NP_MATCHING2_ERROR_INVALID_SERVER_ID);

		tServer = serverId;

		std::string npid = net::RPCNAuthAgent::generate_npid();
		int ret;
		ret = servers[tServer]->Connect();
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "Could not connect.");
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, ret));
		}

		/*ret = servers[tServer]->CreateAccount(npid.c_str(), "lemmein", "fox", "http://DummyAvatarUrl", "test2@email.com");
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "Unable to Register");
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, ret));
		}*/

		ret = servers[tServer]->Login("RPCS3_ZSgScc4D7x", "4D571528FECEBD1A", "lemmein");
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "Unable to Log In");
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, ret));
		}

		// FIXME: Get worldInfo from PSN
		ret = servers[tServer]->GetWorldInfo(tServer, npTitleId.data, &npData.worlds);
		if (ret < 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, ret));

		NOTICE_LOG(Log::sceNet, "Received %d worlds", npData.worlds.size());

		u32 worldInfoSize = sizeof(SceNpMatching2World) * npData.worlds.size();
		// Allocate space, and write value into the pool
		u32 worldInfoPtr = np_memory.Alloc(worldInfoSize);
		if (!Memory::IsValidAddress(worldInfoPtr) || worldInfoPtr == 0) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for WorldInfo");
			return notifyNpMatching2Handlers(request_id, 0, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY);
		}
		npData.worldInfoPtr = worldInfoPtr;
		
		//int i = 0;
		//for (i = 0; i < npData.worlds.size(); i++) {
		//	const SceNpMatching2World world = npData.worlds[i];
		//	Write_Struct(world, worldInfoPtr + (i * sizeof(SceNpMatching2World)), "world%i", 8);	// worldInfoPtr
		//}
		int i = 0;
		for (const auto& [worldId, world] : npData.worlds) {
			Write_Struct(world, worldInfoPtr + (i * sizeof(SceNpMatching2World)), "world%i", 8);
			i++;
		}

		SceNpMatching2GetWorldInfoListResponse resp{};
		resp.worldNum = npData.worlds.size();
		resp.worldInfoPtr = worldInfoPtr;

		u32 infoSize = sizeof(SceNpMatching2GetWorldInfoListResponse);
		// Allocate space, and write value into the pool
		u32 worldInfoResponsePtr = np_memory.Alloc(infoSize);
		if (!Memory::IsValidAddress(worldInfoResponsePtr) || worldInfoResponsePtr == 0) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for WorldInfo");
			return notifyNpMatching2Handlers(request_id, 0, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY);
		}
		Write_Struct(resp, worldInfoResponsePtr, "SceNpMatching2World", 20);

		return notifyNpMatching2Handlers(request_id, worldInfoResponsePtr);
	}); // ThreadEnd
	return 0;
}

/* Incomplete - Leaves the current Lobby/Party
 * @param reqParamPtr ?
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqId Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2LeaveRoom(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);
	u32 request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		return notifyNpMatching2Handlers(request_id, 0, SCE_NP_MATCHING2_ERROR_ABORTED);
	});

	// After returning, Fat Princess will loop for 64 times (increasing the address by 288 bytes on each loop) or until found a zero status byte (0x08BD4860 + 0x10), looking for empty/available entry to set?
	return 0;
}

/* Incomplete - Unknown
 * @param reqParamPtr ?
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqId Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SetRoomDataExternal(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr) {
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);
	u32 request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataExternal);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		return notifyNpMatching2Handlers(request_id, 0, SCE_NP_MATCHING2_ERROR_ABORTED);
	});

	// After returning, Fat Princess will loop for 64 times (increasing the address by 288 bytes on each loop) or until found a zero status byte (0x08BD4860 + 0x10), looking for empty/available entry to set?
	return 0;
}

/* Incomplete - Searches for all Lobbies/Parties
 * @param reqParamPtr SceNpMatching2SearchRoomRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqId Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SearchRoom(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);
	int request_id = GenerateCallbackInfo(ctxId, optParamPtr, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		SceNpMatching2SearchRoomRequest req;
		Memory::Memcpy(&req, reqParamPtr, sizeof(req));


		// FIXME: Populate all relevant data from req into memory as required
		SceNpMatching2RoomDataExternal roomData{};
		roomData.serverId = servers[tServer]->GetServerInfo().id;
		//req.option
		roomData.worldId = req.worldId;
		roomData.lobbyId = req.lobbyId;
		//roomData.roomId
		//roomData.curMemberNum
		//req.rangeFilter.startIndex
		//req.flagFilter
		roomData.flagAttr = req.flagAttr;

		// FIXME: Get roomData from PSN
		int ret = servers[tServer]->SearchRoom(&roomData);

		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "Unable to retrieve Room Info");
			return -1;
		}

		u32 infoSize = sizeof(SceNpMatching2RoomDataExternal);
		u32 roomInfoPtr = np_memory.Alloc(infoSize);

		if (!Memory::IsValidAddress(roomInfoPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomDataExternal");
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY));
		}
		Write_Struct(roomData, roomInfoPtr, "SceNpMatching2RoomDataExternal", 31);


		SceNpMatching2SearchRoomResponse respData{};
		respData.range = { 0, 0, 0 };
		respData.roomDataExternal = roomInfoPtr;

		u32 respSize = sizeof(SceNpMatching2SearchRoomResponse);
		u32 respPtr = np_memory.Alloc(respSize);

		if (!Memory::IsValidAddress(respPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomResponse");
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY));
		}
		Write_Struct(roomData, respPtr, "SceNpMatching2SearchRoomResponse", 33);

		return notifyNpMatching2Handlers(request_id, respPtr);
	});

	return 0;
}

/* Incomplete - Hosts a Lobby/Party
 * @param reqParamPtr SceNpMatching2CreateJoinRoomRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param unknown1 ?
 * @param unkonwn2 ?
 * @param assignedReqId Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2CreateJoinRoom(int ctxId, u32 reqParamPtr, u32 optParam, u32 unknown1, u32 unknown2, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);
	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		SceNpMatching2CreateJoinRoomRequest req;
		Memory::Memcpy(&req, reqParamPtr, sizeof(req));

		// FIXME: Populate all relevant data from req into memory as required
		SceNpMatching2RoomDataInternal roomData{};
		roomData.serverId = servers[tServer]->GetServerInfo().id;
		//req.option
		roomData.worldId = req.worldId;
		roomData.lobbyId = req.lobbyId;
		//roomData.roomId
		//roomData.curMemberNum
		//req.rangeFilter.startIndex
		//req.flagFilter
		roomData.flagAttr = req.flagAttr;

		// FIXME: Get roomData from PSN
		int ret = servers[tServer]->CreatJoinRoom(&roomData);
		if (ret < 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, ret));


		u32 infoSize = sizeof(roomData);
		u32 roomInfoPtr = np_memory.Alloc(infoSize);

		if (!Memory::IsValidAddress(roomInfoPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomDataExternal");
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY));
		}
		Write_Struct(roomData, roomInfoPtr, "SceNpMatching2RoomDataExternal", 31);

		npData.rooms.emplace(roomData.roomId, roomData);
		npData.roomDataPtr = roomInfoPtr;

		SceNpMatching2CreateJoinRoomResponse respData{};
		respData.roomDataInternal = roomInfoPtr;

		u32 respSize = sizeof(respData);
		u32 respPtr = np_memory.Alloc(respSize);

		if (!Memory::IsValidAddress(respPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomResponse");
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY));
		}
		Write_Struct(roomData, respPtr, "SceNpMatching2CreateJoinRoomResponse", 37);

		// Cache Rooms
		//rooms.push_back(roomData);

		return notifyNpMatching2Handlers(request_id, respPtr);
	});

	return 0;
}

/* Incomplete - Requests attributes of a specific Lobby/Party
 * @param reqParamPtr SceNpMatching2GetRoomDataInternalRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqId Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2GetRoomDataInternal(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataInternal);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));


		SceNpMatching2GetRoomDataInternalRequest req{};
		Memory::Memcpy(&req, reqParamPtr, sizeof(req));

		auto roomData = &npData.rooms[req.roomId];

		int ret;
		if ((ret = servers[tServer]->GetRoomDataInternal(roomData)) < 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_ABORTED));
		
		//u32 respSize = sizeof(SceNpMatching2RoomDataInternal);
		//u32 roomDataPtr = np_memory.Alloc(respSize);
		if (!Memory::IsValidAddress(npData.roomDataPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomResponse");
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY));
		}
		Write_Struct(roomData, npData.roomDataPtr, "SceNpMatching2RoomDataInternal", 31);

		SceNpMatching2GetRoomDataInternalResponse resp{};
		resp.roomDataInternal = npData.roomDataPtr;

		u32 respSize = sizeof(SceNpMatching2GetRoomDataInternalResponse);
		u32 respPtr = np_memory.Alloc(respSize);
		if (!Memory::IsValidAddress(respPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomResponse");
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY));
		}
		Write_Struct(roomData, respPtr, "SceNpMatching2GetRoomDataInternalResponse", 42);

		return notifyNpMatching2Handlers(request_id, respPtr, 0);
	});

	return 0;
}

/* Incomplete - Sets attributes of a specific Lobby/Party
 * @param reqParamPtr SceNpMatching2GetRoomDataInternalRequest Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqId Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SetRoomDataInternal(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomDataInternal);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		SceNpMatching2SetRoomDataInternalRequest req;
		Memory::Memcpy(&req, reqParamPtr, sizeof(req));

		return notifyNpMatching2Handlers(request_id, 0);
	});

	return 0;
}

/* Incomplete - Sends a Chat Message to relevant players?
 * @param reqParamPtr ? Request Information
 * @param optParam Pointer to SceNpMatching2RequestOptParam containing Callback information
 * @param assignedReqId Pointer to the index of a unique callback
 * @return 0; System Errors are entirely ignored
 * @note Performs the operations in an async lambda function
 */
static int sceNpMatching2SendRoomChatMessage(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		return notifyNpMatching2Handlers(request_id, 0);
	});

	// After returning, Fat Princess will loop for 64 times (increasing the address by 288 bytes on each loop) or until found a zero status byte (0x08BD4860 + 0x10), looking for empty/available entry to set?
	return 0;
}

static int sceNpMatching2SetDefaultRequestOptParam(int ctxId, u32 optParam)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x) at %08x", __FUNCTION__, ctxId, optParam, currentMIPS->pc);

	return 0;
}

static int sceNpMatching2SetUserInfo(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_SetUserInfo);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		return notifyNpMatching2Handlers(request_id, 0);
	});

	return 0;
}

static int sceNpMatching2GetUserInfoList(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_GetUserInfoList);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		return notifyNpMatching2Handlers(request_id, 0);
	});

	return 0;
}

static int sceNpMatching2AbortRequest(int ctxId, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x) at %08x", __FUNCTION__, ctxId, assignedReqIdPtr, currentMIPS->pc);

	return 0;
}

static int sceNpMatching2SetSignalingOptParam(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_SetSignalingOptParam);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		return notifyNpMatching2Handlers(request_id, 0);
	});

	return 0;
}

static int sceNpMatching2GetSignalingOptParamLocal(int ctxId, u32 roomId, u32 signalingOptParam)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, signalingOptParam, currentMIPS->pc);

	return 0;
}

static int sceNpMatching2SignalingGetLocalNetInfo(u32 netInfoPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%08x) at %08x", __FUNCTION__, netInfoPtr, currentMIPS->pc);

	return 0;
}

static int sceNpMatching2SignalingGetPeerNetInfo(int ctxId, u32 roomId, u32 roomMemberId, u32 signalingReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, roomId, roomMemberId, signalingReqIdPtr, Memory::Read_U32(signalingReqIdPtr), currentMIPS->pc);

	return 0;
}

static int sceNpMatching2SignalingGetPeerNetInfoResult(int ctxId, u32 signalingReqIdPtr, u32 netInfoPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x[%08x], %08x) at %08x", __FUNCTION__, ctxId, signalingReqIdPtr, Memory::Read_U32(signalingReqIdPtr), netInfoPtr, currentMIPS->pc);

	return 0;
}

static int sceNpMatching2SignalingCancelPeerNetInfo(int ctxId, u32 signalingReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x[%08x]) at %08x", __FUNCTION__, ctxId, signalingReqIdPtr, Memory::Read_U32(signalingReqIdPtr), currentMIPS->pc);

	return 0;
}

static int sceNpMatching2SignalingGetConnectionInfo(int ctxId, u32 roomId, u32 memberId, u32 code, u32 connInfoPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, memberId, code, connInfoPtr, currentMIPS->pc);

	return 0;
}


static int sceNpMatching2GetRoomDataExternalList(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomDataExternalList);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		return notifyNpMatching2Handlers(request_id, 0);
	});

	return 0;
}

static int sceNpMatching2GetRoomPasswordLocal(int ctxId, u32 roomId, u32 withPassword, u32 Password)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x) at %08x", __FUNCTION__, ctxId, roomId, withPassword, Password, currentMIPS->pc);

	return 0;
}

static int sceNpMatching2JoinRoom(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_JoinRoom);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		return notifyNpMatching2Handlers(request_id, 0);
	});

	return 0;
}

static int sceNpMatching2SendRoomMessage(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomMessage);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		return notifyNpMatching2Handlers(request_id, 0);
	});

	return 0;
}

static int sceNpMatching2GrantRoomOwner(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_GrantRoomOwner);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		return notifyNpMatching2Handlers(request_id, 0);
	});

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

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_SetRoomMemberDataInternal);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		return notifyNpMatching2Handlers(request_id, 0);
	});

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

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataInternal);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		return notifyNpMatching2Handlers(request_id, 0);
	});

	return 0;
}

static int sceNpMatching2GetRoomMemberDataExternalList(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_GetRoomMemberDataExternalList);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		return notifyNpMatching2Handlers(request_id, 0);
	});

	return 0;
}

static int sceNpMatching2KickoutRoomMember(int ctxId, u32 reqParamPtr, u32 optParam, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParam, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	int request_id = GenerateCallbackInfo(ctxId, optParam, assignedReqIdPtr, SCE_NP_MATCHING2_REQUEST_EVENT_KickoutRoomMember);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == 0)
			return notifyNpMatching2Handlers(request_id, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		return notifyNpMatching2Handlers(request_id, 0);
	});

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
	{0x6D6D0C75, &WrapI_I<sceNpMatching2SignalingGetConnectionStatus>,		"sceNpMatching2SignalingGetConnectionStatus",	'i', "i" 	  },

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
	{0x7BBFC427, &WrapI_IUUU<sceNpMatching2JoinRoom>,						"sceNpMatching2JoinRoom",						'i', "ixxx"   },
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
