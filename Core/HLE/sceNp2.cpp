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
net::NPAgent* tServer;
std::map<u16, net::NPAgent> servers;
std::vector<SceNpMatching2World> worlds;

template <typename T>
void Write_Struct(const T& object, const u32 address, const char* tag, size_t taglen) {
	Memory::Memcpy(address, &object, sizeof(T), tag, taglen);
}

// Returns the RequestId
static u32 GenerateCallbackInfo(int ctxId, u32 optParam, PS3Matching2RequestEvent event_type) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %d) at %08x", __FUNCTION__, ctxId, optParam, event_type, currentMIPS->pc);

	SceNpMatching2RequestOptParam req{};
	Memory::Memcpy(&req, optParam, sizeof(req));
	INFO_LOG(Log::sceNet, "%s - optParam[%08x, %08x]", __FUNCTION__, req.cbFunc, req.cbFuncArg);

	if (req.cbFunc == 0 || !Memory::IsValidAddress(req.cbFunc)) {
		ERROR_LOG(Log::sceNet, "%s - Invalid Callback FUN_%08x(%08x) for appReqId(%d)", __FUNCTION__, req.cbFunc, req.cbFuncArg, event_type);
		return 0;
	}
	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);

	NpMatching2Handler handler{};

	handler.ctx_id = ctxId; // double handle
	handler.cb = req.cbFunc;
	handler.cb_arg = req.cbFuncArg;
	handler.event_type = event_type;

	// Generate a unique ID for this request
	u32 reqId = 1;
	if (npMatching2Handlers.size() > 0)
		reqId = (npMatching2Handlers.rbegin()->first) + 1;
	npMatching2Handlers[reqId] = handler;
	NOTICE_LOG(Log::sceNet, "%s - Added Callback FUN_%08x(%08x, %d) with appReqId(%d)", __FUNCTION__, handler.cb, handler.cb_arg, event_type, reqId);
	return reqId;
	/*if (npMatching2Handlers.find(event_type) == npMatching2Handlers.end()) {

		return event_type;
	}
	else {
		ERROR_LOG(Log::sceNet, "%s - Callback FUN_%08x(%08x) already exists for appReqId(%d)", __FUNCTION__, handler.cb, handler.cb_arg, event_type);
	}*/

	//return 0; // Default to Aborted Request
}

// serverId: 0 on 0x0103/0x0104/0x0105/0x0107/0x0108/0x0109/0x010a/0x010b/0x010c/0x010d (ie. when already joined to a server?)
// unk1~unk5 usually 0, 
// unk1: 1st 32-bit of LeaveRoom/etc's Arg2 on 0x0103/0x0104/0x0105/0x0107/0x0108/0x0109/0x010a/0x010b/0x010c/0x010d/0x010e
// unk2: 2nd 32-bit of LeaveRoom/etc's Arg2 on 0x0103/0x0104/0x0105/0x0107/0x0108/0x0109/0x010a/0x010b/0x010c/0x010d/0x010e
// unk5: 1 on 0x0002/0x0003/0x0005/0x0006/0x0007/0x0101/0x0102/0x0106
// unk6 (new state?): 8-bit?(masked with 0xff) 0x01 on 0x0001, 0x03 on 0x0002, 0x04 on 0x0003, 0x05 on 0x0004, 0x06 on 0x0005, 0x07 on 0x0006, 0x08 on 0x0007,
//		0x09 on 0x0101, 0x0A on 0x0102, 0x0C on 0x0103, 0x0D on 0x0104, 0x0E on 0x0105, 0x0F on 0x0106, 0x10 on 0x0107, 0x11 on 0x0108,
//		0x12 on 0x0109, 0x13 on 0x010a, 0x14 on 0x010b, 0x15 on 0x010c, 0x16 on 0x010d, 0x17 on 0x010e, 0x18 on 0xa102
static int notifyNpMatching2Handlers(u32 appReqId, u32 dataPtr, u32 errorCode) {
	if (npMatching2Handlers.find(appReqId) == npMatching2Handlers.end())
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_CONTEXT_ID, "%s - No Handler Found for appReqId %d", __FUNCTION__, appReqId);

	std::lock_guard<std::recursive_mutex> npMatching2Guard(npMatching2EvtMtx);
	//NOTICE_LOG(Log::sceNet, "%s - Matching Handler for appReqId(%d)", __FUNCTION__, appReqId);

	auto handler = npMatching2Handlers[appReqId];

	u32_le args[6];
	args[0] = handler.ctx_id;				// ContextID
	args[1] = appReqId;						// RequestId || 0 indicates aborted request
	args[2] = handler.event_type;			// Event
	args[3] = errorCode;					// ErrorCode
	args[4] = dataPtr;						// ServerInfo struct [ u16 ID, u8 Status, 0x00 ]
	args[5] = handler.cb_arg;				// Struct to some valid information?

	npMatching2Events.push_back(NpMatching2Args(appReqId, 6, args));
	if (appReqId == 0)
		return SCE_NP_MATCHING2_ERROR_ABORTED;
	return errorCode;
}

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
			NOTICE_LOG(Log::sceNet, "NpMatching2ProcessEvents - FUN_%08x(%08x, %08x, %08x, %08x, %08x, %08x, %08x, %08x)", it->second.cb,
				event.args[0], event.args[1], event.args[2], event.args[3], event.args[4], event.args[5], event.args[6], event.args[7]);
			hleEnqueueCall(it->second.cb, event.argc, event.args);
			return true;
		}
	}
	ERROR_LOG(Log::sceNet, "NpMatching2ProcessEvents - No Handler Found for CtxId %d", event.reqId);

	//// Per npMatching2 function callback
	//u32* inStruct = (u32*)Memory::GetPointer(event.cbFunc);
	//if (inStruct != nullptr) {
	//	if (Memory::IsValidAddress(inStruct[0])) {
	//		//DEBUG_LOG(Log::sceNet, "NpMatching2Callback [ServerID=%i][EventID=%04x][State=%04x][FuncAddr=%08x][ArgsPtr=%08x]", *(u32*)Memory::GetPointer(serverIdPtr), event, stat, inStruct[0], inStruct[1]);

	//		DEBUG_LOG(Log::sceNet, "NpMatching2Callback FUN_%08x(%s)", inStruct[0], event.ToString());
	//		hleEnqueueCall(inStruct[0], event.argc, event.args);
	//		return true;
	//	}
	//}
	//ERROR_LOG(Log::sceNet, "NpMatching2Callback - Invalid Callback %d", event.ctxId);
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
	Url url("http://static-resource.np.community.playstation.net/np/resource/psp-title/" + std::string(npTitleId.data) + "_00/matching/" + std::string(npTitleId.data) + "_00-matching.xml");
	http::Client client;
	bool cancelled = false;
	net::RequestProgress progress(&cancelled);
	if (!client.Resolve(url.Host().c_str(), url.Port())) {
		return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "HTTP failed to resolve %s", url.Resource().c_str());
	}
	
	client.SetDataTimeout(20.0);
	if (client.Connect()) {
		char requestHeaders[4096];
		snprintf(requestHeaders, sizeof(requestHeaders),
			"User-Agent: PS3Community-agent/1.0.0 libhttp/1.0.0\r\n");

		DEBUG_LOG(Log::sceNet, "GET URI: %s", url.ToString().c_str());
		http::RequestParams req(url.Resource(), "*/*");
		int err = client.SendRequest("GET", req, requestHeaders, &progress);
		if (err < 0) {
			client.Disconnect();
			return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_FORBIDDEN, "HTTP GET Error = %d", err);
		}

		net::Buffer readbuf;
		std::vector<std::string> responseHeaders;
		int code = client.ReadResponse(&readbuf, &progress);
		if (code != 200) {
			client.Disconnect();
			return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_INTERNAL_SERVER_ERROR, "HTTP Error Code = %d", code);
		}
		/*int code = client.ReadResponseHeaders(&readbuf, responseHeaders, &progress);
		if (code != 200) {
			client.Disconnect();
			return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "HTTP Error Code = %d", code);
		}

		net::Buffer output;
		int res = client.ReadResponseEntity(&readbuf, responseHeaders, &output, &progress);
		if (res != 0) {
			WARN_LOG(Log::sceNet, "Unable to read HTTP response entity: %d", res);
		}*/
		client.Disconnect();

		std::string entity;
		size_t readBytes = readbuf.size();
		readbuf.Take(readBytes, &entity);

		INFO_LOG(Log::sceNet, "Entity Data: %d", entity);

		// TODO: Use XML Parser to get the Tag and it's attributes instead of searching for keywords on the string
		std::string text;
		size_t ofs = entity.find("titleid=");
		if (ofs == std::string::npos) 
			return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "titleid not found");

		ofs += 9;
		size_t ofs2 = entity.find('"', ofs);
		text = entity.substr(ofs, ofs2-ofs);
		INFO_LOG(Log::sceNet, "%s - Title ID: %s", __FUNCTION__, text.c_str());

		servers = {};
		int i = 1;
		while (true) {
			ofs = entity.find("<agent-fqdn", ++ofs2);
			if (ofs == std::string::npos) {
				if (i == 1)
					return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "agent-fqdn not found");
				else
					break;
			}

			size_t frontPos = ++ofs;
			ofs = entity.find("id=", frontPos);
			if (ofs == std::string::npos)
				return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "agent id not found");

			ofs += 4;
			ofs2 = entity.find('"', ofs);
			text = entity.substr(ofs, ofs2 - ofs);
			int server_id = std::stoi(text.c_str());
			INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d ID: %s", __FUNCTION__, i, text.c_str());

			ofs = entity.find("port=", frontPos);
			if (ofs == std::string::npos)
				return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "agent port not found");

			ofs += 6;
			ofs2 = entity.find('"', ofs);
			text = entity.substr(ofs, ofs2 - ofs);
			int server_port = std::stoi(text.c_str());
			INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d Port: %s", __FUNCTION__, i, text.c_str());

			ofs = entity.find("status=", frontPos);
			if (ofs == std::string::npos)
				return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "agent status not found");

			ofs += 8;
			ofs2 = entity.find('"', ofs);
			text = entity.substr(ofs, ofs2 - ofs);
			std::string alive = { 'a','l','i','v','e' };
			int server_status = SCE_NP_MATCHING2_SERVER_STATUS_UNAVAILABLE;
			if (text == alive)
				server_status = SCE_NP_MATCHING2_SERVER_STATUS_AVAILABLE;
			INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d Status: %s", __FUNCTION__, i, text.c_str());

			ofs = entity.find('>', ++ofs2);
			if (ofs == std::string::npos)
				return hleLogError(Log::sceNet, SCE_NP_COMMUNITY_SERVER_ERROR_NO_SUCH_TITLE, "agent host not found");

			ofs2 = entity.find("</agent-fqdn", ++ofs);
			text = entity.substr(ofs, ofs2 - ofs);
			std::string server_host = text;
			// TODO: Get IPAddr from DNS
			//server.IPAddr = std::stoi();
			INFO_LOG(Log::sceNet, "%s - Agent-FQDN#%d Host: %s", __FUNCTION__, i, text.c_str());

			servers[server_id] = net::NPAgent(server_id, server_host, server_port, server_status);
			i++;
		}
	}
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

	u32 reqId = 1;
	if (npMatching2Handlers.size() > 0)
		reqId = (npMatching2Handlers.rbegin()->first) + 1;
	npMatching2Handlers[reqId] = handler;
	NOTICE_LOG(Log::sceNet, "%s - Added SignalingCallback FUN_%08x(%08x) with appReqId(%d)", __FUNCTION__, handler.cb, handler.cb_arg, reqId);
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

// Allocates the list of server Id's to memory
// - serverIdsPtr = pointer to where the servers should be written
// - maxServerIds = maximum number of servers the client can receive
// Returns the number of servers we allocated
static int sceNpMatching2GetServerIdListLocal(int ctxId, u32 serverIdsPtr, int maxServerIds)
{
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x, %d) at %08x", __FUNCTION__, ctxId, serverIdsPtr, maxServerIds, currentMIPS->pc);
	if (!npMatching2Inited)
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED);

	if (!Memory::IsValidAddress(serverIdsPtr))
		return hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT);

	// Preserve original server list
	std::map<u16, net::NPAgent> rooms = servers;
	if (rooms.size() > maxServerIds) {
		// Shouldn't happen, but in the event we have more servers than were requested, log, resize, and continue
		ERROR_LOG(Log::sceNet, "%s - %d servers available > %d servers requested", __FUNCTION__, ctxId, serverIdsPtr, maxServerIds, servers.size(), maxServerIds);
		auto it = rooms.begin();
		std::advance(it, maxServerIds);
		rooms.erase(it, rooms.end());
	}
	// These are usually last to first order
	int ofs = 0;
	for (auto it = rooms.rbegin(); it != rooms.rend(); ++it) {
		Memory::Write_U16(it->first, serverIdsPtr + ofs);
		ofs += 2;
	}

	// Return the number of servers allocated to memory
	return rooms.size();
}

// Produces information about a target server
// - serverIdPtr = Pointer to the target Server ID
// - optParam = Struct containing related pointers
// - assignedReqId = ?
// Unknown1 = optParam, unknown2 = assignedReqId according to https://github.com/RPCS3/rpcs3/blob/master/rpcs3/Emu/Cell/Modules/sceNp2.cpp ?
static int sceNpMatching2GetServerInfo(int ctxId, u32 serverIdPtr, u32 optParam, u32 assignedReqId) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x[%d], %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, serverIdPtr, Memory::Read_U16(serverIdPtr), optParam, assignedReqId, Memory::Read_U32(assignedReqId), currentMIPS->pc);
	u32 request_id = GenerateCallbackInfo(ctxId, optParam, SCE_NP_MATCHING2_REQUEST_EVENT_GetServerInfo);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(serverIdPtr) || !Memory::IsValidAddress(assignedReqId))
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		// Server ID is a 16-bit variable according to JPCSP
		u16 serverId;
		if ((serverId = Memory::Read_U16(serverIdPtr)) == 0)
			return notifyNpMatching2Handlers(0, 0, SCE_NP_MATCHING2_ERROR_INVALID_SERVER_ID);

		tServer = &servers[serverId];
		// Check server status
		tServer->Resolve();

		u32 infoSize = 4;

		// Allocate space, and write value into the pool
		u32 serverInfoPtr = np_memory.Alloc(infoSize);
		Memory::Write_U16(serverId, serverInfoPtr);
		Memory::Write_U8(servers[serverId].GetStatus(), serverInfoPtr + 2);

		return notifyNpMatching2Handlers(request_id, serverInfoPtr, 0);
	}); // ThreadEnd
	return 0;
}

// This function produces information about the lobbies, parties, and existing player counts
// This function occurs immediately after a server has been selected
static int sceNpMatching2GetWorldInfoList(int ctxId, u32 serverIdPtr, u32 optParam, u32 assignedReqId) {
	WARN_LOG(Log::sceNet, "UNTESTED %s(%d, %08x[%d], %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, serverIdPtr, Memory::Read_U16(serverIdPtr), optParam, assignedReqId, Memory::Read_U32(assignedReqId), currentMIPS->pc);
	u32 request_id = GenerateCallbackInfo(ctxId, optParam, SCE_NP_MATCHING2_REQUEST_EVENT_GetWorldInfoList);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(serverIdPtr) || !Memory::IsValidAddress(assignedReqId))
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		// Server ID is a 16-bit variable according to JPCSP
		u16 serverId;
		if ((serverId = Memory::Read_U16(serverIdPtr)) == 0)
			return notifyNpMatching2Handlers(0, 0, SCE_NP_MATCHING2_ERROR_INVALID_SERVER_ID);

		tServer = &servers[serverId];
		// Connect to server before we collect information
		tServer->Connect();
		// FIXME: Get worldInfo from PSN
		int ret = tServer->GetWorldInfo(npTitleId.data, &worlds);
		tServer->Disconnect();

		if (ret < 0)
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, ret));

		u32 worldInfoSize = sizeof(SceNpMatching2World) * worlds.size();
		// Allocate space, and write value into the pool
		u32 worldInfoPtr = np_memory.Alloc(worldInfoSize);
		if (!Memory::IsValidAddress(worldInfoPtr) || worldInfoPtr == 0) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for WorldInfo");
			return notifyNpMatching2Handlers(0, 0, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY);
		}
		int i = 0;
		for (i = 0; i < worlds.size(); i++) {
			Write_Struct(worlds[i], worldInfoPtr + (i * sizeof(SceNpMatching2World)), "world%i", 8);	// worldInfoPtr
		}

		SceNpMatching2GetWorldInfoListResponse resp{};
		resp.worldNum = worlds.size();
		resp.worldInfoPtr = worldInfoPtr;

		u32 infoSize = sizeof(SceNpMatching2GetWorldInfoListResponse);
		// Allocate space, and write value into the pool
		u32 worldInfoResponsePtr = np_memory.Alloc(infoSize);
		if (!Memory::IsValidAddress(worldInfoResponsePtr) || worldInfoResponsePtr == 0) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for WorldInfo");
			return notifyNpMatching2Handlers(0, 0, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY);
		}
		Write_Struct(resp, worldInfoResponsePtr, "SceNpMatching2World", 20);

		return notifyNpMatching2Handlers(request_id, worldInfoResponsePtr, 0);
	}); // ThreadEnd
	return 0;
}

static int sceNpMatching2LeaveRoom(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);
	u32 request_id = GenerateCallbackInfo(ctxId, optParamPtr, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		return notifyNpMatching2Handlers(request_id, 0, SCE_NP_MATCHING2_ERROR_ABORTED);
	});

	// After returning, Fat Princess will loop for 64 times (increasing the address by 288 bytes on each loop) or until found a zero status byte (0x08BD4860 + 0x10), looking for empty/available entry to set?
	return 0;
}

static int sceNpMatching2SetRoomDataExternal(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr) {
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);
	u32 request_id = GenerateCallbackInfo(ctxId, optParamPtr, SCE_NP_MATCHING2_REQUEST_EVENT_LeaveRoom);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		return notifyNpMatching2Handlers(request_id, 0, SCE_NP_MATCHING2_ERROR_ABORTED);
	});

	// After returning, Fat Princess will loop for 64 times (increasing the address by 288 bytes on each loop) or until found a zero status byte (0x08BD4860 + 0x10), looking for empty/available entry to set?
	return 0;
}

// Used to host a room
static int sceNpMatching2CreateJoinRoom(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 unknown1, u32 unknown2, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);
	int request_id = GenerateCallbackInfo(ctxId, optParamPtr, SCE_NP_MATCHING2_REQUEST_EVENT_CreateJoinRoom);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == nullptr)
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		u32 cbFunc = Memory::Read_U32(reqParamPtr);
		u32 cbArg = Memory::Read_U32(reqParamPtr + 0x04);
		SceNpMatching2CreateJoinRoomRequest req;
		Memory::Memcpy(&req, reqParamPtr, sizeof(req));

		tServer->Connect();

		// FIXME: Populate all relevant data from req into memory as required
		SceNpMatching2RoomDataInternal roomData{};
		roomData.serverId = tServer->GetID();
		//req.option
		roomData.worldId = req.worldId;
		roomData.lobbyId = req.lobbyId;
		//roomData.roomId
		//roomData.curMemberNum
		//req.rangeFilter.startIndex
		//req.flagFilter
		roomData.flagAttr = req.flagAttr;

		// FIXME: Get roomData from PSN
		int ret = tServer->CreatJoinRoom(&roomData);
		tServer->Disconnect();

		if (ret < 0)
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, ret));

		u32 infoSize = sizeof(roomData);
		u32 roomInfoPtr = np_memory.Alloc(infoSize);

		if (!Memory::IsValidAddress(roomInfoPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomDataExternal");
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY));
		}
		Write_Struct(roomData, roomInfoPtr, "SceNpMatching2RoomDataExternal", 31);


		SceNpMatching2CreateJoinRoomResponse respData{};
		respData.roomDataInternal = roomInfoPtr;

		u32 respSize = sizeof(respData);
		u32 respPtr = np_memory.Alloc(respSize);

		if (!Memory::IsValidAddress(respPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomResponse");
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY));
		}
		Write_Struct(roomData, respPtr, "SceNpMatching2CreateJoinRoomResponse", 37);

		return notifyNpMatching2Handlers(request_id, respPtr, 0);
	});

	return 0;
}

static int sceNpMatching2SearchRoom(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);
	int request_id = GenerateCallbackInfo(ctxId, optParamPtr, SCE_NP_MATCHING2_REQUEST_EVENT_SearchRoom);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == nullptr)
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		SceNpMatching2SearchRoomRequest req;
		Memory::Memcpy(&req, reqParamPtr, sizeof(req));

		tServer->Connect();

		// FIXME: Populate all relevant data from req into memory as required
		SceNpMatching2RoomDataExternal roomData{};
		roomData.serverId = tServer->GetID();
		//req.option
		roomData.worldId = req.worldId;
		roomData.lobbyId = req.lobbyId;
		//roomData.roomId
		//roomData.curMemberNum
		//req.rangeFilter.startIndex
		//req.flagFilter
		roomData.flagAttr = req.flagAttr;

		// FIXME: Get roomData from PSN
		int ret = tServer->SearchRoom(&roomData);
		tServer->Disconnect();

		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "Unable to retrieve Room Info");
			return -1;
		}

		u32 infoSize = sizeof(SceNpMatching2RoomDataExternal);
		u32 roomInfoPtr = np_memory.Alloc(infoSize);

		if (!Memory::IsValidAddress(roomInfoPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomDataExternal");
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY));
		}
		Write_Struct(roomData, roomInfoPtr, "SceNpMatching2RoomDataExternal", 31);


		SceNpMatching2SearchRoomResponse respData{};
		respData.range = { req.rangeFilter.startIndex, req.rangeFilter.max, req.rangeFilter.max };
		respData.roomDataExternal = roomInfoPtr;

		u32 respSize = sizeof(SceNpMatching2SearchRoomResponse);
		u32 respPtr = np_memory.Alloc(respSize);

		if (!Memory::IsValidAddress(respPtr)) {
			ERROR_LOG(Log::sceNet, "Unable to allocate memory for RoomResponse");
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_OUT_OF_MEMORY));
		}
		Write_Struct(roomData, respPtr, "SceNpMatching2SearchRoomResponse", 33);

		return notifyNpMatching2Handlers(request_id, respPtr, 0);
	});

	return 0;
}

static int sceNpMatching2SendRoomChatMessage(int ctxId, u32 reqParamPtr, u32 optParamPtr, u32 assignedReqIdPtr)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%d, %08x, %08x, %08x[%08x]) at %08x", __FUNCTION__, ctxId, reqParamPtr, optParamPtr, assignedReqIdPtr, Memory::Read_U32(assignedReqIdPtr), currentMIPS->pc);

	int request_id = GenerateCallbackInfo(ctxId, optParamPtr, SCE_NP_MATCHING2_REQUEST_EVENT_SendRoomChatMessage);

	// ThreadStart
	std::async(std::launch::async, [=]() {
		if (!npMatching2Inited)
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_NOT_INITIALIZED));

		if (!Memory::IsValidAddress(reqParamPtr) || !Memory::IsValidAddress(assignedReqIdPtr))
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_INVALID_ARGUMENT));

		if (tServer == nullptr)
			return notifyNpMatching2Handlers(0, 0, hleLogError(Log::sceNet, SCE_NP_MATCHING2_ERROR_SERVER_NOT_FOUND));

		return notifyNpMatching2Handlers(request_id, 0, SCE_NP_MATCHING2_ERROR_ABORTED);
	});

	// After returning, Fat Princess will loop for 64 times (increasing the address by 288 bytes on each loop) or until found a zero status byte (0x08BD4860 + 0x10), looking for empty/available entry to set?
	return 0;
}

const HLEFunction sceNpMatching2[] = {
	{0xF47342FC, &WrapI_IUI<sceNpMatching2GetServerIdListLocal>,		"sceNpMatching2GetServerIdListLocal",			'i', "ixi"    },
	{0x4EE3A8EC, &WrapI_IUUU<sceNpMatching2GetServerInfo>,				"sceNpMatching2GetServerInfo",					'i', "ixxx"   },
	{0xA53E7C69, &WrapI_IUUU< sceNpMatching2GetWorldInfoList>,			"sceNpMatching2GetWorldInfoList",				'i', "ixxx"   },
	{0x631682CC, nullptr,												"sceNpMatching2SetDefaultRequestOptParam",		'i', "" 	  },
	{0x22F38DAF, &WrapI_U<sceNpMatching2GetMemoryStat>,					"sceNpMatching2GetMemoryStat",					'i', "x"      },
	{0x7D1D5F5E, nullptr,												"sceNpMatching2SetUserInfo",					'i', "" 	  },
	{0xC8FC5D41, nullptr,												"sceNpMatching2GetUserInfoList",				'i', "" 	  },
	{0xFADBA9DB, nullptr,												"sceNpMatching2AbortRequest",					'i', "" 	  },

	{0xA3C298D1, &WrapI_IUU<sceNpMatching2RegisterSignalingCallback>,	"sceNpMatching2RegisterSignalingCallback",		'i', "ixx"    },
	{0x9A67F5D0, nullptr,												"sceNpMatching2SetSignalingOptParam",			'i', "" 	  },
	{0xC7E72EC5, nullptr,												"sceNpMatching2GetSignalingOptParamLocal",		'i', "" 	  },
	{0xFF32EA05, nullptr,												"sceNpMatching2SignalingGetLocalNetInfo",		'i', "" 	  },
	{0x8CD109E7, nullptr,												"sceNpMatching2SignalingGetPeerNetInfo",		'i', "" 	  },
	{0xDFEDB642, nullptr,												"sceNpMatching2SignalingGetPeerNetInfoResult",	'i', "" 	  },
	{0x9462C05A, nullptr,												"sceNpMatching2SignalingCancelPeerNetInfo",		'i', "" 	  },
	{0x3892E9A6, nullptr,												"sceNpMatching2SignalingGetConnectionInfo",		'i', "" 	  },
	{0x6D6D0C75, &WrapI_I<sceNpMatching2SignalingGetConnectionStatus>,	"sceNpMatching2SignalingGetConnectionStatus",	'i', "i" 	  },

	{0x2E61F6E1, &WrapI_IIII<sceNpMatching2Init>,						"sceNpMatching2Init",							'i', "iiii"   },
	{0x8BF37D8C, &WrapI_V<sceNpMatching2Term>,							"sceNpMatching2Term",							'i', ""       },
	{0x5030CC53, &WrapI_UUUI<sceNpMatching2CreateContext>,				"sceNpMatching2CreateContext",					'i', "xxxi"   },
	{0x3DE70241, &WrapI_I<sceNpMatching2DestroyContext>,				"sceNpMatching2DestroyContext",					'i', "i"      },
	{0x190FF903, &WrapI_I<sceNpMatching2ContextStart>,					"sceNpMatching2ContextStart",					'i', "i"      },
	{0x2B3892FC, &WrapI_I<sceNpMatching2ContextStop>,					"sceNpMatching2ContextStop",					'i', "i"      },

	{0x1421514B, nullptr,												"sceNpMatching2SetDefaultRoomEventOptParam",	'i', ""		  },
	{0xD13491AB, nullptr,												"sceNpMatching2SetDefaultRoomMessageOptParam",	'i', "" 	  },
	{0xE6C93DBD, nullptr,												"sceNpMatching2SetRoomDataInternal",			'i', "" 	  },
	{0xE313E586, nullptr,												"sceNpMatching2GetRoomDataInternal",			'i', "" 	  },
	{0xEF683F4F, nullptr,												"sceNpMatching2GetRoomDataInternalLocal",		'i', "" 	  },
	{0xD7D4AEB2, &WrapI_IUUU<sceNpMatching2SetRoomDataExternal>,		"sceNpMatching2SetRoomDataExternal",			'i', "ixxx"   },
	{0x12C5A111, nullptr,												"sceNpMatching2GetRoomDataExternalList",		'i', ""		  },
	{0xF739BE92, nullptr,												"sceNpMatching2GetRoomPasswordLocal",			'i', "" 	  },

	{0xAAD0946A, &WrapI_IUUUUU<sceNpMatching2CreateJoinRoom>,			"sceNpMatching2CreateJoinRoom",					'i', "ixxxxx" },
	{0x7BBFC427, nullptr,												"sceNpMatching2JoinRoom",						'i', "" 	  },
	{0xC870535A, &WrapI_IUUU<sceNpMatching2LeaveRoom>,					"sceNpMatching2LeaveRoom",						'i', "ixxx"   },
	{0x81C13E6D, &WrapI_IUUU<sceNpMatching2SearchRoom>,					"sceNpMatching2SearchRoom",						'i', "ixxx"   },
	{0xF940D9AD, nullptr,												"sceNpMatching2SendRoomMessage",				'i', "" 	  },
	{0x55F7837F, &WrapI_IUUU<sceNpMatching2SendRoomChatMessage>,		"sceNpMatching2SendRoomChatMessage",			'i', "ixxx"   },
	{0x495E97BD, nullptr,												"sceNpMatching2GrantRoomOwner",					'i', "" 	  },

	{0x80F61558, nullptr,												"sceNpMatching2GetRoomMemberIdListLocal",		'i', "" 	  },
	{0x7DAA8A90, nullptr,												"sceNpMatching2SetRoomMemberDataInternal",		'i', "" 	  },
	{0xF22C7ADC, nullptr,												"sceNpMatching2GetRoomMemberDataInternalLocal",	'i', "" 	  },
	{0xA5775DBF, nullptr,												"sceNpMatching2GetRoomMemberDataInternal",		'i', "" 	  },
	{0x5C7DB6A4, nullptr,												"sceNpMatching2GetRoomMemberDataInternalList",	'i', "" 	  },
	{0xFBF494C0, nullptr,												"sceNpMatching2GetRoomMemberDataExternalList",	'i', "" 	  },
	{0x97529ECC, nullptr,												"sceNpMatching2KickoutRoomMember",				'i', "" 	  },
};

void Register_sceNpMatching2()
{
	RegisterHLEModule("sceNpMatching2", ARRAY_SIZE(sceNpMatching2), sceNpMatching2);
}
