#pragma once
#include <mutex>
#include <deque>
#include <map>

#include <sstream>
#include <string>
#include <iomanip>
#include <cstdint>
#include <Swap.h>
#include <algorithm>

#include "Core/MemMap.h"
#include "Core/HLE/Np2Types.h"

#include <optional>
#include <condition_variable>
#include <thread>
#include <variant>
#include <vector>
#include <functional>

// Used By Score and Tus
struct generic_async_transaction_context
{
	~generic_async_transaction_context();

	generic_async_transaction_context(const SceNpCommunicationId& communicationId, const SceNpCommunicationPassphrase& passphrase, u64 timeout);

	std::optional<s32> get_transaction_status();
	void abort_transaction();
	u32 wait_for_completion();
	void set_result_and_wake(u32 err);

	std::recursive_mutex mutex;
	std::condition_variable_any wake_cond, completion_cond;
	std::optional<u32> result;
	SceNpCommunicationId communicationId;
	SceNpCommunicationPassphrase passphrase;
	u64 timeout;

	std::thread thread;

	u32 idm_id;
};

// Match2 related
struct match2_ctx
{
	match2_ctx(PSPPointer<SceNpCommunicationId> communicationId, PSPPointer<SceNpCommunicationPassphrase> passphrase, s32 option);

	static const u32 id_base = 1;
	static const u32 id_step = 1;
	static const u32 id_count = 255; // TODO: constant here?
	SAVESTATE_INIT_POS(27);

	std::atomic<u32> started = 0;

std::recursive_mutex mutex;

	SceNpCommunicationId communicationId{};
	SceNpCommunicationPassphrase passphrase{};
	bool include_onlinename = false, include_avatarurl = false;

	PSPPointer<SceNpMatching2ContextCallback> context_callback{};
	PSPPointer<void> context_callback_param{};

	SceNpMatching2RequestOptParam default_match2_optparam{};

	PSPPointer<SceNpMatching2SignalingCallback> signaling_cb{};
	PSPPointer<void> signaling_cb_arg{};
};
u16 create_match2_context(PSPPointer<SceNpCommunicationId> communicationId, PSPPointer<SceNpCommunicationPassphrase> passphrase, s32 option);
bool check_match2_context(u16 ctx_id);
std::shared_ptr<match2_ctx> get_match2_context(u16 ctx_id);
bool destroy_match2_context(u16 ctx_id);

struct lookup_title_ctx
{
	lookup_title_ctx(PSPPointer<SceNpCommunicationId> communicationId);

	static const u32 id_base = 0x3001;
	static const u32 id_step = 1;
	static const u32 id_count = SCE_NP_LOOKUP_MAX_CTX_NUM;
	SAVESTATE_INIT_POS(28);

	SceNpCommunicationId communicationId{};
	SceNpCommunicationPassphrase passphrase{};
};
s32 create_lookup_title_context(PSPPointer<SceNpCommunicationId> communicationId);
bool destroy_lookup_title_context(s32 ctx_id);

struct lookup_transaction_ctx
{
	lookup_transaction_ctx(s32 lt_ctx);

	static const u32 id_base = 0x4001;
	static const u32 id_step = 1;
	static const u32 id_count = SCE_NP_LOOKUP_MAX_CTX_NUM;
	SAVESTATE_INIT_POS(29);

	s32 lt_ctx = 0;
};
s32 create_lookup_transaction_context(s32 lt_ctx);
bool destroy_lookup_transaction_context(s32 ctx_id);

struct commerce2_ctx
{
	commerce2_ctx(u32 version, PSPPointer<SceNpId> npid, PSPPointer<SceNpCommerce2Handler> handler, void* arg);

	static const u32 id_base = 0x5001;
	static const u32 id_step = 1;
	static const u32 id_count = SCE_NP_COMMERCE2_CTX_MAX;
	SAVESTATE_INIT_POS(30);

	u32 version{};
	SceNpId npid{};
	PSPPointer<SceNpCommerce2Handler> context_callback{};
	PSPPointer<void> context_callback_param{};
};
s32 create_commerce2_context(u32 version, PSPPointer<SceNpId> npid, PSPPointer<SceNpCommerce2Handler> handler, void* arg);
std::shared_ptr<commerce2_ctx> get_commerce2_context(u16 ctx_id);
bool destroy_commerce2_context(u32 ctx_id);

struct signaling_ctx
{
	signaling_ctx(PSPPointer<SceNpId> npid, PSPPointer<SceNpSignalingHandler> handler, void* arg);

	static const u32 id_base = 0x6001;
	static const u32 id_step = 1;
	static const u32 id_count = SCE_NP_SIGNALING_CTX_MAX;
	SAVESTATE_INIT_POS(31);

	std::recursive_mutex mutex;

	SceNpId npid{};
	PSPPointer<SceNpSignalingHandler> handler{};
	PSPPointer<void> arg{};
	PSPPointer<SceNpSignalingHandler> ext_handler{};
	PSPPointer<void> ext_arg{};
};
s32 create_signaling_context(PSPPointer<SceNpId> npid, PSPPointer<SceNpSignalingHandler> handler, void* arg);
std::shared_ptr<signaling_ctx> get_signaling_context(u32 ctx_id);
bool destroy_signaling_context(u32 ctx_id);

struct matching_ctx
{
	matching_ctx(PSPPointer<SceNpId> npid, PSPPointer<SceNpMatchingHandler> handler, void* arg);

	void queue_callback(u32 req_id, s32 event, s32 u32) const;
	void queue_gui_callback(s32 event, s32 u32) const;

	static const u32 id_base = 0x9001;
	static const u32 id_step = 1;
	static const u32 id_count = 1;
	SAVESTATE_INIT_POS(32);

	SceNpId npid{};
	PSPPointer<SceNpMatchingHandler> handler{};
	PSPPointer<void> arg{};

	std::atomic<u32> busy = 0;
	u32 ctx_id = 0;
	PSPPointer<SceNpMatchingGUIHandler> gui_handler{};
	PSPPointer<void> gui_arg{};

	// Used by QuickMatchGUI
	u64 timeout = 0;
	std::unique_ptr<named_thread<std::function<void(SceNpRoomId)>>> thread;
	std::atomic<u32> wakey = 0;

	// To keep track of which callback to use for sceNpMatchingGetRoomListWithoutGUI / sceNpMatchingGetRoomListGUI / sceNpMatchingGetRoomListLimitGUI
	std::atomic<bool> get_room_limit_version = false;
};
s32 create_matching_context(PSPPointer<SceNpId> npid, PSPPointer<SceNpMatchingHandler> handler, void* arg);
std::shared_ptr<matching_ctx> get_matching_context(u32 ctx_id);
bool destroy_matching_context(u32 ctx_id);
