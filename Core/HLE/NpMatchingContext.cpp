#include "Core/HLE/NpMatchingContext.h"
#include <Log.h>

generic_async_transaction_context::generic_async_transaction_context(const SceNpCommunicationId& communicationId, const SceNpCommunicationPassphrase& passphrase, u64 timeout)
	: communicationId(communicationId), passphrase(passphrase), timeout(timeout)
	, idm_id(idm::last_id())
{
}

generic_async_transaction_context::~generic_async_transaction_context()
{
	if (thread.joinable())
		thread.join();
}

std::optional<s32> generic_async_transaction_context::get_transaction_status()
{
	std::lock_guard lock(mutex);
	return result;
}
void generic_async_transaction_context::abort_transaction()
{
	std::lock_guard lock(mutex);

	result = SCE_NP_COMMUNITY_ERROR_ABORTED;
	wake_cond.notify_one();
}
u32 generic_async_transaction_context::wait_for_completion()
{
	std::unique_lock lock(mutex);

	if (result)
	{
		return *result;
	}

	completion_cond.wait(lock);

	return *result;
}

void generic_async_transaction_context::set_result_and_wake(u32 err)
{
	result = err;
	wake_cond.notify_one();
}

match2_ctx::match2_ctx(PSPPointer<SceNpCommunicationId> communicationId, PSPPointer<SceNpCommunicationPassphrase> passphrase, s32 option)
{
	ensure(!communicationId->data[9] && strlen(communicationId->data) == 9);
	memcpy(&this->communicationId, Memory::GetPointer(communicationId.ptr), sizeof(SceNpCommunicationId));
	memcpy(&this->passphrase, Memory::GetPointer(passphrase.ptr), sizeof(SceNpCommunicationPassphrase));

	include_onlinename = option & SCE_NP_MATCHING2_CONTEXT_OPTION_USE_ONLINENAME;
	include_avatarurl = option & SCE_NP_MATCHING2_CONTEXT_OPTION_USE_AVATARURL;
}
u16 create_match2_context(PSPPointer<SceNpCommunicationId> communicationId, PSPPointer<SceNpCommunicationPassphrase> passphrase, s32 option)
{
	//sceNp2.notice("Creating match2 context with communicationId: <%s>", static_cast<const char*>(communicationId->data));
	NOTICE_LOG(Log::sceNet, "Creating match2 context with communicationId: <%s>", static_cast<const char*>(communicationId->data));
	return static_cast<u16>(idm::make<match2_ctx>(communicationId, passphrase, option));
}
bool destroy_match2_context(u16 ctx_id)
{
	return idm::remove<match2_ctx>(static_cast<u32>(ctx_id));
}
bool check_match2_context(u16 ctx_id)
{
	return (idm::check_unlocked<match2_ctx>(ctx_id) != nullptr);
}
std::shared_ptr<match2_ctx> get_match2_context(u16 ctx_id)
{
	return idm::get_unlocked<match2_ctx>(ctx_id);
}

lookup_title_ctx::lookup_title_ctx(PSPPointer<SceNpCommunicationId> communicationId)
{
	ensure(!communicationId->data[9] && strlen(communicationId->data) == 9);
	memcpy(&this->communicationId, Memory::GetPointer(communicationId.ptr), sizeof(SceNpCommunicationId));
}
s32 create_lookup_title_context(PSPPointer<SceNpCommunicationId> communicationId)
{
	return static_cast<s32>(idm::make<lookup_title_ctx>(communicationId));
}
bool destroy_lookup_title_context(s32 ctx_id)
{
	return idm::remove<lookup_title_ctx>(static_cast<u32>(ctx_id));
}

lookup_transaction_ctx::lookup_transaction_ctx(s32 lt_ctx)
{
	this->lt_ctx = lt_ctx;
}
s32 create_lookup_transaction_context(s32 lt_ctx)
{
	return static_cast<s32>(idm::make<lookup_transaction_ctx>(lt_ctx));
}
bool destroy_lookup_transaction_context(s32 ctx_id)
{
	return idm::remove<lookup_transaction_ctx>(static_cast<u32>(ctx_id));
}

commerce2_ctx::commerce2_ctx(u32 version, PSPPointer<SceNpId> npid, PSPPointer<SceNpCommerce2Handler> handler, void* arg)
{
	this->version = version;
	memcpy(&this->npid, Memory::GetPointer(npid.ptr), sizeof(SceNpId));
	this->context_callback = handler;
	this->context_callback_param = arg;
}
s32 create_commerce2_context(u32 version, PSPPointer<SceNpId> npid, PSPPointer<SceNpCommerce2Handler> handler, void* arg)
{
	return static_cast<s32>(idm::make<commerce2_ctx>(version, npid, handler, arg));
}
bool destroy_commerce2_context(u32 ctx_id)
{
	return idm::remove<commerce2_ctx>(static_cast<u32>(ctx_id));
}
std::shared_ptr<commerce2_ctx> get_commerce2_context(u16 ctx_id)
{
	return idm::get_unlocked<commerce2_ctx>(ctx_id);
}

signaling_ctx::signaling_ctx(PSPPointer<SceNpId> npid, PSPPointer<SceNpSignalingHandler> handler, void* arg)
{
	memcpy(&this->npid, Memory::GetPointer(npid.ptr), sizeof(SceNpId));
	this->handler = handler;
	this->arg = arg;
}
s32 create_signaling_context(PSPPointer<SceNpId> npid, PSPPointer<SceNpSignalingHandler> handler, void* arg)
{
	return static_cast<s32>(idm::make<signaling_ctx>(npid, handler, arg));
}
bool destroy_signaling_context(u32 ctx_id)
{
	return idm::remove<signaling_ctx>(static_cast<u32>(ctx_id));
}
std::shared_ptr<signaling_ctx> get_signaling_context(u32 ctx_id)
{
	return idm::get_unlocked<signaling_ctx>(ctx_id);
}

matching_ctx::matching_ctx(PSPPointer<SceNpId> npId, PSPPointer<SceNpMatchingHandler> handler, void* arg)
{
	memcpy(&this->npid, Memory::GetPointer(npId.ptr), sizeof(SceNpId));
	this->handler = handler;
	this->arg = arg;
}
void matching_ctx::queue_callback(u32 req_id, s32 event, s32 u32) const
{
	if (handler)
	{
		sysutil_register_cb([=, handler = this->handler, ctx_id = this->ctx_id, arg = this->arg](ppu_thread& cb_ppu) -> s32
		{
			handler(cb_ppu, ctx_id, req_id, event, u32, arg);
			return 0;
		});
	}
}
void matching_ctx::queue_gui_callback(s32 event, s32 u32) const
{
	if (gui_handler)
	{
		sysutil_register_cb([=, gui_handler = this->gui_handler, ctx_id = this->ctx_id, gui_arg = this->gui_arg](ppu_thread& cb_ppu) -> s32
		{
			gui_handler(cb_ppu, ctx_id, event, u32, gui_arg);
			return 0;
		});
	}
}
s32 create_matching_context(PSPPointer<SceNpId> npId, PSPPointer<SceNpMatchingHandler> handler, void* arg)
{
	const u32 ctx_id = idm::make<matching_ctx>(npId, handler, arg);
	auto ctx = get_matching_context(ctx_id);
	ctx->ctx_id = ctx_id;
	return static_cast<s32>(ctx_id);
}
std::shared_ptr<matching_ctx> get_matching_context(u32 ctx_id)
{
	return idm::get_unlocked<matching_ctx>(ctx_id);
}
bool destroy_matching_context(u32 ctx_id)
{
	return idm::remove<matching_ctx>(static_cast<u32>(ctx_id));
}
