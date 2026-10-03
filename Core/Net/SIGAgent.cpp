#include "Core/Net/SIGAgent.h"

namespace net {
	int SIGAgent::NATKeepAlive() {
		return 0;
	}

    int SIGAgent::MainThreadTick(BlockAllocator* signaling_memory) {
        return 0;
    }
    int SIGAgent::EchoThreadTick(BlockAllocator* signaling_memory) {
        return 0;
    }
	int SIGAgent::HandleP2PPacket() {
		return 0;
	}

    std::chrono::microseconds SIGAgent::ProcessNATResponses() {
		return std::chrono::duration_cast<std::chrono::microseconds>(5s);
	}

    bool SIGAgent::IsRunning() { return running; }
	bool SIGAgent::IsInitialized() { return initialized; }
	// Signaling Helpers

	u32 SIGAgent::init_sig(const SceNpId& npid) {
		return 0;
	}

	u32 SIGAgent::init_sig(const SceNpId& npid, SceNpMatching2RoomId room_id, SceNpMatching2RoomMemberId member_id) {
		return 0;
	}

	u32 SIGAgent::get_always_conn_id(const SceNpId& npid) {
		return 0;
	}

	std::optional<u32> SIGAgent::get_conn_id_from_npid(const SceNpId& npid) {
		return std::nullopt;
	}

	std::optional<SceSignalingPeer> SIGAgent::get_sig_infos(u32 conn_id) {
		return std::nullopt;
	}

	void SIGAgent::set_self_sig_info(SceNpId& npid) {
	}

	std::shared_ptr<SceSignalingPeer> SIGAgent::get_signaling_ptr(const SignalingPacket* sp) {
		return nullptr;
	}

	void SIGAgent::update_si_addr(std::shared_ptr<SceSignalingPeer>& si, u32 new_addr, u16 new_port) {
	}

	void SIGAgent::update_si_mapped_addr(std::shared_ptr<SceSignalingPeer>& si, u32 new_addr, u16 new_port) {
	}

	void SIGAgent::update_si_status(std::shared_ptr<SceSignalingPeer>& si, s32 new_status, s32 error_code) {
	}

	void SIGAgent::update_ext_si_status(std::shared_ptr<SceSignalingPeer>& si, bool op_activated) {
	}

	// Connection Helpers

	void SIGAgent::connect(u32 conn_id, u32 addr, u16 port) {
	}

	bool SIGAgent::create_connection() {
		return false;
	}

	bool SIGAgent::destroy_connection() {
		return false;
	}

	void SIGAgent::stop(const char* reason) {
	}

	void SIGAgent::DisconnectUsers(SceNpMatching2RoomId room_id) {
	}

	// Notification Functions

	int SIGAgent::UserJoinedRoom(net::RPCNResponse resp) {
		return 0;
	}

	int SIGAgent::UserLeftRoom(net::RPCNResponse resp) {
		return 0;
	}

	int SIGAgent::RoomDestroyed(net::RPCNResponse resp) {
		return 0;
	}

	int SIGAgent::UpdatedRoomDataInternal(net::RPCNResponse resp) {
		return 0;
	}

	int SIGAgent::UpdatedRoomMemberDataInternal(net::RPCNResponse resp) {
		return 0;
	}

	int SIGAgent::RoomMessageReceived(net::RPCNResponse resp) {
		return 0;
	}

	void SIGAgent::SignalingHelper(net::RPCNResponse resp) {
	}

	void SIGAgent::MemberJoinedRoomGUI(net::RPCNResponse resp) {
	}

	void SIGAgent::MemberLeftRoomGUI(net::RPCNResponse resp) {
	}

	void SIGAgent::RoomDisappearedGUI(net::RPCNResponse resp) {
	}

	void SIGAgent::RoomOwnerChangedGUI(net::RPCNResponse resp) {
	}

	void SIGAgent::UserKickedGUI(net::RPCNResponse resp) {
	}

	void SIGAgent::QuickMatchCompleteGUI(net::RPCNResponse resp) {
	}
}
