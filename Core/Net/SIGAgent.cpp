#include "Core/Net/SIGAgent.h"

namespace net {
	int SIGAgent::UpnpThreadTick() {
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

    std::chrono::microseconds SIGAgent::ProcessUPnPMessages() {
		return std::chrono::duration_cast<std::chrono::microseconds>(5s);
	}

    bool SIGAgent::IsRunning() { return running; }
	bool SIGAgent::IsIntialized() { return initialized; }

    // Returns Local Address in Network Order
    u32 SIGAgent::GetLocalAddr() {
        std::unique_lock<std::mutex> lock(rpcn_mtx_);
        if (local_addr_sig.load() == 0)
            sigv.wait_for(lock, std::chrono::seconds(5), [&] { return local_addr_sig.load() != 0; });
        return local_addr_sig.load();
    }
    // Returns Signaling Address in Network Order
    u32 SIGAgent::GetSigAddr() {
        std::unique_lock<std::mutex> lock(rpcn_mtx_);
        if (addr_sig.load() == 0)
            sigv.wait_for(lock, std::chrono::seconds(5), [&] { return addr_sig.load() != 0; });
        return addr_sig.load();
    }
    // Returns Signaling Port in Host Order
    u16 SIGAgent::GetSigPort() {
        std::unique_lock<std::mutex> lock(rpcn_mtx_);
        if (port_sig.load() == 0)
            sigv.wait_for(lock, std::chrono::seconds(5), [&] { return port_sig.load() != 0; });
        u16 sig_port = port_sig.load();
        if (sig_port == SCE_SIGN_PORT)
            sig_port = SCE_INTERNAL_PORT;
        return sig_port;
    }
    u8 SIGAgent::GetNatType() {
        std::unique_lock<std::mutex> lock(rpcn_mtx_);
        return nat_type.load();
    }
    u64 SIGAgent::GetLatencyUs() {
        return latency.load();
    }

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
