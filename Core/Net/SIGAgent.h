#pragma once
#include <optional>
#include <type_traits> // is_constant_evaluated
#include <unordered_set>
#include <condition_variable>
#include <unordered_map>
#include <thread>   // For std::thread
#include <atomic>
#include <chrono>

#include "Common/CommonTypes.h"
#include "Core/Config.h"
#include "Core/Util/PortManager.h"
#include "Core/Net/NPAgent.h"
#include "Core/HLE/SocketManager.h"
#include "Core/HLE/sceNpSignaling.h"

// Used for things like 10s
using namespace std::chrono_literals;

namespace net {
	enum class SIGAgentType { NONE, PSN, RPCN };

	class SIGAgent {
	public:
		virtual ~SIGAgent() = default;

		virtual int UpnpThreadTick();
		virtual int MainThreadTick(BlockAllocator* signaling_memory);
		virtual int EchoThreadTick(BlockAllocator* signaling_memory);
		virtual int HandleP2PPacket();
		virtual std::chrono::microseconds ProcessUPnPMessages();
		// virtual void ProcessP2PMessages(PSPPointer<PipePacket> packet);

		bool IsRunning();
		bool IsIntialized();

		// Returns Local Address in Network Order
		u32 GetLocalAddr();
		// Returns Signaling Address in Network Order
		u32 GetSigAddr();
		// Returns Signaling Port in Host Order
		u16 GetSigPort();
		u8 GetNatType();
		u64 GetLatencyUs();

		std::vector<SceNpMatching2RoomMemberId> GetPeerList() {
			std::vector<SceNpMatching2RoomMemberId> active_members;
			// Iterate through the unordered_map of shared_ptrs
			for (auto const& [id, peer] : sig_peers) {
				if (peer && 
					// peer->sig_status == SCE_NP_SIGNALING_EVENT_EXT_MUTUAL_ACTIVATED && 
					peer->conn_status == SCE_NP_SIGNALING_CONN_STATUS_ACTIVE) {
					
					active_members.push_back(peer->member_id);
				}
			}
			
			return active_members;
		}
		
		SceNpMatching2RoomMemberId GetPeerFrom(uint32_t addr, uint16_t port) {
			for (auto const& [id, peer] : sig_peers) {
				if (peer && 
					peer->addr == addr && 
					peer->port == port &&
					// peer->sig_status == SCE_NP_SIGNALING_EVENT_EXT_MUTUAL_ACTIVATED && 
					peer->conn_status == SCE_NP_SIGNALING_CONN_STATUS_ACTIVE) {
					
					return peer->member_id;
				}
			}
			
			return 0; // Return 0 as 'not found' or 'unidentified'
		}
		// Signaling Helpers

		virtual u32 init_sig(const SceNpId& npid);
		virtual u32 init_sig(const SceNpId& npid, SceNpMatching2RoomId room_id, SceNpMatching2RoomMemberId member_id);
		virtual u32 get_always_conn_id(const SceNpId& npid);
		virtual std::optional<u32> get_conn_id_from_npid(const SceNpId& npid);
		virtual std::optional<SceSignalingPeer> get_sig_infos(u32 conn_id);
		virtual void set_self_sig_info(SceNpId& npid);
		virtual std::shared_ptr<SceSignalingPeer> get_signaling_ptr(const SignalingPacket* sp);
		virtual void update_si_addr(std::shared_ptr<SceSignalingPeer>& si, u32 new_addr, u16 new_port);
		virtual void update_si_mapped_addr(std::shared_ptr<SceSignalingPeer>& si, u32 new_addr, u16 new_port);
		virtual void update_si_status(std::shared_ptr<SceSignalingPeer>& si, s32 new_status, s32 error_code);
		virtual void update_ext_si_status(std::shared_ptr<SceSignalingPeer>& si, bool op_activated);
		
		// Connection Helpers

		virtual void connect(u32 conn_id, u32 addr, u16 port);
		virtual bool create_connection();
		virtual bool destroy_connection();
		virtual void stop(const char* reason);
		virtual void DisconnectUsers(SceNpMatching2RoomId room_id);

		// Notification Functions

		virtual int UserJoinedRoom(net::RPCNResponse resp);
		virtual int UserLeftRoom(net::RPCNResponse resp);
		virtual int RoomDestroyed(net::RPCNResponse resp);
		virtual int UpdatedRoomDataInternal(net::RPCNResponse resp);
		virtual int UpdatedRoomMemberDataInternal(net::RPCNResponse resp);
		virtual int RoomMessageReceived(net::RPCNResponse resp);
		virtual void SignalingHelper(net::RPCNResponse resp);
		virtual void MemberJoinedRoomGUI(net::RPCNResponse resp);
		virtual void MemberLeftRoomGUI(net::RPCNResponse resp);
		virtual void RoomDisappearedGUI(net::RPCNResponse resp);
		virtual void RoomOwnerChangedGUI(net::RPCNResponse resp);
		virtual void UserKickedGUI(net::RPCNResponse resp);
		virtual void QuickMatchCompleteGUI(net::RPCNResponse resp);

	public:
		int tries = 0;
		// Public and Private addresses
		std::condition_variable sigv;
		// Network Order
		std::atomic<u32> addr_sig;
		// Host Order
		std::atomic<u16> port_sig;
		// Network Order
		std::atomic<u32> local_addr_sig = 0;
		std::atomic<u8> nat_type = SCE_NP_SIGNALING_NETINFO_NAT_STATUS_UNKNOWN;
        std::atomic<u64> latency = 0;

	private:

	protected:
		mutable std::mutex rpcn_mtx_;
		u32 cur_conn_id = 1;
		std::unordered_map<std::string, u32> npid_to_conn_id;               // (npid, conn_id)
		std::unordered_map<u32, std::shared_ptr<SceSignalingPeer>> sig_peers; // (conn_id, sig_info)

		bool cancelled = false;
		bool running = false;
		bool initialized = false;
	};


}

extern std::unique_ptr<net::SIGAgent> sigServer;