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

	class PSNSigAgent : public SIGAgent {
	public:
		~PSNSigAgent();
		PSNSigAgent();

        int UpnpThreadTick() override;
		int MainThreadTick(BlockAllocator* signaling_memory) override;
		int EchoThreadTick(BlockAllocator* signaling_memory) override;
        int HandleP2PPacket() override;
		std::chrono::microseconds ProcessUPnPMessages() override;
		void ProcessP2PMessages(PSPPointer<PipePacket> packet);
		// Signaling Helpers

		u32 init_sig(const SceNpId& npid) override;
		u32 init_sig(const SceNpId& npid, SceNpMatching2RoomId room_id, SceNpMatching2RoomMemberId member_id) override;
		u32 get_always_conn_id(const SceNpId& npid) override;
		std::optional<u32> get_conn_id_from_npid(const SceNpId& npid) override;
		std::optional<SceSignalingPeer> get_sig_infos(u32 conn_id) override;
		void set_self_sig_info(SceNpId& npid) override;
		std::shared_ptr<SceSignalingPeer> get_signaling_ptr(const SignalingPacket* sp) override;
		void update_si_addr(std::shared_ptr<SceSignalingPeer>& si, u32 new_addr, u16 new_port) override;
		void update_si_mapped_addr(std::shared_ptr<SceSignalingPeer>& si, u32 new_addr, u16 new_port) override;
		void update_si_status(std::shared_ptr<SceSignalingPeer>& si, s32 new_status, s32 error_code) override;
		void update_ext_si_status(std::shared_ptr<SceSignalingPeer>& si, bool op_activated) override;

		// Connection Helpers

		void connect(u32 conn_id, u32 addr, u16 port) override;
		bool create_connection() override;
		bool destroy_connection() override;
		void stop(const char* reason) override;
		void DisconnectUsers(SceNpMatching2RoomId room_id) override;

		// Notification Functions

		int UserJoinedRoom(net::RPCNResponse resp) override;
		int UserLeftRoom(net::RPCNResponse resp) override;
		int RoomDestroyed(net::RPCNResponse resp) override;
		int UpdatedRoomDataInternal(net::RPCNResponse resp) override;
		int UpdatedRoomMemberDataInternal(net::RPCNResponse resp) override;
		int RoomMessageReceived(net::RPCNResponse resp) override;
		void SignalingHelper(net::RPCNResponse resp) override;
		void MemberJoinedRoomGUI(net::RPCNResponse resp) override;
		void MemberLeftRoomGUI(net::RPCNResponse resp) override;
		void RoomDisappearedGUI(net::RPCNResponse resp) override;
		void RoomOwnerChangedGUI(net::RPCNResponse resp) override;
		void UserKickedGUI(net::RPCNResponse resp) override;
		void QuickMatchCompleteGUI(net::RPCNResponse resp) override;
    private:
        
	};

    struct SignalingMessage
    {
        u32 src_addr = 0;
        u16 src_port = 0;

        std::vector<u8> data;
    };

	struct queued_packet
	{
		SignalingPacket packet{};
		std::shared_ptr<SceSignalingPeer> sig_info;
	};
	
	class RPCNSigAgent : public SIGAgent {
	public:
		static const u32 PROTOCOL_VERSION = 27;
		~RPCNSigAgent();
		RPCNSigAgent();

        int UpnpThreadTick() override;
		int MainThreadTick(BlockAllocator* signaling_memory) override;
		int EchoThreadTick(BlockAllocator* signaling_memory) override;
        int HandleP2PPacket() override;
		std::chrono::microseconds ProcessUPnPMessages() override;
		void ProcessP2PMessages(SignalingMessage msg);

		std::vector<std::vector<u8>> get_rpcn_msgs() {
			std::vector<std::vector<u8>> msgs;
			{
				std::lock_guard lock(rpcn_mtx_);
				msgs = std::move(rpcn_msgs);
				rpcn_msgs.clear();
			}
			return msgs;
		}
		std::vector<SignalingMessage> get_sign_msgs() {
			std::vector<SignalingMessage> msgs;
			std::lock_guard lock(sign_mtx_);
			msgs = std::move(sign_msgs);
			sign_msgs.clear();

			return msgs;
		}
		void handle_ping(const SignalingPacket* sp, SignalingPacket& sent_packet, u32 op_addr, u16 op_port);
		void handle_pong(const SignalingPacket* sp, std::shared_ptr<SceSignalingPeer> si);
		void handle_info(const SignalingPacket* sp, std::shared_ptr<SceSignalingPeer> si, u32 op_addr, u16 op_port);
		void handle_connect(const SignalingPacket* sp, std::shared_ptr<SceSignalingPeer> si, SignalingPacket& sent_packet, u32 op_addr, u16 op_port);
		void handle_connect_ack(const SignalingPacket* sp, std::shared_ptr<SceSignalingPeer> si, SignalingPacket& sent_packet, u32 op_addr, u16 op_port);
		void handle_confirm(const SignalingPacket* sp, std::shared_ptr<SceSignalingPeer> si, SignalingPacket& sent_packet, u32 op_addr, u16 op_port);
		void handle_finished(const SignalingPacket* sp, std::shared_ptr<SceSignalingPeer> si, SignalingPacket& sent_packet, u32 op_addr, u16 op_port);
		void handle_finished_ack(const SignalingPacket* sp, std::shared_ptr<SceSignalingPeer> si);

		// Signaling Helpers

		u32 init_sig(const SceNpId& npid) override;
		u32 init_sig(const SceNpId& npid, SceNpMatching2RoomId room_id, SceNpMatching2RoomMemberId member_id) override;
		u32 get_always_conn_id(const SceNpId& npid) override;
		std::optional<u32> get_conn_id_from_npid(const SceNpId& npid) override;
		std::optional<SceSignalingPeer> get_sig_infos(u32 conn_id) override;
		void set_self_sig_info(SceNpId& npid) override;
		std::shared_ptr<SceSignalingPeer> get_signaling_ptr(const SignalingPacket* sp) override;
		void update_si_addr(std::shared_ptr<SceSignalingPeer>& si, u32 new_addr, u16 new_port) override;
		void update_si_mapped_addr(std::shared_ptr<SceSignalingPeer>& si, u32 new_addr, u16 new_port) override;
		void update_si_status(std::shared_ptr<SceSignalingPeer>& si, s32 new_status, s32 error_code) override;
		void update_ext_si_status(std::shared_ptr<SceSignalingPeer>& si, bool op_activated) override;

		// Connection Helpers

		void connect(u32 conn_id, u32 addr, u16 port) override;
		bool create_connection() override;
		bool destroy_connection() override;
		void stop(const char* reason) override;
		// bool send_packet_ipv4(const std::vector<u8>& data, sockaddr_in dest);
		void DisconnectUsers(SceNpMatching2RoomId room_id) override;
		void stop_sig_nl(u32 conn_id, bool forceful);
		void stop_sig(u32 conn_id, bool forceful);

		// Packet Helpers

		static u64 get_micro_timestamp(const std::chrono::steady_clock::time_point& time_point);
		bool send_upnp_packet(const std::vector<u8>& data, sockaddr_in* dest);
		void send_signaling_packet(SignalingPacket& sp, u32 addr, u16 port);
		void send_information_packets(u32 addr, u16 port, const SceNpId& npid);
		void reschedule_packet(std::shared_ptr<SceSignalingPeer>& si, SceNpSignalingCommand cmd, std::chrono::steady_clock::time_point new_timepoint);
		void retire_packet(std::shared_ptr<SceSignalingPeer>& si, SceNpSignalingCommand cmd);
		void retire_all_packets(std::shared_ptr<SceSignalingPeer>& si);
		void queue_signaling_packet(SignalingPacket& sp, std::shared_ptr<SceSignalingPeer> si, std::chrono::steady_clock::time_point wakeup_time);

		// Notification Functions

		int UserJoinedRoom(net::RPCNResponse resp) override;
		int UserLeftRoom(net::RPCNResponse resp) override;
		int RoomDestroyed(net::RPCNResponse resp) override;
		int UpdatedRoomDataInternal(net::RPCNResponse resp) override;
		int UpdatedRoomMemberDataInternal(net::RPCNResponse resp) override;
		int RoomMessageReceived(net::RPCNResponse resp) override;
		void SignalingHelper(net::RPCNResponse resp) override;
		void MemberJoinedRoomGUI(net::RPCNResponse resp) override;
		void MemberLeftRoomGUI(net::RPCNResponse resp) override;
		void RoomDisappearedGUI(net::RPCNResponse resp) override;
		void RoomOwnerChangedGUI(net::RPCNResponse resp) override;
		void UserKickedGUI(net::RPCNResponse resp) override;
		void QuickMatchCompleteGUI(net::RPCNResponse resp) override;
	private:
		std::mutex buffer_mutex;
		std::condition_variable buffer_cv;

		// This mutex handles general Signaling variables
		mutable std::mutex mtx_;

		// This mutex controls RPCN Message Packets
		mutable std::mutex rpcn_mtx_;
		std::condition_variable rpcn_msg_cv;
		std::vector<std::vector<u8>> rpcn_msgs{};

		mutable std::mutex sign_mtx_;
		std::condition_variable sign_msg_cv;
		std::vector<SignalingMessage> sign_msgs{};

		std::map<std::chrono::steady_clock::time_point, queued_packet> qpackets;
		
		std::mutex sig_mutex;
		std::chrono::steady_clock::time_point last_ping_time_ipv4{}, last_pong_time_ipv4{};
		std::chrono::steady_clock::time_point last_ping_time_ipv6{}, last_pong_time_ipv6{};
		bool sendto(const std::vector<u8>& data, sockaddr_in dest);
	};

	inline std::unique_ptr<SIGAgent> InitSigAgent(NPAgentType type) {
		switch (type) {
		case NPAgentType::RPCN: return std::make_unique<RPCNSigAgent>();
		case NPAgentType::FAKE_PSN: return std::make_unique<PSNSigAgent>();
		case NPAgentType::PSN: return std::make_unique<PSNSigAgent>();
		}
		return nullptr;
	}

}

extern std::unique_ptr<net::SIGAgent> sigServer;