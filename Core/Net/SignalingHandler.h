#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <optional>

#include "Core/HLE/HLE.h"
#include "Core/HLE/Np2Types.h"
#include <Core/Net/NPAgent.h>

#include "Common/Net/SocketCompat.h"
#include "Core/HLE/SocketManager.h"
#include <Core/Util/BlockAllocator.h>

constexpr s32 VPORT_0_HEADER_SIZE = sizeof(u16) + sizeof(u8); // u16 vport(LE) + u8 subset

enum VPORT_0_SUBSET : u8
{
	SUBSET_RPCN = 0,
	SUBSET_SIGNALING = 1,
};

enum SignalingCommand : u32_le {
	Ping,
	Pong,
	Connect,
	ConnectAck,
	Confirm,
	Finished,
	FinishedAck,
	Info,
};

static constexpr auto REPEAT_CONNECT_DELAY = std::chrono::milliseconds(200);
static constexpr auto REPEAT_PING_DELAY = std::chrono::milliseconds(500);
static constexpr auto REPEAT_FINISHED_DELAY = std::chrono::milliseconds(500);
static constexpr auto REPEAT_INFO_DELAY = std::chrono::milliseconds(200);
//static constexpr be_t<u32> SIGNALING_SIGNATURE = (static_cast<u32>('S') << 24 | static_cast<u32>('I') << 16 | static_cast<u32>('G') << 8 | static_cast<u32>('N'));
static constexpr u32 SIGNALING_SIGNATURE = (static_cast<u32>('N') << 24 | static_cast<u32>('G') << 16 | static_cast<u32>('I') << 8 | static_cast<u32>('S'));
static constexpr u32_le SIGNALING_VERSION = 3;

struct signaling_info
{
	s32 conn_status = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;
	u32_be addr = 0;
	u16_be port = 0;

	// User seen from that peer
	u32_be mapped_addr = 0;
	u16_be mapped_port = 0;

	// For handler
	std::chrono::steady_clock::time_point time_last_msg_recvd = std::chrono::steady_clock::now();
	bool self = false;
	SceNpId npid{};

	// Signaling
	u32 conn_id = 0;
	bool op_activated = false;
	u32 info_counter = 10;

	// Matching2
	SceNpMatching2RoomId room_id = 0;
	SceNpMatching2RoomMemberId member_id = 0;

	// Stats
	u64 last_rtts[6] = {};
	std::size_t rtt_counters = 0;
	u32 rtt = 0;
	u32 pings_sent = 1, lost_pings = 0;
	u32 packet_loss = 0;
};

struct signaling_packet {
	u32_be signature = SIGNALING_SIGNATURE;
	u32_le version = SIGNALING_VERSION;
	u64_le timestamp_sender;
	u64_le timestamp_receiver;
	SignalingCommand command;
	u32_be sent_addr;
	u16_be sent_port;
	SceNpId npid;
};

struct signaling_message
{
	u32_be src_addr = 0;
	u16_be src_port = 0;

	std::vector<u8> data;
};

struct queued_packet
{
	signaling_packet packet{};
	std::shared_ptr<signaling_info> sig_info;
};

// user callback signature
// invoked on any packet that belongs to a context
using SignalingCallback = std::function<void(const signaling_packet& incoming)>;

struct ContextState {
	u32 ctx_id;
	PSPPointer<SceNpMatching2RequestCallback> cb;
	PSPPointer<u8> cb_arg;
	u32 event_type;

	std::chrono::steady_clock::time_point last_activity{};
	// optionally track expected next step for sanity/timeouts
	std::optional<SignalingCommand> expected_next{};
};

class signaling_handler {
public:
	signaling_handler();
	~signaling_handler();

	static void print_interfaces();
	static u64 get_micro_timestamp(const std::chrono::steady_clock::time_point& time_point);
	// DEBUGGING
	bool create_connection();
	bool destroy_connection();
	void connect(u32 conn_id, u32_be addr, u16_be port);
	void stop();

	std::shared_ptr<signaling_info> get_signaling_ptr(const signaling_packet* sp);

	u32 get_always_conn_id(const SceNpId& npid);
	std::optional<u32> get_conn_id_from_npid(const SceNpId& npid);
	std::optional<signaling_info> get_sig_infos(u32 conn_id);
	void set_self_sig_info(SceNpId& npid);
	// Create connection to RPCN
	u32 init_sig(const SceNpId& npid);
	// Create connection to P2P
	u32 init_sig(const SceNpId& npid, SceNpMatching2RoomId room_id, SceNpMatching2RoomMemberId member_id);
	void update_si_addr(std::shared_ptr<signaling_info>& si, u32_be new_addr, u16_be new_port);
	void update_si_mapped_addr(std::shared_ptr<signaling_info>& si, u32_be new_addr, u16_be new_port);
	void update_si_status(std::shared_ptr<signaling_info>& si, s32 new_status, s32 error_code);
	void update_ext_si_status(std::shared_ptr<signaling_info>& si, bool op_activated);
	void DisconnectUsers(SceNpMatching2RoomId room_id);
	void stop_sig_nl(u32 conn_id, bool forceful);
	//void sig2_callback(u64 room_id, u16 member_id, SceNpMatching2Event event, s32 error_code) const;

	// send helpers (you already have an implementation; we call into it)
	void send_signaling_packet(signaling_packet& sp, u32_be addr, u16_be port) const;
	void send_information_packets(u32_be addr, u16_be port, const SceNpId& npid);
	void reschedule_packet(std::shared_ptr<signaling_info>& si, SignalingCommand cmd, std::chrono::steady_clock::time_point new_timepoint);
	void retire_packet(std::shared_ptr<signaling_info>& si, SignalingCommand cmd);
	void retire_all_packets(std::shared_ptr<signaling_info>& si);

	bool send_packet_ipv4(const std::vector<u8>& data, sockaddr_in dest) const;
	// Signal Triggers
	void UserJoinedRoom(net::RPCNResponse resp);
	void UserLeftRoom(net::RPCNResponse resp);
	void RoomDestroyed(net::RPCNResponse resp);
	void UpdatedRoomDataInternal(net::RPCNResponse resp);
	void UpdatedRoomMemberDataInternal(net::RPCNResponse resp);
	void RoomMessageReceived(net::RPCNResponse resp);
	void SignalingHelper(net::RPCNResponse resp);
	// GUI
	void MemberJoinedRoomGUI(net::RPCNResponse resp);
	void MemberLeftRoomGUI(net::RPCNResponse resp);
	void RoomDisappearedGUI(net::RPCNResponse resp);
	void RoomOwnerChangedGUI(net::RPCNResponse resp);
	void UserKickedGUI(net::RPCNResponse resp);
	void QuickMatchCompleteGUI(net::RPCNResponse resp);

	void wait_for_rpcn(bool* running, bool* cancelled, std::chrono::nanoseconds duration) {
		std::unique_lock<std::mutex> lock(rpcn_mtx_);
		rpcn_msg_cv.wait_for(lock, duration, [&] { return (!*running || *cancelled) || (!rpcn_msgs.empty()); });
	}
	// Needs to wake when a packet is queued
	// Needs to wake when a new connection is made
	void wait_for_sign(std::chrono::nanoseconds duration) {
		std::unique_lock<std::mutex> lock(sign_mtx_);
		sign_msg_cv.wait_for(lock, duration, [&] { return (!running_.load(std::memory_order_relaxed) || wakey.load(std::memory_order_relaxed) || !sign_msgs.empty()); });
	}

	std::vector<std::vector<u8>> get_rpcn_msgs() {
		std::vector<std::vector<u8>> msgs;
		{
			std::lock_guard lock(rpcn_mtx_);
			msgs = std::move(rpcn_msgs);
			rpcn_msgs.clear();
		}
		return msgs;
	}
private:
	void recv_loop(InetSocket* inetSocket);
	void signaling_thread();
	void ping_loop(s64* user_id, u32* local_addr);
	std::vector<signaling_message> get_sign_msgs();
	void process_incoming_messages();

	void handle_ping(const signaling_packet* sp, signaling_packet& sent_packet, u32_be op_addr, u16_be op_port);
	void handle_pong(const signaling_packet* sp, std::shared_ptr<signaling_info> si);
	void handle_info(const signaling_packet* sp, std::shared_ptr<signaling_info> si, u32_be op_addr, u16_be op_port);
	void handle_connect(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32_be op_addr, u16_be op_port);
	void handle_connect_ack(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32_be op_addr, u16_be op_port);
	void handle_confirm(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32_be op_addr, u16_be op_port);
	void handle_finished(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32_be op_addr, u16_be op_port);
	void handle_finished_ack(const signaling_packet* sp, std::shared_ptr<signaling_info> si);

	// context helpers
	//std::optional<ContextState> get_ctx(u32 ctx);
	//void touch_ctx(u32 ctx);
	//create/register a new context id and callback
	//u32 create_context(SignalingCallback cb);
	//void add_match2_ctx(ContextState context);
	//void remove_match2_ctx(ContextState context);
	void queue_signaling_packet(signaling_packet& sp, std::shared_ptr<signaling_info> si, std::chrono::steady_clock::time_point wakeup_time);
	
private:
	std::atomic<bool> running_{ false };
	std::atomic<bool> wakey{ false };
	std::thread recv_thread_;
	std::thread signaling_thread_;
	// This mutex handles general Signaling variables
	mutable std::mutex mtx_;

	// This mutex controls RPCN Message Packets
	mutable std::mutex rpcn_mtx_;
	std::condition_variable rpcn_msg_cv;
	std::vector<std::vector<u8>> rpcn_msgs{};

	// This mutex controls P2P Message Packets
	mutable std::mutex sign_mtx_;
	std::condition_variable sign_msg_cv;
	std::vector<signaling_message> sign_msgs{};

	std::unordered_map<u32, ContextState> contexts_;
	std::map<std::chrono::steady_clock::time_point, queued_packet> qpackets; // (wakeup time, packet)
	std::atomic<u32> next_ctx_{ 1 }; // simple monotonic id

	u32 cur_conn_id = 1;
	std::unordered_map<std::string, u32> npid_to_conn_id;               // (npid, conn_id)
	std::unordered_map<u32, std::shared_ptr<signaling_info>> sig_peers; // (conn_id, sig_info)

};

extern signaling_handler g_signaling;
extern BlockAllocator np_memory;
