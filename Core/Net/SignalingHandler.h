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

enum SignalingCommand : u32 {
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
	u32 addr = 0;
	u16 port = 0;

	// User seen from that peer
	u32 mapped_addr = 0;
	u16 mapped_port = 0;

	// For handler
	std::chrono::steady_clock::time_point time_last_msg_recvd = std::chrono::steady_clock::now();
	bool self = false;
	SceNpId npid{};

	// Signaling
	u32 conn_id = 0;
	bool op_activated = false;
	u32 info_counter = 10;

	// Matching2
	u64 room_id = 0;
	u16 member_id = 0;

	// Stats
	u64 last_rtts[6] = {};
	std::size_t rtt_counters = 0;
	u32 rtt = 0;
	u32 pings_sent = 1, lost_pings = 0;
	u32 packet_loss = 0;
};

struct signaling_packet {
	u32_le signature = SIGNALING_SIGNATURE;
	u32_le version = SIGNALING_VERSION;
	u64_le timestamp_sender;
	u64_le timestamp_receiver;
	SignalingCommand command;
	u32_le sent_addr;
	u16_le sent_port;
	SceNpId npid;
};

struct signaling_message
{
	u32 src_addr = 0;
	u16 src_port = 0;

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
	void connect(u32 conn_id, u32 addr, u16 port);
	void stop();

	std::shared_ptr<signaling_info> get_signaling_ptr(const signaling_packet* sp);

	u32 get_always_conn_id(const SceNpId& npid);
	std::optional<signaling_info> get_sig_infos(u32 conn_id);
	// Create connection to RPCN
	u32 init_sig(const SceNpId& npid);
	// Create connection to P2P
	u32 init_sig(const SceNpId& npid, u64 room_id, u16 member_id);
	void DisconnectUsers(u64 room_id);
	void stop_sig_nl(u32 conn_id, bool forceful);
	void sig2_callback(u64 room_id, u16 member_id, SceNpMatching2Event event, s32 error_code) const;

	// send helpers (you already have an implementation; we call into it)
	void send_signaling_packet(signaling_packet& sp, u32 addr, u16 port) const;
	bool send_packet_ipv4(const std::vector<u8>& data, u32 addr, u16 port) const;
	void retire_all_packets(std::shared_ptr<signaling_info>& si);

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

	std::vector<std::vector<u8>> get_rpcn_msgs() {
		std::vector<std::vector<u8>> msgs;
		{
			std::lock_guard lock(mtx_);
			msgs = std::move(rpcn_msgs);
			rpcn_msgs.clear();
		}
		return msgs;
	}
private:
	void recv_loop();
	void ping_loop(s64* user_id, u32* local_addr);
	void dispatch_packet(signaling_message msg);

	void handle_ping(const signaling_packet* sp, u32 op_addr, u32 op_port);
	void handle_pong(const signaling_packet* sp);
	void handle_info(const signaling_packet* sp, u32 op_addr, u32 op_port);
	void handle_connect(const signaling_packet* sp, u32 op_addr, u32 op_port);
	void handle_connect_ack(const signaling_packet* sp, u32 op_addr, u32 op_port);
	void handle_confirm(const signaling_packet* sp, u32 op_addr, u32 op_port);
	void handle_finished(const signaling_packet* sp, u32 op_addr, u32 op_port);
	void handle_finished_ack(const signaling_packet* sp);

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
	std::thread recv_thread_;
	std::thread ping_thread_;

	mutable std::mutex mtx_;
	std::vector<std::vector<u8>> rpcn_msgs{};
	std::unordered_map<u32, ContextState> contexts_;
	std::map<std::chrono::steady_clock::time_point, queued_packet> qpackets; // (wakeup time, packet)
	std::atomic<u32> next_ctx_{ 1 }; // simple monotonic id

	u32 cur_conn_id = 1;
	std::unordered_map<std::string, u32> npid_to_conn_id;               // (npid, conn_id)
	std::unordered_map<u32, std::shared_ptr<signaling_info>> sig_peers; // (conn_id, sig_info)

};

extern signaling_handler g_signaling;
extern BlockAllocator np_memory;
