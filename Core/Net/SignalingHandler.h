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

constexpr s32 VPORT_0_HEADER_SIZE = sizeof(u8); // u16 vport(LE) + u8 subset

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
static const char* SignalingCommandStr[] = {
	"PING",
	"PONG",
	"CONNECT",
	"CONNECT_ACK",
	"CONFIRM",
	"FINISHED",
	"FINISHED_ACK",
	"INFO",
};

static constexpr auto REPEAT_CONNECT_DELAY = std::chrono::milliseconds(200);
static constexpr auto REPEAT_PING_DELAY = std::chrono::milliseconds(500);
static constexpr auto REPEAT_FINISHED_DELAY = std::chrono::milliseconds(500);
static constexpr auto REPEAT_INFO_DELAY = std::chrono::milliseconds(200);
//static constexpr be_t<u32> SIGNALING_SIGNATURE = (static_cast<u32>('S') << 24 | static_cast<u32>('I') << 16 | static_cast<u32>('G') << 8 | static_cast<u32>('N'));
static constexpr u32 SIGNALING_SIGNATURE = (static_cast<u32>('S') << 24 | static_cast<u32>('I') << 16 | static_cast<u32>('G') << 8 | static_cast<u32>('N'));
static constexpr u32_le SIGNALING_VERSION = 3;

struct signaling_info
{
	SceNpSignalingState sig_status = SCE_NP_SIGNALING_EVENT_DEAD;
	SceNpSignalingConnectionState conn_status = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;
	// Network Order NAT bypass address for this Peer
	u32 addr = 0;
	// Host Order NAT bypass port for this Peer
	u16 port = 0;

	// Network Order address the Peer sends from
	u32 mapped_addr = 0;
	// Host Order port the Peer sends from
	u16 mapped_port = 0;

	// Calculated NAT type for this Peer
	u8 nat_type = 0;

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

	static u64 get_micro_timestamp(const std::chrono::steady_clock::time_point& time_point);
	// Signaling Helpers

	// Create connection to RPCN
	u32 init_sig(const SceNpId& npid);
	// Create connection to P2P
	u32 init_sig(const SceNpId& npid, SceNpMatching2RoomId room_id, SceNpMatching2RoomMemberId member_id);
	u32 get_always_conn_id(const SceNpId& npid);
	std::optional<u32> get_conn_id_from_npid(const SceNpId& npid);
	std::optional<signaling_info> get_sig_infos(u32 conn_id);
	void set_self_sig_info(SceNpId& npid);
	std::shared_ptr<signaling_info> get_signaling_ptr(const signaling_packet* sp);
	void update_si_addr(std::shared_ptr<signaling_info>& si, u32 new_addr, u16 new_port);
	void update_si_mapped_addr(std::shared_ptr<signaling_info>& si, u32 new_addr, u16 new_port);
	void update_si_status(std::shared_ptr<signaling_info>& si, s32 new_status, s32 error_code);
	void update_ext_si_status(std::shared_ptr<signaling_info>& si, bool op_activated);
	void DisconnectUsers(SceNpMatching2RoomId room_id);
	void stop_sig_nl(u32 conn_id, bool forceful);
	void stop_sig(u32 conn_id, bool forceful);

	// Connection Helpers

	InetSocket* create_socket(u16 port, int domain, int type, int protocol);
	bool create_connection();
	bool destroy_connection();
	void connect(u32 conn_id, u32 addr, u16 port);
	void stop(const char* reason);

	// Packet Helpers

	void send_signaling_packet(signaling_packet& sp, u32 addr, u16 port) const;
	void send_information_packets(u32 addr, u16 port, const SceNpId& npid);
	void reschedule_packet(std::shared_ptr<signaling_info>& si, SignalingCommand cmd, std::chrono::steady_clock::time_point new_timepoint);
	void retire_packet(std::shared_ptr<signaling_info>& si, SignalingCommand cmd);
	void retire_all_packets(std::shared_ptr<signaling_info>& si);

	// P2P Logic Functions

	std::vector<std::vector<u8>> get_rpcn_msgs() {
		std::vector<std::vector<u8>> msgs;
		{
			std::lock_guard lock(rpcn_mtx_);
			msgs = std::move(rpcn_msgs);
			rpcn_msgs.clear();
		}
		return msgs;
	}
	std::chrono::microseconds HandleResponses();

	// Notification Functions

	int UserJoinedRoom(net::RPCNResponse resp);
	int UserLeftRoom(net::RPCNResponse resp);
	int RoomDestroyed(net::RPCNResponse resp);
	int UpdatedRoomDataInternal(net::RPCNResponse resp);
	int UpdatedRoomMemberDataInternal(net::RPCNResponse resp);
	int RoomMessageReceived(net::RPCNResponse resp);
	void SignalingHelper(net::RPCNResponse resp);
	void MemberJoinedRoomGUI(net::RPCNResponse resp);
	void MemberLeftRoomGUI(net::RPCNResponse resp);
	void RoomDisappearedGUI(net::RPCNResponse resp);
	void RoomOwnerChangedGUI(net::RPCNResponse resp);
	void UserKickedGUI(net::RPCNResponse resp);
	void QuickMatchCompleteGUI(net::RPCNResponse resp);

	// Socket Functions
	bool send_packet_ipv4(const std::vector<u8>& data, sockaddr_in dest) const;

	// Returns Local Address in Network Order
	u32 GetLocalAddr() {
		std::unique_lock<std::mutex> lock(rpcn_mtx_);
		if (local_addr_sig.load() == 0)
			sigv.wait_for(lock, std::chrono::seconds(5), [&] { return local_addr_sig.load() != 0; });
		return local_addr_sig.load();
	}

	// Returns Signaling Address in Network Order
	u32 GetSigAddr() {
		std::unique_lock<std::mutex> lock(rpcn_mtx_);
		if (addr_sig.load() == 0)
			sigv.wait_for(lock, std::chrono::seconds(5), [&] { return addr_sig.load() != 0; });
		return addr_sig.load();
	}

	// Returns Signaling Port in Host Order
	u16 GetSigPort() {
		std::unique_lock<std::mutex> lock(rpcn_mtx_);
		if (port_sig.load() == 0)
			sigv.wait_for(lock, std::chrono::seconds(5), [&] { return port_sig.load() != 0; });
		u16 sig_port = port_sig.load();
		if (sig_port == SCE_SIGN_PORT)
			sig_port = SCE_INTERNAL_PORT;
		return sig_port;
	}

	u8 GetNatType() {
		std::unique_lock<std::mutex> lock(rpcn_mtx_);
		return nat_type.load();
	}

	u64 GetLatencyUs() {
		return latency.load();
	}

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
	void recv_loop(InetSocket* DccpSocket, InetSocket* ConnSocket);
	std::vector<signaling_message> get_sign_msgs() {
		std::vector<signaling_message> msgs;
		std::lock_guard lock(sign_mtx_);
		msgs = std::move(sign_msgs);
		sign_msgs.clear();

		return msgs;
	}

	// Packet Helpers

	void queue_signaling_packet(signaling_packet& sp, std::shared_ptr<signaling_info> si, std::chrono::steady_clock::time_point wakeup_time);

	// P2P Logic Functions

	void process_incoming_messages();
	void handle_ping(const signaling_packet* sp, signaling_packet& sent_packet, u32 op_addr, u16 op_port);
	void handle_pong(const signaling_packet* sp, std::shared_ptr<signaling_info> si);
	void handle_info(const signaling_packet* sp, std::shared_ptr<signaling_info> si, u32 op_addr, u16 op_port);
	void handle_connect(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32 op_addr, u16 op_port);
	void handle_connect_ack(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32 op_addr, u16 op_port);
	void handle_confirm(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32 op_addr, u16 op_port);
	void handle_finished(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32 op_addr, u16 op_port);
	void handle_finished_ack(const signaling_packet* sp, std::shared_ptr<signaling_info> si);
	
private:
	bool running_ = false;
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
