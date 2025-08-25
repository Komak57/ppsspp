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

#include "HLE.h"
#include "Np2Types.h"
#include <Core\Util\NPAgent.h>

#include <iphlpapi.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

constexpr size_t VPORT_0_HEADER_SIZE = 3; // u16 vport(LE) + u8 subset
constexpr u8 SUBSET_SIGNALING = -1;     // set to your value

// wire-level command ids. ensure these match your protocol.
enum class SigCmd : u8 {
	Ping = 0x01,
	Pong = 0x02,
	Info = 0x03,
	Connect = 0x04,
	ConnectAck = 0x05,
	Confirm = 0x06,
	Finished = 0x07,
	FinishedAck = 0x08,
};

static constexpr auto REPEAT_CONNECT_DELAY = std::chrono::milliseconds(200);
static constexpr auto REPEAT_PING_DELAY = std::chrono::milliseconds(500);
static constexpr auto REPEAT_FINISHED_DELAY = std::chrono::milliseconds(500);
static constexpr auto REPEAT_INFO_DELAY = std::chrono::milliseconds(200);
static constexpr u32 SIGNALING_SIGNATURE = (static_cast<u32>('S') << 24 | static_cast<u32>('I') << 16 | static_cast<u32>('G') << 8 | static_cast<u32>('N'));
static constexpr u32 SIGNALING_VERSION = 3;
#pragma pack(push, 1)
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
	u32 signature = SIGNALING_SIGNATURE;
	u32 version = SIGNALING_VERSION;
	u64 timestamp_sender;
	u64 timestamp_receiver;
	SigCmd command;
	u32 sent_addr;
	u16 sent_port;
	SceNpId npid;
};

struct queued_packet
{
	signaling_packet packet{};
	std::shared_ptr<signaling_info> sig_info;
};
#pragma pack(pop)

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
	std::optional<SigCmd> expected_next{};
};

class signaling_handler {
public:
	signaling_handler();
	~signaling_handler();

	static void print_interfaces();
	static u64 get_micro_timestamp(const std::chrono::steady_clock::time_point& time_point);
	// DEBUGGING
	bool connect();
	bool connect(const std::string& host, u16 port, u64 scope);
	void start(u32 conn_id, u32 addr, u16 port);
	void stop();

	void add_match2_ctx(ContextState context);
	void remove_match2_ctx(ContextState context);
	std::shared_ptr<signaling_info> get_signaling_ptr(const signaling_packet* sp);
	// create/register a new context id and callback
	u32 create_context(SignalingCallback cb);
	u32 get_always_conn_id(const SceNpId& npid);
	u32 init_sig1(const SceNpId& npid);
	u32 init_sig2(const SceNpId& npid, u64 room_id, u16 member_id);
	void sig2_callback(u64 room_id, u16 member_id, SceNpMatching2Event event, s32 error_code) const;

	// send helpers (you already have an implementation; we call into it)
	void send_signaling_packet(signaling_packet& sp, u32 addr, u16 port) const;

	// Signal Triggers
	void UserJoinedRoom(net::RPCNResponse resp);
	void RoomMessageReceived(net::RPCNResponse resp);
	
private:
	void recv_loop();
	void dispatch_packet(const u8* buf, size_t len, const sockaddr_in& src);

	void handle_ping(const signaling_packet* sp, u32 op_addr, u32 op_port);
	void handle_pong(const signaling_packet* sp);
	void handle_info(const signaling_packet* sp, u32 op_addr, u32 op_port);
	void handle_connect(const signaling_packet* sp, u32 op_addr, u32 op_port);
	void handle_connect_ack(const signaling_packet* sp, u32 op_addr, u32 op_port);
	void handle_confirm(const signaling_packet* sp, u32 op_addr, u32 op_port);
	void handle_finished(const signaling_packet* sp, u32 op_addr, u32 op_port);
	void handle_finished_ack(const signaling_packet* sp);

	// context helpers
	std::optional<ContextState> get_ctx(u32 ctx);
	void touch_ctx(u32 ctx);
	void queue_signaling_packet(signaling_packet& sp, std::shared_ptr<signaling_info> si, std::chrono::steady_clock::time_point wakeup_time);

private:
	std::atomic<bool> running_{ false };
	std::thread recv_thread_;

	SOCKET sock_{ INVALID_SOCKET };
	sockaddr_in6 remote_addr;
	ULONG scope;

	mutable std::mutex mtx_;
	std::unordered_map<u32, ContextState> contexts_;
	std::map<std::chrono::steady_clock::time_point, queued_packet> qpackets; // (wakeup time, packet)
	std::atomic<u32> next_ctx_{ 1 }; // simple monotonic id

	u32 cur_conn_id = 1;
	std::unordered_map<std::string, u32> npid_to_conn_id;               // (npid, conn_id)
	std::unordered_map<u32, std::shared_ptr<signaling_info>> sig_peers; // (conn_id, sig_info)

};

extern signaling_handler g_signaling;
extern BlockAllocator np_memory;
