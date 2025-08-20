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

#include <winsock2.h>
#include <ws2tcpip.h>
#include "Np2Types.h"
// if you’re cross-platform, swap the above for your existing PPSSPP socket wrappers.

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

#pragma pack(push, 1)
struct signaling_packet {
	u8				command;      // SigCmd
	u32				context_id;   // unique per conversation
	u32				token;        // whatever your flow uses (optional)
	std::vector<u8> payload;      // variable tail (if any)

	// not serialized: convenience for send() logging/routing
	mutable u32 sent_addr{};
	mutable u16 sent_port{};
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

	// lifecycle
	bool start(u32 bind_addr_be, u16 bind_port_be);
	bool start(const std::string& host, u16 port);
	void stop();

	void add_match2_ctx(ContextState context);
	void remove_match2_ctx(ContextState context);

	// create/register a new context id and callback
	u32 create_context(SignalingCallback cb);

	// send helpers (you already have an implementation; we call into it)
	void send_signaling_packet(signaling_packet& sp, u32 addr_be, u16 port_be) const;

	// optional utility to initiate a connect flow to a peer
	// returns context id
	u32 begin_connect(u32 peer_addr_be, u16 peer_port_be, SignalingCallback cb);

private:
	void recv_loop();
	void dispatch_packet(const u8* buf, size_t len, const sockaddr_in& src);

	void handle_ping(const signaling_packet& sp, const sockaddr_in& src);
	void handle_pong(const signaling_packet& sp);
	void handle_info(const signaling_packet& sp, const sockaddr_in& src);
	void handle_connect(const signaling_packet& sp, const sockaddr_in& src);
	void handle_connect_ack(const signaling_packet& sp);
	void handle_confirm(const signaling_packet& sp, const sockaddr_in& src);
	void handle_finished(const signaling_packet& sp, const sockaddr_in& src);
	void handle_finished_ack(const signaling_packet& sp);

	// context helpers
	std::optional<ContextState> get_ctx(u32 ctx);
	void touch_ctx(u32 ctx);
	void set_ctx_expected(u32 ctx, SigCmd next);

private:
	std::atomic<bool> running_{ false };
	std::thread recv_thread_;

	SOCKET sock_{ INVALID_SOCKET };

	mutable std::mutex mtx_;
	std::unordered_map<u32, ContextState> contexts_;
	std::atomic<u32> next_ctx_{ 1 }; // simple monotonic id
};
