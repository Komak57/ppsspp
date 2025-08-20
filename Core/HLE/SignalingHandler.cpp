#include "Core/HLE/SignalingHandler.h"
#include <cassert>
#include <cstring>
#include "HLE.h"

static inline u16 be16(u16 x) { return htons(x); }
static inline u32 be32(u32 x) { return htonl(x); }
static inline u16 le16(u16 x) { return _byteswap_ushort(x); } // or your le helpers

signaling_handler::signaling_handler() {}
signaling_handler::~signaling_handler() { stop(); }

bool signaling_handler::start(u32 bind_addr_be, u16 bind_port_be) {
	if (running_.load()) return true;

	sock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock_ == INVALID_SOCKET) return false;

	sockaddr_in sa{};
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = bind_addr_be; // already BE per your codebase
	sa.sin_port = bind_port_be;

	if (::bind(sock_, reinterpret_cast<const sockaddr*>(&sa), sizeof(sa)) != 0) {
		::closesocket(sock_);
		sock_ = INVALID_SOCKET;
		return false;
	}

	running_ = true;
	recv_thread_ = std::thread([this] { recv_loop(); });
	return true;
}
bool signaling_handler::start(const std::string& host, u16 port) {
	if (running_.load()) return true;

	sock_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock_ == INVALID_SOCKET) return false;

	// Optional: bind to any local port
	sockaddr_in local{};
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = 0;
	if (::bind(sock_, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0) {
		::closesocket(sock_);
		sock_ = INVALID_SOCKET;
		return false;
	}

	// Resolve remote
	addrinfo hints{};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	addrinfo* res = nullptr;
	if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
		::closesocket(sock_);
		sock_ = INVALID_SOCKET;
		return false;
	}

	// "Connect" the UDP socket (sets default peer)
	if (::connect(sock_, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
		freeaddrinfo(res);
		::closesocket(sock_);
		sock_ = INVALID_SOCKET;
		return false;
	}

	freeaddrinfo(res);

	running_ = true;
	recv_thread_ = std::thread([this] { recv_loop(); });
	return true;
}

void signaling_handler::stop() {
	if (!running_.exchange(false)) return;

	// IMPORTANT: close socket first → unblock recvfrom → join
	if (sock_ != INVALID_SOCKET) {
		//freeaddrinfo(res);
		::closesocket(sock_);
		sock_ = INVALID_SOCKET;
	}

	if (recv_thread_.joinable())
		recv_thread_.join();

	// optional: clear contexts after all callbacks are done
	std::scoped_lock lk(mtx_);
	contexts_.clear();
}

void signaling_handler::add_match2_ctx(ContextState context) {
	context.last_activity = std::chrono::steady_clock::now();
	context.expected_next = std::nullopt;
	std::lock_guard lock(mtx_);
	contexts_[context.ctx_id] = context;
}

void signaling_handler::remove_match2_ctx(ContextState context) {
	std::lock_guard lock(mtx_);
	contexts_.erase(context.ctx_id);
}

u32 signaling_handler::create_context(SignalingCallback cb) {
	const u32 id = next_ctx_.fetch_add(1, std::memory_order_relaxed);
	std::scoped_lock lk(mtx_);
	//contexts_[id] = ContextState{
	//	.cb = std::move(cb),
	//	.last_activity = std::chrono::steady_clock::now(),
	//	.expected_next = std::nullopt
	//};
	return id;
}

std::optional<ContextState> signaling_handler::get_ctx(u32 ctx) {
	std::scoped_lock lk(mtx_);
	auto it = contexts_.find(ctx);
	if (it == contexts_.end()) return std::nullopt;
	return it->second;
}
void signaling_handler::touch_ctx(u32 ctx) {
	std::scoped_lock lk(mtx_);
	auto it = contexts_.find(ctx);
	if (it != contexts_.end()) it->second.last_activity = std::chrono::steady_clock::now();
}
void signaling_handler::set_ctx_expected(u32 ctx, SigCmd next) {
	std::scoped_lock lk(mtx_);
	auto it = contexts_.find(ctx);
	if (it != contexts_.end()) it->second.expected_next = next;
}

void signaling_handler::recv_loop() {
	// single-threaded receive path; no busy wait
	while (running_) {
		u8 buf[1500];
		sockaddr_in src{};
		int slen = sizeof(src);
		int n = ::recvfrom(sock_, reinterpret_cast<char*>(buf), sizeof(buf), 0,
			reinterpret_cast<sockaddr*>(&src), &slen);
		if (n <= 0) {
			if (!running_) break;
			// EWOULDBLOCK/WSAEINTR can happen; continue
			continue;
		}
		dispatch_packet(buf, static_cast<size_t>(n), src);
	}
}

void signaling_handler::dispatch_packet(const u8* buf, size_t len, const sockaddr_in& src) {
	if (len < VPORT_0_HEADER_SIZE + sizeof(signaling_packet)) return;

	char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	int i;
	std::string hexdata = "";
	for (i = 0; i < len; i++) {
		char const c = buf[i];
		hexdata += hex_chars[(c & 0xF0) >> 4];
		hexdata += hex_chars[(c & 0x0F) >> 0];
	}
	INFO_LOG(Log::sceNet, "SIGSERV: %s", hexdata.c_str());

	// vport + subset
	const u16 vport_le = *reinterpret_cast<const u16*>(&buf[0]);
	const u8 subset = buf[2];
	if (subset != SUBSET_SIGNALING || vport_le != 0) return;

	const auto* sp = reinterpret_cast<const signaling_packet*>(buf + VPORT_0_HEADER_SIZE);
	const auto cmd = static_cast<SigCmd>(sp->command);

	switch (cmd) {
	case SigCmd::Ping:        handle_ping(*sp, src); break;
	case SigCmd::Pong:        handle_pong(*sp); break;
	case SigCmd::Info:        handle_info(*sp, src); break;
	case SigCmd::Connect:     handle_connect(*sp, src); break;
	case SigCmd::ConnectAck:  handle_connect_ack(*sp); break;
	case SigCmd::Confirm:     handle_confirm(*sp, src); break;
	case SigCmd::Finished:    handle_finished(*sp, src); break;
	case SigCmd::FinishedAck: handle_finished_ack(*sp); break;
	default: break;
	}
}

void signaling_handler::handle_ping(const signaling_packet& in, const sockaddr_in& src) {
	INFO_LOG(Log::sceNet, "SIGSERV: Ping");
	touch_ctx(in.context_id);

	signaling_packet out = in;
	out.command = static_cast<u8>(SigCmd::Pong);
	send_signaling_packet(out, src.sin_addr.s_addr, _byteswap_ushort(src.sin_port));
	// optionally callback
	u32_le args[NpMatching2Args::MAX_ARGS];
	if (auto ctx = get_ctx(in.context_id)) hleEnqueueCall(ctx->cb.ptr, 0, args);
}

void signaling_handler::handle_pong(const signaling_packet& in) {
	INFO_LOG(Log::sceNet, "SIGSERV: Pong");
	touch_ctx(in.context_id);
	u32_le args[NpMatching2Args::MAX_ARGS];
	if (auto ctx = get_ctx(in.context_id)) hleEnqueueCall(ctx->cb.ptr, 0, args);
}

void signaling_handler::handle_info(const signaling_packet& in, const sockaddr_in& src) {
	INFO_LOG(Log::sceNet, "SIGSERV: Info");
	touch_ctx(in.context_id);
	u32_le args[NpMatching2Args::MAX_ARGS];
	if (auto ctx = get_ctx(in.context_id)) hleEnqueueCall(ctx->cb.ptr, 0, args);
}

void signaling_handler::handle_connect(const signaling_packet& in, const sockaddr_in& src) {
	INFO_LOG(Log::sceNet, "SIGSERV: Connect");
	touch_ctx(in.context_id);

	// respond with ConnectAck
	signaling_packet ack = in;
	ack.command = static_cast<u8>(SigCmd::ConnectAck);
	send_signaling_packet(ack, src.sin_addr.s_addr, _byteswap_ushort(src.sin_port));
	set_ctx_expected(in.context_id, SigCmd::Confirm);

	u32_le args[NpMatching2Args::MAX_ARGS];
	if (auto ctx = get_ctx(in.context_id)) hleEnqueueCall(ctx->cb.ptr, 0, args);
}

void signaling_handler::handle_connect_ack(const signaling_packet& in) {
	INFO_LOG(Log::sceNet, "SIGSERV: Connect ACK");
	touch_ctx(in.context_id);
	u32_le args[NpMatching2Args::MAX_ARGS];
	if (auto ctx = get_ctx(in.context_id)) hleEnqueueCall(ctx->cb.ptr, 0, args);
}

void signaling_handler::handle_confirm(const signaling_packet& in, const sockaddr_in& src) {
	INFO_LOG(Log::sceNet, "SIGSERV: Confirm");
	touch_ctx(in.context_id);

	// respond Finished
	signaling_packet fin = in;
	fin.command = static_cast<u8>(SigCmd::Finished);
	send_signaling_packet(fin, src.sin_addr.s_addr, _byteswap_ushort(src.sin_port));
	set_ctx_expected(in.context_id, SigCmd::FinishedAck);

	u32_le args[NpMatching2Args::MAX_ARGS];
	if (auto ctx = get_ctx(in.context_id)) hleEnqueueCall(ctx->cb.ptr, 0, args);
}

void signaling_handler::handle_finished(const signaling_packet& in, const sockaddr_in& src) {
	INFO_LOG(Log::sceNet, "SIGSERV: Finished");
	touch_ctx(in.context_id);

	// respond FinishedAck
	signaling_packet ack = in;
	ack.command = static_cast<u8>(SigCmd::FinishedAck);
	send_signaling_packet(ack, src.sin_addr.s_addr, _byteswap_ushort(src.sin_port));

	u32_le args[NpMatching2Args::MAX_ARGS];
	if (auto ctx = get_ctx(in.context_id)) hleEnqueueCall(ctx->cb.ptr, 0, args);
}

void signaling_handler::handle_finished_ack(const signaling_packet& in) {
	INFO_LOG(Log::sceNet, "SIGSERV: Finished ACK");
	touch_ctx(in.context_id);
	u32_le args[NpMatching2Args::MAX_ARGS];
	if (auto ctx = get_ctx(in.context_id)) hleEnqueueCall(ctx->cb.ptr, 0, args);
}

u32 signaling_handler::begin_connect(u32 peer_addr_be, u16 peer_port_be, SignalingCallback cb) {
	const u32 ctx = create_context(std::move(cb));

	signaling_packet sp{};
	sp.command = static_cast<u8>(SigCmd::Connect);
	sp.context_id = ctx;
	// fill token/payload if needed

	send_signaling_packet(sp, peer_addr_be, peer_port_be);
	set_ctx_expected(ctx, SigCmd::ConnectAck);
	return ctx;
}

// NOTE: this calls your existing send implementation. keep the logging/IPv6 path you showed.
void signaling_handler::send_signaling_packet(signaling_packet& sp, u32 addr_be, u16 port_be) const {
	std::vector<u8> packet(sizeof(signaling_packet) + VPORT_0_HEADER_SIZE);
	reinterpret_cast<u16&>(packet[0]) = 0; // VPort 0 (LE)
	packet[2] = SUBSET_SIGNALING;
	sp.sent_addr = addr_be;
	sp.sent_port = port_be;
	std::memcpy(packet.data() + VPORT_0_HEADER_SIZE, &sp, sizeof(signaling_packet));

	sockaddr_in dest{};
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = addr_be;
	dest.sin_port = port_be; // already BE in your codebase

	// you can reuse your IPv6 translator/send paths here
	::sendto(sock_, reinterpret_cast<const char*>(packet.data()), (int)packet.size(), 0,
		reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
}
