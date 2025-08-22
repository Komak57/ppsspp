#include "Core/HLE/SignalingHandler.h"
#include <cassert>
#include <cstring>
#include "HLE.h"
#include <netioapi.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

static inline u16 be16(u16 x) { return htons(x); }
static inline u32 be32(u32 x) { return htonl(x); }
static inline u16 le16(u16 x) { return _byteswap_ushort(x); } // or your le helpers

signaling_handler::signaling_handler() {}
signaling_handler::~signaling_handler() { stop(); }
signaling_packet sig_packet{};

void signaling_handler::print_interfaces() {
	ULONG bufferSize = 15000;
	IP_ADAPTER_ADDRESSES* addresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);

	if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, addresses, &bufferSize) == NO_ERROR) {
		for (auto* addr = addresses; addr; addr = addr->Next) {
			INFO_LOG(Log::sceNet, "Interface: %s", addr->FriendlyName);

			for (auto* ua = addr->FirstUnicastAddress; ua; ua = ua->Next) {
				char buf[INET6_ADDRSTRLEN];
				if (ua->Address.lpSockaddr->sa_family == AF_INET6) {
					auto* sa6 = (sockaddr_in6*)ua->Address.lpSockaddr;
					inet_ntop(AF_INET6, &sa6->sin6_addr, buf, sizeof(buf));
					INFO_LOG(Log::sceNet, "- IPv6: %s (scope: %d)", buf, sa6->sin6_scope_id);
				}
				else if (ua->Address.lpSockaddr->sa_family == AF_INET) {
					auto* sa4 = (sockaddr_in*)ua->Address.lpSockaddr;
					inet_ntop(AF_INET, &sa4->sin_addr, buf, sizeof(buf));
					INFO_LOG(Log::sceNet, "- IPv4: %s", buf);
				}
			}
		}
	}
	free(addresses);
}

u64 signaling_handler::get_micro_timestamp(const std::chrono::steady_clock::time_point& time_point)
{
	return std::chrono::duration_cast<std::chrono::microseconds>(time_point.time_since_epoch()).count();
}

bool signaling_handler::connect() {
	if (running_.load()) return true;

	// Create IPv6 UDP socket
	sock_ = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
	if (sock_ == INVALID_SOCKET) return false;
#else
	if (sock_ < 0) return false;
#endif

	sockaddr_in6 sa{};
	sa.sin6_family = AF_INET6;
	sa.sin6_port = 3657;
	sa.sin6_scope_id = 21;

	// Parse link-local IPv6 address
	if (::inet_pton(AF_INET6, "fe80::be24:11ff:fed8:39c4", &sa.sin6_addr) != 1) {
		ERROR_LOG(Log::sceNet, "Unable to resolve SIGSERV[ipv6]!");
#ifdef _WIN32
		::closesocket(sock_);
#else
		::close(sock_);
#endif
		sock_ = -1;
		return false;
	}

	// Set scope id (interface index)
#ifdef _WIN32
	// On Windows, use if_nametoindex replacement (requires Windows 8+)
	DWORD ifindex = 0;
	if (ifindex == if_nametoindex("E")) {
		ERROR_LOG(Log::sceNet, "Invalid SIGSERV Interface!");
		return false;
	}
	sa.sin6_scope_id = ifindex;
#else
	unsigned ifindex = if_nametoindex(iface.c_str());
	if (ifindex == 0) {
		perror("if_nametoindex");
		return false;
	}
	sa.sin6_scope_id = ifindex;
#endif

	// Bind
	if (::bind(sock_, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
		ERROR_LOG(Log::sceNet, "Unable to bind SIGSERV Socket!");
#ifdef _WIN32
		::closesocket(sock_);
#else
		::close(sock_);
#endif
		sock_ = -1;
		return false;
	}

	running_ = true;
	recv_thread_ = std::thread([this] { recv_loop(); });
	return true;
}

bool signaling_handler::connect(const std::string& host, u16 port, u64 scope) {
	if (running_.load()) return true;

	sock_ = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock_ == INVALID_SOCKET) return false;

	// Bind to any local IPv6 port
	sockaddr_in6 local{};
	local.sin6_family = AF_INET6;
	local.sin6_addr = in6addr_any;
	local.sin6_port = 0;
	if (::bind(sock_, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0) {
		::closesocket(sock_);
		sock_ = INVALID_SOCKET;
		return false;
	}

	// Remote address
	//sockaddr_in6 remote{};
	remote_addr.sin6_family = AF_INET6;
	remote_addr.sin6_port = htons(port);
	inet_pton(AF_INET6, host.c_str(), &remote_addr.sin6_addr);

	// REQUIRED for fe80:: addresses
	remote_addr.sin6_scope_id = scope;

	if (::connect(sock_, reinterpret_cast<sockaddr*>(&remote_addr), sizeof(remote_addr)) != 0) {
		::closesocket(sock_);
		sock_ = INVALID_SOCKET;
		return false;
	}

	this->scope = scope;
	running_ = true;
	recv_thread_ = std::thread([this] { recv_loop(); });
	return true;
}
void signaling_handler::start(u32 conn_id, u32 addr, u16 port) {

	std::scoped_lock lk(mtx_);
	// Send Connect?
	auto& sent_packet = sig_packet;
	sent_packet.command = SigCmd::Connect;
	sent_packet.timestamp_sender = get_micro_timestamp(std::chrono::steady_clock::now());

	std::shared_ptr<signaling_info> si = sig_peers.at(conn_id);
	const auto now = std::chrono::steady_clock::now();
	si->time_last_msg_recvd = now;

	// Only update if those haven't been set before(possible we received a signal_info before)
	if (si->addr == 0 || si->port == 0)
	{
		si->addr = addr;
		si->port = port;
	}

	send_signaling_packet(sent_packet, si->addr, si->port);
	queue_signaling_packet(sent_packet, si, now + REPEAT_CONNECT_DELAY);
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

std::shared_ptr<signaling_info> signaling_handler::get_signaling_ptr(const signaling_packet* sp)
{
	u32 conn_id;

	char npid_buf[17]{};
	memcpy(npid_buf, sp->npid.handle.data, 16);
	std::string npid(npid_buf);

	if (npid_to_conn_id.find(npid) == npid_to_conn_id.end())
		return nullptr;

	conn_id = npid_to_conn_id.at(npid);

	if (sig_peers.find(conn_id) == sig_peers.end())
	{
		ERROR_LOG(Log::sceNet, "SIGSERV: ID Discrepancy");
		return nullptr;
	}

	return sig_peers.at(conn_id);
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
void signaling_handler::queue_signaling_packet(signaling_packet& sp, std::shared_ptr<signaling_info> si, std::chrono::steady_clock::time_point wakeup_time) {
	queued_packet qp;
	qp.sig_info = std::move(si);
	qp.packet = sp;
	qpackets.emplace(wakeup_time, std::move(qp));
}

u32 signaling_handler::get_always_conn_id(const SceNpId& npid)
{
	std::string npid_str(reinterpret_cast<const char*>(npid.handle.data));
	if (npid_to_conn_id.find(npid_str) == npid_to_conn_id.end())
		return npid_to_conn_id.at(npid_str);

	const u32 conn_id = cur_conn_id++;
	npid_to_conn_id.emplace(std::move(npid_str), conn_id);
	sig_peers.emplace(conn_id, std::make_shared<signaling_info>());
	auto& si = sig_peers.at(conn_id);
	si->conn_id = conn_id;
	si->npid = npid;

	return conn_id;
}

u32 signaling_handler::init_sig1(const SceNpId& npid)
{
	std::lock_guard lock(mtx_);

	const u32 conn_id = get_always_conn_id(npid);

	if (sig_peers[conn_id]->conn_status == SCE_NP_SIGNALING_CONN_STATUS_INACTIVE)
	{
		INFO_LOG(Log::sceNet, "SIGSERV: Creating new sig1 connection and requesting infos from RPCN");
		sig_peers[conn_id]->conn_status = SCE_NP_SIGNALING_CONN_STATUS_PENDING;

		// Request peer infos from RPCN
		std::string npid_str(reinterpret_cast<const char*>(npid.handle.data));
		//req_sign_infos(npid_str, conn_id);
	}

	return conn_id;
}

u32 signaling_handler::init_sig2(const SceNpId& npid, u64 room_id, u16 member_id)
{
	std::lock_guard lock(mtx_);
	u32 conn_id = get_always_conn_id(npid);
	auto& si = sig_peers.at(conn_id);
	si->room_id = room_id;
	si->member_id = member_id;

	// If connection exists from prior state notify
	if (si->conn_status == SCE_NP_SIGNALING_CONN_STATUS_ACTIVE)
		sig2_callback(si->room_id, si->member_id, SCE_NP_MATCHING2_SIGNALING_EVENT_Established, SCE_NP_MATCHING2_OKAY);
	else
		si->conn_status = SCE_NP_SIGNALING_CONN_STATUS_PENDING;

	return conn_id;
}

void signaling_handler::sig2_callback(u64 room_id, u16 member_id, SceNpMatching2Event event, s32 error_code) const
{
	if (room_id)
	{
		for (const auto [ctx_id, ctx] : contexts_)
		{
			//auto ctx = get_ctx(ctx_id);

			if (ctx.cb)
			{
				/*sysutil_register_cb([sig2_cb = ctx->signaling_cb, sig2_cb_ctx = ctx_id, room_id, member_id, event, error_code, sig2_cb_arg = ctx->signaling_cb_arg](ppu_thread& cb_ppu) -> s32
				{
					sig2_cb(cb_ppu, sig2_cb_ctx, room_id, member_id, event, error_code, sig2_cb_arg);
					return 0;
				});*/
				u32_le args[NpMatching2Args::MAX_ARGS];
				args[0] = ctx_id;						// ContextID
				args[1] = room_id;						// RoomId
				args[2] = event;						// Event
				args[3] = error_code;					// Error Code
				args[4] = ctx.cb_arg.ptr;				// cb_args
				hleEnqueueCall(ctx.cb.ptr, 5, args);
				NOTICE_LOG(Log::sceNet, "Called sig2 CB: 0x%x (room_id: %d, member_id: %d)", event, room_id, member_id);
			}
		}
	}
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

	//auto op_addr = msg.src_addr;
	//auto op_port = msg.src_port;

	//switch (cmd) {
	//case SigCmd::Ping:        handle_ping(*sp, src); break;
	//case SigCmd::Pong:        handle_pong(*sp); break;
	//case SigCmd::Info:        handle_info(*sp, src); break;
	//case SigCmd::Connect:     handle_connect(*sp, src); break;
	//case SigCmd::ConnectAck:  handle_connect_ack(*sp); break;
	//case SigCmd::Confirm:     handle_confirm(*sp, src); break;
	//case SigCmd::Finished:    handle_finished(*sp, src); break;
	//case SigCmd::FinishedAck: handle_finished_ack(*sp); break;
	//default: break;
	//}
}

void signaling_handler::handle_ping(const signaling_packet* sp, u32 op_addr, u32 op_port) {
	INFO_LOG(Log::sceNet, "SIGSERV: Ping");
	//touch_ctx(in.context_id);

	//signaling_packet out = in;
	//out.command = static_cast<u8>(SigCmd::Pong);
	//send_signaling_packet(out, src.sin_addr.s_addr, _byteswap_ushort(src.sin_port));
	//// optionally callback
	//u32_le args[NpMatching2Args::MAX_ARGS];
	//if (auto ctx = get_ctx(in.context_id)) hleEnqueueCall(ctx->cb.ptr, 0, args);
	auto& sent_packet = sig_packet;

	// Get signaling info for user to know if we should even bother looking further
	auto si = get_signaling_ptr(sp);

	sent_packet.command = SigCmd::Pong;
	sent_packet.timestamp_sender = sp->timestamp_sender;

	send_signaling_packet(sent_packet, op_addr, op_port);
}

void signaling_handler::handle_pong(const signaling_packet* sp) {
	INFO_LOG(Log::sceNet, "SIGSERV: Pong");
	//update_rtt(sp->timestamp_sender);
	const auto now = std::chrono::steady_clock::now();
	auto si = get_signaling_ptr(sp);
	//reschedule_packet(si, SigCmd::Ping, now + 10s);
}

void signaling_handler::handle_info(const signaling_packet* in, u32 op_addr, u32 op_port) {
	INFO_LOG(Log::sceNet, "SIGSERV: Info");
}

void signaling_handler::handle_connect(const signaling_packet* in, u32 op_addr, u32 op_port) {
	INFO_LOG(Log::sceNet, "SIGSERV: Connect");
}

void signaling_handler::handle_connect_ack(const signaling_packet* in, u32 op_addr, u32 op_port) {
	INFO_LOG(Log::sceNet, "SIGSERV: Connect ACK");
}

void signaling_handler::handle_confirm(const signaling_packet* in, u32 op_addr, u32 op_port) {
	INFO_LOG(Log::sceNet, "SIGSERV: Confirm");
}

void signaling_handler::handle_finished(const signaling_packet* in, u32 op_addr, u32 op_port) {
	INFO_LOG(Log::sceNet, "SIGSERV: Finished");
}

void signaling_handler::handle_finished_ack(const signaling_packet* in) {
	INFO_LOG(Log::sceNet, "SIGSERV: Finished ACK");
}

// NOTE: this calls your existing send implementation. keep the logging/IPv6 path you showed.
void signaling_handler::send_signaling_packet(signaling_packet& sp, u32 addr, u16 port) const {
	std::vector<u8> packet(sizeof(signaling_packet) + VPORT_0_HEADER_SIZE);
	reinterpret_cast<u16&>(packet[0]) = 0; // VPort 0 (LE)
	packet[2] = SUBSET_SIGNALING;
	sp.sent_addr = addr;
	sp.sent_port = port;
	std::memcpy(packet.data() + VPORT_0_HEADER_SIZE, &sp, sizeof(signaling_packet));

	// --- IPv6 send path ---
	sockaddr_in6 dest{};
	dest.sin6_family = AF_INET6;
	dest.sin6_port = port; // already big endian in your code
	dest.sin6_scope_id = this->scope; // store your interface index from getifaddrs() earlier

	// Parse the fixed server address (replace with configurable later)
	if (inet_pton(AF_INET6, "fe80::be24:11ff:fed8:39c4", &dest.sin6_addr) != 1) {
		ERROR_LOG(Log::sceNet, "Failed to convert IPv6 signaling server address!");
		return;
	}

	int ret = ::sendto(sock_, reinterpret_cast<const char*>(packet.data()),
		(int)packet.size(), 0,
		reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
}

void signaling_handler::UserJoinedRoom(net::RPCNResponse resp) {
	auto stream = new vec_stream(resp.data);
	auto notification = stream->get_flatbuffer<NotificationUserJoinedRoom>();
	if (stream->is_error()) {
		ERROR_LOG(Log::sceNet, "Malformed UserJoinedRoom notification");
		return;
	}
	const auto room_id = notification->room_id();

	u32 _size = sizeof(SceNpMatching2RoomMemberUpdateInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomMemberUpdateInfo>::Create(ptr);
	np::RoomMemberUpdateInfo_to_SceNpMatching2RoomMemberUpdateInfo(np_memory, notification->update_info(), notif_data, false, false);

	// Ensures we do not call the callback if the room is not in the cache(ie we left the room already)
	// TODO: check cache for member

	NOTICE_LOG(Log::sceNet, "User %s(%d) joined the room(%d)", notif_data->roomMemberDataInternal->userInfo.npId.handle.data, notif_data->roomMemberDataInternal->memberId, room_id);

	// We initiate signaling if necessary
	if (const auto* signaling_info = notification->signaling())
	{
		auto vec = signaling_info->ip();
		const u32 ip = static_cast<u32>(vec->Get(0)) << 24 | static_cast<u32>(vec->Get(1)) << 16 |
			static_cast<u32>(vec->Get(2)) << 8 | static_cast<u32>(vec->Get(3));

		u32 result_ip = htonl(ip);

		const u32 addr_p2p = result_ip; // register_ip()
		const u16 port_p2p = signaling_info->port();

		const u16 member_id = notif_data->roomMemberDataInternal->memberId;
		const SceNpId& npid = notif_data->roomMemberDataInternal->userInfo.npId;

		//rpcn_log.notice("Join notification told to connect to member(%d=%s) of room(%d): %s:%d", member_id, reinterpret_cast<const char*>(npid.handle.data), room_id, ip_to_string(addr_p2p), port_p2p);

		// Attempt Signaling
		//auto& sigh = g_fxo->get<named_thread<signaling_handler>>();
		const u32 conn_id = init_sig2(npid, room_id, member_id);
		start(conn_id, addr_p2p, port_p2p);
	}
	auto ctx = get_ctx(resp.header.reqId);
	const u32 event_key = 0;// get_event_key();

	/*if (room_event_cb)
	{
		sysutil_register_cb([room_event_cb = this->room_event_cb, room_id, event_key, room_event_cb_ctx = this->room_event_cb_ctx, room_event_cb_arg = this->room_event_cb_arg, size = edata.size()](ppu_thread& cb_ppu) -> s32
		{
			room_event_cb(cb_ppu, room_event_cb_ctx, room_id, SCE_NP_MATCHING2_ROOM_EVENT_MemberJoined, event_key, 0, size, room_event_cb_arg);
			return 0;
		});
	}*/

	u32_le args[NpMatching2Args::MAX_ARGS];
	args[0] = resp.header.reqId;			// ContextID
	args[1] = room_id;						// RoomId
	args[2] = SCE_NP_MATCHING2_ROOM_EVENT_MemberJoined;	// Event
	args[3] = event_key;					// Event Key
	args[4] = 0;							// ?
	args[5] = _size;						// Size?
	args[6] = ctx->cb_arg.ptr;				// cb_args
	hleEnqueueCall(ctx->cb.ptr, 7, args);
}
