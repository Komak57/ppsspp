#include "Core/Net/SignalingHandler.h"
#include <cassert>
#include <cstring>
#include "Core/Net/fb_helpers.h"
#include <Core/Util/PortManager.h>
#include "Core/HLE/sceNp.h"
#include "Core/HLE/sceNp2.h"
#include <Core/HLE/proAdhoc.h>
#include <Core/HLE/NetInetConstants.h>
#include <Core/HLE/sceNetInet.cpp>

signaling_handler::signaling_handler() {}
signaling_handler::~signaling_handler() { stop(); }
signaling_packet sig_packet{};

u64 signaling_handler::get_micro_timestamp(const std::chrono::steady_clock::time_point& time_point)
{
	return std::chrono::duration_cast<std::chrono::microseconds>(time_point.time_since_epoch()).count();
}

void signaling_handler::connect(u32 conn_id, u32 addr, u16 port) {
	NOTICE_LOG(Log::sceNet, "Signaling Connecting to %s:%d", ip2str(addr).c_str(), port);
	std::scoped_lock lk(mtx_);
	// Send Connect?
	auto& sent_packet = sig_packet;
	sent_packet.command = SignalingCommand::Connect;
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

	if (recv_thread_.joinable())
		recv_thread_.join();

	destroy_connection();
	// optional: clear contexts after all callbacks are done
	std::scoped_lock lk(mtx_);
	contexts_.clear();
}

bool signaling_handler::create_connection() {
	// Get the InetSocket object from the socket manager
	auto inetSocket = g_socketManager.FindSocketByPort(SCE_NP_PORT);
	if (inetSocket == nullptr) {
		WARN_LOG(Log::sceNet, "Creating new socket for port %d", SCE_NP_PORT);
		//return;

		int socket;
		int hostErrno = 0;
		// PSP_NET_INET_AF_INET = 2
		// PSP_NET_INET_SOCK_CONN_DGRAM = 6
		// PSP_NET_INET_IPPROTO_UNSPEC = 0
		// PSP_NET_INET_IPPROTO_UDP = 17
		inetSocket = g_socketManager.CreateSocket(&socket, &hostErrno, SocketState::UsedNetInet, 2, 6, 0);
		if (!inetSocket) {
			ERROR_LOG(Log::sceNet, "Unable to create new socket");
			return false;
		}

		// Ignore SIGPIPE when supported (ie. BSD/MacOS)
		setSockNoSIGPIPE(inetSocket->sock, 1);
		// TODO: We should always use non-blocking mode and simulate blocking mode
		changeBlockingMode(inetSocket->sock, 1);
		// Enable Port Re-use, required for multiple-instance
		setSockReuseAddrPort(inetSocket->sock);
		// Disable Connection Reset error on UDP to avoid strange behavior
		setUDPConnReset(inetSocket->sock, false);

		inetSocket->state = SocketState::UsedNetInet;
		inetSocket->port = SCE_NP_PORT;

		bool ok = g_PortManager.Add("UDP", SCE_NP_PORT, SCE_NP_PORT);
	}
	// If not running, spin up the recv thread
	if (!running_.exchange(false))
		recv_thread_ = std::thread(&signaling_handler::recv_loop, this, inetSocket);
	return true;
}

bool signaling_handler::destroy_connection() {
	auto inetSocket = g_socketManager.FindSocketByPort(SCE_NP_PORT);
	if (inetSocket == nullptr)
		return true;
	g_socketManager.Close(inetSocket);
	g_PortManager.Remove("UDP", SCE_NP_PORT);
	return true;
}

bool signaling_handler::send_packet_ipv4(const std::vector<u8>& data, u32 addr, u16 port) const {
	sockaddr_in dest;
	memset(&dest, 0, sizeof(sockaddr_in));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = htonl(addr);
	dest.sin_port = htons(port);

	DEBUG_LOG(Log::sceNet, "Sending packet(%d bytes) to %s:%d", data.size(), ip2str(dest.sin_addr).c_str(), port);

	std::string datahex;
	HEX_LOG(Log::sceNet, "signaling_handler::send_signaling_packet", reinterpret_cast<const char*>(data.data()), data.size());
	auto inetSocket = g_socketManager.FindSocketByPort(SCE_NP_PORT);
	if (!inetSocket) {
		ERROR_LOG(Log::sceNet, "Socket not found");
		return false;
	}
	int ret = sendto(inetSocket->sock, reinterpret_cast<const char*>(data.data()), data.size(), 0, reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
	int err = errno;
	if (ret == -1)
	{
		return false;
	}
	DEBUG_LOG(Log::sceNet, "Sent %i bytes", ret);
	return true;
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
//
//void signaling_handler::add_match2_ctx(ContextState context) {
//	context.last_activity = std::chrono::steady_clock::now();
//	context.expected_next = std::nullopt;
//	std::lock_guard lock(mtx_);
//	contexts_[context.ctx_id] = context;
//}
//
//void signaling_handler::remove_match2_ctx(ContextState context) {
//	std::lock_guard lock(mtx_);
//	contexts_.erase(context.ctx_id);
//}
//
//u32 signaling_handler::create_context(SignalingCallback cb) {
//	const u32 id = next_ctx_.fetch_add(1, std::memory_order_relaxed);
//	std::scoped_lock lk(mtx_);
//	//contexts_[id] = ContextState{
//	//	.cb = std::move(cb),
//	//	.last_activity = std::chrono::steady_clock::now(),
//	//	.expected_next = std::nullopt
//	//};
//	return id;
//}
//
//std::optional<ContextState> signaling_handler::get_ctx(u32 ctx) {
//	std::scoped_lock lk(mtx_);
//	auto it = contexts_.find(ctx);
//	if (it == contexts_.end()) return std::nullopt;
//	return it->second;
//}
//
//void signaling_handler::touch_ctx(u32 ctx) {
//	std::scoped_lock lk(mtx_);
//	auto it = contexts_.find(ctx);
//	if (it != contexts_.end()) it->second.last_activity = std::chrono::steady_clock::now();
//}

void signaling_handler::queue_signaling_packet(signaling_packet& sp, std::shared_ptr<signaling_info> si, std::chrono::steady_clock::time_point wakeup_time) {
	queued_packet qp;
	qp.sig_info = std::move(si);
	qp.packet = sp;
	qpackets.emplace(wakeup_time, std::move(qp));
}

u32 signaling_handler::get_always_conn_id(const SceNpId& npid)
{
	std::string npid_str(reinterpret_cast<const char*>(npid.handle.data));
	if (npid_to_conn_id.find(npid_str) != npid_to_conn_id.end())
		return npid_to_conn_id.at(npid_str);

	const u32 conn_id = cur_conn_id++;
	npid_to_conn_id.emplace(std::move(npid_str), conn_id);
	sig_peers.emplace(conn_id, std::make_shared<signaling_info>());
	auto& si = sig_peers.at(conn_id);
	si->conn_id = conn_id;
	si->npid = npid;

	return conn_id;
}

std::optional<u32> signaling_handler::get_conn_id_from_npid(const SceNpId& npid)
{
	std::lock_guard lock(mtx_);

	std::string npid_str(reinterpret_cast<const char*>(npid.handle.data));
	if (npid_to_conn_id.find(npid_str) != npid_to_conn_id.end())
		return npid_to_conn_id.at(npid_str);

	return std::nullopt;
}

std::optional<signaling_info> signaling_handler::get_sig_infos(u32 conn_id)
{
	std::lock_guard lock(mtx_);
	if (sig_peers.find(conn_id) != sig_peers.end())
		return *sig_peers.at(conn_id);

	return std::nullopt;
}

// Creates Signaling connection to RPCN
u32 signaling_handler::init_sig(const SceNpId& npid)
{
	std::lock_guard lock(mtx_);

	const u32 conn_id = get_always_conn_id(npid);

	if (sig_peers[conn_id]->conn_status == SCE_NP_SIGNALING_CONN_STATUS_INACTIVE)
	{
		INFO_LOG(Log::sceNet, "SIGSERV: Creating new sig1 connection and requesting infos from RPCN");
		sig_peers[conn_id]->conn_status = SCE_NP_SIGNALING_CONN_STATUS_PENDING;

		// Request peer infos from RPCN
		std::string npid_str(reinterpret_cast<const char*>(npid.handle.data));
		npServer->RequestSignalingInfo(npid_str, conn_id);
	}

	return conn_id;
}

// Creates P2P Signaling connection
u32 signaling_handler::init_sig(const SceNpId& npid, u64 room_id, u16 member_id)
{
	std::lock_guard lock(mtx_);
	u32 conn_id = get_always_conn_id(npid);
	auto& si = sig_peers.at(conn_id);
	si->room_id = room_id;
	si->member_id = member_id;

	// If connection exists from prior state notify
	if (si->conn_status == SCE_NP_SIGNALING_CONN_STATUS_ACTIVE)
		notifySignalingHandler(room_id, conn_id, 0, member_id, SCE_NP_MATCHING2_SIGNALING_EVENT_Established, SCE_NP_MATCHING2_OKAY);
	else
		si->conn_status = SCE_NP_SIGNALING_CONN_STATUS_PENDING;

	return conn_id;
}

void signaling_handler::DisconnectUsers(u64 room_id)
{
	std::lock_guard lock(mtx_);

	for (auto& [conn_id, si] : sig_peers)
	{
		if (si->room_id == room_id)
		{
			stop_sig_nl(conn_id, false);
		}
	}
}

void signaling_handler::stop_sig_nl(u32 conn_id, bool forceful)
{
	if (sig_peers.find(conn_id) == sig_peers.end())
		return;

	std::shared_ptr<signaling_info> si = sig_peers.at(conn_id);

	retire_all_packets(si);

	// If forceful we don't go through any transition and don't call any CB
	if (forceful)
	{
		si->conn_status = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;
		si->op_activated = false;
	}

	// Do not queue packets for an already dead connection
	if (si->conn_status == SCE_NP_SIGNALING_CONN_STATUS_INACTIVE)
		return;

	auto& sent_packet = sig_packet;
	sent_packet.command = SignalingCommand::Finished;

	send_signaling_packet(sent_packet, si->addr, si->port);
	queue_signaling_packet(sent_packet, std::move(si), std::chrono::steady_clock::now() + REPEAT_FINISHED_DELAY);
}
/*
	46:41:364 user_main    I[SCENET]: Common\Log.h:181 00000000: 00 00 01 53 49 47 4E 03 00 00 00 9A F6 3F B0 00  ...SIGN......?..
	46:41:364 user_main    I[SCENET]: Common\Log.h:181 00000010: 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 47  ...............G
	46:41:364 user_main    I[SCENET]: Common\Log.h:181 00000020: 87 4D CD 0E 49 46 6F 78 4C 6F 76 65 73 59 6F 75  .M..IFoxLovesYou
	46:41:364 user_main    I[SCENET]: Common\Log.h:181 00000030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	46:41:364 user_main    I[SCENET]: Common\Log.h:181 00000040: 00 00 00 00 00 00 00 00 00 00 00                 ...........
*/
// NOTE: this calls your existing send implementation. keep the logging/IPv6 path you showed.
void signaling_handler::send_signaling_packet(signaling_packet& sp, u32 addr, u16 port) const {
	INFO_LOG(Log::sceNet, "send_signaling_packet(__, %08x, %04x)", addr, port);
	std::vector<u8> packet(sizeof(signaling_packet) + VPORT_0_HEADER_SIZE);
	reinterpret_cast<u16_le&>(packet[0]) = 0; // VPort 0 (LE)
	packet[2] = SUBSET_SIGNALING;
	//sockaddr_in local_ip;
	//getLocalIp(&local_ip);
	sp.sent_addr = addr;
	sp.sent_port = port;
	std::memcpy(packet.data() + VPORT_0_HEADER_SIZE, &sp, sizeof(signaling_packet));

	if (!send_packet_ipv4(packet, addr, port)) {
		ERROR_LOG(Log::sceNet, "Failed to send signaling packet on IPv4 socket %s:%d", ip2str(addr).c_str(), port);
	}
}

void signaling_handler::retire_all_packets(std::shared_ptr<signaling_info>& si)
{
	for (auto it = qpackets.begin(); it != qpackets.end();)
	{
		if (it->second.sig_info == si)
			it = qpackets.erase(it);
		else
			it++;
	}
}
//
//void signaling_handler::sig2_callback(u64 room_id, u16 member_id, SceNpMatching2Event event, s32 error_code) const
//{
//	if (room_id)
//	{
//		for (const auto [ctx_id, ctx] : contexts_)
//		{
//			//auto ctx = get_ctx(ctx_id);
//
//			if (ctx.cb)
//			{
//				/*sysutil_register_cb([sig2_cb = ctx->signaling_cb, sig2_cb_ctx = ctx_id, room_id, member_id, event, error_code, sig2_cb_arg = ctx->signaling_cb_arg](ppu_thread& cb_ppu) -> s32
//				{
//					sig2_cb(cb_ppu, sig2_cb_ctx, room_id, member_id, event, error_code, sig2_cb_arg);
//					return 0;
//				});*/
//				u32_le args[NpMatching2Args::MAX_ARGS];
//				args[0] = ctx_id;						// ContextID
//				args[1] = room_id;						// RoomId
//				args[2] = event;						// Event
//				args[3] = error_code;					// Error Code
//				args[4] = ctx.cb_arg.ptr;				// cb_args
//				hleEnqueueCall(ctx.cb.ptr, 5, args);
//				NOTICE_LOG(Log::sceNet, "Called sig2 CB: 0x%x (room_id: %d, member_id: %d)", event, room_id, member_id);
//			}
//		}
//	}
//}

void signaling_handler::recv_loop(InetSocket* inetSocket) {
	// single-threaded receive path; no busy wait
	running_ = true;
	while (running_) {
		if (!inetSocket) {
			// Socket lost. Try to find it again!
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			inetSocket = g_socketManager.FindSocketByPort(SCE_NP_PORT);
			continue;
		}
		u8 buf[1500];
		sockaddr_in src{};
		socklen_t slen = sizeof(src);
		int n = recvfrom(inetSocket->sock, reinterpret_cast<char*>(buf), sizeof(buf), 0,
			reinterpret_cast<sockaddr*>(&src), &slen);
		if (n < 0) {
			int errorCode = 0;
			fd_set readfds;
			FD_ZERO(&readfds);
			FD_SET(inetSocket->sock, &readfds);
			timeval tv{};
			tv.tv_sec = 1;      // timeout 1s
			tv.tv_usec = 0;
#if PPSSPP_PLATFORM(WINDOWS)
			errorCode = WSAGetLastError();
			if (errorCode == WSAEWOULDBLOCK) {
				// Nothing wrong here, just check again after a short recess
				int ready = select(inetSocket->sock, &readfds, nullptr, nullptr, &tv);
				continue;
			}
#else
			errorCode = errno;
			if (errorCode == EAGAIN || errorCode == EWOULDBLOCK) {
				// Nothing wrong here, just check again after a short recess
				int ready = select(inetSocket->sock, &readfds, nullptr, nullptr, &tv);
				continue;
			}
#endif
			ERROR_LOG(Log::sceNet, "Error recvfrom on IPv4 P2P socket: returned %d, error code %d", n, errorCode);
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			continue;
		}
		if (n < static_cast<s32>(sizeof(u16))) {
			ERROR_LOG(Log::sceNet, "Malformed packet on P2P port (no vport)");
			continue;
		}
		if (n < VPORT_0_HEADER_SIZE) {
			ERROR_LOG(Log::sceNet, "Bad vport 0 packet (no subset)");
			return;
		}

		HEX_LOG(Log::sceNet, "signaling_handler::dispatch_packet", reinterpret_cast<const char*>(buf), n);

		// vport + subset
		const u16 vport_le = *reinterpret_cast<const u16_le*>(&buf[0]);
		const u8 subset = buf[2];
		const auto data_size = n - VPORT_0_HEADER_SIZE;
		std::vector<u8> vport_0_data;
		std::copy(std::begin(buf) + VPORT_0_HEADER_SIZE, std::begin(buf) + VPORT_0_HEADER_SIZE + data_size, std::back_inserter(vport_0_data));

		if (vport_le == 0) {
			switch (subset) {
			case SUBSET_RPCN:
				{
					// push_back to rpcn_msgs
					std::lock_guard lock(mtx_);
					rpcn_msgs.push_back(std::move(vport_0_data));
				}	
				break;
			case SUBSET_SIGNALING:
				{
					signaling_message msg;
					msg.src_addr = src.sin_addr.s_addr;
					msg.src_port = htons(src.sin_port);
					msg.data = std::move(vport_0_data);

					dispatch_packet(msg);
				}
				break;
			default:
				ERROR_LOG(Log::sceNet, "Invalid vport 0 subset (%d)", subset);
				return;
			}
		}
	}
}

void signaling_handler::dispatch_packet(signaling_message msg) {
	const auto* sp = reinterpret_cast<const signaling_packet*>(msg.data.data());
	switch (sp->command) {
	case SignalingCommand::Ping:        handle_ping(sp, msg.src_addr, msg.src_port); break;
	case SignalingCommand::Pong:        handle_pong(sp); break;
	case SignalingCommand::Connect:     handle_connect(sp, msg.src_addr, msg.src_port); break;
	case SignalingCommand::ConnectAck:  handle_connect_ack(sp, msg.src_addr, msg.src_port); break;
	case SignalingCommand::Confirm:     handle_confirm(sp, msg.src_addr, msg.src_port); break;
	case SignalingCommand::Finished:    handle_finished(sp, msg.src_addr, msg.src_port); break;
	case SignalingCommand::FinishedAck: handle_finished_ack(sp); break;
	case SignalingCommand::Info:        handle_info(sp, msg.src_addr, msg.src_port); break;
	default: break;
	}
}

void signaling_handler::handle_ping(const signaling_packet* sp, u32 op_addr, u32 op_port) {
	INFO_LOG(Log::sceNet, "SIGSERV: Ping");
	//touch_ctx(in.context_id);

	//signaling_packet out = in;
	//out.command = static_cast<u8>(SignalingCommand::Pong);
	//send_signaling_packet(out, src.sin_addr.s_addr, _byteswap_ushort(src.sin_port));
	//// optionally callback
	//u32_le args[NpMatching2Args::MAX_ARGS];
	//if (auto ctx = get_ctx(in.context_id)) hleEnqueueCall(ctx->cb.ptr, 0, args);
	auto& sent_packet = sig_packet;

	// Get signaling info for user to know if we should even bother looking further
	auto si = get_signaling_ptr(sp);

	sent_packet.command = SignalingCommand::Pong;
	sent_packet.timestamp_sender = sp->timestamp_sender;

	send_signaling_packet(sent_packet, op_addr, op_port);
}

void signaling_handler::handle_pong(const signaling_packet* sp) {
	INFO_LOG(Log::sceNet, "SIGSERV: Pong");
	//update_rtt(sp->timestamp_sender);
	const auto now = std::chrono::steady_clock::now();
	auto si = get_signaling_ptr(sp);
	//reschedule_packet(si, SignalingCommand::Ping, now + 10s);
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

void signaling_handler::UserJoinedRoom(net::RPCNResponse resp) {
	auto notification = resp.stream->get_flatbuffer<NotificationUserJoinedRoom>();
	if (resp.stream->is_error()) {
		ERROR_LOG(Log::sceNet, "NOTI Malformed UserJoinedRoom notification");
		return;
	}

	const auto room_id = notification->room_id();

	u32 _size = sizeof(SceNpMatching2RoomMemberUpdateInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomMemberUpdateInfo>::Create(ptr);
	np::RoomMemberUpdateInfo_to_SceNpMatching2RoomMemberUpdateInfo(np_memory, notification->update_info(), notif_data, false, false);

	// Ensures we do not call the callback if the room is not in the cache(ie we left the room already)
	auto member = npServer->cache.GetMember(notif_data->roomMemberDataInternal->memberId);
	if (member) {
		//get_match2_event(event_key, 0, 0);
		return;
	}
	// Cache new Room Member
	npServer->cache.AddMember(*notif_data->roomMemberDataInternal);
	
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
		auto connId = init_sig(npid, room_id, member_id);
		// Connect to Signaling Server
		g_signaling.connect(connId, addr_p2p, port_p2p);
	}
	//auto ctx = get_ctx(resp.header.reqId);
	const u32 event_key = 0;// get_event_key();

	/*if (room_event_cb)
	{
		sysutil_register_cb([room_event_cb = this->room_event_cb, room_id, event_key, room_event_cb_ctx = this->room_event_cb_ctx, room_event_cb_arg = this->room_event_cb_arg, size = edata.size()](ppu_thread& cb_ppu) -> s32
		{
			room_event_cb(cb_ppu, room_event_cb_ctx, room_id, SCE_NP_MATCHING2_ROOM_EVENT_MemberJoined, event_key, 0, size, room_event_cb_arg);
			return 0;
		});
	}*/
	//notifySignalingHandlers(resp.header.reqId, room_id, SCE_NP_MATCHING2_ROOM_EVENT_MemberJoined, event_key, 0, _size);
	notifyRoomEventHandler(room_id, notif_data->roomMemberDataInternal->memberId, SCE_NP_MATCHING2_ROOM_EVENT_MemberJoined, notif_data.ptr);
}

void signaling_handler::UserLeftRoom(net::RPCNResponse resp) {
	ERROR_LOG(Log::sceNet, "NOTI UserLeftRoom UNINPLEMENTED");
	u64 room_id = resp.stream->get<u64>();
	const auto* update_info = resp.stream->get_flatbuffer<RoomMemberUpdateInfo>();

	if (resp.stream->is_error())
	{
		ERROR_LOG(Log::sceNet, "NOTI UserLeftRoom Malformed UserLeftRoom notification");
		return;
	}

	const u32 event_key = 0;// get_event_key();
	//auto [include_onlinename, include_avatarurl] = get_match2_context_options(room_event_cb_ctx);
	bool include_onlinename = false, include_avatarurl = false;

	u32 _size = sizeof(SceNpMatching2RoomMemberUpdateInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomMemberUpdateInfo>::Create(ptr);
	np::RoomMemberUpdateInfo_to_SceNpMatching2RoomMemberUpdateInfo(np_memory, update_info, notif_data, include_onlinename, include_avatarurl);

	// Ensures we do not call the callback if the room is not in the cache(ie we left the room already)
	auto member = npServer->cache.GetMember(notif_data->roomMemberDataInternal->memberId);
	if (!member) {
		//get_match2_event(event_key, 0, 0);
		return;
	}
	npServer->cache.RemoveMember(notif_data->roomMemberDataInternal->memberId);

	NOTICE_LOG(Log::sceNet, "NOTI UserLeftRoom User %s(%d) left room(%d)", notif_data->roomMemberDataInternal->userInfo.npId.handle.data, notif_data->roomMemberDataInternal->memberId, room_id);
	//extra_nps::print_SceNpMatching2RoomMemberDataInternal(notif_data->roomMemberDataInternal.get_ptr());

	/*if (room_event_cb)
	{
		sysutil_register_cb([room_event_cb = this->room_event_cb, room_event_cb_ctx = this->room_event_cb_ctx, room_id, event_key, room_event_cb_arg = this->room_event_cb_arg, size = edata.size()](ppu_thread& cb_ppu) -> s32
		{
			room_event_cb(cb_ppu, room_event_cb_ctx, room_id, SCE_NP_MATCHING2_ROOM_EVENT_MemberLeft, event_key, 0, size, room_event_cb_arg);
			return 0;
		});
	}*/

	notifyRoomEventHandler(room_id, notif_data->roomMemberDataInternal->memberId, SCE_NP_MATCHING2_ROOM_EVENT_MemberLeft, notif_data.ptr);
}

void signaling_handler::RoomDestroyed(net::RPCNResponse resp) {
	ERROR_LOG(Log::sceNet, "NOTI RoomDestroyed UNINPLEMENTED");

	u64 room_id = resp.stream->get<u64>();
	const auto* update_info = resp.stream->get_flatbuffer<RoomUpdateInfo>();

	if (resp.stream->is_error())
	{
		ERROR_LOG(Log::sceNet, "NOTI Malformed RoomDestroyed notification");
		return;
	}

	const u32 event_key = 0;// get_event_key();

	u32 _size = sizeof(SceNpMatching2RoomUpdateInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomUpdateInfo>::Create(ptr);
	np::RoomUpdateInfo_to_SceNpMatching2RoomUpdateInfo(update_info, notif_data);

	// Remove room from cache
	npServer->cache.RemoveRoom(room_id);

	NOTICE_LOG(Log::sceNet, "NOTI RoomDestroyed Received notification that room(%d) was destroyed", room_id);

	//disconnect_sig2_users(room_id);

	/*if (room_event_cb)
	{
		sysutil_register_cb([room_event_cb = this->room_event_cb, room_event_cb_ctx = this->room_event_cb_ctx, room_id, event_key, room_event_cb_arg = this->room_event_cb_arg, size = edata.size()](ppu_thread& cb_ppu) -> s32
		{
			room_event_cb(cb_ppu, room_event_cb_ctx, room_id, SCE_NP_MATCHING2_ROOM_EVENT_RoomDestroyed, event_key, 0, size, room_event_cb_arg);
			return 0;
		});
	}*/

	notifyRoomEventHandler(room_id, 0, SCE_NP_MATCHING2_ROOM_EVENT_RoomDestroyed, notif_data.ptr);
}

void signaling_handler::UpdatedRoomDataInternal(net::RPCNResponse resp) {
	ERROR_LOG(Log::sceNet, "NOTI UpdatedRoomDataInternal UNINPLEMENTED");

	SceNpMatching2RoomId room_id = resp.stream->get<u64>();
	const auto* update_info = resp.stream->get_flatbuffer<RoomDataInternalUpdateInfo>();

	if (resp.stream->is_error())
	{
		ERROR_LOG(Log::sceNet, "NOTI Malformed UpdatedRoomDataInternal notification");
		return;
	}

	const u32 event_key = 0;// get_event_key();
	//auto [include_onlinename, include_avatarurl] = get_match2_context_options(room_event_cb_ctx);
	bool include_onlinename = false, include_avatarurl = false;

	u32 _size = sizeof(SceNpMatching2RoomDataInternalUpdateInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomDataInternalUpdateInfo>::Create(ptr);
	SceNpId* npId = NpGetNpId();
	np::RoomDataInternalUpdateInfo_to_SceNpMatching2RoomDataInternalUpdateInfo(np_memory, update_info, notif_data, npId, include_onlinename, include_avatarurl);

	//np_cache.insert_room(notif_data->newRoomDataInternal.get_ptr());

	//extra_nps::print_SceNpMatching2RoomDataInternal(notif_data->newRoomDataInternal.get_ptr());

	NOTICE_LOG(Log::sceNet, "NOTI RoomDestroyed Received notification that room(% d)'s data was updated", room_id);

	/*if (room_event_cb)
	{
		sysutil_register_cb([room_event_cb = this->room_event_cb, room_event_cb_ctx = this->room_event_cb_ctx, room_id, event_key, room_event_cb_arg = this->room_event_cb_arg, size = edata.size()](ppu_thread& cb_ppu) -> s32
		{
			room_event_cb(cb_ppu, room_event_cb_ctx, room_id, SCE_NP_MATCHING2_ROOM_EVENT_UpdatedRoomDataInternal, event_key, 0, size, room_event_cb_arg);
			return 0;
		});
	}*/

	notifyRoomEventHandler(room_id, 0, SCE_NP_MATCHING2_ROOM_EVENT_UpdatedRoomDataInternal, notif_data.ptr);
}

void signaling_handler::UpdatedRoomMemberDataInternal(net::RPCNResponse resp) {
	ERROR_LOG(Log::sceNet, "NOTI UpdatedRoomMemberDataInternal UNINPLEMENTED");

	SceNpMatching2RoomId room_id = resp.stream->get<u64>();
	const auto* update_info = resp.stream->get_flatbuffer<RoomMemberDataInternalUpdateInfo>();

	if (resp.stream->is_error())
	{
		ERROR_LOG(Log::sceNet, "NOTI Malformed UpdatedRoomMemberDataInternal notification");
		return;
	}

	const u32 event_key = 0;// get_event_key();
	//auto [include_onlinename, include_avatarurl] = get_match2_context_options(room_event_cb_ctx);
	bool include_onlinename = false, include_avatarurl = false;

	u32 _size = sizeof(SceNpMatching2RoomMemberDataInternalUpdateInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomMemberDataInternalUpdateInfo>::Create(ptr);
	np::RoomMemberDataInternalUpdateInfo_to_SceNpMatching2RoomMemberDataInternalUpdateInfo(np_memory, update_info, notif_data, include_onlinename, include_avatarurl);

	/*if (!np_cache.add_member(room_id, notif_data->newRoomMemberDataInternal.get_ptr()))
	{
		get_match2_event(event_key, 0, 0);
		return;
	}*/

	NOTICE_LOG(Log::sceNet, "NOTI RoomDestroyed User's %s(%d) room (%d) data was updated", notif_data->newRoomMemberDataInternal->userInfo.npId.handle.data, notif_data->newRoomMemberDataInternal->memberId, room_id);
	//extra_nps::print_SceNpMatching2RoomMemberDataInternal(notif_data->newRoomMemberDataInternal.get_ptr());

	/*if (room_event_cb)
	{
		sysutil_register_cb([room_event_cb = this->room_event_cb, room_event_cb_ctx = this->room_event_cb_ctx, room_id, event_key, room_event_cb_arg = this->room_event_cb_arg, size = edata.size()](ppu_thread& cb_ppu) -> s32
		{
			room_event_cb(cb_ppu, room_event_cb_ctx, room_id, SCE_NP_MATCHING2_ROOM_EVENT_UpdatedRoomMemberDataInternal, event_key, 0, size, room_event_cb_arg);
			return 0;
		});
	}*/

	notifyRoomEventHandler(room_id, 0, SCE_NP_MATCHING2_ROOM_EVENT_UpdatedRoomMemberDataInternal, notif_data.ptr);
}

void signaling_handler::RoomMessageReceived(net::RPCNResponse resp) {
	// 0000000000000010 0090 00000014 00000000000E0014000000070008000C0010000E00000000000001700000006800000004000000580000000500000000000000903D9B08A0F1FF090C79A6089078A6086889A30878A89B0860F4FF09D0F4FF09B01815090000000060F4FF0980F3FF0978567609EFBEADDED06DA60840547609B0181509B46CA308A51894038C6EA608040004000400000000000000

	resp.stream = new vec_stream(resp.data);
	//auto noti = new vec_stream(resp.data);

	u64 room_id = resp.stream->get<u64>();
	u16 member_id = resp.stream->get<u16>();
	NOTICE_LOG(Log::sceNet, "NOTI RoomMessageReceived(room: %d, member: %d)", room_id, member_id);

	const auto* message_info = resp.stream->get_flatbuffer<RoomMessageInfo>();

	if (resp.stream->is_error())
	{
		ERROR_LOG(Log::sceNet, "NOTI Malformed RoomMessageReceived notification");
		return;
	}
	//g_signaling.start(connId, (u32)0x0202A8C0, 3657);

	const u32 event_key = 0; //get_event_key();
	//auto [include_onlinename, include_avatarurl] = get_match2_context_options(room_event_cb_ctx);
	bool include_onlinename = true, include_avatarurl = false;

	u32 _size = sizeof(SceNpMatching2RoomMessageInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomMessageInfo>::Create(ptr);

	np::RoomMessageInfo_to_SceNpMatching2RoomMessageInfo(np_memory, message_info, notif_data, include_onlinename, include_avatarurl);

	/*if (room_msg_cb)
	{
		sysutil_register_cb([room_msg_cb = this->room_msg_cb, room_msg_cb_ctx = this->room_msg_cb_ctx, room_id, member_id, event_key, room_msg_cb_arg = this->room_msg_cb_arg, size = edata.size()](ppu_thread& cb_ppu) -> s32
		{
			room_msg_cb(cb_ppu, room_msg_cb_ctx, room_id, member_id, SCE_NP_MATCHING2_ROOM_MSG_EVENT_Message, event_key, 0, size, room_msg_cb_arg);
			return 0;
		});
	}*/

	notifyRoomMessageHandler(room_id, member_id, SCE_NP_MATCHING2_ROOM_MSG_EVENT_Message, notif_data.ptr);
}

void signaling_handler::SignalingHelper(net::RPCNResponse resp) {
	ERROR_LOG(Log::sceNet, "NOTI SignalingHelper UNINPLEMENTED");

	u64 room_id = resp.stream->get<u64>();
	u16 member_id = resp.stream->get<u16>();
	NOTICE_LOG(Log::sceNet, "NOTI Member %d sent message in room(%d)", member_id, room_id);

	const auto* message_info = resp.stream->get_flatbuffer<RoomMessageInfo>();

	if (resp.stream->is_error())
	{
		ERROR_LOG(Log::sceNet, "NOTI Malformed RoomMessageReceived notification");
		return;
	}

	const u32 event_key = 0;// get_event_key();
	//auto [include_onlinename, include_avatarurl] = get_match2_context_options(room_event_cb_ctx);
	bool include_onlinename = false, include_avatarurl = false;

	u32 _size = sizeof(SceNpMatching2RoomMessageInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomMessageInfo>::Create(ptr);
	np::RoomMessageInfo_to_SceNpMatching2RoomMessageInfo(np_memory, message_info, notif_data, include_onlinename, include_avatarurl);


	/*if (room_msg_cb)
	{
		sysutil_register_cb([room_msg_cb = this->room_msg_cb, room_msg_cb_ctx = this->room_msg_cb_ctx, room_id, member_id, event_key, room_msg_cb_arg = this->room_msg_cb_arg, size = edata.size()](ppu_thread& cb_ppu) -> s32
		{
			room_msg_cb(cb_ppu, room_msg_cb_ctx, room_id, member_id, SCE_NP_MATCHING2_ROOM_MSG_EVENT_Message, event_key, 0, size, room_msg_cb_arg);
			return 0;
		});
	}*/

	notifyRoomMessageHandler(room_id, member_id, SCE_NP_MATCHING2_ROOM_MSG_EVENT_Message, notif_data.ptr);
}

// GUI
void signaling_handler::MemberJoinedRoomGUI(net::RPCNResponse resp) {
	ERROR_LOG(Log::sceNet, "NOTI MemberJoinedRoomGUI UNINPLEMENTED");
	auto noti = resp.stream;
}

void signaling_handler::MemberLeftRoomGUI(net::RPCNResponse resp) {
	ERROR_LOG(Log::sceNet, "NOTI MemberLeftRoomGUI UNINPLEMENTED");
	auto noti = resp.stream;
}

void signaling_handler::RoomDisappearedGUI(net::RPCNResponse resp) {
	ERROR_LOG(Log::sceNet, "NOTI RoomDisappearedGUI UNINPLEMENTED");
	auto noti = resp.stream;
}

void signaling_handler::RoomOwnerChangedGUI(net::RPCNResponse resp) {
	ERROR_LOG(Log::sceNet, "NOTI RoomOwnerChangedGUI UNINPLEMENTED");
	auto noti = resp.stream;
}

void signaling_handler::UserKickedGUI(net::RPCNResponse resp) {
	ERROR_LOG(Log::sceNet, "NOTI UserKickedGUI UNINPLEMENTED");
	auto noti = resp.stream;
}

void signaling_handler::QuickMatchCompleteGUI(net::RPCNResponse resp) {
	ERROR_LOG(Log::sceNet, "NOTI QuickMatchCompleteGUI UNINPLEMENTED");
	auto noti = resp.stream;
}
