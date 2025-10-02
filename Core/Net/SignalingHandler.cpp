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
#include <System/OSD.h>
#include <Data/Text/I18n.h>
// Used for things like 10s
using namespace std::chrono_literals;

signaling_handler::signaling_handler() {}
signaling_handler::~signaling_handler() { stop(); }
signaling_packet sig_packet{};

u64 signaling_handler::get_micro_timestamp(const std::chrono::steady_clock::time_point& time_point)
{
	return std::chrono::duration_cast<std::chrono::microseconds>(time_point.time_since_epoch()).count();
}

// This function assumes addr and port are in network order
void signaling_handler::connect(u32 conn_id, u32_be addr, u16_be port) {
	NOTICE_LOG(Log::sceNet, "Signaling Connecting to %s:%d", ip2str(addr).c_str(), ntohs(port));
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

	INFO_LOG(Log::sceNet, "CONNECT -> P2P");
	send_signaling_packet(sent_packet, si->addr, si->port);
	queue_signaling_packet(sent_packet, si, now + REPEAT_CONNECT_DELAY);
}

void signaling_handler::stop() {
	if (!running_.exchange(false)) return;

	if (recv_thread_.joinable())
		recv_thread_.join();
	if (signaling_thread_.joinable())
		signaling_thread_.join();

	destroy_connection();
	// optional: clear contexts after all callbacks are done
	std::scoped_lock lk(mtx_);
	contexts_.clear();
}

bool signaling_handler::create_connection() {
	// Get the InetSocket object from the socket manager
	auto inetSocket = g_socketManager.FindSocketByPort(ntohs(SCE_NP_PORT));
	if (inetSocket == nullptr) {
		WARN_LOG(Log::sceNet, "Creating new socket for port %d", ntohs(SCE_NP_PORT));
		//return;

		int index;
		int hostErrno = 0;
		// PSP_NET_INET_AF_INET = 2
		// PSP_NET_INET_SOCK_CONN_DGRAM = 6
		// PSP_NET_INET_IPPROTO_UNSPEC = 0
		// PSP_NET_INET_IPPROTO_UDP = 17
		inetSocket = g_socketManager.CreateSocket(&index, &hostErrno, SocketState::UsedNetInet, 2, 6, 0);
		if (!inetSocket) {
			ERROR_LOG(Log::sceNet, "Unable to create new socket");
			return false;
		}

		// Bind socket for listening
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = SCE_NP_PORT;

		if (bind(inetSocket->sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
			ERROR_LOG(Log::sceNet, "Unable to bind new socket for listening");
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
		inetSocket->port = ntohs(SCE_NP_PORT);

		bool ok = g_PortManager.Add("UDP", ntohs(SCE_NP_PORT), ntohs(SCE_NP_PORT));
	}
	// If not running, spin up the recv thread
	if (!running_.exchange(false)) {
		recv_thread_ = std::thread(&signaling_handler::recv_loop, this, inetSocket);
		signaling_thread_ = std::thread(&signaling_handler::signaling_thread, this);
		npServer->start_signal_thread();
	}
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
// This function assumes addr and port are in network order
bool signaling_handler::send_packet_ipv4(const std::vector<u8>& data, sockaddr_in dest) const {

	INFO_LOG(Log::sceNet, "Sending packet(%d bytes) to %s:%d", data.size(), ip2str(dest.sin_addr).c_str(), ntohs(dest.sin_port));

	std::string datahex;
	DEBUG_HEXLOG(Log::sceNet, "signaling_handler::send_signaling_packet", reinterpret_cast<const char*>(data.data()), data.size(), 386);
	auto inetSocket = g_socketManager.FindSocketByPort(ntohs(SCE_NP_PORT));
	if (!inetSocket) {
		ERROR_LOG(Log::sceNet, "Socket not found");
		return false;
	}
	int ret = sendto(inetSocket->sock, reinterpret_cast<const char*>(data.data()), data.size(), 0, reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
	if (ret < 0)
	{
		int errorCode = 0;
#if PPSSPP_PLATFORM(WINDOWS)
		errorCode = WSAGetLastError();
#else
		errorCode = errno;
#endif
		ERROR_LOG(Log::sceNet, "SendTo Failed: %d", errorCode);
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

void signaling_handler::set_self_sig_info(SceNpId& npid)
{
	std::lock_guard lock(mtx_);
	sig_packet.npid = npid;
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
u32 signaling_handler::init_sig(const SceNpId& npid, SceNpMatching2RoomId room_id, SceNpMatching2RoomMemberId member_id)
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

void signaling_handler::update_si_addr(std::shared_ptr<signaling_info>& si, u32_be new_addr, u16_be new_port)
{
	if (!si)
		return;

	if (si->addr != new_addr || si->port != new_port)
	{
		in_addr addr_old, addr_new;
		addr_old.s_addr = si->addr;
		addr_new.s_addr = new_addr;

		char ip_str_old[16];
		char ip_str_new[16];
		inet_ntop(AF_INET, &addr_old, ip_str_old, sizeof(ip_str_old));
		inet_ntop(AF_INET, &addr_new, ip_str_new, sizeof(ip_str_new));

		NOTICE_LOG(Log::sceNet, "Updated Address from %s:%d to %s:%d", ip_str_old, si->port, ip_str_new, new_port);

		si->addr = new_addr;
		si->port = new_port;
	}
}

void signaling_handler::update_si_mapped_addr(std::shared_ptr<signaling_info>& si, u32_be new_addr, u16_be new_port)
{
	if (!si)
		return;

	// If the address given to us by op is a translation IP, just replace it with our public ip(v4)
	/*if (np::is_ipv6_supported() && np::ip_address_translator::is_ipv6(new_addr))
	{
		auto& nph = g_fxo->get<named_thread<np::np_handler>>();
		new_addr = nph.get_public_ip_addr();
	}*/

	if (si->mapped_addr != new_addr || si->mapped_port != new_port)
	{
		in_addr addr_old, addr_new;
		addr_old.s_addr = si->mapped_addr;
		addr_new.s_addr = new_addr;

		char ip_str_old[16];
		char ip_str_new[16];
		inet_ntop(AF_INET, &addr_old, ip_str_old, sizeof(ip_str_old));
		inet_ntop(AF_INET, &addr_new, ip_str_new, sizeof(ip_str_new));

		NOTICE_LOG(Log::sceNet, "Updated Mapped Address from %s:%d to %s:%d", ip_str_old, si->mapped_port, ip_str_new, new_port);

		si->mapped_addr = new_addr;
		si->mapped_port = new_port;
	}
}

void signaling_handler::update_si_status(std::shared_ptr<signaling_info>& si, s32 new_status, s32 error_code)
{
	if (!si)
		return;

	if (si->conn_status == SCE_NP_SIGNALING_CONN_STATUS_PENDING && new_status == SCE_NP_SIGNALING_CONN_STATUS_ACTIVE)
	{
		si->conn_status = SCE_NP_SIGNALING_CONN_STATUS_ACTIVE;

		//signal_sig_callback(si->conn_id, SCE_NP_SIGNALING_EVENT_ESTABLISHED, error_code);
		notifySignalingHandler(si->room_id, si->conn_id, 0, si->member_id, SCE_NP_SIGNALING_EVENT_ESTABLISHED, error_code);
		//signal_sig2_callback(si->room_id, si->member_id, SCE_NP_MATCHING2_SIGNALING_EVENT_Established, error_code);
		notifySignalingHandler(si->room_id, si->conn_id, 0, si->member_id, SCE_NP_MATCHING2_SIGNALING_EVENT_Established, error_code);

		if (si->op_activated)
			//signal_ext_sig_callback(si->conn_id, SCE_NP_SIGNALING_EVENT_EXT_MUTUAL_ACTIVATED, CELL_OK);
			notifySignalingHandler(si->room_id, si->conn_id, 0, si->member_id, SCE_NP_SIGNALING_EVENT_EXT_MUTUAL_ACTIVATED, error_code);
	}
	else if ((si->conn_status == SCE_NP_SIGNALING_CONN_STATUS_PENDING || si->conn_status == SCE_NP_SIGNALING_CONN_STATUS_ACTIVE) && new_status == SCE_NP_SIGNALING_CONN_STATUS_INACTIVE)
	{
		si->conn_status = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;
		//signal_sig_callback(si->conn_id, SCE_NP_SIGNALING_EVENT_DEAD, error_code);
		notifySignalingHandler(si->room_id, si->conn_id, 0, si->member_id, SCE_NP_SIGNALING_EVENT_DEAD, error_code);
		//signal_sig2_callback(si->room_id, si->member_id, SCE_NP_MATCHING2_SIGNALING_EVENT_Dead, error_code);
		notifySignalingHandler(si->room_id, si->conn_id, 0, si->member_id, SCE_NP_MATCHING2_SIGNALING_EVENT_Dead, error_code);
		retire_all_packets(si);
	}
}

void signaling_handler::update_ext_si_status(std::shared_ptr<signaling_info>& si, bool op_activated)
{
	if (!si)
		return;

	if (op_activated && !si->op_activated)
	{
		si->op_activated = true;

		if (si->conn_status != SCE_NP_SIGNALING_CONN_STATUS_ACTIVE)
			//signal_ext_sig_callback(si->conn_id, SCE_NP_SIGNALING_EVENT_EXT_PEER_ACTIVATED, CELL_OK);
			notifySignalingHandler(si->room_id, si->conn_id, 0, si->member_id, SCE_NP_SIGNALING_EVENT_EXT_PEER_ACTIVATED, SCE_NP_MATCHING2_OKAY);
		else
			//signal_ext_sig_callback(si->conn_id, SCE_NP_SIGNALING_EVENT_EXT_MUTUAL_ACTIVATED, CELL_OK);
			notifySignalingHandler(si->room_id, si->conn_id, 0, si->member_id, SCE_NP_SIGNALING_EVENT_EXT_MUTUAL_ACTIVATED, SCE_NP_MATCHING2_OKAY);
	}
	else if (!op_activated && si->op_activated)
	{
		si->op_activated = false;

		//signal_ext_sig_callback(si->conn_id, SCE_NP_SIGNALING_EVENT_EXT_PEER_DEACTIVATED, CELL_OK);
		notifySignalingHandler(si->room_id, si->conn_id, 0, si->member_id, SCE_NP_SIGNALING_EVENT_EXT_PEER_DEACTIVATED, SCE_NP_MATCHING2_OKAY);
	}
}

void signaling_handler::DisconnectUsers(SceNpMatching2RoomId room_id)
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

	INFO_LOG(Log::sceNet, "FINISHED -> P2P");
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
void signaling_handler::send_signaling_packet(signaling_packet& sp, u32_be addr, u16_be port) const {
	INFO_LOG(Log::sceNet, "send_signaling_packet(command: %d, ip: %s, port: %d)", sp.command, ip2str(addr).c_str(), ntohs(port));
	std::vector<u8> packet(sizeof(signaling_packet) + VPORT_0_HEADER_SIZE);
	reinterpret_cast<u16_le&>(packet[0]) = 0; // VPort 0 (LE)
	packet[2] = SUBSET_SIGNALING;
	//sockaddr_in local_ip;
	//getLocalIp(&local_ip);
	sp.sent_addr = addr;
	sp.sent_port = port;
	std::memcpy(packet.data() + VPORT_0_HEADER_SIZE, &sp, sizeof(signaling_packet));

	sockaddr_in dest;
	memset(&dest, 0, sizeof(sockaddr_in));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = addr;
	dest.sin_port = port;

	if (!send_packet_ipv4(packet, dest)) {
		ERROR_LOG(Log::sceNet, "Failed to send signaling packet on IPv4 socket %s:%d", ip2str(addr).c_str(), ntohs(port));
	}
}

void signaling_handler::send_information_packets(u32_be addr, u16_be port, const SceNpId& npid)
{
	std::lock_guard lock(mtx_);

	const u32 conn_id = get_always_conn_id(npid);
	std::shared_ptr<signaling_info> si = sig_peers.at(conn_id);
	si->addr = addr;
	si->port = port;
	si->info_counter = 10;

	auto& sent_packet = sig_packet;
	sent_packet.command = SignalingCommand::Info;

	INFO_LOG(Log::sceNet, "INFO -> P2P");
	send_signaling_packet(sent_packet, addr, port);
	queue_signaling_packet(sent_packet, si, std::chrono::steady_clock::now() + REPEAT_INFO_DELAY);
}

void signaling_handler::reschedule_packet(std::shared_ptr<signaling_info>& si, SignalingCommand cmd, std::chrono::steady_clock::time_point new_timepoint)
{
	for (auto it = qpackets.begin(); it != qpackets.end(); it++)
	{
		if (it->second.packet.command == cmd && it->second.sig_info == si)
		{
			auto new_queue = qpackets.extract(it);
			new_queue.key() = new_timepoint;
			qpackets.insert(std::move(new_queue));
			return;
		}
	}
}

void signaling_handler::retire_packet(std::shared_ptr<signaling_info>& si, SignalingCommand cmd)
{
	for (auto it = qpackets.begin(); it != qpackets.end(); it++)
	{
		if (it->second.packet.command == cmd && it->second.sig_info == si)
		{
			qpackets.erase(it);
			return;
		}
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

void signaling_handler::recv_loop(InetSocket* inetSocket) {
	NOTICE_LOG(Log::sceNet, "Signaling Receiver Thread Started");
	// single-threaded receive path; no busy wait
	running_ = true;
	timeval tv{};
	tv.tv_sec = 1;      // timeout 1s
	tv.tv_usec = 0;
//	// Wait for socket to be ready before starting the loop
//	int ready = 0;
//	while (ready == 0 && running_) {
//		fd_set readfds;
//		FD_ZERO(&readfds);
//		FD_SET(inetSocket->sock, &readfds);
//		ready = select(inetSocket->sock, &readfds, nullptr, nullptr, &tv);
//		if (ready < 0) {
//
//			int errorCode = 0;
//#if PPSSPP_PLATFORM(WINDOWS)
//			errorCode = WSAGetLastError();
//#else
//			errorCode = errno;
//#endif
//			ERROR_LOG(Log::sceNet, "SIGSRV Socket Select Failed: %d", errorCode);
//		}
//	}
	while (running_) {
		if (!inetSocket) {
			// Socket lost. Try to find it again!
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			inetSocket = g_socketManager.FindSocketByPort(ntohs(SCE_NP_PORT));
			continue;
		}
		u8 buf[1500];
		sockaddr_in src{};
		socklen_t slen = sizeof(src);
		int n = recvfrom(inetSocket->sock, reinterpret_cast<char*>(buf), sizeof(buf), 0,
			reinterpret_cast<sockaddr*>(&src), &slen);
		if (n < 0) {
			int errorCode = 0;
#if PPSSPP_PLATFORM(WINDOWS)
			errorCode = WSAGetLastError();
			if (errorCode == WSAEWOULDBLOCK) {
				fd_set readfds;
				FD_ZERO(&readfds);
				FD_SET(inetSocket->sock, &readfds);
				// Nothing wrong here, just check again after a short recess
				int ready = select(inetSocket->sock, &readfds, nullptr, nullptr, &tv);
				continue;
			}
#else
			errorCode = errno;
			if (errorCode == EAGAIN || errorCode == EWOULDBLOCK) {
				fd_set readfds;
				FD_ZERO(&readfds);
				FD_SET(inetSocket->sock, &readfds);
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
			continue;
		}


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
					std::lock_guard lock(rpcn_mtx_);
					rpcn_msgs.push_back(std::move(vport_0_data));
					rpcn_msg_cv.notify_all();
				}	
				break;
			case SUBSET_SIGNALING:
				{
					signaling_message msg;
					msg.src_addr = src.sin_addr.s_addr;
					msg.src_port = src.sin_port;
					msg.data = std::move(vport_0_data);
					INFO_HEXLOG(Log::sceNet, "recv_loop::SIGSERV", reinterpret_cast<const char*>(msg.data.data()), msg.data.size(), 386);

					{
						std::lock_guard lock(sign_mtx_);
						sign_msgs.push_back(std::move(msg));
						sign_msg_cv.notify_all();
					}
					//dispatch_packet(msg);
				}
				break;
			default:
				ERROR_LOG(Log::sceNet, "Invalid vport 0 subset (%d)", subset);
				continue;
			}
		}

	}
}

void signaling_handler::signaling_thread() {
	NOTICE_LOG(Log::sceNet, "Signaling P2P Handler Thread Started");
	while (running_)
	{
		process_incoming_messages();

		const auto now = std::chrono::steady_clock::now();

		for (auto it = qpackets.begin(); it != qpackets.end();)
		{
			auto& [timestamp, sig] = *it;

			if (timestamp > now)
				break;

			SignalingCommand cmd = sig.packet.command;

			if (sig.sig_info->time_last_msg_recvd < now - 60s && cmd != SignalingCommand::Info)
			{
				// We had no connection to opponent for 60 seconds, consider the connection dead
				ERROR_LOG(Log::sceNet, "Timeout disconnection");
				update_si_status(sig.sig_info, SCE_NP_SIGNALING_CONN_STATUS_INACTIVE, SCE_NP_SIGNALING_ERROR_TIMEOUT);
				retire_packet(sig.sig_info, SignalingCommand::Ping); // Retire ping packet if necessary
				break; // qpackets has been emptied of all packets for this user so we're requeuing
			}

			// Update the timestamp if necessary
			switch (sig.packet.command)
			{
			case SignalingCommand::Connect:
			case SignalingCommand::Ping:
				sig.packet.timestamp_sender = get_micro_timestamp(now);
				break;
			case SignalingCommand::ConnectAck:
				sig.packet.timestamp_receiver = get_micro_timestamp(now);
				break;
			default:
				break;
			}

			// Resend the packet
			send_signaling_packet(sig.packet, sig.sig_info->addr, sig.sig_info->port);

			// Reschedule another packet
			auto& si = sig.sig_info;

			std::chrono::milliseconds delay(500);
			switch (cmd)
			{
			case SignalingCommand::Ping:
			case SignalingCommand::Pong:
				delay = REPEAT_PING_DELAY;
				break;
			case SignalingCommand::Connect:
			case SignalingCommand::ConnectAck:
			case SignalingCommand::Confirm:
				delay = REPEAT_CONNECT_DELAY;
				break;
			case SignalingCommand::Finished:
			case SignalingCommand::FinishedAck:
				delay = REPEAT_FINISHED_DELAY;
				break;
			case SignalingCommand::Info:
				// Don't reschedule
				if (si->info_counter == 0)
				{
					it = qpackets.erase(it);
					continue;
				}

				delay = REPEAT_INFO_DELAY;
				si->info_counter--;
				break;
			}

			it++;

			reschedule_packet(si, cmd, now + delay);
		}
		// TODO: Sleep until next expected packet, or wake signal?

		if (!qpackets.empty())
		{
			const auto expected_timepoint = qpackets.begin()->first;
			if (now < expected_timepoint)
			{
				auto duration = (expected_timepoint - now);
				wait_for_sign(duration);
			}
		}
	}
}

std::vector<signaling_message> signaling_handler::get_sign_msgs()
{
	std::vector<signaling_message> msgs;
	std::lock_guard lock(sign_mtx_);
	msgs = std::move(sign_msgs);
	sign_msgs.clear();

	return msgs;
}

void signaling_handler::process_incoming_messages() {

	auto msgs = get_sign_msgs();

	for (const auto& msg : msgs)
	{
		const auto* sp = reinterpret_cast<const signaling_packet*>(msg.data.data());
		INFO_LOG(Log::sceNet, "SIGSERV Packet Received from %s", sp->npid.handle.data);
		auto& sent_packet = sig_packet;
		auto si = get_signaling_ptr(sp);

		if (sp->command == SignalingCommand::Connect || sp->command == SignalingCommand::Info) {
			const u32 conn_id = get_always_conn_id(sp->npid);
			si = sig_peers.at(conn_id);
		}
		if (sp->command == SignalingCommand::Finished) {
			// User is unknown to us or the connection is inactive
			// Ignore packet unless it's a finished packet in case the finished_ack wasn't received by opponent
			return;
		}
		const auto now = std::chrono::steady_clock::now();
		if (si)
			si->time_last_msg_recvd = now;

		switch (sp->command) {
		case SignalingCommand::Ping:        handle_ping(sp, sent_packet, msg.src_addr, msg.src_port); break;
		case SignalingCommand::Pong:        handle_pong(sp, si); break;
		case SignalingCommand::Connect:     handle_connect(sp, si, sent_packet, msg.src_addr, msg.src_port); break;
		case SignalingCommand::ConnectAck:  handle_connect_ack(sp, si, sent_packet, msg.src_addr, msg.src_port); break;
		case SignalingCommand::Confirm:     handle_confirm(sp, si, sent_packet, msg.src_addr, msg.src_port); break;
		case SignalingCommand::Finished:    handle_finished(sp, si, sent_packet, msg.src_addr, msg.src_port); break;
		case SignalingCommand::FinishedAck: handle_finished_ack(sp, si); break;
		case SignalingCommand::Info:        handle_info(sp, si, msg.src_addr, msg.src_port); break;
		default: ERROR_LOG(Log::sceNet, "Invalid signaling command received");  break;
		}
	}
}

void signaling_handler::handle_ping(const signaling_packet* sp, signaling_packet& sent_packet, u32_be op_addr, u16_be op_port) {
	INFO_LOG(Log::sceNet, "SIGSERV: Ping");
	/*reply = true;
	schedule_repeat = false;
	sent_packet.command = signal_pong;
	sent_packet.timestamp_sender = sp->timestamp_sender;*/

	sent_packet.command = SignalingCommand::Pong;
	sent_packet.timestamp_sender = sp->timestamp_sender;
	// Reply
	INFO_LOG(Log::sceNet, "PONG -> P2P");
	send_signaling_packet(sent_packet, op_addr, op_port);
	// Don't Schedule Repeat
}

void signaling_handler::handle_pong(const signaling_packet* sp, std::shared_ptr<signaling_info> si) {
	INFO_LOG(Log::sceNet, "SIGSERV: Pong");
	/*update_rtt(sp->timestamp_sender);
	reply = false;
	schedule_repeat = false;
	reschedule_packet(si, signal_ping, now + 10s);*/
	const auto update_rtt = [&](u64 rtt_timestamp)
	{
		u64 timestamp_now = get_micro_timestamp(std::chrono::steady_clock::now());
		u64 rtt = timestamp_now - rtt_timestamp;
		si->last_rtts[(si->rtt_counters % 6)] = rtt;
		si->rtt_counters++;

		size_t num_rtts = std::min(static_cast<std::size_t>(6), si->rtt_counters);
		u64 sum = 0;
		for (size_t index = 0; index < num_rtts; index++)
		{
			sum += si->last_rtts[index];
		}

		si->rtt = (u32)(sum / num_rtts);
	};

	update_rtt(sp->timestamp_sender);
	reschedule_packet(si, SignalingCommand::Ping, std::chrono::steady_clock::now() + 10s);
	// Don't Reply
	// Don't Schedule Repeat
}

void signaling_handler::handle_info(const signaling_packet* sp, std::shared_ptr<signaling_info> si, u32_be op_addr, u16_be op_port) {
	INFO_LOG(Log::sceNet, "SIGSERV: Info");
	/*update_si_addr(si, op_addr, op_port);
	reply = false;
	schedule_repeat = false;*/
	update_si_addr(si, op_addr, op_port);
	// Don't Reply
	// Don't Schedule Repeat
}

void signaling_handler::handle_connect(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32_be op_addr, u16_be op_port) {
	INFO_LOG(Log::sceNet, "SIGSERV: Connect");
	/*reply = true;
	schedule_repeat = true;
	sent_packet.command = signal_connect_ack;
	sent_packet.timestamp_sender = sp->timestamp_sender;
	sent_packet.timestamp_receiver = get_micro_timestamp(now);
	update_si_addr(si, op_addr, op_port);*/
	sent_packet.command = SignalingCommand::ConnectAck;
	sent_packet.timestamp_sender = sp->timestamp_sender;
	sent_packet.timestamp_receiver = get_micro_timestamp(std::chrono::steady_clock::now());
	update_si_addr(si, op_addr, op_port);
	// Reply
	INFO_LOG(Log::sceNet, "CONNECT_ACK -> P2P");
	send_signaling_packet(sent_packet, op_addr, op_port);
	// Schedule Repeat
	queue_signaling_packet(sent_packet, si, std::chrono::steady_clock::now() + REPEAT_CONNECT_DELAY);
}

void signaling_handler::handle_connect_ack(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32_be op_addr, u16_be op_port) {
	INFO_LOG(Log::sceNet, "SIGSERV: Connect ACK");
	/*update_rtt(sp->timestamp_sender);
	reply = true;
	schedule_repeat = false;
	setup_ping();
	sent_packet.command = signal_confirm;
	sent_packet.timestamp_receiver = sp->timestamp_receiver;
	retire_packet(si, signal_connect);
	update_si_addr(si, op_addr, op_port);
	update_si_mapped_addr(si, sp->sent_addr, sp->sent_port);
	update_si_status(si, SCE_NP_SIGNALING_CONN_STATUS_ACTIVE, CELL_OK);*/
	const auto setup_ping = [&]()
	{
		for (auto it = qpackets.begin(); it != qpackets.end(); it++)
		{
			if (it->second.packet.command == SignalingCommand::Ping && it->second.sig_info == si)
			{
				return;
			}
		}

		sent_packet.command = SignalingCommand::Ping;
		sent_packet.timestamp_sender = get_micro_timestamp(std::chrono::steady_clock::now());
		INFO_LOG(Log::sceNet, "PING -> P2P");
		send_signaling_packet(sent_packet, si->addr, si->port);
		queue_signaling_packet(sent_packet, si, std::chrono::steady_clock::now() + REPEAT_PING_DELAY);
	};
	setup_ping();
	sent_packet.command = SignalingCommand::Confirm;
	sent_packet.timestamp_receiver = sp->timestamp_receiver;
	retire_packet(si, SignalingCommand::Connect);
	update_si_addr(si, op_addr, op_port);
	update_si_mapped_addr(si, sp->sent_addr, sp->sent_port);
	update_si_status(si, SCE_NP_SIGNALING_CONN_STATUS_ACTIVE, SCE_NP_MATCHING2_OKAY);
	// Reply
	INFO_LOG(Log::sceNet, "CONFIRM -> P2P");
	send_signaling_packet(sent_packet, op_addr, op_port);
	// Don't Schedule Repeat
}

void signaling_handler::handle_confirm(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32_be op_addr, u16_be op_port) {
	INFO_LOG(Log::sceNet, "SIGSERV: Confirm");
	/*update_rtt(sp->timestamp_receiver);
	reply = false;
	schedule_repeat = false;
	setup_ping();
	retire_packet(si, signal_connect_ack);
	update_si_addr(si, op_addr, op_port);
	update_si_mapped_addr(si, sp->sent_addr, sp->sent_port);
	update_ext_si_status(si, true);*/
	const auto setup_ping = [&]()
	{
		for (auto it = qpackets.begin(); it != qpackets.end(); it++)
		{
			if (it->second.packet.command == SignalingCommand::Ping && it->second.sig_info == si)
			{
				return;
			}
		}

		sent_packet.command = SignalingCommand::Ping;
		sent_packet.timestamp_sender = get_micro_timestamp(std::chrono::steady_clock::now());
		INFO_LOG(Log::sceNet, "PING -> P2P");
		send_signaling_packet(sent_packet, si->addr, si->port);
		queue_signaling_packet(sent_packet, si, std::chrono::steady_clock::now() + REPEAT_PING_DELAY);
	};
	setup_ping();
	retire_packet(si, SignalingCommand::ConnectAck);
	update_si_addr(si, op_addr, op_port);
	update_si_mapped_addr(si, sp->sent_addr, sp->sent_port);
	update_ext_si_status(si, true);
	// Don't Reply
	// Don't Schedule Repeat
}

void signaling_handler::handle_finished(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32_be op_addr, u16_be op_port) {
	INFO_LOG(Log::sceNet, "SIGSERV: Finished");
	/*reply = true;
	schedule_repeat = false;
	sent_packet.command = signal_finished_ack;
	update_ext_si_status(si, false);
	update_si_status(si, SCE_NP_SIGNALING_CONN_STATUS_INACTIVE, SCE_NP_SIGNALING_ERROR_TERMINATED_BY_PEER);*/
	sent_packet.command = SignalingCommand::FinishedAck;
	update_ext_si_status(si, false);
	update_si_status(si, SCE_NP_SIGNALING_CONN_STATUS_INACTIVE, SCE_NP_SIGNALING_ERROR_TERMINATED_BY_PEER);
	// Reply
	INFO_LOG(Log::sceNet, "FINISHED_ACK -> P2P");
	send_signaling_packet(sent_packet, op_addr, op_port);
	// Don't Schedule Repeat
}

void signaling_handler::handle_finished_ack(const signaling_packet* sp, std::shared_ptr<signaling_info> si) {
	INFO_LOG(Log::sceNet, "SIGSERV: Finished ACK");
	/*reply = false;
	schedule_repeat = false;
	update_si_status(si, SCE_NP_SIGNALING_CONN_STATUS_INACTIVE, SCE_NP_SIGNALING_ERROR_TERMINATED_BY_MYSELF);
	retire_packet(si, signal_finished);*/
	update_si_status(si, SCE_NP_SIGNALING_CONN_STATUS_INACTIVE, SCE_NP_SIGNALING_ERROR_TERMINATED_BY_MYSELF);
	retire_packet(si, SignalingCommand::Finished);
	// Don't Reply
	// Don't Schedule Repeat
}

void signaling_handler::UserJoinedRoom(net::RPCNResponse resp) {
	auto notification = resp.stream->get_flatbuffer<NotificationUserJoinedRoom>();
	if (resp.stream->is_error()) {
		ERROR_LOG(Log::sceNet, "NOTI Malformed UserJoinedRoom notification");
		return;
	}

	const SceNpMatching2RoomId room_id = notification->room_id();

	u32 _size = sizeof(SceNpMatching2RoomMemberUpdateInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomMemberUpdateInfo>::Create(ptr);
	np::RoomMemberUpdateInfo_to_SceNpMatching2RoomMemberUpdateInfo(np_memory, notification->update_info(), notif_data, false, false);

	char buffer[256];
	snprintf(buffer, sizeof(buffer), "%s Joined the room",
		notif_data->roomMemberDataInternal->userInfo.npId.handle.data);
	auto gr = GetI18NCategory(I18NCat::GRAPHICS);
	g_OSD.Show(OSDType::MESSAGE_SUCCESS, gr->T(buffer), 3.0f);
	NOTICE_LOG(Log::sceNet, "User %s(%d) joined the room(%d)", notif_data->roomMemberDataInternal->userInfo.npId.handle.data, notif_data->roomMemberDataInternal->memberId, room_id);

	// Ensures we do not call the callback if the room is not in the cache(ie we left the room already)
	auto member = npServer->cache.GetMember(notif_data->roomMemberDataInternal->memberId);
	if (member) {
		//get_match2_event(event_key, 0, 0);
		return;
	}
	// Cache new Room Member
	npServer->cache.AddMember(*notif_data->roomMemberDataInternal);

	// We initiate signaling if necessary
	if (const auto* signaling_info = notification->signaling())
	{
		auto vec = signaling_info->ip();
		const u32_be result_ip = 
			static_cast<u32_be>(vec->Get(0)) << 24 |
			static_cast<u32_be>(vec->Get(1)) << 16 |
			static_cast<u32_be>(vec->Get(2)) << 8 |
			static_cast<u32_be>(vec->Get(3));

		const u32_be addr_p2p = result_ip; // register_ip()
		const u16_be port_p2p = htons(signaling_info->port());
		
		const SceNpMatching2RoomMemberId member_id = notif_data->roomMemberDataInternal->memberId;
		const SceNpId& npid = notif_data->roomMemberDataInternal->userInfo.npId;

		// Attempt Signaling
		auto connId = init_sig(npid, room_id, member_id);
		// Connect to Signaling Server
		g_signaling.connect(connId, addr_p2p, SCE_NP_PORT);
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
	WARN_LOG(Log::sceNet, "NOTI UserLeftRoom UNTESTED");
	SceNpMatching2RoomId room_id = resp.stream->get<u64>();
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

	char buffer[256];
	snprintf(buffer, sizeof(buffer), "%s Left the room",
		notif_data->roomMemberDataInternal->userInfo.npId.handle.data);
	auto gr = GetI18NCategory(I18NCat::GRAPHICS);
	g_OSD.Show(OSDType::MESSAGE_ERROR, gr->T(buffer), 3.0f);
	NOTICE_LOG(Log::sceNet, "NOTI UserLeftRoom User %s(%d) left room(%d)", notif_data->roomMemberDataInternal->userInfo.npId.handle.data, notif_data->roomMemberDataInternal->memberId, room_id);

	// Stop signaling. PS3 handles this in sceNpSignalingDeactivateConnection
	auto conn = get_conn_id_from_npid(notif_data->roomMemberDataInternal->userInfo.npId);
	if (conn)
		stop_sig_nl(conn.value(), true);
	// Ensures we do not call the callback if the room is not in the cache(ie we left the room already)
	auto room = npServer->cache.GetRoom(room_id);
	if (!room) {
		//get_match2_event(event_key, 0, 0);
		return;
	}
	npServer->cache.RemoveMember(notif_data->roomMemberDataInternal->memberId);

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

	SceNpMatching2RoomId room_id = resp.stream->get<u64>();
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

	DisconnectUsers(room_id);
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
	npServer->cache.AddRoom(*notif_data->newRoomDataInternal);

	//extra_nps::print_SceNpMatching2RoomDataInternal(notif_data->newRoomDataInternal.get_ptr());

	NOTICE_LOG(Log::sceNet, "NOTI Received notification that room(%d)'s data was updated", room_id);

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

	auto member = npServer->cache.GetMember(notif_data->newRoomMemberDataInternal->memberId);
	if (member) {
		//get_match2_event(event_key, 0, 0);
		return;
	}
	npServer->cache.AddMember(*notif_data->newRoomMemberDataInternal);

	NOTICE_LOG(Log::sceNet, "NOTI User %s(%d) data was updated for room (%d)", notif_data->newRoomMemberDataInternal->userInfo.npId.handle.data, notif_data->newRoomMemberDataInternal->memberId, room_id);
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

	SceNpMatching2RoomId room_id = resp.stream->get<u64>();
	SceNpMatching2RoomMemberId member_id = resp.stream->get<u16>();
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
	resp.stream = new vec_stream(resp.data);

	const auto* matching_info = resp.stream->get_flatbuffer<MatchingSignalingInfo>();

	if (resp.stream->is_error() || !matching_info->addr() || !matching_info->npid() || !matching_info->addr()->ip())
	{
		ERROR_LOG(Log::sceNet, "NOTI Malformed RoomMessageReceived notification");
		return;
	}

	SceNpId npid_p2p;
	memset(&npid_p2p, 0, sizeof(npid_p2p));
	memcpy(&npid_p2p, matching_info->npid(), std::min<size_t>(16, matching_info->npid()->Length()));

	auto vec = matching_info->addr()->ip();
	const u32_be result_ip =
		static_cast<u32_be>(vec->Get(0)) << 24 |
		static_cast<u32_be>(vec->Get(1)) << 16 |
		static_cast<u32_be>(vec->Get(2)) << 8 |
		static_cast<u32_be>(vec->Get(3));

	const u32 addr_p2p = result_ip;
	const u16 port_p2p = htons(matching_info->addr()->port());

	send_information_packets(addr_p2p, port_p2p, npid_p2p);
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
