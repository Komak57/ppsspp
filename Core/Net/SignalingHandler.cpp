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
#include "fb_helpers.h"
#include <Core/Debugger/Np2Printer.h>
// Used for things like 10s
using namespace std::chrono_literals;

signaling_handler::signaling_handler() {}
signaling_handler::~signaling_handler() { stop("signaling_handler destroyed"); }
signaling_packet sig_packet{};

u64 signaling_handler::get_micro_timestamp(const std::chrono::steady_clock::time_point& time_point)
{
	return std::chrono::duration_cast<std::chrono::microseconds>(time_point.time_since_epoch()).count();
}

// ====================================
// Signaling Helper Functions
// ====================================
#pragma region Signaling Helpers
// Creates Signaling connection to SELF
u32 signaling_handler::init_sig(const SceNpId& npid)
{
	std::lock_guard lock(mtx_);

	const u32 conn_id = get_always_conn_id(npid);

	if (sig_peers[conn_id]->conn_status == SCE_NP_SIGNALING_CONN_STATUS_INACTIVE)
	{
		INFO_LOG(Log::sceNet, "SIGSERV: Creating new sig1 connection and requesting infos from RPCN");
		sig_peers[conn_id]->conn_status = SCE_NP_SIGNALING_CONN_STATUS_PENDING;

		// Request peer infos from RPCN
	if (npServer->RequestSignalingInfo(npid.ToString(), conn_id) < 0)
			ERROR_LOG(Log::sceNet, "SIGSERV: RPCN Request Failed");
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
	if (si->conn_status != SCE_NP_SIGNALING_CONN_STATUS_ACTIVE)
		si->conn_status = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;

	notifySignalingHandler(si->room_id, si->member_id, si->conn_id, si->conn_status, SCE_NP_MATCHING2_SIGNALING_EVENT_Established, SCE_NP_MATCHING2_OKAY);

	si->nat_type = SCE_NP_SIGNALING_NETINFO_NAT_STATUS_UNKNOWN;

	return conn_id;
}

u32 signaling_handler::get_always_conn_id(const SceNpId& npid)
{
	std::string npid_str = npid.ToString();

	if (npid_to_conn_id.find(npid_str) != npid_to_conn_id.end())
		return npid_to_conn_id.at(npid_str);

	u32 conn_id = 0;
	if (npid.Equals(*NpGetNpId())) {
		WARN_LOG(Log::sceNet, "Creating ConnID for Self for '%s'", npid_str.c_str());
	}
	else {
		WARN_LOG(Log::sceNet, "ConnID for member '%s' not found. Creating.", npid_str.c_str());
		conn_id = cur_conn_id++;
	}

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

	std::string npid_str = npid.ToString();

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

std::shared_ptr<signaling_info> signaling_handler::get_signaling_ptr(const signaling_packet* sp)
{
	std::string npid = sp->npid.ToString();

	if (npid_to_conn_id.find(npid) == npid_to_conn_id.end())
		return nullptr;

	u32 conn_id = npid_to_conn_id.at(npid);

	if (sig_peers.find(conn_id) == sig_peers.end())
	{
		ERROR_LOG(Log::sceNet, "SIGSERV: ID Discrepancy");
		return nullptr;
	}

	return sig_peers.at(conn_id);
}

void signaling_handler::update_si_addr(std::shared_ptr<signaling_info>& si, u32 new_addr, u16 new_port)
{
	if (!si)
		return;

	if (si->addr != new_addr || si->port != new_port)
	{
		in_addr addr_old, addr_new;
		addr_old.s_addr = si->addr;
		addr_new.s_addr = new_addr;

		NOTICE_LOG(Log::sceNet, "Updated Address from %s:%d to %s:%d", ip2str(addr_old).c_str(), si->port, ip2str(addr_new).c_str(), new_port);

		si->addr = new_addr;
		si->port = new_port;
	}
}

void signaling_handler::update_si_mapped_addr(std::shared_ptr<signaling_info>& si, u32 new_addr, u16 new_port)
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

		NOTICE_LOG(Log::sceNet, "Updated Mapped Address from %s:%d to %s:%d", ip2str(addr_old).c_str(), si->mapped_port, ip2str(addr_new).c_str(), new_port);

		si->mapped_addr = new_addr;
		si->mapped_port = new_port;

		if (si->addr == si->mapped_addr) // Direct Connection
			si->nat_type = SCE_NP_SIGNALING_NETINFO_NAT_STATUS_TYPE1;
		else if(si->port == si->mapped_port) // Direct Port
			si->nat_type = SCE_NP_SIGNALING_NETINFO_NAT_STATUS_TYPE2;
		else // We don't currently have a secondary STUN server to confirm TYPE 2 vs TYPE 3
			si->nat_type = SCE_NP_SIGNALING_NETINFO_NAT_STATUS_TYPE3;
	}
}

void signaling_handler::update_si_status(std::shared_ptr<signaling_info>& si, s32 new_status, s32 error_code)
{
	if (!si)
		return;

	if (si->conn_status == SCE_NP_SIGNALING_CONN_STATUS_PENDING && new_status == SCE_NP_SIGNALING_CONN_STATUS_ACTIVE)
	{
		si->conn_status = SCE_NP_SIGNALING_CONN_STATUS_ACTIVE;

		auto last_sig_status = si->sig_status;
		if (si->op_activated)
			si->sig_status = SCE_NP_SIGNALING_EVENT_EXT_MUTUAL_ACTIVATED;
		else if (si->sig_status < SCE_NP_SIGNALING_EVENT_ESTABLISHED)
			si->sig_status = SCE_NP_SIGNALING_EVENT_ESTABLISHED;

		if (last_sig_status != SCE_NP_SIGNALING_EVENT_EXT_MUTUAL_ACTIVATED && si->sig_status == SCE_NP_SIGNALING_EVENT_EXT_MUTUAL_ACTIVATED) {
			notifySignalingHandler(si->room_id, si->member_id, si->conn_id, si->conn_status, SCE_NP_MATCHING2_SIGNALING_EVENT_Established, error_code);
		}
	}
	else if ((si->conn_status == SCE_NP_SIGNALING_CONN_STATUS_PENDING || si->conn_status == SCE_NP_SIGNALING_CONN_STATUS_ACTIVE) && new_status == SCE_NP_SIGNALING_CONN_STATUS_INACTIVE)
	{
		si->conn_status = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;
		si->sig_status = SCE_NP_SIGNALING_EVENT_DEAD;

		notifySignalingHandler(si->room_id, si->member_id, si->conn_id, si->conn_status, SCE_NP_MATCHING2_SIGNALING_EVENT_Dead, error_code);
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

		auto last_sig_status = si->sig_status;
		if (si->conn_status != SCE_NP_SIGNALING_CONN_STATUS_ACTIVE)
			si->sig_status = SCE_NP_SIGNALING_EVENT_EXT_PEER_ACTIVATED;
		else
			si->sig_status = SCE_NP_SIGNALING_EVENT_EXT_MUTUAL_ACTIVATED;

		if (last_sig_status != SCE_NP_SIGNALING_EVENT_EXT_MUTUAL_ACTIVATED && si->sig_status == SCE_NP_SIGNALING_EVENT_EXT_MUTUAL_ACTIVATED) {
			notifySignalingHandler(si->room_id, si->member_id, si->conn_id, si->conn_status, SCE_NP_MATCHING2_SIGNALING_EVENT_Established, SCE_NP_MATCHING2_OKAY);
		}
	}
	else if (!op_activated && si->op_activated)
	{
		si->op_activated = false;
		si->sig_status = SCE_NP_SIGNALING_EVENT_EXT_PEER_DEACTIVATED;

		notifySignalingHandler(si->room_id, si->member_id, si->conn_id, si->conn_status, SCE_NP_MATCHING2_SIGNALING_EVENT_Dead, SCE_NP_SIGNALING_ERROR_TERMINATED_BY_PEER);
		retire_all_packets(si);
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
	if (np2P2PThreadID)
		__KernelResumeThreadFromWait(np2P2PThreadID, 0);
}

void signaling_handler::stop_sig(u32 conn_id, bool forceful)
{
	std::lock_guard lock(mtx_);
	stop_sig_nl(conn_id, forceful);
}
#pragma endregion

// ====================================
// Connection Functions
// ====================================
#pragma region Connection Functions

bool signaling_handler::create_connection() {
	auto DccpSocket = g_socketManager.GetDCCP();
	// Create the Virtual Socket for p2p handshakes
	WARN_LOG(Log::sceNet, "Creating new socket for vport %d", SCE_INTERNAL_PORT);
	auto ConnSocket = create_socket(SCE_INTERNAL_PORT, PSP_NET_INET_AF_INET, PSP_NET_INET_SOCK_CONN_DGRAM, PSP_NET_INET_IPPROTO_UNSPEC);
	
	if (!DccpSocket || !ConnSocket) {
		ERROR_LOG(Log::sceNet, "Could not initialize connection.");
		_dbg_assert_msg_(false, "Could not initialize connection.");
		return false;
	}
	ConnSocket->vport = SCE_INTERNAL_PORT; // Bind will configure this to a random vport. We need this particular socket to communicate on vport 0
	// If not running, spin up the recv thread
	if (!running_) {
		recv_thread_ = std::thread(&signaling_handler::recv_loop, this, DccpSocket, ConnSocket);
		//signaling_thread_ = std::thread(&signaling_handler::signaling_thread, this);
		//npServer->start_signal_thread();
	}
	return true;
}

bool signaling_handler::destroy_connection() {
	//{
	//	// Close our master socket
	//	auto inetSocket = g_socketManager.GetDCCP();
	//	if (inetSocket != nullptr) {
	//		inetSocket->shutdown(SHUT_RDWR);
	//		inetSocket->state = SocketState::Unused;
	//		g_socketManager.Close(inetSocket);
	//		g_PortManager.Remove("UDP", SCE_SIGN_PORT);
	//	}
	//}
	//{
	//	// Close our virtual socket
	//	auto inetSocket = g_socketManager.FindSocketByPort(SCE_INTERNAL_PORT);
	//	if (inetSocket != nullptr) {
	//		inetSocket->shutdown(SHUT_RDWR);
	//		inetSocket->state = SocketState::Unused;
	//		g_socketManager.Close(inetSocket);
	//	}
	//}
	return true;
}

// This function assumes addr is in network order
// and port is in host order
void signaling_handler::connect(u32 conn_id, u32 addr, u16 port) {
	NOTICE_LOG(Log::sceNet, "Signaling Connecting to %s:%d", ip2str(addr).c_str(), port);
	std::scoped_lock lk(mtx_);
	// Send Connect?
	auto& sent_packet = sig_packet;
	sent_packet.command = SignalingCommand::Connect;
	sent_packet.timestamp_sender = get_micro_timestamp(std::chrono::steady_clock::now());

	std::shared_ptr<signaling_info> si = sig_peers.at(conn_id);
	si->conn_status = SCE_NP_SIGNALING_CONN_STATUS_PENDING;
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
	if (np2P2PThreadID)
		__KernelResumeThreadFromWait(np2P2PThreadID, 0);
}

void signaling_handler::stop(const char* reason) {
	if (!running_) return;

	// Tell everyone goodbye
	std::scoped_lock lk(mtx_);
	for (auto& [conn_id, si] : sig_peers)
	{
		retire_all_packets(si);

		auto& sent_packet = sig_packet;
		sent_packet.command = SignalingCommand::Finished;
		INFO_LOG(Log::sceNet, "FINISHED -> P2P");
		send_signaling_packet(sent_packet, si->addr, si->port);
	}

	running_ = false;
	if (recv_thread_.joinable())
		recv_thread_.join();
	/*if (signaling_thread_.joinable())
		signaling_thread_.join();*/
	//if (np2RPCNThreadID)
		//__KernelStopThread(np2RPCNThreadID, 0, "");

	destroy_connection();
	// optional: clear contexts after all callbacks are done
	contexts_.clear();
}

void signaling_handler::queue_signaling_packet(signaling_packet& sp, std::shared_ptr<signaling_info> si, std::chrono::steady_clock::time_point wakeup_time) {
	INFO_LOG(Log::sceNet, "queue_signaling_packet(command: %d, dest: %s:%d (%s), wake: %d)", sp.command, ip2str(si->addr).c_str(), si->port, si->npid.ToString().c_str(), wakeup_time);
	queued_packet qp;
	qp.sig_info = std::move(si);
	qp.packet = sp;
	qpackets.emplace(wakeup_time, std::move(qp));
}

// Assumes addr is in Network order
// Assumes port is in Host order
void signaling_handler::send_signaling_packet(signaling_packet& sp, u32 addr, u16 port) const {
	INFO_LOG(Log::sceNet, "send_signaling_packet(command: %d, ip: %s, port: %d)", sp.command, ip2str(addr).c_str(), port);
	std::vector<u8> packet(sizeof(signaling_packet) + VPORT_0_HEADER_SIZE);
	//reinterpret_cast<u16_le&>(packet[0]) = 0; // VPort 0 (LE)
	packet[0] = SUBSET_SIGNALING;
	//sockaddr_in local_ip;
	//getLocalIp(&local_ip);
	sp.sent_addr = addr;
	sp.sent_port = port;
	std::memcpy(packet.data() + VPORT_0_HEADER_SIZE, &sp, sizeof(signaling_packet));

	sockaddr_in dest;
	memset(&dest, 0, sizeof(sockaddr_in));
	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = addr;
	dest.sin_port = htons(port);

	if (!send_packet_ipv4(packet, dest)) {
		ERROR_LOG(Log::sceNet, "Failed to send signaling packet on IPv4 socket %s:%d", ip2str(addr).c_str(), port);
	}
}

void signaling_handler::send_information_packets(u32 addr, u16 port, const SceNpId& npid)
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
	send_signaling_packet(sent_packet, si->addr, si->port);
	queue_signaling_packet(sent_packet, si, std::chrono::steady_clock::now() + REPEAT_INFO_DELAY);
	if (np2P2PThreadID)
		__KernelResumeThreadFromWait(np2P2PThreadID, 0);
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
#pragma endregion

// ====================================
// P2P Logic Functions
// ====================================
#pragma region P2P Logic Functions

template <typename T, typename U>
constexpr void write_to_ptr(U&& array, int pos, const T& value)
{
	static_assert(sizeof(T) % sizeof(array[0]) == 0);
	std::memcpy(static_cast<void*>(&array[pos]), &value, sizeof(value));
}

std::chrono::microseconds signaling_handler::HandleUPnPResponses() {
	DEBUG_LOG(Log::sceNet, "Signaling RPCN Handler Thread Started");
	if (cancelled) {
		WARN_LOG(Log::sceNet, "RPCN Cancelling");
		return std::chrono::duration_cast<std::chrono::microseconds>(5s);
	}
	const auto now = std::chrono::steady_clock::now();
	const auto rpcn_msgs = g_signaling.get_rpcn_msgs();

	for (const auto& msg : rpcn_msgs)
	{
		if (cancelled) {
			WARN_LOG(Log::sceNet, "RPCN Cancelling");
			return std::chrono::duration_cast<std::chrono::microseconds>(5s);
		}
		if (msg.size() == 6)
		{
			DEBUG_LOG(Log::sceNet, "RPCN Signal Pong Received");
			// Pull addr in Network Order
			const u32 new_addr_sig = read_from_ptr<u32_le>(&msg[0]);
			// Pull port in Host Order
			const u16 new_port_sig = read_from_ptr<u16_be>(&msg[4]);
			const u32 old_addr_sig = g_signaling.addr_sig;
			const u16 old_port_sig = g_signaling.port_sig;
			g_signaling.latency = std::chrono::duration_cast<std::chrono::microseconds>(now - last_ping_time_ipv4).count() / 2;

			if (new_addr_sig != old_addr_sig)
			{
				{
					std::lock_guard<std::mutex> lock(sig_mutex);
					g_signaling.addr_sig = new_addr_sig;
					auto local_ip = g_signaling.local_addr_sig.load();


					if (new_addr_sig == local_ip) // Direct Connection
						g_signaling.nat_type.store(SCE_NP_SIGNALING_NETINFO_NAT_STATUS_TYPE1);
					else if (new_port_sig == SCE_SIGN_PORT) // Direct Port
						g_signaling.nat_type.store(SCE_NP_SIGNALING_NETINFO_NAT_STATUS_TYPE2);
					else // We don't currently have a secondary STUN server to confirm TYPE 2 vs TYPE 3
						g_signaling.nat_type.store(SCE_NP_SIGNALING_NETINFO_NAT_STATUS_TYPE3);
				}

				auto n = GetI18NCategory(I18NCat::NETWORKING);
				g_OSD.Show(OSDType::MESSAGE_SUCCESS, std::string(n->T("SH: Connected")) + std::string(" [") + ip2str(new_addr_sig) + std::string("]:") + std::to_string(new_port_sig), 0.0f, "userjoinroom");

				NOTICE_LOG(Log::sceNet, "New P2P IP: %s", ip2str(new_addr_sig).c_str());
				if (old_addr_sig == 0)
				{
					// wake thread
					g_signaling.sigv.notify_one();
				}
			}

			if (new_port_sig != old_port_sig)
			{
				{
					std::lock_guard<std::mutex> lock(sig_mutex);
					g_signaling.port_sig = new_port_sig;
				}
				NOTICE_LOG(Log::sceNet, "New P2P PORT: %d", new_port_sig);
				if (old_port_sig == 0)
				{
					// wake thread
					g_signaling.sigv.notify_one();
				}
			}

			last_pong_time_ipv4 = now;
		}
		else if (msg.size() == 18)
		{
			// We don't really need ipv6 info stored so we just update the pong data
			// std::array<u8, 16> new_ipv6_addr;
			// std::memcpy(new_ipv6_addr.data(), &msg[3], 16);
			// const u32 new_ipv6_port = read_from_ptr<be_t<u16>>(&msg[16]);

			//last_pong_time_ipv6 = now;
		}
		else
		{
			ERROR_LOG(Log::sceNet, "Received faulty RPCN UDP message!");
		}
	}

	const std::chrono::nanoseconds time_since_last_ipv4_ping = now - last_ping_time_ipv4;
	const std::chrono::nanoseconds time_since_last_ipv4_pong = now - last_pong_time_ipv4;
	auto forge_ping_packet = [&]() -> std::vector<u8>
		{
			std::vector<u8> ping(13);
			ping[0] = 1;
			//ping.emplace(ping.begin() + 1, _user_id);
			//ping.emplace(ping.begin() + 9, +local_addr);
			write_to_ptr<s64_le>(ping, 1, user_id.load());
			write_to_ptr<u32_le>(ping, 9, +g_signaling.local_addr_sig.load());
			return ping;
		};

	// Send a packet every 5 seconds and then every 500 ms until reply is received
	if (time_since_last_ipv4_pong >= 5s && time_since_last_ipv4_ping > 500ms)
	{
		const auto ping = forge_ping_packet();

		struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(STUN_addr->ai_addr);
		addr->sin_port = htons(SCE_RPCN_PORT);

		INFO_LOG(Log::sceNet, "PING -> RPCN");
		if (!send_raw_ipv4(ping, *addr))
			ERROR_LOG(Log::sceNet, "Failed to send IPv4 PING to RPCN");

		last_ping_time_ipv4 = now;
		return std::chrono::duration_cast<std::chrono::microseconds>(500ms);
	}

	/*if (np::is_ipv6_supported() && time_since_last_ipv6_pong >= 5s && time_since_last_ipv6_ping > 500ms)
	{
		const auto ping = forge_ping_packet();

		if (!send_packet_from_p2p_port_ipv6(ping, addr_rpcn_udp_ipv6))
			rpcn_log.error("Failed to send IPv6 ping to RPCN!");

		last_ping_time_ipv6 = now;
		continue;
	}*/
	auto min_duration_for = [&](const auto last_ping_time, const auto last_pong_time) -> std::chrono::nanoseconds
		{
			auto current_time = std::chrono::steady_clock::now();
			if ((current_time - last_pong_time) < 5s)
			{
				return (std::chrono::duration_cast<std::chrono::nanoseconds>(5s) - (current_time - last_pong_time));
			}
			else
			{
				return (std::chrono::duration_cast<std::chrono::nanoseconds>(500ms) - (current_time - last_pong_time));
			}
		};

	auto duration = min_duration_for(last_ping_time_ipv4, last_pong_time_ipv4);
	return std::chrono::duration_cast<std::chrono::microseconds>(duration);
	//g_signaling.wait_for_rpcn(&running, &cancelled, duration);
	/*if (np::is_ipv6_supported())
	{
		const auto duration_ipv6 = min_duration_for(last_ping_time_ipv6, last_pong_time_ipv6);
		duration = std::min(duration, duration_ipv6);
	}*/

	// Expected to fail unless rpcn is terminated
	// The check is there to nuke a msvc warning
	/*if (!sem_rpcn.try_acquire_for(duration))
	{
	}*/
}

std::chrono::microseconds signaling_handler::HandleP2PResponses() {
	DEBUG_LOG(Log::sceNet, "Signaling P2P Handler Thread Started");
	process_incoming_messages();

	const auto now = std::chrono::steady_clock::now();

	for (auto it = qpackets.begin(); it != qpackets.end();)
	{
		auto& [timestamp, sig] = *it;

		// Next queued packet still waiting
		if (timestamp > now)
			break;

		SignalingCommand cmd = (SignalingCommand)sig.packet.command;

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
		INFO_LOG(Log::sceNet, "Re-Send %s -> %s", SignalingCommandStr[sig.packet.command], ip2str(sig.sig_info->addr).c_str());
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

	// TODO: Sleep until next queued packet, or next packet received
	const auto current_timestamp = std::chrono::steady_clock::now();
	if (!qpackets.empty())
	{
		const auto next_timestamp = qpackets.begin()->first;
		if (current_timestamp > next_timestamp)
		{
			return 0s;
		} else {
			// set thread wait duration to nanoseconds until next queued packet
			return std::chrono::duration_cast<std::chrono::microseconds>(next_timestamp - current_timestamp);
		}
	}
	else {
		// set thread wait duration to infinity
		return std::chrono::duration_cast<std::chrono::microseconds>(5s); // 5000000 == 5s
	}
}

void signaling_handler::process_incoming_messages() {

	auto msgs = get_sign_msgs();

	for (const auto& msg : msgs)
	{
		if (msg.data.size() != sizeof(signaling_packet)) {
			ERROR_LOG(Log::sceNet, "SIGSERV: Malformed Packet");
			continue;
		}

		auto op_addr = msg.src_addr;
		auto op_port = msg.src_port;
		const auto* sp = reinterpret_cast<const signaling_packet*>(msg.data.data());

		//if (!validate_signaling_packet(sp))
			//continue;

		if (auto conn_id = get_conn_id_from_npid(sp->npid); conn_id != std::nullopt)
			INFO_LOG(Log::sceNet, "SIGSERV %s Packet Received from %s:%d(%s:%d)", SignalingCommandStr[sp->command], ip2str(op_addr).c_str(), op_port, sp->npid.ToString().c_str(), conn_id.value());
		else
			ERROR_LOG(Log::sceNet, "SIGSERV %s Packet Received from %s:%d(%s:UNK)", SignalingCommandStr[sp->command], ip2str(op_addr).c_str(), op_port, sp->npid.ToString().c_str());

		auto& sent_packet = sig_packet;
		auto si = get_signaling_ptr(sp);
		if (si == nullptr)
			ERROR_LOG(Log::sceNet, "SIGSERV SigPtr for member '%s' not found.", sp->npid.ToString().c_str());

		if (sp->command == SignalingCommand::Connect || sp->command == SignalingCommand::Info) {
			const u32 conn_id = get_always_conn_id(sp->npid);
			si = sig_peers.at(conn_id);
		}
		if (sp->command == SignalingCommand::Finished) {
			// User is unknown to us or the connection is inactive
			// Ignore packet unless it's a finished packet in case the finished_ack wasn't received by opponent
			handle_finished(sp, si, sent_packet, op_addr, op_port);
			return;
		}
		const auto now = std::chrono::steady_clock::now();
		if (si)
			si->time_last_msg_recvd = now;

		switch (sp->command) {
		case SignalingCommand::Ping:        handle_ping(sp, sent_packet, op_addr, op_port); break;
		case SignalingCommand::Pong:        handle_pong(sp, si); break;
		case SignalingCommand::Connect:     handle_connect(sp, si, sent_packet, op_addr, op_port); break;
		case SignalingCommand::ConnectAck:  handle_connect_ack(sp, si, sent_packet, op_addr, op_port); break;
		case SignalingCommand::Confirm:     handle_confirm(sp, si, sent_packet, op_addr, op_port); break;
		case SignalingCommand::Finished:    handle_finished(sp, si, sent_packet, op_addr, op_port); break;
		case SignalingCommand::FinishedAck: handle_finished_ack(sp, si); break;
		case SignalingCommand::Info:        handle_info(sp, si, op_addr, op_port); break;
		default: ERROR_LOG(Log::sceNet, "Invalid signaling command received");  break;
		}
	}
}

void signaling_handler::handle_ping(const signaling_packet* sp, signaling_packet& sent_packet, u32 op_addr, u16 op_port) {
	INFO_LOG(Log::sceNet, "PING <- P2P");
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
	INFO_LOG(Log::sceNet, "PONG <- P2P");
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

void signaling_handler::handle_info(const signaling_packet* sp, std::shared_ptr<signaling_info> si, u32 op_addr, u16 op_port) {
	INFO_LOG(Log::sceNet, "INFO <- P2P");
	/*update_si_addr(si, op_addr, op_port);
	reply = false;
	schedule_repeat = false;*/
	update_si_addr(si, op_addr, op_port);
	// Don't Reply
	// Don't Schedule Repeat
}

void signaling_handler::handle_connect(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32 op_addr, u16 op_port) {
	INFO_LOG(Log::sceNet, "CONNECT <- P2P");
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
	if (np2P2PThreadID)
		__KernelResumeThreadFromWait(np2P2PThreadID, 0);
}

void signaling_handler::handle_connect_ack(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32 op_addr, u16 op_port) {
	INFO_LOG(Log::sceNet, "CONNECT_ACK <- P2P");
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
		if (np2P2PThreadID)
			__KernelResumeThreadFromWait(np2P2PThreadID, 0);
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

void signaling_handler::handle_confirm(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32 op_addr, u16 op_port) {
	INFO_LOG(Log::sceNet, "CONFIRM <- P2P");
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
		if (np2P2PThreadID)
			__KernelResumeThreadFromWait(np2P2PThreadID, 0);
	};
	setup_ping();
	retire_packet(si, SignalingCommand::ConnectAck);
	update_si_addr(si, op_addr, op_port);
	update_si_mapped_addr(si, sp->sent_addr, sp->sent_port);
	update_ext_si_status(si, true);
	// Don't Reply
	// Don't Schedule Repeat
}

void signaling_handler::handle_finished(const signaling_packet* sp, std::shared_ptr<signaling_info> si, signaling_packet& sent_packet, u32 op_addr, u16 op_port) {
	INFO_LOG(Log::sceNet, "FINISHED <- P2P");
	/*reply = true;
	schedule_repeat = false;
	sent_packet.command = signal_finished_ack;
	update_ext_si_status(si, false);
	update_si_status(si, SCE_NP_SIGNALING_CONN_STATUS_INACTIVE, SCE_NP_SIGNALING_ERROR_TERMINATED_BY_PEER);*/
	sent_packet.command = SignalingCommand::FinishedAck;
	update_ext_si_status(si, false);
	update_si_status(si, SCE_NP_SIGNALING_CONN_STATUS_INACTIVE, SCE_NP_SIGNALING_ERROR_TERMINATED_BY_PEER);
	// RPCS3 handles this in sceNpSignalingDeactivateConnection
	stop_sig(si->conn_id, false);
	// Reply
	INFO_LOG(Log::sceNet, "FINISHED_ACK -> P2P");
	send_signaling_packet(sent_packet, op_addr, op_port);
	// Don't Schedule Repeat
}

void signaling_handler::handle_finished_ack(const signaling_packet* sp, std::shared_ptr<signaling_info> si) {
	INFO_LOG(Log::sceNet, "FINISHED_ACK <- P2P");
	/*reply = false;
	schedule_repeat = false;
	update_si_status(si, SCE_NP_SIGNALING_CONN_STATUS_INACTIVE, SCE_NP_SIGNALING_ERROR_TERMINATED_BY_MYSELF);
	retire_packet(si, signal_finished);*/
	update_si_status(si, SCE_NP_SIGNALING_CONN_STATUS_INACTIVE, SCE_NP_SIGNALING_ERROR_TERMINATED_BY_MYSELF);
	retire_packet(si, SignalingCommand::Finished);
	// Don't Reply
	// Don't Schedule Repeat
}
#pragma endregion

// ====================================
// Notification Functions
// ====================================
#pragma region Notifications
int signaling_handler::UserJoinedRoom(net::RPCNResponse resp) {
	WARN_LOG(Log::sceNet, "NOTI UserJoinedRoom");
	auto notification = resp.stream->get_flatbuffer<NotificationUserJoinedRoom>();
	if (resp.stream->is_error()) {
		ERROR_LOG(Log::sceNet, "NOTI Malformed UserJoinedRoom notification");
		return SCE_NP_SIGNALING_ERROR_PARSER_FAILED;
	}

	auto def = defaultOptParams.find(SCE_NP_MATCHING2_ROOM_EVENT);
	if (def == defaultOptParams.end()) {
		ERROR_LOG(Log::sceNet, "Default ROOM_EVENT handler not Found");
		return SCE_NP_SIGNALING_ERROR_CTX_NOT_FOUND;
	}
	auto _context = ctx.find(def->second.ctx_id);
	if (_context == ctx.end()) {
		ERROR_LOG(Log::sceNet, "Context not Found");
		return SCE_NP_SIGNALING_ERROR_CTX_NOT_FOUND;
	}

	const SceNpMatching2RoomId room_id = notification->room_id();

	u32 _size = sizeof(SceNpMatching2RoomMemberUpdateInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomMemberUpdateInfo>::Create(ptr);
	np::RoomMemberUpdateInfo_to_SceNpMatching2RoomMemberUpdateInfo(np_memory, notification->update_info(), notif_data, _context->second->include_onlinename, _context->second->include_avatarurl);

	/*char buffer[256];
	snprintf(buffer, sizeof(buffer), "%s Joined the room",
		notif_data->roomMemberDataInternal->userInfo.npId.handle.data);
	g_OSD.Show(OSDType::MESSAGE_SUCCESS, buffer, 3.0f);
	NOTICE_LOG(Log::sceNet, "User %s(%d) joined the room(%d)", notif_data->roomMemberDataInternal->userInfo.npId.handle.data, notif_data->roomMemberDataInternal->memberId, room_id);*/

	// Ensures we do not call the callback if the room is not in the cache(ie we left the room already)
	if (!npServer->cache.Exists(room_id)) {
		//get_match2_event(event_key, 0, 0);
		return SCE_NP_MATCHING2_ERROR_ROOM_NOT_FOUND;
	}
	// Cache new Room Member
	npServer->cache.AddMember(room_id, *notif_data->roomMemberDataInternal);

	// We initiate signaling if necessary
	if (const auto* signaling_info = notification->signaling())
	{
		const u32 addr_p2p = RegisterIp(signaling_info->ip());
		u16 port_p2p = signaling_info->port();
		auto n = GetI18NCategory(I18NCat::NETWORKING);
		if (port_p2p != SCE_SIGN_PORT)
			g_OSD.Show(OSDType::MESSAGE_WARNING, std::string(n->T("SH: Player Joining")) + std::string(" [") + std::string(notif_data->roomMemberDataInternal->userInfo.npId.handle.data) + std::string("]:") + std::to_string(SCE_SIGN_PORT) + std::string(" -> ") + std::to_string(port_p2p), 0.0f, "userjoinroom");
		else
			g_OSD.Show(OSDType::MESSAGE_SUCCESS, std::string(n->T("SH: Player Joining")) + std::string(" [") + std::string(notif_data->roomMemberDataInternal->userInfo.npId.handle.data) + std::string("]:") + std::to_string(port_p2p), 0.0f, "userjoinroom");

		const SceNpMatching2RoomMemberId member_id = notif_data->roomMemberDataInternal->memberId;
		const SceNpId& npid = notif_data->roomMemberDataInternal->userInfo.npId;

		// Attempt Signaling
		auto connId = init_sig(npid, room_id, member_id);
		// Connect to Signaling Server
		g_signaling.connect(connId, addr_p2p, port_p2p);

		return notifyRoomEventHandler(room_id, notif_data->roomMemberDataInternal->memberId, connId, SCE_NP_MATCHING2_ROOM_EVENT_MemberJoined, notif_data.ptr);
	}

	/*if (room_event_cb)
	{
		sysutil_register_cb([room_event_cb = this->room_event_cb, room_id, event_key, room_event_cb_ctx = this->room_event_cb_ctx, room_event_cb_arg = this->room_event_cb_arg, size = edata.size()](ppu_thread& cb_ppu) -> s32
		{
			room_event_cb(cb_ppu, room_event_cb_ctx, room_id, SCE_NP_MATCHING2_ROOM_EVENT_MemberJoined, event_key, 0, size, room_event_cb_arg);
			return 0;
		});
	}*/
	//notifySignalingHandlers(resp.header.uid, room_id, SCE_NP_MATCHING2_ROOM_EVENT_MemberJoined, event_key, 0, _size);
	return notifyRoomEventHandler(room_id, notif_data->roomMemberDataInternal->memberId, 0, SCE_NP_MATCHING2_ROOM_EVENT_MemberJoined, notif_data.ptr);
}

int signaling_handler::UserLeftRoom(net::RPCNResponse resp) {
	WARN_LOG(Log::sceNet, "NOTI UserLeftRoom");

	SceNpMatching2RoomId room_id = resp.stream->get<u64>();
	const auto* update_info = resp.stream->get_flatbuffer<RoomMemberUpdateInfo>();

	if (resp.stream->is_error())
	{
		ERROR_LOG(Log::sceNet, "NOTI UserLeftRoom Malformed UserLeftRoom notification");
		return SCE_NP_SIGNALING_ERROR_PARSER_FAILED;
	}

	auto def = defaultOptParams.find(SCE_NP_MATCHING2_ROOM_EVENT);
	if (def == defaultOptParams.end()) {
		ERROR_LOG(Log::sceNet, "Default ROOM_EVENT handler not Found");
		return SCE_NP_SIGNALING_ERROR_CTX_NOT_FOUND;
	}
	auto _context = ctx.find(def->second.ctx_id);
	if (_context == ctx.end()) {
		ERROR_LOG(Log::sceNet, "Context not Found");
		return SCE_NP_SIGNALING_ERROR_CTX_NOT_FOUND;
	}

	//auto [include_onlinename, include_avatarurl] = get_match2_context_options(room_event_cb_ctx);

	u32 _size = sizeof(SceNpMatching2RoomMemberUpdateInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomMemberUpdateInfo>::Create(ptr);
	np::RoomMemberUpdateInfo_to_SceNpMatching2RoomMemberUpdateInfo(np_memory, update_info, notif_data, _context->second->include_onlinename, _context->second->include_avatarurl);

	NOTICE_LOG(Log::sceNet, "NOTI UserLeftRoom User %s(%d) left room(%d)", notif_data->roomMemberDataInternal->userInfo.npId.handle.data, notif_data->roomMemberDataInternal->memberId, room_id);

	// Ensures we do not call the callback if the room is not in the cache(ie we left the room already)
	if (!npServer->cache.Exists(room_id)) {
		//get_match2_event(event_key, 0, 0);
		return SCE_NP_MATCHING2_ERROR_ROOM_NOT_FOUND;
	}
	auto n = GetI18NCategory(I18NCat::NETWORKING);
	g_OSD.Show(OSDType::MESSAGE_ERROR, std::string(n->T("SH: Player Leaving")) + std::string(" [") + std::string(notif_data->roomMemberDataInternal->userInfo.npId.handle.data) + std::string("]"), 0.0f, "userleaveroom");
	// FIXME: This forces a disconnect, but the process should be a clean exit.
	//		This happens when a user stops the emulator, but doesn't log out first
	//		We should probably log out cleanly when emulation stops, and handle this
	//		a different way when a sudden disconnect occurs.
	//auto conn_id = get_conn_id_from_npid(notif_data->roomMemberDataInternal->userInfo.npId);
	//if (conn_id) {
	//	//stop_sig(conn_id.value(), false);
	//}
	auto conn_id = get_conn_id_from_npid(notif_data->roomMemberDataInternal->userInfo.npId);
	if (conn_id) {
		auto si = sig_peers.at(conn_id.value());
		retire_all_packets(si);
	}
	npServer->cache.RemoveMember(room_id, notif_data->roomMemberDataInternal->memberId);

	//extra_nps::print_SceNpMatching2RoomMemberDataInternal(notif_data->roomMemberDataInternal.get_ptr());

	return notifyRoomEventHandler(room_id, notif_data->roomMemberDataInternal->memberId, (!conn_id ? 0 : *conn_id), SCE_NP_MATCHING2_ROOM_EVENT_MemberLeft, notif_data.ptr);
}

int signaling_handler::RoomDestroyed(net::RPCNResponse resp) {
	WARN_LOG(Log::sceNet, "NOTI RoomDestroyed");

	SceNpMatching2RoomId room_id = resp.stream->get<u64>();
	const auto* update_info = resp.stream->get_flatbuffer<RoomUpdateInfo>();

	if (resp.stream->is_error())
	{
		ERROR_LOG(Log::sceNet, "NOTI Malformed RoomDestroyed notification");
		return SCE_NP_SIGNALING_ERROR_PARSER_FAILED;
	}

	auto def = defaultOptParams.find(SCE_NP_MATCHING2_ROOM_EVENT);
	if (def == defaultOptParams.end()) {
		ERROR_LOG(Log::sceNet, "Default ROOM_EVENT handler not Found");
		return SCE_NP_SIGNALING_ERROR_CTX_NOT_FOUND;
	}
	auto _context = ctx.find(def->second.ctx_id);
	if (_context == ctx.end()) {
		ERROR_LOG(Log::sceNet, "Context not Found");
		return SCE_NP_SIGNALING_ERROR_CTX_NOT_FOUND;
	}

	u32 _size = sizeof(SceNpMatching2RoomUpdateInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomUpdateInfo>::Create(ptr);
	np::RoomUpdateInfo_to_SceNpMatching2RoomUpdateInfo(update_info, notif_data);

	// Remove room from cache - RPCS3 doesn't do this here?
	//npServer->cache.RemoveRoom(room_id);

	NOTICE_LOG(Log::sceNet, "NOTI RoomDestroyed Received notification that room(%d) was destroyed", room_id);

	DisconnectUsers(room_id);
	//disconnect_sig2_users(room_id);
	auto conn_id = get_conn_id_from_npid(*NpGetNpId());

	return notifyRoomEventHandler(room_id, 0, (!conn_id ? 0 : *conn_id), SCE_NP_MATCHING2_ROOM_EVENT_RoomDestroyed, notif_data.ptr);
}

int signaling_handler::UpdatedRoomDataInternal(net::RPCNResponse resp) {
	WARN_LOG(Log::sceNet, "NOTI UpdatedRoomDataInternal");

	auto def = defaultOptParams.find(SCE_NP_MATCHING2_ROOM_EVENT);
	if (def == defaultOptParams.end()) {
		ERROR_LOG(Log::sceNet, "Default ROOM_EVENT handler not Found");
		return SCE_NP_SIGNALING_ERROR_CTX_NOT_FOUND;
	}
	auto _context = ctx.find(def->second.ctx_id);
	if (_context == ctx.end()) {
		ERROR_LOG(Log::sceNet, "Context not Found");
		return SCE_NP_SIGNALING_ERROR_CTX_NOT_FOUND;
	}

	SceNpMatching2RoomId room_id = resp.stream->get<u64>();
	const auto* update_info = resp.stream->get_flatbuffer<RoomDataInternalUpdateInfo>();

	if (resp.stream->is_error())
	{
		ERROR_LOG(Log::sceNet, "NOTI Malformed UpdatedRoomDataInternal notification");
		return SCE_NP_SIGNALING_ERROR_PARSER_FAILED;
	}

	u32 _size = sizeof(SceNpMatching2RoomDataInternalUpdateInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomDataInternalUpdateInfo>::Create(ptr);
	SceNpId* npId = NpGetNpId();
	np::RoomDataInternalUpdateInfo_to_SceNpMatching2RoomDataInternalUpdateInfo(np_memory, update_info, notif_data, npId, _context->second->include_onlinename, _context->second->include_avatarurl);
	print_SceNpMatching2RoomDataInternal(notif_data->newRoomDataInternal);
	//np_cache.insert_room(notif_data->newRoomDataInternal.get_ptr());
	npServer->cache.AddRoom(*notif_data->newRoomDataInternal);

	auto conn_id = get_conn_id_from_npid(notif_data->newRoomDataInternal->memberList.owner->userInfo.npId);
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
	// FIXME: return self member_id?
	return notifyRoomEventHandler(room_id, notif_data->newRoomDataInternal->memberList.owner->memberId, (!conn_id ? 0 : *conn_id), SCE_NP_MATCHING2_ROOM_EVENT_UpdatedRoomDataInternal, notif_data.ptr);
}

int signaling_handler::UpdatedRoomMemberDataInternal(net::RPCNResponse resp) {
	WARN_LOG(Log::sceNet, "NOTI UpdatedRoomMemberDataInternal");

	SceNpMatching2RoomId room_id = resp.stream->get<u64>();
	const auto* update_info = resp.stream->get_flatbuffer<RoomMemberDataInternalUpdateInfo>();

	if (resp.stream->is_error())
	{
		ERROR_LOG(Log::sceNet, "NOTI Malformed UpdatedRoomMemberDataInternal notification");
		return SCE_NP_SIGNALING_ERROR_PARSER_FAILED;
	}

	auto def = defaultOptParams.find(SCE_NP_MATCHING2_ROOM_EVENT);
	if (def == defaultOptParams.end()) {
		ERROR_LOG(Log::sceNet, "Default ROOM_EVENT handler not Found");
		return SCE_NP_SIGNALING_ERROR_CTX_NOT_FOUND;
	}
	auto _context = ctx.find(def->second.ctx_id);
	if (_context == ctx.end()) {
		ERROR_LOG(Log::sceNet, "Context not Found");
		return SCE_NP_SIGNALING_ERROR_CTX_NOT_FOUND;
	}

	u32 _size = sizeof(SceNpMatching2RoomMemberDataInternalUpdateInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomMemberDataInternalUpdateInfo>::Create(ptr);
	np::RoomMemberDataInternalUpdateInfo_to_SceNpMatching2RoomMemberDataInternalUpdateInfo(np_memory, update_info, notif_data, _context->second->include_onlinename, _context->second->include_avatarurl);
	print_SceNpMatching2RoomMemberDataInternal(notif_data->newRoomMemberDataInternal);
	// Does this room exist?
	if (!npServer->cache.Exists(room_id)) {
		//notifyRoomEventHandler(ctxId, room_id, memberId, SCE_NP_MATCHING2_ROOM_EVENT_UpdatedRoomMemberDataInternal, notif_data.ptr);
		return SCE_NP_MATCHING2_ERROR_ROOM_NOT_FOUND;
	}

	// Cache the member's info
	SceNpMatching2RoomMemberId memberId = notif_data->newRoomMemberDataInternal->memberId;
	npServer->cache.AddMember(room_id, *notif_data->newRoomMemberDataInternal);

	NOTICE_LOG(Log::sceNet, "NOTI User %s(%d) data was updated for room (%d)", notif_data->newRoomMemberDataInternal->userInfo.npId.ToString(), memberId, room_id);
	//extra_nps::print_SceNpMatching2RoomMemberDataInternal(notif_data->newRoomMemberDataInternal.get_ptr());
	auto conn_id = get_conn_id_from_npid(notif_data->newRoomMemberDataInternal->userInfo.npId);
	
	return notifyRoomEventHandler(room_id, memberId, (!conn_id ? 0 : *conn_id), SCE_NP_MATCHING2_ROOM_EVENT_UpdatedRoomMemberDataInternal, notif_data.ptr);
}

int signaling_handler::RoomMessageReceived(net::RPCNResponse resp) {
	WARN_LOG(Log::sceNet, "NOTI RoomMessageReceived");
	// 0000000000000010 0090 00000014 00000000000E0014000000070008000C0010000E00000000000001700000006800000004000000580000000500000000000000903D9B08A0F1FF090C79A6089078A6086889A30878A89B0860F4FF09D0F4FF09B01815090000000060F4FF0980F3FF0978567609EFBEADDED06DA60840547609B0181509B46CA308A51894038C6EA608040004000400000000000000

	resp.stream = new vec_stream(resp.data);
	//auto noti = new vec_stream(resp.data);


	auto def = defaultOptParams.find(SCE_NP_MATCHING2_ROOM_MSG_EVENT);
	if (def == defaultOptParams.end()) {
		ERROR_LOG(Log::sceNet, "Default ROOM_EVENT handler not Found");
		return SCE_NP_SIGNALING_ERROR_CTX_NOT_FOUND;
	}
	auto _context = ctx.find(def->second.ctx_id);
	if (_context == ctx.end()) {
		ERROR_LOG(Log::sceNet, "Context not Found");
		return SCE_NP_SIGNALING_ERROR_CTX_NOT_FOUND;
	}

	SceNpMatching2RoomId room_id = resp.stream->get<u64>();
	SceNpMatching2RoomMemberId member_id = resp.stream->get<u16>();
	NOTICE_LOG(Log::sceNet, " - room: %d, member: %d)", room_id, member_id);

	const auto* message_info = resp.stream->get_flatbuffer<RoomMessageInfo>();

	if (resp.stream->is_error())
	{
		ERROR_LOG(Log::sceNet, " - Malformed RoomMessageReceived notification");
		return SCE_NP_SIGNALING_ERROR_PARSER_FAILED;
	}

	u32 _size = sizeof(SceNpMatching2RoomMessageInfo);
	u32 ptr = np_memory.Alloc(_size);
	auto notif_data = PSPPointer<SceNpMatching2RoomMessageInfo>::Create(ptr);
	np::RoomMessageInfo_to_SceNpMatching2RoomMessageInfo(np_memory, message_info, notif_data, _context->second->include_onlinename, _context->second->include_avatarurl);

	auto conn_id = get_conn_id_from_npid(npServer->cache.GetNpId(room_id, member_id));

	return notifyRoomMessageHandler(room_id, member_id, (!conn_id? 0: *conn_id), SCE_NP_MATCHING2_ROOM_MSG_EVENT_Message, notif_data.ptr);
}

void signaling_handler::SignalingHelper(net::RPCNResponse resp) {
	WARN_LOG(Log::sceNet, "NOTI SignalingHelper");
	resp.stream = new vec_stream(resp.data);

	const auto* matching_info = resp.stream->get_flatbuffer<MatchingSignalingInfo>();

	if (resp.stream->is_error() || !matching_info->addr() || !matching_info->npid() || !matching_info->addr()->ip())
	{
		ERROR_LOG(Log::sceNet, " - Malformed SignalingHelper notification");
		return;
	}

	SceNpId npid_p2p;
	memset(&npid_p2p, 0, sizeof(npid_p2p));
	memcpy(&npid_p2p, matching_info->npid(), std::min<size_t>(16, matching_info->npid()->Length()));

	const u32 addr_p2p = RegisterIp(matching_info->addr()->ip());
	u16 port_p2p = matching_info->addr()->port();
	//if (port_p2p == SCE_SIGN_PORT)
		//port_p2p = SCE_INTERNAL_PORT;

	NOTICE_LOG(Log::sceNet, " - IP at %s", ip2str(addr_p2p));
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
#pragma endregion

// ====================================
// Socket Functions
// ====================================
#pragma region Socket Functions
InetSocket* signaling_handler::create_socket(u16 port, int domain, int type, int protocol) {
	auto inetSocket = g_socketManager.FindSocketByPort(port);
	if (inetSocket == nullptr) {
		//return;

		int index;
		int hostErrno = 0;

		// Create the master socket
		inetSocket = g_socketManager.CreateSocket(&index, &hostErrno, SocketState::UsedNetInet, domain, type, protocol);
		if (!inetSocket) {
			ERROR_LOG(Log::sceNet, "Unable to create new socket");
			return nullptr;
		}

		// Bind socket for listening
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = htons(port);

		int ret = inetSocket->bind((sockaddr*)&addr, sizeof(addr));
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "Unable to bind new socket for listening");
			return nullptr;
		}

		inetSocket->state = SocketState::UsedNetInet;
		inetSocket->port = port;

		if (type != PSP_NET_INET_SOCK_CONN_DGRAM) {
			// Ignore SIGPIPE when supported (ie. BSD/MacOS)
			setSockNoSIGPIPE(inetSocket->sock, 1);
			// TODO: We should always use non-blocking mode and simulate blocking mode
			changeBlockingMode(inetSocket->sock, 1);
			// Enable Port Re-use, required for multiple-instance
			setSockReuseAddrPort(inetSocket->sock);
			// Disable Connection Reset error on UDP to avoid strange behavior
			setUDPConnReset(inetSocket->sock, false);

			// Don't open the port for virtual sockets
			if (g_Config.bEnableUPnP)
				bool ok = g_PortManager.Add("UDP", port, port);
		}
		return inetSocket;
	}
	return inetSocket; // Socket already exists
}
// This function assumes addr and port are in network order
bool signaling_handler::send_packet_ipv4(const std::vector<u8>& data, sockaddr_in dest) const {

	INFO_LOG(Log::sceNet, "Sending packet(%d bytes) to %s:%d", data.size(), ip2str(dest.sin_addr).c_str(), ntohs(dest.sin_port));

	std::string datahex;
	DEBUG_HEXLOG(Log::sceNet, "signaling_handler::send_signaling_packet", reinterpret_cast<const char*>(data.data()), data.size(), 386);
	auto inetSocket = g_socketManager.FindSocketByPort(SCE_INTERNAL_PORT);
	if (!inetSocket) {
		ERROR_LOG(Log::sceNet, "Socket not found");
		return false;
	}
	int ret = inetSocket->sendto(reinterpret_cast<const char*>(data.data()), data.size(), 0, reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
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

// Send data on the raw DCCP socket, not the CONN_DGRAM sockets
bool signaling_handler::send_raw_ipv4(const std::vector<u8>& data, sockaddr_in dest) {

	INFO_LOG(Log::sceNet, "Sending packet(%d bytes) to %s:%d", data.size(), ip2str(dest.sin_addr).c_str(), ntohs(dest.sin_port));

	std::string datahex;
	DEBUG_HEXLOG(Log::sceNet, "signaling_handler::send_signaling_packet", reinterpret_cast<const char*>(data.data()), data.size(), 386);
	auto inetSocket = g_socketManager.GetDCCP();
	if (!inetSocket) {
		ERROR_LOG(Log::sceNet, "Socket not found");
		return false;
	}
	int ret = inetSocket->sendto(reinterpret_cast<const char*>(data.data()), data.size(), 0, reinterpret_cast<const sockaddr*>(&dest), sizeof(dest));
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

void signaling_handler::recv_loop(InetSocket* DccpSocket, InetSocket* ConnSocket) {
	NOTICE_LOG(Log::sceNet, "Signaling Receiver Thread Started");
	// single-threaded receive path; no busy wait
	running_ = true;
	timeval tv{};
	tv.tv_sec = 1;      // timeout 1s
	tv.tv_usec = 0;
	while (running_) {
		if (!DccpSocket) {
			// Socket lost. Try to find it again!
			WARN_LOG(Log::sceNet, "Reaquiring DCCP Socket for Signaling Receiver Thread");
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			DccpSocket = g_socketManager.GetDCCP();
			continue;
		}
		if (!ConnSocket) {
			// Socket lost. Try to find it again!
			WARN_LOG(Log::sceNet, "Reaquiring P2P Socket for Signaling Receiver Thread");
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			ConnSocket = g_socketManager.FindSocketByPort(SCE_INTERNAL_PORT);
			continue;
		}
		u8 buf[1500];
		sockaddr_in src{};
		socklen_t slen = sizeof(src);
		int n = ConnSocket->recvfrom(reinterpret_cast<char*>(buf), sizeof(buf), 0,
			reinterpret_cast<sockaddr*>(&src), &slen);
		if (n < 0) {
			int errorCode = 0;
#if PPSSPP_PLATFORM(WINDOWS)
			errorCode = WSAGetLastError();
			if (errorCode == WSAEWOULDBLOCK) {
				fd_set readfds;
				FD_ZERO(&readfds);
				// FIXME: vsocks should technically point to the master socket for these
				FD_SET(DccpSocket->sock, &readfds);
				// Nothing wrong here, just check again after a short recess
				int ready = DccpSocket->select(&readfds, nullptr, nullptr, &tv);
				continue;
			}
#else
			errorCode = errno;
			if (errorCode == EAGAIN || errorCode == EWOULDBLOCK) {
				fd_set readfds;
				FD_ZERO(&readfds);
				FD_SET(DccpSocket->sock, &readfds);
				// Nothing wrong here, just check again after a short recess
				int ready = DccpSocket->select(&readfds, nullptr, nullptr, &tv);
				continue;
			}
#endif
			ERROR_LOG(Log::sceNet, "Error recvfrom on IPv4 P2P socket: returned %d, error code %d", n, errorCode);
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			continue;
		}
		if (n < VPORT_0_HEADER_SIZE) {
			ERROR_LOG(Log::sceNet, "Bad vport %d packet (no subset)", SCE_INTERNAL_PORT);
			continue;
		}

		// UPDATE: vport was moved to SocketManager, and stripped in recvfrom
		//const u16 vport_le = *reinterpret_cast<const u16_le*>(&buf[0]);
		const u8 subset = buf[0];
		const auto data_size = n - VPORT_0_HEADER_SIZE;
		std::vector<u8> vport_0_data;
		std::copy(std::begin(buf) + VPORT_0_HEADER_SIZE, std::begin(buf) + VPORT_0_HEADER_SIZE + data_size, std::back_inserter(vport_0_data));

		switch (subset) {
		case SUBSET_RPCN:
		{
			auto header = "recv_loop::RPCN " + ip2str(src.sin_addr) + ":" + std::to_string(ntohs(src.sin_port));
			INFO_HEXLOG(Log::sceNet, header.c_str(), reinterpret_cast<const char*>(vport_0_data.data()), vport_0_data.size(), 386);
			// push_back to rpcn_msgs
			{
				std::lock_guard lock(rpcn_mtx_);
				rpcn_msgs.push_back(std::move(vport_0_data));
			}
			rpcn_msg_cv.notify_all();
			if (np2RPCNThreadID)
				__KernelResumeThreadFromWait(np2RPCNThreadID, 0);
		}
		continue;
		case SUBSET_SIGNALING:
		{
			signaling_message msg;
			msg.src_addr = src.sin_addr.s_addr;
			msg.src_port = ntohs(src.sin_port);
			msg.data = std::move(vport_0_data);
			auto header = "recv_loop::SIGN " + ip2str(src.sin_addr) + ":" + std::to_string(ntohs(src.sin_port));
			INFO_HEXLOG(Log::sceNet, header.c_str(), reinterpret_cast<const char*>(msg.data.data()), msg.data.size(), 386);

			{
				std::lock_guard lock(sign_mtx_);
				sign_msgs.push_back(std::move(msg));
			}
			sign_msg_cv.notify_all();
			if (np2P2PThreadID)
				__KernelResumeThreadFromWait(np2P2PThreadID, 0);
			//dispatch_packet(msg);
		}
		continue;
		default:
			// Not for our internal system
			auto header = "recv_loop::UNHANDLED " + ip2str(src.sin_addr) + ":" + std::to_string(ntohs(src.sin_port));
			WARN_HEXLOG(Log::sceNet, header.c_str(), reinterpret_cast<const char*>(buf), n, 386);
			break;
		}
	}
}
#pragma endregion
