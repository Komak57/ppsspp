#include "Common/Net/SocketCompat.h"
#include "Core/HLE/NetInetConstants.h"
#include "Core/HLE/SocketManager.h"
#include "Core/HLE/sceNetInet.h"
#include <cstring> // Required by linux
#include <mutex>
#include "sceKernelThread.h"
#include "proAdhoc.h"
#include <Core/Net/SIGAgent.h>
#include "Common/TimeUtil.h"
#include "sceNp.h"

#define TIME_WAIT_US 60000000; // TCP waits 60 seconds
#define BASE_RTO_US 500000.0 // Wait 500ms before first retry
#define MAX_RETRIES 5
SocketManager g_socketManager;
static std::mutex g_socketMutex;  // TODO: Remove once the adhoc thread is gone
// Unique Signature for Tagged Packets
static constexpr u32 TAG_SIGNATURE = (static_cast<u32>('P') << 24 | static_cast<u32>('S') << 16 | static_cast<u32>('P') << 8 | static_cast<u32>('T'));
std::condition_variable trigger;

/* DOCUMENTATION:

 - PSP_NET_INET_SOCK_DCCP is being used as the "MASTER" P2P socket for all inbound and outbound traffic
 - PSP_NET_INET_SOCK_CONN_DGRAM is a virtual UDP port for various P2P channels
 - PSP_NET_INET_SOCK_PACKET is a TCP port for local, or virtual P2P traffic
*/
int SocketManager::NextUnusedSystemSocket() {
	for (int i = 0; i < MIN_VALID_INET_SOCKET; i++) {
		if (inetSockets_[i].state == SocketState::Unused) {
			return i;
		}
	}
	return -1;
}

int SocketManager::NextUnusedSocket() {
	for (int i = MIN_VALID_INET_SOCKET; i < ARRAY_SIZE(inetSockets_); i++) {
		if (inetSockets_[i].state == SocketState::Unused) {
			return i;
		}
	}
	return -1;
}
void SocketManager::exhaustEphemeralPort(u16 port) {
	u64 release_time = (u64)(time_now_d() * 1000000.0) + TIME_WAIT_US;
	exhausted_ports[port] = release_time;
}
// TODO: With the creation of PSN services available for newly developed PSP games,
//   this ratchet-based vport assignment could become problematic if abused.
//   It would be wiser to adhere to a POSIX "first available" vport instead.
u16 SocketManager::generateEphemeralPort() {
    std::lock_guard<std::mutex> guard(g_socketMutex);
	// Start port at 49152, and be 1 higher than all other existing vports
	u64 current_time_us = (u64)(time_now_d() * 1000000.0);
	
    for (auto it = exhausted_ports.begin(); it != exhausted_ports.end(); ) {
        if (current_time_us >= it->second) {
            it = exhausted_ports.erase(it); // Port is clean and ready for reuse
        } else {
            ++it;
        }
    }
	u16 _vport = 49152;
	auto sockets = g_socketManager.Sockets();
	for (int i = SocketManager::MIN_VALID_INET_SOCKET; i < SocketManager::VALID_INET_SOCKET_COUNT; i++) {
		if (sockets[i].state != SocketState::Unused && ntohs(sockets[i].src.virt.vport) >= _vport)
			_vport = ntohs(sockets[i].src.virt.vport) + 1;
		while (exhausted_ports.find(_vport) != exhausted_ports.end())
			_vport++;
		if (_vport > 65535) {
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(EADDRINUSE);
#else
			socket_errno = EADDRINUSE;
#endif
			ERROR_LOG(Log::sceNet, "Unable to allocate PORT, no free ports");
			return 0;
		}
	}
	return _vport;
}

u16 SocketManager::generateVPort() {
	// Start vport at 30000, and be 1 higher than all other existing vports
	u16 _vport = 30000;
	auto sockets = g_socketManager.Sockets();
	for (int i = SocketManager::MIN_VALID_INET_SOCKET; i < SocketManager::VALID_INET_SOCKET_COUNT; i++) {
		if (sockets[i].state != SocketState::Unused && ntohs(sockets[i].src.virt.vport) >= _vport)
			_vport = ntohs(sockets[i].src.virt.vport) + 1;
		if (_vport > 65535) {
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(EADDRINUSE);
#else
			socket_errno = EADDRINUSE;
#endif
			ERROR_LOG(Log::sceNet, "Unable to bind VPORT, no free ports");
			return 0;
		}
	}
	return _vport;
}

bool InetSocket::is_broadcast_enabled() const {
    // 1. Reconstruct the unique key for the Broadcast option
    uint64_t optkey = ((uint64_t)PSP_NET_INET_SOL_SOCKET << 32) | (uint32_t)PSP_NET_INET_SO_DCCP_BROADCAST;

    // 2. Look up the key in our Shadow Registry
    auto it = so_storage.find(optkey);
    if (it != so_storage.end()) {
        const std::vector<uint8_t>& data = it->second;

        // 3. Ensure we actually have data to read
        if (data.size() >= sizeof(int)) {
            // Interpret the first 4 bytes as an integer
            int val = *reinterpret_cast<const int*>(data.data());
            return val != 0;
        }
    }

    // Default to false if the option was never set or is malformed
    return false;
}

bool isLocalTarget(const u32 addr) {
	sockaddr_in local_addr{};
	getLocalIp(&local_addr);
	return (addr == htonl(INADDR_LOOPBACK) || 
				addr == htonl(INADDR_ANY) ||
				(addr == local_addr.sin_addr.s_addr));
}

// InetSocket now has mutex and condition variable, it can't be reset by {}
void InetSocket::clear() {
	// Basic types
    sock = INVALID_SOCKET;
    state = SocketState::Unused;
    domain = 0;
    protocol = 0;
    nonblocking = false;
	src.host = sockaddr_in{};
    memset(&dbg, 0, sizeof(dbg));

    // Virtual fields
    tcp_state = TCPState::Disconnected;
    type = 0;
	dst.host = sockaddr_in{};
	abortPending.exchange(false);

	// Clear the queue safely
	{
		std::lock_guard<std::mutex> queues(queue_lock);
		std::deque<VirtualPacket> empty;
		std::swap(rx_queue, empty);
	}
	{
		std::lock_guard<std::mutex> buffers(buffer_lock);
		std::map<u32, VirtualPacket> _empty;
		std::swap(rx_buffer, _empty);
		std::swap(tx_buffer, _empty);
		rx_seq = 0;
		tx_seq = 0;
	}
	{
		std::lock_guard<std::mutex> connections(conn_lock);
		pending_connections.clear();
	}
    
    // Reset pointers
    pending_connections.clear();
}

InetSocket *SocketManager::CreateSystemSocket(int *index, int *returned_errno, SocketState state, int domain, int type, int protocol) {
	_dbg_assert_(state != SocketState::Unused);

	int hostDomain = convertSocketDomainPSP2Host(domain);
	int hostType = convertSocketTypePSP2Host(type);
	int hostProtocol = convertSocketProtoPSP2Host(protocol);

	std::lock_guard<std::mutex> guard(g_socketMutex);
	InetSocket* inetSock = nullptr;
	{
		int i = NextUnusedSystemSocket();
		if (i < 0 || i > MIN_VALID_INET_SOCKET) {
			*returned_errno = ENOMEM; // or something..
			return nullptr;
		}

		*index = i;
		inetSock = inetSockets_ + i;

		// Destroy the old object and construct the appropriate derived type using placement new
		inetSock->~InetSocket();

#pragma push_macro("new")
#undef new
		inetSock = InetSocketFactory[type](inetSock, domain, protocol);
		_dbg_assert_msg_(sizeof(*inetSock) == sizeof(InetSocket), "Socket size mismatch!");
#pragma pop_macro("new")
	}

	switch (type) {
	case PSP_NET_INET_SOCK_DCCP: // Parent to all Virtual Sockets
		p2p_sock = inetSock;
	default: // Normal Socket
		break;
	}

	// Most Wanted creates a socket 2,3,1 for ICMP (Internet Control Message Protocol)
	// but SOCK_RAW may require elevated permissions
	if (inetSock->sock <= 0)
	{
		ERROR_LOG(Log::sceNet, "Ran out of socket handles! This is BAD.");
		_dbg_assert_(false);
		::closesocket(inetSock->sock);
		*index = 0;
		*returned_errno = ENOMEM; // or something..
		return nullptr;
	}
	inetSock->state = state;
	return inetSock;
}

InetSocket *SocketManager::CreateSocket(int *index, int *returned_errno, SocketState state, int domain, int type, int protocol) {
	_dbg_assert_(state != SocketState::Unused);

	int hostDomain = convertSocketDomainPSP2Host(domain);
	int hostType = convertSocketTypePSP2Host(type);
	int hostProtocol = convertSocketProtoPSP2Host(protocol);

	std::lock_guard<std::mutex> guard(g_socketMutex);
	InetSocket* inetSock = nullptr;
	{
		int i = NextUnusedSocket();
		if (i < 0 || i > VALID_INET_SOCKET_COUNT) {
			*returned_errno = ENOMEM; // or something..
			return nullptr;
		}

		*index = i;
		inetSock = inetSockets_ + i;

		// Clean up threads
		if (inetSock->thread.joinable())
			inetSock->thread.join();
		// Destroy the old object and construct the appropriate derived type using placement new
		inetSock->~InetSocket();
		
#pragma push_macro("new")
#undef new
		inetSock = InetSocketFactory[type](inetSock, domain, protocol);
#pragma pop_macro("new")
	}

	// Most Wanted creates a socket 2,3,1 for ICMP (Internet Control Message Protocol)
	// but SOCK_RAW may require elevated permissions
	if (inetSock->sock < 0) {
		ERROR_LOG(Log::sceNet, "Ran out of socket handles! This is BAD.");
		_dbg_assert_(false);
		closesocket(inetSock->sock);
		*index = 0;
		*returned_errno = ENOMEM; // or something..
		return nullptr;
	}
	inetSock->state = state;
	return inetSock;
}

InetSocket *SocketManager::AdoptSocket(int *index, SOCKET hostSocket, const InetSocket *derive) {
	std::lock_guard<std::mutex> guard(g_socketMutex);

	for (int i = MIN_VALID_INET_SOCKET; i < ARRAY_SIZE(inetSockets_); i++) {
		if (inetSockets_[i].state == SocketState::Unused) {
			*index = i;

			InetSocket *inetSock = inetSockets_ + i;
			
			// Clean up threads
			if (inetSock->thread.joinable())
				inetSock->thread.join();
			// Determine the type from derive and reconstruct with the correct derived class
			// This ensures the vtable matches the socket type
			inetSock->~InetSocket();
#pragma push_macro("new")
#undef new
		inetSock = InetSocketFactory[derive->type](inetSock, derive->domain, derive->protocol);
#pragma pop_macro("new")

			inetSock->sock = hostSocket;
			inetSock->state = derive->state;
			inetSock->domain = derive->domain;
			inetSock->type = derive->type;
			inetSock->protocol = derive->protocol;
			inetSock->nonblocking = derive->nonblocking;  // should we inherit blocking state?
			return inetSock;
		}
	}

	// No space? Return nullptr and let the caller handle it. Shouldn't ever happen.
	*index = 0;
	return nullptr;
}

void SocketManager::NetworkDemultiplexer(int* timeout) {
	// Process Remote to Local first
	while (P2PRecv()) {
		// auto start = std::chrono::steady_clock::now();
		// bool hadPacket = ;
		// auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
		// *timeout = (*timeout > elapsed) ? (*timeout - elapsed) : 0;
		// if (!hadPacket) return;
	}
	std::vector<std::pair<VirtualPacket, VirtualSockAddr>> outbuf; // <packet, dst.virt.port>
	// Process Each Local Once
	for (int i = MIN_VALID_INET_SOCKET; i < VALID_INET_SOCKET_COUNT; i++) {
		InetSocket* s = &inetSockets_[i];
		if (s->state != SocketState::Unused && s->type == PSP_NET_INET_SOCK_PACKET) {

			uint8_t expected_flag = 0;
			switch (s->tcp_state) {
				case TCPState::SynSent:			expected_flag = (p2ps_tcp_flags::SYN | p2ps_tcp_flags::TCP); break;
				case TCPState::SynReceived:		expected_flag = (p2ps_tcp_flags::SYN|p2ps_tcp_flags::ACK | p2ps_tcp_flags::TCP); break;
				case TCPState::Disconnected:	expected_flag = (p2ps_tcp_flags::FIN | p2ps_tcp_flags::TCP); break;
				default: break; // Established/Closed/etc. don't need control retransmit
			}

			// Find all sent packets
    		std::lock_guard<std::mutex> buffer(s->buffer_lock);
			for (auto& [seq, pkt] : s->tx_buffer) {
				// Skip if we've already received a response
				if (pkt.seq_ack)
					continue;
				// We're waiting for control packets
				if (expected_flag != 0 && pkt.header_flags != expected_flag)
					continue;
				// We're just not getting a response
				if (pkt.sent_count > MAX_RETRIES)
					continue;
				// Skip if it's too soon
				u64 now_us = (u64)(time_now_d() * BASE_RTO_US);
				if (now_us - pkt.last_sent_us < BASE_RTO_US)
					continue;

				auto vpkt = pkt.clone();
				std::string flags;
				if (vpkt.header_flags & p2ps_tcp_flags::SYN) flags += "SYN|";
				if (vpkt.header_flags & p2ps_tcp_flags::PSH) flags += "PSH|";
				if (vpkt.header_flags & p2ps_tcp_flags::ACK) flags += "ACK|";
				if (vpkt.header_flags & p2ps_tcp_flags::FIN) flags += "FIN|";
				if (vpkt.header_flags & p2ps_tcp_flags::RST) flags += "RST|";
				if (vpkt.header_flags & p2ps_tcp_flags::TCP) flags += "TCP|";
				if (!flags.empty()) flags.pop_back(); // strip trailing '|'

				WARN_LOG(Log::sceNet, "PACKET: Re-Sending %s at listening socket from %s:%u|%u to %s:%u|%u",
					flags.c_str(), inet_ntoa(pkt.src.virt.addr), ntohs(pkt.src.virt.port), ntohs(pkt.src.virt.vport), ip2str(s->dst.virt.addr).c_str(), ntohs(s->dst.virt.port), ntohs(s->dst.virt.vport));
				if (isLocalTarget(s->dst.virt.addr.s_addr)) {
					outbuf.push_back({std::move(vpkt), s->dst});
					// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
					// g_socketManager.vBroadcast(std::move(vpkt), htons(s->dst.virt.vport));
					pkt.last_sent_us = now_us;
					pkt.sent_count++;
				} else {
					auto [_len, _data] = vpkt.Pack(s->dst);
					auto p2p_sock = g_socketManager.GetP2PSocket();
					// Physical delivery goes to the peer's real UDP endpoint (game vport)
					sockaddr_in phys = s->dst.host;
					phys.sin_port = s->dst.virt.vport;
					int ret = ::sendto(p2p_sock->sock, _data.get(), _len, 0, (struct sockaddr*)&phys, sizeof(sockaddr_in));
					if (ret < 0) {
						ERROR_LOG(Log::sceNet, "SOCK_PACKET connect: Failed to send ACK");
					} else {
						pkt.last_sent_us = now_us;
					}
					pkt.sent_count++;
				}
			}
			std::lock_guard<std::mutex> connections(s->conn_lock);
			for (auto conn : s->pending_connections) {
				uint8_t expected_flag = 0;
				switch (conn->tcp_state) {
					case TCPState::SynSent:			expected_flag = (p2ps_tcp_flags::SYN | p2ps_tcp_flags::TCP); break;
					case TCPState::SynReceived:		expected_flag = (p2ps_tcp_flags::SYN|p2ps_tcp_flags::ACK | p2ps_tcp_flags::TCP); break;
					case TCPState::Disconnected:	expected_flag = (p2ps_tcp_flags::FIN | p2ps_tcp_flags::TCP); break;
					default: break; // Established/Closed/etc. don't need control retransmit
				}

				// Find all sent packets
				std::lock_guard<std::mutex> buffers(conn->buffer_lock);
				for (auto& [seq, pkt] : conn->tx_buffer) {
					// Skip if we've already received a response
					if (pkt.seq_ack)
						continue;
					// We're waiting for control packets
					if (expected_flag != 0 && pkt.header_flags != expected_flag)
						continue;
					// We're just not getting a response
					if (pkt.sent_count > MAX_RETRIES)
						continue;
					// Skip if it's too soon
					u64 now_us = (u64)(time_now_d() * BASE_RTO_US);
					if (now_us - pkt.last_sent_us < BASE_RTO_US)
						continue;

					auto vpkt = pkt.clone();
					std::string flags;
					if (vpkt.header_flags & p2ps_tcp_flags::SYN) flags += "SYN|";
					if (vpkt.header_flags & p2ps_tcp_flags::PSH) flags += "PSH|";
					if (vpkt.header_flags & p2ps_tcp_flags::ACK) flags += "ACK|";
					if (vpkt.header_flags & p2ps_tcp_flags::FIN) flags += "FIN|";
					if (vpkt.header_flags & p2ps_tcp_flags::RST) flags += "RST|";
					if (vpkt.header_flags & p2ps_tcp_flags::TCP) flags += "TCP|";
					if (!flags.empty()) flags.pop_back(); // strip trailing '|'

					WARN_LOG(Log::sceNet, "PACKET: Re-Sending %s at listening socket from %s:%u|%u to %s:%u|%u",
						flags.c_str(), inet_ntoa(pkt.src.virt.addr), ntohs(pkt.src.virt.port), ntohs(pkt.src.virt.vport), ip2str(conn->dst.virt.addr).c_str(), ntohs(conn->dst.virt.port), ntohs(conn->dst.virt.vport));
					if (isLocalTarget(conn->dst.virt.addr.s_addr)) {
						outbuf.push_back({std::move(vpkt), conn->dst});
						// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
						// g_socketManager.vBroadcast(std::move(vpkt), htons(conn->dst.virt.vport));
						pkt.last_sent_us = now_us;
						pkt.sent_count++;
					} else {
						auto [_len, _data] = vpkt.Pack(conn->dst);
						auto p2p_sock = g_socketManager.GetP2PSocket();
						// Physical delivery goes to the peer's real UDP endpoint (game vport)
						sockaddr_in phys = conn->dst.host;
						phys.sin_port = conn->dst.virt.vport;
						int ret = ::sendto(p2p_sock->sock, _data.get(), _len, 0, (struct sockaddr*)&phys, sizeof(sockaddr_in));
						if (ret < 0) {
							ERROR_LOG(Log::sceNet, "SOCK_PACKET connect: Failed to send ACK");
						} else {
							pkt.last_sent_us = now_us;
						}
						pkt.sent_count++;
					}
				}
			}
		}
	}
	for (auto& [vpkt, dest] : outbuf) {
        g_socketManager.vBroadcast(std::move(vpkt), dest);
    }
}

bool SocketManager::P2PRecv() {
	// Clear the error
#if PPSSPP_PLATFORM(WINDOWS)
	SetLastError(0);
#else
	socket_errno = 0;
#endif

	char data[0x3000]; // Supplied by many psp buffers
	sockaddr_in _from{};
	socklen_t _fromlen = sizeof(_from);
	int ret = ::recvfrom(p2p_sock->sock, data, sizeof(data), 0, reinterpret_cast<sockaddr*>(&_from), &_fromlen);
	if (ret <= 0) {
		// This is normal if no packet is available (non-blocking mode)
		return false;
	}
	
	// Extract VPORT_HEADER (first 3 bytes: vport + flags)
	if (ret < VPORT_HEADER_SIZE) {
		INFO_LOG(Log::sceNet, "RouteDCCP: Packet too small (%d bytes) from %s:%u, ignoring", 
			ret, inet_ntoa(_from.sin_addr), ntohs(_from.sin_port));
		return false; // Packet too small, ignore
	}

	VPORT_HEADER header;
	memcpy(&header, data, VPORT_HEADER_SIZE);
	
	int i = VPORT_HEADER_SIZE;
	// Generate the transmission vpacket
	VirtualPacket vpkt;
	vpkt.seq_id = 0;
	// Seed src with the REAL transport endpoint FIRST: src.host and src.virt alias
	// the same union, so this must happen before the ext-header parse below
	// overwrites port/vport with the sender's game-space keys (addr stays real).
	vpkt.src.host = _from;
	vpkt.src.host.sin_family = AF_INET;
	// vport 0 (RPCN/signaling) is matched on the 3-byte header ALONE - no extended
	// header, no seq_id. Only p2p packets (dest != 0) carry more.
	if (header.dest != 0) {
		if ((header.flags & p2ps_tcp_flags::TCP) != 0 &&
			ret - i >= VPKT_HEADER_SIZE + (int)sizeof(vpkt.seq_id)) {
			// RELIABLE p2p: extended header with full game-space addressing.
			// The dest game port is the VPORT_HEADER key, not in the ext block.
			memcpy(&vpkt.src.virt.port, data + i, 2); i += 2;
			memcpy(&vpkt.src.virt.vport, data + i, 2); i += 2;
			vpkt.dst.virt.port = header.dest;
			memcpy(&vpkt.dst.virt.vport, data + i, 2); i += 2;
			uint32_t net_seq_id = 0;
			memcpy(&net_seq_id, data + i, sizeof(net_seq_id));
			vpkt.seq_id = ntohl(net_seq_id);
			i += sizeof(net_seq_id);
		} else if ((header.flags & p2ps_tcp_flags::TCP) == 0 && ret - i >= (int)sizeof(vpkt.seq_id)) {
			uint32_t net_seq_id = 0;
			memcpy(&net_seq_id, data + i, sizeof(net_seq_id));
			vpkt.seq_id = ntohl(net_seq_id);
			i += sizeof(net_seq_id);
		}
	}
	vpkt.len = ret - i;
	if (vpkt.len > 0) {
		vpkt.data = std::make_unique<char[]>(vpkt.len);
		memcpy(vpkt.data.get(), data+i, vpkt.len);
	}
	vpkt.header_flags = header.flags;
	// Add timestamp for TTL tracking
	vpkt.enqueue_time_us = (u64)(time_now_d() * 1000000.0);

	// Log incoming packet details (convert vport from network to host byte order for
	// display). For TCP packets show the sender's GAME endpoint from the ext header;
	// the real sockaddr's sin_zero always displays as vport 0.
	if ((header.flags & p2ps_tcp_flags::TCP) != 0 && header.dest != 0)
		INFO_LOG(Log::sceNet, "RouteDCCP: Received %d bytes from %s:%u|%u -> peer %u|%u (flags=0x%02x(=%d))",
			ret, ip2str(vpkt.src.virt.addr).c_str(), ntohs(vpkt.src.virt.port), ntohs(vpkt.src.virt.vport), ntohs(vpkt.dst.virt.port), ntohs(vpkt.dst.virt.vport), header.flags, header.flags & 0xFF);
	else
		INFO_LOG(Log::sceNet, "RouteDCCP: Received %d bytes from %s:%u|%u -> vport %d (flags=0x%02x(=%d))",
			ret, ip2str(vpkt.src.virt.addr).c_str(), ntohs(vpkt.src.virt.port), ntohs(vpkt.src.virt.vport), ntohs(header.dest), header.flags, header.flags & 0xFF);

	VirtualSockAddr dest{};
	getLocalIp(&dest.host);
	if ((header.flags & p2ps_tcp_flags::TCP) != 0 && header.dest != 0) {
		// Flip back to game-space: the datagram physically arrived on our real UDP
		// port (3658), but it's addressed to the game endpoint in the ext header.
		dest.virt.port = vpkt.dst.virt.port;
		dest.virt.vport = vpkt.dst.virt.vport;
	} else {
		dest.virt.port = 0;
		dest.virt.vport = header.dest;
	}
	g_socketManager.vBroadcast(std::move(vpkt), dest);

	return true;
}

bool SocketManager::Close(InetSocket *inetSocket) {
	_dbg_assert_(inetSocket->state != SocketState::Unused);

	int ret = inetSocket->closesocket();
	if (ret != 0) {
		ERROR_LOG(Log::sceNet, "closesocket(%d) failed", inetSocket->sock);
		return false;
	}
	inetSocket->state = SocketState::Unused;
	inetSocket->sock = 0;
	return true;
}

bool SocketManager::GetInetSocket(int sock, InetSocket **inetSocket) {
	std::lock_guard<std::mutex> guard(g_socketMutex);
	if (/*sock < MIN_VALID_INET_SOCKET || */sock >= ARRAY_SIZE(inetSockets_) || inetSockets_[sock].state == SocketState::Unused) {
		*inetSocket = nullptr;
		return false;
	}
	*inetSocket = inetSockets_ + sock;
	return true;
}

// Simplified mappers, only really useful in select/poll
SOCKET SocketManager::GetHostSocketFromInetSocket(int sock) {
	std::lock_guard<std::mutex> guard(g_socketMutex);
	if (sock < MIN_VALID_INET_SOCKET || sock >= ARRAY_SIZE(inetSockets_) || inetSockets_[sock].state == SocketState::Unused) {
		//_dbg_assert_(false); // Triggers error when quitting Np2 Matching
		return -1;
	}
	if (sock == 0) {
		// Map 0 to 0, special case.
		return 0;
	}
	return inetSockets_[sock].sock;
}

void SocketManager::CloseAll() {
	for (auto &sock : inetSockets_) {
		if (sock.state != SocketState::Unused) {
			if (sock.thread.joinable())
        		sock.thread.join();
			if (sock.type == PSP_NET_INET_SOCK_CONN_DGRAM)
				sock.closesocket();
			else
				closesocket(sock.sock);
		}
		sock.state = SocketState::Unused;
		sock.sock = 0;
	}
}

int SocketManager::vBroadcast(VirtualPacket&& vpkt, VirtualSockAddr dest) {
    int delivered_count = 0;

	// RELIABLE (TCP-flagged) packets are strictly addressed - each PacketSocket is
	// a pseudo-server keyed by its game port/vport, so deliver to exactly ONE
	// socket: an established/connecting socket whose peer matches the packet's
	// game-space source, or failing that the listening socket that owns the
	// destination endpoint (for SYN and pre-accept handshake traffic).
	if ((vpkt.header_flags & p2ps_tcp_flags::TCP) != 0) {
		InetSocket* listener = nullptr;
		InetSocket* exact = nullptr;
		for (int i = 0; i < SocketManager::VALID_INET_SOCKET_COUNT; i++) {
			InetSocket* target_sock = &inetSockets_[i];
			if (!target_sock || target_sock->state == SocketState::Unused)
				continue;
			if (target_sock->p2p_mode != p2p_type::RELIABLE)
				continue;
			// The socket must own the destination game endpoint (port 12000 / vport 3658,
			// or the connector's ephemeral port for replies)
			if (target_sock->src.virt.port != dest.virt.port)
				continue;
			if (target_sock->src.virt.vport != dest.virt.vport)
				continue;
			if (target_sock->src.virt.addr.s_addr != INADDR_ANY && target_sock->src.virt.addr.s_addr != dest.virt.addr.s_addr)
				continue;
			if (target_sock->tcp_state == TCPState::Listening) {
				if (!listener)
					listener = target_sock;
				continue;
			}
			// Connecting/connected: the packet's game-space source must be our peer
			if (target_sock->dst.virt.addr.s_addr != INADDR_ANY && target_sock->dst.virt.addr.s_addr != vpkt.src.host.sin_addr.s_addr)
				continue;
			if (target_sock->dst.virt.port != vpkt.src.virt.port)
				continue;
			if (target_sock->dst.virt.vport != vpkt.src.virt.vport)
				continue;
			exact = target_sock;
			break;
		}
		InetSocket* target_sock = exact ? exact : listener;
		if (!target_sock) {
			ERROR_LOG(Log::sceNet, "RouteDCCP: No RELIABLE socket for %s:%u|%u -> %u|%u (flags=0x%02x)",
				inet_ntoa(vpkt.src.host.sin_addr), ntohs(vpkt.src.virt.port), ntohs(vpkt.src.virt.vport),
				ntohs(dest.virt.port), ntohs(dest.virt.vport), vpkt.header_flags);
			return 0;
		}
		INFO_LOG(Log::sceNet, "RouteDCCP: DELIVERING %i bytes from %s:%u|%u to port %s:%u|%u (type=%d)",
			(int)vpkt.len, inet_ntoa(vpkt.src.host.sin_addr), ntohs(vpkt.src.virt.port), ntohs(vpkt.src.virt.vport),
			ip2str(target_sock->src.virt.addr).c_str(), ntohs(target_sock->src.virt.port), ntohs(target_sock->src.virt.vport), target_sock->type);
		target_sock->enqueue_packet(vpkt.clone());
		target_sock->Process_Reliable();
		return 1;
	}

    // Match sockets by vport (port-based routing instead of subscriptions)
    for (int i = 0; i < SocketManager::VALID_INET_SOCKET_COUNT; i++) {
        InetSocket* target_sock = &inetSockets_[i];

        // Skip unused sockets
        if (!target_sock || target_sock->state == SocketState::Unused) {
            continue;
        }

		{
			if (target_sock->p2p_mode != p2p_type::UNRELIABLE)
				continue;

			// Matches endpoint address
			if ((target_sock->src.virt.addr.s_addr != INADDR_ANY && target_sock->src.virt.addr.s_addr != dest.virt.addr.s_addr))
				continue;
			// Match endpoint port (3658)
			if (dest.virt.port != 0 && target_sock->src.virt.port != dest.virt.port)
				continue;
			// Matches endpoint vport (0)
			if (target_sock->src.virt.vport != dest.virt.vport)
				continue;

			DEBUG_LOG(Log::sceNet, "RouteDCCP: Processing socket dst.virt.port %d (type=%d)", 
				target_sock->src.virt.vport, target_sock->type);

			INFO_LOG(Log::sceNet, "RouteDCCP: DELIVERING %i bytes from %s:%u|%u to port %s:%u|%u (type=%d)", 
				(int)vpkt.len, inet_ntoa(vpkt.src.virt.addr), ntohs(vpkt.src.virt.port), ntohs(vpkt.src.virt.vport), ip2str(target_sock->src.virt.addr).c_str(), ntohs(target_sock->src.virt.port), ntohs(target_sock->src.virt.vport), target_sock->type);
			
			target_sock->enqueue_packet(vpkt.clone());
			delivered_count++;
			
			if (target_sock->Process_Unreliable()) {
				continue;
			}
		}
        
		DEBUG_LOG(Log::sceNet, "RouteDCCP: NOT delivering to vport %d (deliver_data=false)", ntohs(target_sock->src.virt.vport));
    }
    
    if (delivered_count > 0) {
        DEBUG_LOG(Log::sceNet, "RouteDCCP: Total delivered to %d subscribers matching  %s:%u|%u", delivered_count, ip2str(dest.virt.addr).c_str(), ntohs(dest.virt.port), ntohs(dest.virt.vport));
    } else {
        ERROR_LOG(Log::sceNet, "RouteDCCP: Total delivered to %d subscribers matching  %s:%u|%u", delivered_count, ip2str(dest.virt.addr).c_str(), ntohs(dest.virt.port), ntohs(dest.virt.vport));
	}

    return delivered_count;
}

const char *SocketStateToString(SocketState state) {
	switch (state) {
	case SocketState::Unused: return "unused";
	case SocketState::UsedNetInet: return "netInet";
	case SocketState::UsedProAdhoc: return "proAdhoc";
	default:
		return "N/A";
	}
}

// ============================================================================
// Base Socket Class
// Default fallback functions for things not yet implemented by other sockets
// ============================================================================
int InetSocket::send(const char* buf, int len, int flags) { errno = EOPNOTSUPP; return -1; }
int InetSocket::sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) { errno = EOPNOTSUPP; return -1; }
int InetSocket::recv(char* buf, int len, int flags) { errno = EOPNOTSUPP; return -1; }
int InetSocket::recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) { errno = EOPNOTSUPP; return -1; }
int InetSocket::setsockopt(int level, int optname, int optval, socklen_t optlen) {
	const char* host_level_srt = inetSockoptLevel2str(level).c_str();
	const std::string host_optname_str = inetSockoptName2str(optname, level);

	// save the flag for lookup
	uint64_t optkey = ((uint64_t)level << 32) | (uint32_t)optname;
	auto& so_flags = so_storage[optkey];
	const uint8_t* optval_ptr = reinterpret_cast<const uint8_t*>(&optval);
	so_flags.assign(optval_ptr, 
                 optval_ptr + optlen);

	// Handle PSP-specific socket options
	if (level == PSP_NET_INET_SOL_SOCKET) {
		switch (optname) {
		case PSP_NET_INET_SO_NBIO:// TODO: Ignoring SO_NBIO/SO_NONBLOCK flag if we always use non-bloking mode (ie. simulated blocking mode)
			{
				nonblocking = optval == 1;
				// return hleLogWarning(Log::sceNet, 0, "%s emulated", host_optname_str.c_str());

				// WARN_LOG(Log::sceNet, "%s emulated", host_optname_str.c_str());
				changeBlockingMode(sock, nonblocking);
			}
			return hleLogWarning(Log::sceNet, 0, "%s emulated", host_optname_str.c_str());
			// break;
		case 0x1022:// TODO: Ignoring SO_NOSIGPIPE flag to prevent crashing PPSSPP (not sure if PSP has NOSIGPIPE or not tho, defined as 0x1022 on Darwin)
			return hleLogWarning(Log::sceNet, 0, "%s not supported, ignoring", host_optname_str.c_str());
		case PSP_NET_INET_SO_DCCP_BROADCAST:
			return hleLogWarning(Log::sceNet, 0, "%s not supported, ignoring", host_optname_str.c_str());
		case PSP_NET_INET_SO_DCCP_LINGER:
			return hleLogWarning(Log::sceNet, 0, "%s not supported, ignoring", host_optname_str.c_str());
		case PSP_NET_INET_SO_RCVTIMEO:
		case PSP_NET_INET_SO_SNDTIMEO:
		{
			timeval tval{};
			socklen_t tvlen = sizeof(tval);

			int retval = getsockopt(convertSockoptLevelPSP2Host(level), convertSockoptNamePSP2Host(optname, level), (char*)&tval, &tvlen);
			//retval = getsockopt(inetSock->sock, convertSockoptLevelPSP2Host(level), convertSockoptNamePSP2Host(optname, level), (char*)&tval, &tvlen);
			if (retval != SOCKET_ERROR) {
				u64_le val = (tval.tv_sec * 1000000LL) + tval.tv_usec;
				memcpy(&optval, &val, std::min(static_cast<socklen_t>(sizeof(val)), std::min(static_cast<socklen_t>(sizeof(optval)), optlen)));
			}
			return hleLogWarning(Log::sceNet, 0, "%s emulated", host_optname_str.c_str());
		}
		default:
			break;  // Fall through to host socket options
		}
	}
	int host_level = convertSockoptLevelPSP2Host(level);
	int host_optname = convertSockoptNamePSP2Host(optname, level);

	int ret = ::setsockopt(sock, host_level, host_optname, reinterpret_cast<char*>(&optval), optlen);
	if (ret < 0) {
		WARN_LOG(Log::sceNet, "InetSocket::setsockopt: failed for level=%d optname=%d, accepting gracefully", level, optname);
		return 0;
	}
	return ret;
}
int InetSocket::setsockopt(int level, int optname, const char* optval, socklen_t optlen) {
	const char* host_level_srt = inetSockoptLevel2str(level).c_str();
	const std::string host_optname_str = inetSockoptName2str(optname, level);

	// save the flag for lookup
	uint64_t optkey = ((uint64_t)level << 32) | (uint32_t)optname;
	auto& so_flags = so_storage[optkey];
	const uint8_t* optval_ptr = reinterpret_cast<const uint8_t*>(&optval);
	so_flags.assign(optval_ptr, 
                 optval_ptr + optlen);

	// Handle PSP-specific socket options
	if (level == PSP_NET_INET_SOL_SOCKET) {
		switch (optname) {
		case PSP_NET_INET_SO_NBIO:
			{
				if (so_flags.size() >= sizeof(int)) {
					int flag = *reinterpret_cast<const int*>(so_flags.data());
					nonblocking = (flag != 0);
				} else if (!so_flags.empty()) {
					nonblocking = (so_flags[0] != 0);
				}

				WARN_LOG(Log::sceNet, "%s emulated", host_optname_str.c_str());
			}
			return hleLogWarning(Log::sceNet, 0, "%s emulated", host_optname_str.c_str());
			// break;
		case PSP_NET_INET_SO_BROADCAST:
			return hleLogWarning(Log::sceNet, 0, "%s not supported, ignoring", host_optname_str.c_str());
		case PSP_NET_INET_SO_NOSIGPIPE:
			return hleLogWarning(Log::sceNet, 0, "NOSIGPIPE should never be modified (should always be off)");
		case PSP_NET_INET_SO_RCVBUF:
		case PSP_NET_INET_SO_SNDBUF:
			// TODO: For SOCK_STREAM max buffer size is 8 Mb on BSD, while max SOCK_DGRAM is 65535 minus the IP & UDP Header size
			if (*(const u32*)optval > (u32)(8 * 1024 * 1024)) {
				if (type == PSP_NET_INET_SOCK_PACKET) {
#if PPSSPP_PLATFORM(WINDOWS)
					SetLastError(ENOBUFS);
#else
					socket_errno = ENOBUFS;
#endif
				} else {
#if PPSSPP_PLATFORM(WINDOWS)
					SetLastError(EINVAL);
#else
					socket_errno = EINVAL;
#endif
				}
				return hleLogError(Log::sceNet, -1, "buffer size too large?");
			}
			return hleLogWarning(Log::sceNet, 0, "%s emulated", host_optname_str.c_str());
		case PSP_NET_INET_SO_ONESBCAST:
			return hleLogWarning(Log::sceNet, 0, "%s not supported, ignoring", host_optname_str.c_str());
		case PSP_NET_INET_SO_RCVTIMEO:
		case PSP_NET_INET_SO_SNDTIMEO:
			{
				timeval tval{};
				tval.tv_sec = *(const u32*)optval / 1000000; // seconds
				tval.tv_usec = (*(const u32*)optval % 1000000); // microseconds
				
				optval = (char*)&tval;
				optlen = sizeof(tval);
				break;
			}
		case PSP_NET_INET_SO_DCCP_BROADCAST:
			return hleLogWarning(Log::sceNet, 0, "%s not supported, ignoring", host_optname_str.c_str());
		case PSP_NET_INET_SO_DCCP_LINGER:
			return hleLogWarning(Log::sceNet, 0, "%s not supported, ignoring", host_optname_str.c_str());
		default:
			break;  // Fall through to host socket options
		}
	}
	int host_level = convertSockoptLevelPSP2Host(level);
	int host_optname = convertSockoptNamePSP2Host(optname, level);

	int ret = ::setsockopt(sock, host_level, host_optname, const_cast<char*>(optval), optlen);
	if (ret < 0) {
		return hleLogWarning(Log::sceNet, 0, "InetSocket::setsockopt: failed for level=%d optname=%d, accepting gracefully", level, optname);
	}
	return ret;
}
int InetSocket::getsockopt(int level, int optname, char* optval, socklen_t* optlen) {
	if (!optval || !optlen) return -1;

	// SPECIAL CASE: SO_ERROR for hybrid sockets needs custom handling
	if (level == PSP_NET_INET_SOL_SOCKET && optname == PSP_NET_INET_SO_ERROR && 
	    p2p_mode != p2p_type::DISABLED) {
		// For hybrid sockets, check if connection succeeded locally
		if (tcp_state == TCPState::Established) {
			// Local connection succeeded, return 0
			if (*optlen >= sizeof(int)) {
				*(int*)optval = 0;
				*optlen = sizeof(int);
				// Clear our cached error too
				uint64_t optkey = ((uint64_t)level << 32) | (uint32_t)optname;
				so_storage.erase(optkey);
				return 0;
			}
		}
		// Fall through to normal handling for other states
	}
    // 1. Check our Internal Shadow Registry first
    uint64_t optkey = ((uint64_t)level << 32) | (uint32_t)optname;
    
    if (so_storage.count(optkey)) {
        auto& cached_data = so_storage[optkey];
        
        // Copy only what fits in the caller's buffer to prevent overflows
        socklen_t copy_len = std::min(*optlen, (socklen_t)cached_data.size());
        memcpy(optval, cached_data.data(), copy_len);
        
        // Update the caller on how many bytes were actually written
        *optlen = copy_len;

		// SO_ERROR should clear itself after being read
		if (level == PSP_NET_INET_SOL_SOCKET && optname == PSP_NET_INET_SO_ERROR) {
			so_storage.erase(optkey);
		}
        return 0;
    }

    // 2. Fallback: Ask the Host OS
    int host_level = convertSockoptLevelPSP2Host(level);
    int host_optname = convertSockoptNamePSP2Host(optname, level);

    if (host_optname != -1) {
        int ret = ::getsockopt(sock, host_level, host_optname, reinterpret_cast<char*>(optval), optlen);
        
        // If the host call succeeds, cache it for next time
        if (ret == 0) {
			// Cache it for next time, but SO_ERROR shouldn't be cached
			// since it clears itself
			if (!(level == PSP_NET_INET_SOL_SOCKET && optname == PSP_NET_INET_SO_ERROR)) {
				auto& so_flags = so_storage[optkey];
				so_flags.assign(reinterpret_cast<const uint8_t*>(optval), 
					         reinterpret_cast<const uint8_t*>(optval) + *optlen);
			}
        }
        return ret;
    }

    // 3. Last Resort: Silent Failure
    DEBUG_LOG(Log::sceNet, "getsockopt: Option level=%d name=%d not found in cache or host", level, optname);
    return -1;
}
int InetSocket::bind(SceNetInetSockaddr* name, int namelen) { errno = EOPNOTSUPP; return -1; }
int InetSocket::connect(SceNetInetSockaddr* name, int namelen) { errno = EOPNOTSUPP; return -1; }
int InetSocket::listen(int backlog) { errno = EOPNOTSUPP; return -1; }
int InetSocket::accept(sockaddr* addr, socklen_t* addrlen) { errno = EOPNOTSUPP; return -1; }
int InetSocket::shutdown(int how) { errno = EOPNOTSUPP; return -1; }
void InetSocket::enqueue_packet(VirtualPacket packet) {
	std::lock_guard<std::mutex> queue(queue_lock);
	// Add timestamp for TTL tracking
	packet.enqueue_time_us = (u64)(time_now_d() * 1000000.0);
	rx_queue.push_back(std::move(packet));
	DEBUG_LOG(Log::sceNet, "Enqueued packet for vport %d (queue size: %zu)", ntohs(src.virt.vport), rx_queue.size());
}
bool InetSocket::dequeue_packet(VirtualPacket& packet, bool seq) {
	std::lock_guard<std::mutex> buffers(buffer_lock);
	const u64 MAX_PACKET_AGE_US = 30000000;  // 30 seconds
	
	while (((seq && (rx_buffer.find(rx_seq + 1) != rx_buffer.end())) || !seq) && !rx_buffer.empty()) {
		if (seq)
			rx_seq++;
		else
			rx_seq = rx_buffer.begin()->first;
		packet = std::move(rx_buffer.find(rx_seq)->second);
		rx_buffer.erase(rx_seq);
		
		// Check packet TTL
		u64 current_time_us = (u64)(time_now_d() * 1000000.0);
		u64 packet_age_us = current_time_us - packet.enqueue_time_us;
		
		if (packet_age_us > MAX_PACKET_AGE_US) {
            WARN_LOG(Log::sceNet, "dequeue_stream: Receiving stale packet (age: %.2f seconds)", (float)packet_age_us / 1000000.0f);
		}
		
		DEBUG_LOG(Log::sceNet, "Dequeued packet from vport %d (queue size: %zu)", ntohs(src.virt.vport), rx_buffer.size());
		return true;
	}
	
	return false;  // Queue is empty
}
int InetSocket::dequeue_stream(char* buf, int len, sockaddr_in* out_addr, bool seq) {
	std::lock_guard<std::mutex> buffers(buffer_lock);
    const u64 MAX_PACKET_AGE_US = 30000000;  // 30 seconds
    u64 current_time_us = (u64)(time_now_d() * 1000000.0);
    
    int total_copied = 0;
    bool target_locked = false;
    sockaddr_in target_addr{};

	if ((seq && (rx_buffer.find(rx_seq + 1) == rx_buffer.end()) || !seq) && !rx_buffer.empty())
		WARN_LOG(Log::sceNet, "dequeue_stream: Missing next packet at %d", rx_seq+1);
    
    while (total_copied < len && (((seq && (rx_buffer.find(rx_seq + 1) != rx_buffer.end())) || !seq) && !rx_buffer.empty())) {
        // Peek at the front packet (do NOT pop yet)
		u32 seq_id = (seq? rx_seq + 1 : rx_buffer.begin()->first);
        VirtualPacket& peek_pkt = rx_buffer.find(seq_id)->second;
        
        // Check packet TTL
        u64 packet_age_us = current_time_us - peek_pkt.enqueue_time_us;
        if (packet_age_us > MAX_PACKET_AGE_US) {
            WARN_LOG(Log::sceNet, "dequeue_stream: Receiving stale packet (age: %.2f seconds)", (float)packet_age_us / 1000000.0f);
        }

        // Lock onto the first valid packet's source address
        if (!target_locked) {
            target_addr = peek_pkt.src.host;
            target_locked = true;
            if (out_addr) {
                *out_addr = target_addr;
            }
        } else {
            // If we are continuing to fill the buffer, ensure this next packet is from the SAME source
            if (peek_pkt.src.virt.addr.s_addr != target_addr.sin_addr.s_addr ||
                peek_pkt.src.virt.port != target_addr.sin_port ||
				(peek_pkt.src.host.sin_zero[0] != target_addr.sin_zero[0] || peek_pkt.src.host.sin_zero[1] != target_addr.sin_zero[1])) {
                
                DEBUG_LOG(Log::sceNet, "dequeue_stream: Source mismatch detected. Halting coalescing. (Expected %s:%u, got %s:%u)",
                    inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port),
                    inet_ntoa(peek_pkt.src.virt.addr), ntohs(peek_pkt.src.virt.port));
                break; // Stop coalescing and leave this packet in the queue
            }
        }
        
        // Now we know we are consuming this packet (at least partially), so pop it
		rx_seq++;
        VirtualPacket packet = std::move(peek_pkt);
        rx_buffer.erase(seq_id);
        
        int available_in_pkt = packet.len;
        int room_in_buf = len - total_copied;
        int bytes_to_copy = std::min(available_in_pkt, room_in_buf);
        
        // Copy data to the caller's buffer
        if (bytes_to_copy > 0 && packet.data != nullptr) {
            memcpy(buf + total_copied, packet.data.get(), bytes_to_copy);
            total_copied += bytes_to_copy;
        }
        
        // If we didn't consume the whole packet, push the remainder back to the FRONT
        if (bytes_to_copy < available_in_pkt) {
            VirtualPacket remainder;
            int remaining_len = available_in_pkt - bytes_to_copy;
            
            remainder.data = std::make_unique<char[]>(remaining_len);
            memcpy(remainder.data.get(), packet.data.get() + bytes_to_copy, remaining_len);
            
            remainder.len = remaining_len;
            remainder.header_flags = packet.header_flags;
            remainder.src.virt = packet.src.virt;
            remainder.enqueue_time_us = packet.enqueue_time_us; // Preserve TTL
            
			rx_buffer[seq_id] = std::move(remainder);
			rx_seq--; // mark this as the next packet to receive
            break; // Buffer is full
        }
    }
    
    return total_copied;
}
bool InetSocket::has_pending_data(bool seq) const {
	std::lock_guard<std::mutex> buffers(buffer_lock);
	return (((seq && ((rx_buffer.find(rx_seq + 1) != rx_buffer.end()) || tcp_state == TCPState::CloseWait)) || !seq) && !rx_buffer.empty());
}
bool InetSocket::set_pending_connection(InetSocket* conn) {
	std::lock_guard<std::mutex> connections(conn_lock);
	if ((int)pending_connections.size() >= backlog) {
		ERROR_LOG(Log::sceNet, "Backlog full, dropping SYN from %s:%u", ip2str(conn->dst.virt.addr.s_addr).c_str(), ntohs(conn->dst.virt.port));
		delete conn;
		return false;
	}
	// Check for an existing connection. The game port is the distinguishing key -
	// every p2p socket shares the same vport (3658), so it alone can't identify a
	// connector (two joins from one IP, e.g. multi-instance, differ only by port).
	for (auto& existing : pending_connections) {
        if (existing->dst.virt.addr.s_addr == conn->dst.virt.addr.s_addr &&
            existing->dst.virt.port == conn->dst.virt.port &&
            existing->dst.virt.vport == conn->dst.virt.vport) {
			ERROR_LOG(Log::sceNet, "Request already exists, dropping SYN from %s:%u", ip2str(conn->dst.virt.addr.s_addr).c_str(), ntohs(conn->dst.virt.vport));
            delete conn; // discard the duplicate
            return false;
        }
    }

	pending_connections.push_back(conn);
	DEBUG_LOG(Log::sceNet, "Set pending connection on vport %d from %s:%u",
		ntohs(src.virt.vport), ip2str(conn->dst.virt.addr.s_addr).c_str(), ntohs(conn->dst.virt.port));
	return true;
}
bool InetSocket::update_pending_connection(const VirtualSockAddr& peer) {
	std::lock_guard<std::mutex> connections(conn_lock);
	for (auto& conn : pending_connections) {
        if (conn->dst.virt.addr.s_addr == peer.virt.addr.s_addr && 
            (conn->dst.virt.port == peer.virt.port) &&
			(peer.virt.vport == 0 || conn->dst.virt.vport == peer.virt.vport)) {
            
            if (conn->tcp_state == TCPState::SynReceived) {
                conn->tcp_state = TCPState::Established;
				{
					mark_ack(conn, 1); // (p2ps_tcp_flags::SYN|p2ps_tcp_flags::ACK|p2ps_tcp_flags::TCP)
					conn->rx_seq++; // ACK received
				}
                DEBUG_LOG(Log::sceNet, "Promoted connection to Established for %s:%u",
                    ip2str(conn->dst.virt.addr.s_addr).c_str(), ntohs(conn->dst.virt.port));
                return true;
            }
        }
    }
	return false;
}
InetSocket* InetSocket::get_pending_connection() {
	std::lock_guard<std::mutex> connections(conn_lock);
	// Find the first connection that has finished the 3-way handshake
    for (auto& conn : pending_connections) {
        if (conn->tcp_state == TCPState::Established) {
			return conn;
        }
    }
	return nullptr;
}
void InetSocket::remove_pending_connection(InetSocket* conn) {
    std::lock_guard<std::mutex> connections(conn_lock);
    // pending_connections.erase(
    //     std::remove_if(pending_connections.begin(), pending_connections.end(),
    //         [conn](const std::unique_ptr<InetSocket>& p) { return p.get() == conn; }),
    //     pending_connections.end()
    // );
	// pending_connections.remove(conn);
    // for (auto it = pending_connections.begin(); it != pending_connections.end(); ++it) {
    //     if (&*it == conn) {
    //         pending_connections.erase(it);
    //         return;
    //     }
    // }
    auto it = std::find(pending_connections.begin(), pending_connections.end(), conn);
    if (it != pending_connections.end()) {
        delete *it;          // free the heap allocation
        pending_connections.erase(it);
    }
}
bool InetSocket::has_pending_connection() const {
	std::lock_guard<std::mutex> connections(conn_lock);
	for (const auto& conn : pending_connections) {
        if (conn->tcp_state == TCPState::Established) {
            return true;
        }
    }
    return false;
}
void InetSocket::mark_ack(InetSocket* inetSock, int seq_id) {
	std::lock_guard<std::mutex> buffers(inetSock->buffer_lock);
	// Flag SYN|ACK as acquired
	auto psh_syn = std::find_if(inetSock->tx_buffer.begin(), inetSock->tx_buffer.end(), [seq_id](const auto& pair) { return pair.second.seq_id == seq_id; });
	if (psh_syn != inetSock->tx_buffer.end())
		psh_syn->second.seq_ack = true;
}

int InetSocket::Send_Unrealiable(const char* buf, int len, int flags, const sockaddr* to, int tolen, u16 dest_vport) {
	// DCCP must exist for P2P traffic
	auto p2p_sock = g_socketManager.GetP2PSocket();
	if (!p2p_sock) {
#if PPSSPP_PLATFORM(WINDOWS)
		SetLastError(EINVAL);
#else
		socket_errno = EINVAL;
#endif
		return hleLogError(Log::sceNet, -1, "Send_Unreliable: P2P_SOCK Not Present");
	}

	// Create the transmission vpacket
	VirtualPacket vpkt;
	vpkt.data = std::make_unique<char[]>(len);
	memcpy(vpkt.data.get(), buf, len);
	vpkt.len = len;
	vpkt.header_flags = p2ps_tcp_flags::PSH;
	vpkt.src.host = src.host;
	vpkt.seq_id = tx_seq+1;
	// Add timestamp for TTL tracking
	vpkt.enqueue_time_us = (u64)(time_now_d() * 1000000.0);
	VirtualSockAddr dest{};
	memcpy(&dest.host, to, sizeof(sockaddr_in));
	dest.virt.vport = dest_vport;

	// Send the packet over P2P. dest_vport is the per-call destination (from the
	// caller's `to` address), NOT this->dst.virt.vport - ConnDgramSocket sends are
	// connectionless and never populate dst.virt.vport (only StreamSocket/PacketSocket
	// connect()/accept() do), so using dst.virt.vport here always packed vport 0.
	auto [_len, _data] = vpkt.Pack(dest);
	// Send through DCCP
	int ret = ::sendto(p2p_sock->sock, _data.get(), _len, flags, to, sizeof(sockaddr));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret, "Send_Unreliable: Failed to send to peer");
	tx_seq++;
	// Report PAYLOAD bytes, not wire bytes (see Send_Reliable)
	return (int)len;
}
bool InetSocket::Process_Unreliable() {
    std::lock_guard<std::mutex> queue(queue_lock);
    const u64 MAX_PACKET_AGE_US = 30000000; // 30 seconds
    u64 current_time_us = (u64)(time_now_d() * 1000000.0);

	bool ret = false;
    auto it = rx_queue.begin();
    while (it != rx_queue.end()) {
        VirtualPacket pkt = (*it).clone();
		it = rx_queue.erase(it);
		// FIXME: Should technically support non-broadcast sends
		// if (!target_sock->is_broadcast_enabled())
			// continue;

        // 1. Cleanup Stale Packets (Protocol Housekeeping)
        u64 packet_age_us = current_time_us - pkt.enqueue_time_us;
        if (packet_age_us > MAX_PACKET_AGE_US) {
            WARN_LOG(Log::sceNet, "Process_Unreliable: Discarding stale packet (age: %.2f s)", 
                (float)packet_age_us / 1000000.0f);
            continue;
        }
		ret = true;

		{
			std::lock_guard<std::mutex> buffers(buffer_lock);
			int next_id = 1;
			if (!rx_buffer.empty())
				next_id = rx_buffer.rbegin()->first + 1;
			rx_buffer[next_id] = std::move(pkt);
		}
		// DEBUG_LOG(Log::sceNet, "%d=recvfrom(%s:%u) -> vport %d{%02X} (type=%d); [%lld/%lld, %lld/%lld]", 
		// 	pkt.len, inet_ntoa(pkt.src_addr.sin_addr), ntohs(pkt.src_addr.sin_port), 
		// 	vport, pkt.header_flags, type,
		// 	dbg.send, dbg.sent, dbg.recv, dbg.read);
	}
	return ret;
}

int InetSocket::Send_Reliable(const char* buf, int len, int flags) {
	// DCCP must exist for P2P traffic
	auto p2p_sock = g_socketManager.GetP2PSocket();
	if (!p2p_sock) {
#if PPSSPP_PLATFORM(WINDOWS)
		SetLastError(EINVAL);
#else
		socket_errno = EINVAL;
#endif
		return hleLogError(Log::sceNet, -1, "SOCK_PACKET connect: P2P_SOCK Not Present");
	}

	// Create the transmission vpacket
	VirtualPacket vpkt;
	vpkt.data = std::make_unique<char[]>(len);
	memcpy(vpkt.data.get(), buf, len);
	vpkt.len = len;
	vpkt.header_flags = flags;
	vpkt.src.host = src.host;
	vpkt.seq_id = tx_seq+1;
	// Game-space addressing for the extended wire header
	vpkt.src.virt.port = src.virt.port;
	vpkt.src.virt.vport = src.virt.vport;
	vpkt.dst.virt.port = dst.virt.port;
	vpkt.dst.virt.vport = dst.virt.vport;
	// Add timestamp for TTL tracking
	vpkt.enqueue_time_us = (u64)(time_now_d() * 1000000.0);
	vpkt.last_sent_us = (u64)(time_now_d() * BASE_RTO_US);

	auto send_pkt = vpkt.clone();
	{
		// Add to transmit buffer
		std::lock_guard<std::mutex> lock(queue_lock);
		// Place at end
		tx_buffer[tx_seq+1] = std::move(vpkt);
	}

	auto [_len, _data] = send_pkt.Pack(dst);
	// Flip port/vport for physical delivery: the datagram must reach the peer's
	// REAL UDP endpoint - their DCCP master, i.e. the game vport (3658) - while the
	// game port (12000/ephemeral) rides in the vport header + ext header for routing.
	sockaddr_in phys = dst.host;
	phys.sin_port = dst.virt.vport;
	int ret = ::sendto(p2p_sock->sock, _data.get(), _len, 0, (const sockaddr*)&phys, sizeof(sockaddr_in));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret, "Send_Reliable: Failed to send to peer");
	tx_seq++;
	// Report PAYLOAD bytes, not wire bytes: ::sendto's result includes the vport +
	// ext + seq headers (e.g. 32 -> 47), and a stream layer that believes 47 bytes
	// of its 32-byte buffer were consumed desyncs its framing.
	return (int)len;
}
bool InetSocket::Process_Reliable() {
	bool hadData = has_pending_data(true); // Needs queue_lock
    const u64 MAX_PACKET_AGE_US = 30000000; // 30 seconds
    u64 current_time_us = (u64)(time_now_d() * 1000000.0);

	std::deque<VirtualPacket> local_queue;
	{
		std::lock_guard<std::mutex> queue(queue_lock);
		std::swap(local_queue, rx_queue);
	}

    auto it = local_queue.begin();
    while (it != local_queue.end()) {
        VirtualPacket pkt = (*it).clone();
		it = local_queue.erase(it);

        // 1. Cleanup Stale Packets (Protocol Housekeeping)
        u64 packet_age_us = current_time_us - pkt.enqueue_time_us;
        if (packet_age_us > MAX_PACKET_AGE_US) {
            WARN_LOG(Log::sceNet, "Process_Reliable: Discarding stale packet (age: %.2f seconds)", (float)packet_age_us / 1000000.0f);
            continue;
        }

        // if (pkt.header_flags == (p2ps_tcp_flags::PSH | p2ps_tcp_flags::FIN)) {
		// 	INFO_LOG(Log::sceNet, "PACKET: Received PSH|FIN at listening socket from %s:%u to port %u",
		// 		inet_ntoa(pkt.src_addr.sin_addr), ntohs(pkt.src_addr.sin_port), port);
		// }
        // else 
		if (pkt.header_flags == (p2ps_tcp_flags::PSH | p2ps_tcp_flags::ACK | p2ps_tcp_flags::TCP)) {
			if (tcp_state != TCPState::Listening) {
				INFO_LOG(Log::sceNet, "PACKET: Received PSH|ACK at listening socket on %s:%u|%u",
					ip2str(src.virt.addr).c_str(), ntohs(src.virt.port), ntohs(src.virt.vport));
				// Do not increment rx_seq, this is just a confirmation

				mark_ack(this, pkt.seq_id);
			}
		}
        else if (pkt.header_flags == (p2ps_tcp_flags::PSH | p2ps_tcp_flags::TCP)) {
			if (tcp_state != TCPState::Listening) {
				INFO_LOG(Log::sceNet, "PACKET: Received PSH at listening socket from on %s:%u|%u [seq=%d,tx=%d/rx=%d,hpd=%d]",
					ip2str(src.virt.addr).c_str(), ntohs(src.virt.port), ntohs(src.virt.vport), pkt.seq_id, tx_seq, rx_seq, has_pending_data(true));

				// Store the payload for recv()/dequeue_stream, keyed by wire seq so
				// the stream is reassembled in order. A duplicate (retransmit) or an
				// already-consumed seq is not re-stored - just re-ACKed below.
				{
					std::lock_guard<std::mutex> buffers(buffer_lock);
					if (pkt.seq_id > rx_seq && rx_buffer.find(pkt.seq_id) == rx_buffer.end())
						rx_buffer[pkt.seq_id] = pkt.clone();
				}

				INFO_LOG(Log::sceNet, "SOCK_PACKET connect: Returning PSH|ACK to %s:%u|%u",
					ip2str(dst.virt.addr.s_addr).c_str(), ntohs(dst.virt.port), ntohs(dst.virt.vport));

				// Pure acknowledgement: echoes the RECEIVED seq (so the peer's
				// mark_ack hits the right tx_buffer entry), sent directly - it does
				// not consume a tx seq and is never itself retransmitted.
				VirtualPacket ack{};
				ack.len = 0;
				ack.header_flags = (p2ps_tcp_flags::PSH | p2ps_tcp_flags::ACK | p2ps_tcp_flags::TCP);
				ack.seq_id = pkt.seq_id;
				ack.src.host = src.host;
				ack.src.virt.port = src.virt.port;
				ack.src.virt.vport = src.virt.vport;
				ack.dst.virt.port = dst.virt.port;
				ack.dst.virt.vport = dst.virt.vport;
				auto p2p_sock = g_socketManager.GetP2PSocket();
				if (p2p_sock) {
					auto [_len, _data] = ack.Pack(dst);
					sockaddr_in phys = dst.host;
					phys.sin_port = dst.virt.vport;
					int ret = ::sendto(p2p_sock->sock, _data.get(), _len, 0, (struct sockaddr*)&phys, sizeof(phys));
					if (ret < 0) {
						ERROR_LOG(Log::sceNet, "SOCK_PACKET connect: Failed to send PSH|ACK");
					}
				}
			}
        }
        // 2. Process Control Plane (The "Kernel" Logic)
        else if (pkt.header_flags == (p2ps_tcp_flags::SYN | p2ps_tcp_flags::TCP)) {
			if (tcp_state == TCPState::Listening) {
				InetSocket* conn = new InetSocket();
				// Default assume local connection
				conn->src.host = this->src.host;
				conn->src.host.sin_family = AF_INET;
				// Save the sender's address for replies
				conn->dst.host = pkt.src.host;
				conn->dst.host.sin_family = AF_INET;
				// Adopt the connector's game-space endpoint from the extended wire
				// header - the reply key is their (ephemeral) game port; the vport
				// alone (legacy 2-byte payload) is shared by every p2p socket and
				// cannot address the reply.
				conn->dst.virt.port = pkt.src.virt.port;
				conn->dst.virt.vport = pkt.src.virt.vport;
				conn->tcp_state = TCPState::SynReceived;
				conn->tx_seq = 0;
				if (!set_pending_connection(conn))
					continue;
				conn->rx_seq = 1; // Mark this packet received
				
				INFO_LOG(Log::sceNet, "PACKET: Received SYN at listening socket from on %s:%u|%u",
					ip2str(conn->src.virt.addr).c_str(), ntohs(conn->src.virt.port), ntohs(conn->src.virt.vport));

				INFO_LOG(Log::sceNet, "SOCK_PACKET connect: Returning SYN-ACK to %s:%u|%u",
					ip2str(conn->dst.virt.addr.s_addr).c_str(), ntohs(conn->dst.virt.port), ntohs(conn->dst.virt.vport));

				// Reply from conn, not the listener: conn->dst holds the peer (the
				// listener's dst is empty), and this way the SYN-ACK lands in
				// conn->tx_buffer where the pending-connection retransmit loop
				// expects it. Send_Reliable increments conn->tx_seq itself.
				char data[1] = {};
				int ret = conn->Send_Reliable(data, 0, (p2ps_tcp_flags::SYN | p2ps_tcp_flags::ACK | p2ps_tcp_flags::TCP));
				if (ret < 0) {
					ERROR_LOG(Log::sceNet, "SOCK_PACKET connect: Failed to send SYN-ACK");
				}
			}
        } 
        else if (pkt.header_flags == (p2ps_tcp_flags::SYN | p2ps_tcp_flags::ACK | p2ps_tcp_flags::TCP)) {
			if (tcp_state == TCPState::SynSent) {
				INFO_LOG(Log::sceNet, "PACKET: Received SYN|ACK at listening socket to %s:%u|%u",
					ip2str(src.virt.addr).c_str(), ntohs(src.virt.port), ntohs(src.virt.vport));
				dst.host.sin_family = AF_INET;
				// Adopt the real source address; do NOT overwrite sin_port - it
				// aliases dst.virt.port (the peer's GAME port, needed for routing),
				// while pkt's real source port is their DCCP transport port.
				dst.host.sin_addr = pkt.src.host.sin_addr;
				mark_ack(this, 1);
				tcp_state = TCPState::Established;
				rx_seq++;
				
                // Resume the thread that is currently blocked in sceNetInetConnect
				// int tid = threadID.exchange(-1);
                // if (tid > 0) {
                //     DEBUG_LOG(Log::sceNet, "Process_Reliable: SYN|ACK received, resuming thread %d", tid);
                //     __KernelResumeThreadFromWait(tid, 0);
                // }

				// TODO: Mark the tx_buffer SYN packet as acquired
				// pkt.seq_ack = true;

				// Do not resend. Let the peer re-send SYN|ACK if it hasn't connected yet

				INFO_LOG(Log::sceNet, "SOCK_PACKET connect: Returning ACK to %s:%u|%u",
					ip2str(dst.virt.addr.s_addr).c_str(), ntohs(dst.virt.port), ntohs(dst.virt.vport));
				
				char data[1] = {};
				// Send_Reliable increments tx_seq itself - no manual increment here
				int ret = Send_Reliable(data, 0, (p2ps_tcp_flags::ACK | p2ps_tcp_flags::TCP));
				if (ret < 0) {
					ERROR_LOG(Log::sceNet, "SOCK_PACKET connect: Failed to send ACK");
				}
			}
		}
        else if (pkt.header_flags == (p2ps_tcp_flags::ACK | p2ps_tcp_flags::TCP)) {
            if (tcp_state == TCPState::Listening) {
				INFO_LOG(Log::sceNet, "PACKET: Received ACK at listening socket on %s:%u|%u",
					ip2str(src.virt.addr).c_str(), ntohs(src.virt.port), ntohs(src.virt.vport));

				
				// tcp_state = TCPState::Established;
				// Match the pending conn by the peer's GAME endpoint (from the
				// extended header) - pkt.src holds the real transport endpoint,
				// whose port is the peer's DCCP port, not their game port.
				VirtualSockAddr peer{};
				peer.virt.addr = pkt.src.host.sin_addr;
				peer.virt.port = pkt.src.virt.port;
				peer.virt.vport = pkt.src.virt.vport;
				update_pending_connection(peer); // Increments rx_seq

                // Resume the thread that is currently blocked in sceNetInetConnect
                // if (threadID > 0) {
                //     DEBUG_LOG(Log::sceNet, "Process_Reliable: ACK received, resuming thread %d", threadID);
                //     __KernelResumeThreadFromWait(threadID, 0);
                //     threadID = -1;
                // }
            }
        } 
        else if (pkt.header_flags == (p2ps_tcp_flags::FIN | p2ps_tcp_flags::TCP)) {
            if (tcp_state != TCPState::Listening) {
				INFO_LOG(Log::sceNet, "PACKET: Received FIN at listening socket on %s:%u|%u",
					ip2str(src.virt.addr).c_str(), ntohs(src.virt.port), ntohs(src.virt.vport));
                tcp_state = TCPState::CloseWait;
				rx_seq++;
            }
        }
    }

	return hadData;
}

// Close a virtual socket
int InetSocket::closesocket() {
	return ::closesocket(sock);
}

// ============================================================================
// 
// ============================================================================
int StreamSocket::send(const char* buf, int len, int flags) { return ::send(sock, buf, len, flags); }
int StreamSocket::recv(char* buf, int len, int flags) { return ::recv(sock, buf, len, flags); }
int StreamSocket::connect(SceNetInetSockaddr* name, int namelen) {
	SockAddrIN4 saddr{};
	int dstlen = std::min(namelen > 0 ? namelen : 0, static_cast<int>(sizeof(saddr)));
	saddr.addr.sa_family = name->sa_family;
	memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));

	sockaddr_in* paddr = reinterpret_cast<sockaddr_in*>(&saddr);
	// If PSP tried to connect to 0.0.0.0, replace with loopback
	// if (paddr->sin_addr.s_addr == htonl(INADDR_ANY)) {
	// 	WARN_LOG(Log::sceNet, "Socket attempting to connect to INADDR_ANY! (socket #%d)", socket);
	// 	sockaddr_in sockAddr{};
	// 	getLocalIp(&sockAddr);
	// 	//paddr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	// 	//paddr->sin_addr.s_addr = htonl((ULONG)0xC0A802FE); // hard coded to dev machine
	// 	paddr->sin_addr.s_addr = sockAddr.sin_addr.s_addr;
	// }

	// Enforcing real blocking-mode on games that use blocking-mode socket (as a temporary fix for UNO), since we don't simulate blocking-mode yet
	if (!nonblocking) {
		WARN_LOG(Log::sceNet, "Enforcing blocking-mode on Connect! (socket #%d)", socket);
		// changeBlockingMode(sock, 0);
		// Workaround to avoid blocking for indefinitely
		setSockTimeout(sock, SO_SNDTIMEO, 5000000);
		setSockTimeout(sock, SO_RCVTIMEO, 5000000);
	}
	INFO_LOG(Log::sceNet, "Connect(%s, %i)", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
	int ret = ::connect(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	int hostErrno = socket_errno;

	if (!nonblocking) {
		// changeBlockingMode(sock, 1);
		// Since we're temporarily forcing blocking-mode, we'll need to change errno from ETIMEDOUT to EAGAIN
		if (hostErrno == ETIMEDOUT)
			hostErrno = EAGAIN;
	}

	if (saddr.in.sin_port == 53) {
		WARN_LOG(Log::G3D, "Game connected to DNS server %s (port 53), likely for doing its own DNS lookups!", ip2str(saddr.in.sin_addr, false).c_str());
		// We should sniff these messages...
	}
	return ret;
}
int StreamSocket::listen(int backlog) { return ::listen(sock, backlog); }
int StreamSocket::accept(sockaddr* addr, socklen_t* addrlen) { return ::accept(sock, addr, addrlen); }
int StreamSocket::bind(SceNetInetSockaddr* name, int namelen) { 
	SockAddrIN4 saddr{};
	// TODO: Should've created convertSockaddrPSP2Host (and Host2PSP too) function as it's being used pretty often, thus fixing a bug on it will be tedious when scattered all over the places
	saddr.addr.sa_family = name->sa_family;
	int len = std::min(namelen > 0 ? namelen : 0, static_cast<int>(sizeof(saddr)));
	memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));
	if (isLocalServer) {
		getLocalIp(&saddr.in);
	}
	// FIXME: On non-Windows broadcast to INADDR_BROADCAST(255.255.255.255) might not be received by the sender itself when binded to specific IP (ie. 192.168.0.2) or INADDR_BROADCAST.
	//        Meanwhile, it might be received by itself when binded to subnet (ie. 192.168.0.255) or INADDR_ANY(0.0.0.0).
	//
	// Replace INADDR_ANY (and INADDR_BROADCAST too) with a specific IP (using AdhocServer IP address as reference) in order not to send data through the wrong interface (especially during broadcast),
	// But let's do this only when using built-in Adhoc Server, otherwise UNO won't works
	// if (saddr.in.sin_addr.s_addr == INADDR_ANY || (g_Config.bEnableAdhocServer && saddr.in.sin_addr.s_addr == INADDR_BROADCAST)) {
	// 	// Get Local IP Address
	// 	sockaddr_in sockAddr{};
	// 	getLocalIp(&sockAddr);
	// 	INFO_LOG(Log::sceNet, "Bind: Address Replacement = %s => %s", ip2str(saddr.in.sin_addr).c_str(), ip2str(sockAddr.sin_addr).c_str());
	// 	saddr.in.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
	// }
	// TODO: Make use Port Offset only for PPSSPP to PPSSPP communications (ie. IP addresses available in the group/friendlist), otherwise should be considered as Online Service thus should use the port as is.
	//saddr.in.sin_port = htons(ntohs(saddr.in.sin_port) + portOffset);

	// Update socket debug metadata
	src.host = saddr.in;

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(src.virt.family).c_str(), ip2str(src.virt.addr).c_str(), ntohs(src.virt.port), ntohs(src.virt.vport));

	// changeBlockingMode(sock, 0);
	int ret = ::bind(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret);
	return ret;
}
int StreamSocket::shutdown(int how) { return ::shutdown(sock, how); }

// ============================================================================
// 
// ============================================================================
int DgramSocket::sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) {
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	SockAddrIN4 saddr{};
	int dstlen = std::min(tolen > 0 ? tolen : 0, static_cast<int>(sizeof(saddr)));
	if (to) {
		saddr.addr.sa_family = to->sa_family;
		memcpy(saddr.addr.sa_data, to->sa_data, sizeof(to->sa_data));
	}

	int retval = ::sendto(sock, buf, len, flgs | MSG_NOSIGNAL, (struct sockaddr*)&saddr.addr, sizeof(sockaddr));

	return hleLogDebug(Log::sceNet, retval, "SendTo: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
}
int DgramSocket::recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) {
	SockAddrIN4 saddr{};
	if (fromlen)
		*fromlen = std::min((*fromlen) > 0 ? *fromlen : 0, static_cast<socklen_t>(sizeof(saddr)));
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	int ret = ::recvfrom(sock, buf, len, flags, (struct sockaddr*)&saddr.addr, fromlen);

	if (from) {
		from->sa_family = saddr.addr.sa_family;
		memcpy(from->sa_data, saddr.addr.sa_data, sizeof(from->sa_data));
		from->sa_len = fromlen ? *fromlen : 0;
	}
	
	return hleLogDebug(Log::sceNet, ret, "RecvFrom: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
}
int DgramSocket::bind(SceNetInetSockaddr* name, int namelen) { 
	SockAddrIN4 saddr{};
	// TODO: Should've created convertSockaddrPSP2Host (and Host2PSP too) function as it's being used pretty often, thus fixing a bug on it will be tedious when scattered all over the places
	saddr.addr.sa_family = name->sa_family;
	int len = std::min(namelen > 0 ? namelen : 0, static_cast<int>(sizeof(saddr)));
	memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));
	if (isLocalServer) {
		getLocalIp(&saddr.in);
	}
	// FIXME: On non-Windows broadcast to INADDR_BROADCAST(255.255.255.255) might not be received by the sender itself when binded to specific IP (ie. 192.168.0.2) or INADDR_BROADCAST.
	//        Meanwhile, it might be received by itself when binded to subnet (ie. 192.168.0.255) or INADDR_ANY(0.0.0.0).
	//
	// Replace INADDR_ANY (and INADDR_BROADCAST too) with a specific IP (using AdhocServer IP address as reference) in order not to send data through the wrong interface (especially during broadcast),
	// But let's do this only when using built-in Adhoc Server, otherwise UNO won't works
	// if (saddr.in.sin_addr.s_addr == INADDR_ANY || (g_Config.bEnableAdhocServer && saddr.in.sin_addr.s_addr == INADDR_BROADCAST)) {
	// 	// Get Local IP Address
	// 	sockaddr_in sockAddr{};
	// 	getLocalIp(&sockAddr);
	// 	INFO_LOG(Log::sceNet, "Bind: Address Replacement = %s => %s", ip2str(saddr.in.sin_addr).c_str(), ip2str(sockAddr.sin_addr).c_str());
	// 	saddr.in.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
	// }
	// TODO: Make use Port Offset only for PPSSPP to PPSSPP communications (ie. IP addresses available in the group/friendlist), otherwise should be considered as Online Service thus should use the port as is.
	//saddr.in.sin_port = htons(ntohs(saddr.in.sin_port) + portOffset);

	// Update socket debug metadata
	src.host = saddr.in;

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(src.virt.family).c_str(), ip2str(src.virt.addr).c_str(), ntohs(src.virt.port), ntohs(src.virt.vport));

	// changeBlockingMode(sock, 0);
	int ret = ::bind(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret);
	return ret;
}
int DgramSocket::shutdown(int how) { return ::closesocket(sock); }

// ============================================================================
// 
// ============================================================================
int RawSocket::send(const char* buf, int len, int flags) { return ::send(sock, buf, len, flags); }
int RawSocket::recv(char* buf, int len, int flags) { return ::recv(sock, buf, len, flags); }
int RawSocket::sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) {
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	SockAddrIN4 saddr{};
	int dstlen = std::min(tolen > 0 ? tolen : 0, static_cast<int>(sizeof(saddr)));
	if (to) {
		saddr.addr.sa_family = to->sa_family;
		memcpy(saddr.addr.sa_data, to->sa_data, sizeof(to->sa_data));
	}

	int retval = ::sendto(sock, buf, len, flgs | MSG_NOSIGNAL, (struct sockaddr*)&saddr.addr, sizeof(sockaddr));

	return hleLogDebug(Log::sceNet, retval, "SendTo: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
}
int RawSocket::recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) {
	SockAddrIN4 saddr{};
	if (fromlen)
		*fromlen = std::min((*fromlen) > 0 ? *fromlen : 0, static_cast<socklen_t>(sizeof(saddr)));
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	int ret = ::recvfrom(sock, buf, len, flags, (struct sockaddr*)&saddr.addr, fromlen);

	if (from) {
		from->sa_family = saddr.addr.sa_family;
		memcpy(from->sa_data, saddr.addr.sa_data, sizeof(from->sa_data));
		from->sa_len = fromlen ? *fromlen : 0;
	}
	
	return hleLogDebug(Log::sceNet, ret, "RecvFrom: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
}
int RawSocket::bind(SceNetInetSockaddr* name, int namelen) { 
	SockAddrIN4 saddr{};
	// TODO: Should've created convertSockaddrPSP2Host (and Host2PSP too) function as it's being used pretty often, thus fixing a bug on it will be tedious when scattered all over the places
	saddr.addr.sa_family = name->sa_family;
	int len = std::min(namelen > 0 ? namelen : 0, static_cast<int>(sizeof(saddr)));
	memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));
	if (isLocalServer) {
		getLocalIp(&saddr.in);
	}
	// FIXME: On non-Windows broadcast to INADDR_BROADCAST(255.255.255.255) might not be received by the sender itself when binded to specific IP (ie. 192.168.0.2) or INADDR_BROADCAST.
	//        Meanwhile, it might be received by itself when binded to subnet (ie. 192.168.0.255) or INADDR_ANY(0.0.0.0).
	//
	// Replace INADDR_ANY (and INADDR_BROADCAST too) with a specific IP (using AdhocServer IP address as reference) in order not to send data through the wrong interface (especially during broadcast),
	// But let's do this only when using built-in Adhoc Server, otherwise UNO won't works
	// if (saddr.in.sin_addr.s_addr == INADDR_ANY || (g_Config.bEnableAdhocServer && saddr.in.sin_addr.s_addr == INADDR_BROADCAST)) {
	// 	// Get Local IP Address
	// 	sockaddr_in sockAddr{};
	// 	getLocalIp(&sockAddr);
	// 	INFO_LOG(Log::sceNet, "Bind: Address Replacement = %s => %s", ip2str(saddr.in.sin_addr).c_str(), ip2str(sockAddr.sin_addr).c_str());
	// 	saddr.in.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
	// }
	// TODO: Make use Port Offset only for PPSSPP to PPSSPP communications (ie. IP addresses available in the group/friendlist), otherwise should be considered as Online Service thus should use the port as is.
	//saddr.in.sin_port = htons(ntohs(saddr.in.sin_port) + portOffset);

	// Update socket debug metadata
	src.host = saddr.in;

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(src.virt.family).c_str(), ip2str(src.virt.addr).c_str(), ntohs(src.virt.port), ntohs(src.virt.vport));

	// changeBlockingMode(sock, 0);
	int ret = ::bind(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret);
	return ret;
}

// ============================================================================
// 
// ============================================================================
int RdmSocket::send(const char* buf, int len, int flags) { return ::send(sock, buf, len, flags); }
int RdmSocket::recv(char* buf, int len, int flags) { return ::recv(sock, buf, len, flags); }
int RdmSocket::sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) {
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	SockAddrIN4 saddr{};
	int dstlen = std::min(tolen > 0 ? tolen : 0, static_cast<int>(sizeof(saddr)));
	if (to) {
		saddr.addr.sa_family = to->sa_family;
		memcpy(saddr.addr.sa_data, to->sa_data, sizeof(to->sa_data));
	}

	int retval = ::sendto(sock, buf, len, flgs | MSG_NOSIGNAL, (struct sockaddr*)&saddr.addr, sizeof(sockaddr));

	return hleLogDebug(Log::sceNet, retval, "SendTo: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
}
int RdmSocket::recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) {
	SockAddrIN4 saddr{};
	if (fromlen)
		*fromlen = std::min((*fromlen) > 0 ? *fromlen : 0, static_cast<socklen_t>(sizeof(saddr)));
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	int ret = ::recvfrom(sock, buf, len, flags, (struct sockaddr*)&saddr.addr, fromlen);

	if (from) {
		from->sa_family = saddr.addr.sa_family;
		memcpy(from->sa_data, saddr.addr.sa_data, sizeof(from->sa_data));
		from->sa_len = fromlen ? *fromlen : 0;
	}
	
	return hleLogDebug(Log::sceNet, ret, "RecvFrom: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
}
int RdmSocket::bind(SceNetInetSockaddr* name, int namelen) { 
	SockAddrIN4 saddr{};
	// TODO: Should've created convertSockaddrPSP2Host (and Host2PSP too) function as it's being used pretty often, thus fixing a bug on it will be tedious when scattered all over the places
	saddr.addr.sa_family = name->sa_family;
	int len = std::min(namelen > 0 ? namelen : 0, static_cast<int>(sizeof(saddr)));
	memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));
	if (isLocalServer) {
		getLocalIp(&saddr.in);
	}
	// FIXME: On non-Windows broadcast to INADDR_BROADCAST(255.255.255.255) might not be received by the sender itself when binded to specific IP (ie. 192.168.0.2) or INADDR_BROADCAST.
	//        Meanwhile, it might be received by itself when binded to subnet (ie. 192.168.0.255) or INADDR_ANY(0.0.0.0).
	//
	// Replace INADDR_ANY (and INADDR_BROADCAST too) with a specific IP (using AdhocServer IP address as reference) in order not to send data through the wrong interface (especially during broadcast),
	// But let's do this only when using built-in Adhoc Server, otherwise UNO won't works
	// if (saddr.in.sin_addr.s_addr == INADDR_ANY || (g_Config.bEnableAdhocServer && saddr.in.sin_addr.s_addr == INADDR_BROADCAST)) {
	// 	// Get Local IP Address
	// 	sockaddr_in sockAddr{};
	// 	getLocalIp(&sockAddr);
	// 	INFO_LOG(Log::sceNet, "Bind: Address Replacement = %s => %s", ip2str(saddr.in.sin_addr).c_str(), ip2str(sockAddr.sin_addr).c_str());
	// 	saddr.in.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
	// }
	// TODO: Make use Port Offset only for PPSSPP to PPSSPP communications (ie. IP addresses available in the group/friendlist), otherwise should be considered as Online Service thus should use the port as is.
	//saddr.in.sin_port = htons(ntohs(saddr.in.sin_port) + portOffset);

	// Update socket debug metadata
	src.host = saddr.in;

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(src.virt.family).c_str(), ip2str(src.virt.addr).c_str(), ntohs(src.virt.port), ntohs(src.virt.vport));

	// changeBlockingMode(sock, 0);
	int ret = ::bind(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret);
	return ret;
}

// ============================================================================
// 
// ============================================================================
int SeqpacketSocket::send(const char* buf, int len, int flags) { return ::send(sock, buf, len, flags); }
int SeqpacketSocket::recv(char* buf, int len, int flags) { return ::recv(sock, buf, len, flags); }
int SeqpacketSocket::sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) {
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	SockAddrIN4 saddr{};
	int dstlen = std::min(tolen > 0 ? tolen : 0, static_cast<int>(sizeof(saddr)));
	if (to) {
		saddr.addr.sa_family = to->sa_family;
		memcpy(saddr.addr.sa_data, to->sa_data, sizeof(to->sa_data));
	}

	int retval = ::sendto(sock, buf, len, flgs | MSG_NOSIGNAL, (struct sockaddr*)&saddr.addr, sizeof(sockaddr));

	return hleLogDebug(Log::sceNet, retval, "SendTo: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
}
int SeqpacketSocket::recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) {
	SockAddrIN4 saddr{};
	if (fromlen)
		*fromlen = std::min((*fromlen) > 0 ? *fromlen : 0, static_cast<socklen_t>(sizeof(saddr)));
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	int ret = ::recvfrom(sock, buf, len, flags, (struct sockaddr*)&saddr.addr, fromlen);

	if (from) {
		from->sa_family = saddr.addr.sa_family;
		memcpy(from->sa_data, saddr.addr.sa_data, sizeof(from->sa_data));
		from->sa_len = fromlen ? *fromlen : 0;
	}
	
	return hleLogDebug(Log::sceNet, ret, "RecvFrom: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
}
int SeqpacketSocket::connect(SceNetInetSockaddr* name, int namelen) {
	SockAddrIN4 saddr{};
	int dstlen = std::min(namelen > 0 ? namelen : 0, static_cast<int>(sizeof(saddr)));
	saddr.addr.sa_family = name->sa_family;
	memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));

	sockaddr_in* paddr = reinterpret_cast<sockaddr_in*>(&saddr);
	// If PSP tried to connect to 0.0.0.0, replace with loopback
	// if (paddr->sin_addr.s_addr == htonl(INADDR_ANY)) {
	// 	WARN_LOG(Log::sceNet, "Socket attempting to connect to INADDR_ANY! (socket #%d)", socket);
	// 	sockaddr_in sockAddr{};
	// 	getLocalIp(&sockAddr);
	// 	//paddr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	// 	//paddr->sin_addr.s_addr = htonl((ULONG)0xC0A802FE); // hard coded to dev machine
	// 	paddr->sin_addr.s_addr = sockAddr.sin_addr.s_addr;
	// }

	// Enforcing real blocking-mode on games that use blocking-mode socket (as a temporary fix for UNO), since we don't simulate blocking-mode yet
	if (!nonblocking) {
		WARN_LOG(Log::sceNet, "Enforcing blocking-mode on Connect! (socket #%d)", socket);
		// changeBlockingMode(sock, 0);
		// Workaround to avoid blocking for indefinitely
		setSockTimeout(sock, SO_SNDTIMEO, 5000000);
		setSockTimeout(sock, SO_RCVTIMEO, 5000000);
	}
	INFO_LOG(Log::sceNet, "Connect(%s, %i)", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
	int ret = ::connect(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	int hostErrno = socket_errno;

	if (!nonblocking) {
		// changeBlockingMode(sock, 1);
		// Since we're temporarily forcing blocking-mode, we'll need to change errno from ETIMEDOUT to EAGAIN
		if (hostErrno == ETIMEDOUT)
			hostErrno = EAGAIN;
	}

	if (saddr.in.sin_port == 53) {
		WARN_LOG(Log::G3D, "Game connected to DNS server %s (port 53), likely for doing its own DNS lookups!", ip2str(saddr.in.sin_addr, false).c_str());
		// We should sniff these messages...
	}
	return ret;
}
int SeqpacketSocket::listen(int backlog) { return ::listen(sock, backlog); }
int SeqpacketSocket::accept(sockaddr* addr, socklen_t* addrlen) { return ::accept(sock, addr, addrlen); }
int SeqpacketSocket::bind(SceNetInetSockaddr* name, int namelen) { 
	SockAddrIN4 saddr{};
	// TODO: Should've created convertSockaddrPSP2Host (and Host2PSP too) function as it's being used pretty often, thus fixing a bug on it will be tedious when scattered all over the places
	saddr.addr.sa_family = name->sa_family;
	int len = std::min(namelen > 0 ? namelen : 0, static_cast<int>(sizeof(saddr)));
	memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));
	if (isLocalServer) {
		getLocalIp(&saddr.in);
	}
	// FIXME: On non-Windows broadcast to INADDR_BROADCAST(255.255.255.255) might not be received by the sender itself when binded to specific IP (ie. 192.168.0.2) or INADDR_BROADCAST.
	//        Meanwhile, it might be received by itself when binded to subnet (ie. 192.168.0.255) or INADDR_ANY(0.0.0.0).
	//
	// Replace INADDR_ANY (and INADDR_BROADCAST too) with a specific IP (using AdhocServer IP address as reference) in order not to send data through the wrong interface (especially during broadcast),
	// But let's do this only when using built-in Adhoc Server, otherwise UNO won't works
	// if (saddr.in.sin_addr.s_addr == INADDR_ANY || (g_Config.bEnableAdhocServer && saddr.in.sin_addr.s_addr == INADDR_BROADCAST)) {
	// 	// Get Local IP Address
	// 	sockaddr_in sockAddr{};
	// 	getLocalIp(&sockAddr);
	// 	INFO_LOG(Log::sceNet, "Bind: Address Replacement = %s => %s", ip2str(saddr.in.sin_addr).c_str(), ip2str(sockAddr.sin_addr).c_str());
	// 	saddr.in.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
	// }
	// TODO: Make use Port Offset only for PPSSPP to PPSSPP communications (ie. IP addresses available in the group/friendlist), otherwise should be considered as Online Service thus should use the port as is.
	//saddr.in.sin_port = htons(ntohs(saddr.in.sin_port) + portOffset);

	// Update socket debug metadata
	src.host = saddr.in;
	
	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(src.virt.family).c_str(), ip2str(src.virt.addr).c_str(), ntohs(src.virt.port), ntohs(src.virt.vport));

	// changeBlockingMode(sock, 0);
	int ret = ::bind(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret);
	return ret;
}
int SeqpacketSocket::shutdown(int how) { return ::shutdown(sock, how); }

// ============================================================================
// Primary socket for UPnP/P2P traffic (UDP)
// ============================================================================
int DccpSocket::send(const char* buf, int len, int flags) { return ::send(sock, buf, len, flags); }
int DccpSocket::recv(char* buf, int len, int flags) { return ::recv(sock, buf, len, flags); }
int DccpSocket::sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) {
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	SockAddrIN4 saddr{};
	int dstlen = std::min(tolen > 0 ? tolen : 0, static_cast<int>(sizeof(saddr)));
	if (to) {
		saddr.addr.sa_family = to->sa_family;
		memcpy(saddr.addr.sa_data, to->sa_data, sizeof(to->sa_data));
	}

	int retval = ::sendto(sock, buf, len, flgs | MSG_NOSIGNAL, (struct sockaddr*)&saddr.addr, sizeof(sockaddr));

	return hleLogDebug(Log::sceNet, retval, "SendTo: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
}
int DccpSocket::recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) { 
	SockAddrIN4 saddr{};
	if (fromlen)
		*fromlen = std::min((*fromlen) > 0 ? *fromlen : 0, static_cast<socklen_t>(sizeof(saddr)));
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	int ret = ::recvfrom(sock, buf, len, flags, (struct sockaddr*)&saddr.addr, fromlen);

	if (from) {
		from->sa_family = saddr.addr.sa_family;
		memcpy(from->sa_data, saddr.addr.sa_data, sizeof(from->sa_data));
		from->sa_len = fromlen ? *fromlen : 0;
	}
	
	return hleLogDebug(Log::sceNet, ret, "RecvFrom: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
}
int DccpSocket::connect(SceNetInetSockaddr* name, int namelen) {
	SockAddrIN4 saddr{};
	int dstlen = std::min(namelen > 0 ? namelen : 0, static_cast<int>(sizeof(saddr)));
	saddr.addr.sa_family = name->sa_family;
	memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));

	sockaddr_in* paddr = reinterpret_cast<sockaddr_in*>(&saddr);
	// If PSP tried to connect to 0.0.0.0, replace with loopback
	// if (paddr->sin_addr.s_addr == htonl(INADDR_ANY)) {
	// 	WARN_LOG(Log::sceNet, "Socket attempting to connect to INADDR_ANY! (socket #%d)", socket);
	// 	sockaddr_in sockAddr{};
	// 	getLocalIp(&sockAddr);
	// 	//paddr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	// 	//paddr->sin_addr.s_addr = htonl((ULONG)0xC0A802FE); // hard coded to dev machine
	// 	paddr->sin_addr.s_addr = sockAddr.sin_addr.s_addr;
	// }

	// Enforcing real blocking-mode on games that use blocking-mode socket (as a temporary fix for UNO), since we don't simulate blocking-mode yet
	if (!nonblocking) {
		WARN_LOG(Log::sceNet, "Enforcing blocking-mode on Connect! (socket #%d)", socket);
		// changeBlockingMode(sock, 0);
		// Workaround to avoid blocking for indefinitely
		setSockTimeout(sock, SO_SNDTIMEO, 5000000);
		setSockTimeout(sock, SO_RCVTIMEO, 5000000);
	}
	INFO_LOG(Log::sceNet, "Connect(%s, %i)", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
	int ret = ::connect(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	int hostErrno = socket_errno;

	if (!nonblocking) {
		// changeBlockingMode(sock, 1);
		// Since we're temporarily forcing blocking-mode, we'll need to change errno from ETIMEDOUT to EAGAIN
		if (hostErrno == ETIMEDOUT)
			hostErrno = EAGAIN;
	}

	if (saddr.in.sin_port == 53) {
		WARN_LOG(Log::G3D, "Game connected to DNS server %s (port 53), likely for doing its own DNS lookups!", ip2str(saddr.in.sin_addr, false).c_str());
		// We should sniff these messages...
	}
	return ret;
}
int DccpSocket::listen(int backlog) { return ::listen(sock, backlog); }
int DccpSocket::accept(sockaddr* addr, socklen_t* addrlen) { return ::accept(sock, addr, addrlen); }
int DccpSocket::bind(SceNetInetSockaddr* name, int namelen) { 
	SockAddrIN4 saddr{};
	// TODO: Should've created convertSockaddrPSP2Host (and Host2PSP too) function as it's being used pretty often, thus fixing a bug on it will be tedious when scattered all over the places
	saddr.addr.sa_family = name->sa_family;
	int len = std::min(namelen > 0 ? namelen : 0, static_cast<int>(sizeof(saddr)));
	memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));
	if (isLocalServer) {
		getLocalIp(&saddr.in);
	}
	// FIXME: On non-Windows broadcast to INADDR_BROADCAST(255.255.255.255) might not be received by the sender itself when binded to specific IP (ie. 192.168.0.2) or INADDR_BROADCAST.
	//        Meanwhile, it might be received by itself when binded to subnet (ie. 192.168.0.255) or INADDR_ANY(0.0.0.0).
	//
	// Replace INADDR_ANY (and INADDR_BROADCAST too) with a specific IP (using AdhocServer IP address as reference) in order not to send data through the wrong interface (especially during broadcast),
	// But let's do this only when using built-in Adhoc Server, otherwise UNO won't works
	// if (saddr.in.sin_addr.s_addr == INADDR_ANY || (g_Config.bEnableAdhocServer && saddr.in.sin_addr.s_addr == INADDR_BROADCAST)) {
	// 	// Get Local IP Address
	// 	sockaddr_in sockAddr{};
	// 	getLocalIp(&sockAddr);
	// 	INFO_LOG(Log::sceNet, "Bind: Address Replacement = %s => %s", ip2str(saddr.in.sin_addr).c_str(), ip2str(sockAddr.sin_addr).c_str());
	// 	saddr.in.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
	// }
	// TODO: Make use Port Offset only for PPSSPP to PPSSPP communications (ie. IP addresses available in the group/friendlist), otherwise should be considered as Online Service thus should use the port as is.
	//saddr.in.sin_port = htons(ntohs(saddr.in.sin_port) + portOffset);

	// Update socket debug metadata
	src.host = saddr.in;
	
	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(src.virt.family).c_str(), ip2str(src.virt.addr).c_str(), ntohs(src.virt.port), ntohs(src.virt.vport));

	// changeBlockingMode(sock, 0);
	int ret = ::bind(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret);
	return ret;
}
int DccpSocket::shutdown(int how) { return ::shutdown(sock, how); }

// ============================================================================
// Standard P2P Comm Channel (UDP)
// ============================================================================
int ConnDgramSocket::sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) { 
	dbg.send++;
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	SockAddrIN4 saddr{};
	int dstlen = std::min(tolen > 0 ? tolen : 0, static_cast<int>(sizeof(saddr)));
	if (to) {
		saddr.addr.sa_family = to->sa_family;
		memcpy(saddr.addr.sa_data, to->sa_data, sizeof(to->sa_data));
	}
	const sockaddr_in* _dest = reinterpret_cast<const sockaddr_in*>(&saddr.addr);

	// Network Order
	u16 dest_vport = ntohs((saddr.in.sin_zero[1] << 8) | saddr.in.sin_zero[0]);
	if (dest_vport == 0)
		dest_vport = 1;

	if (isLocalTarget(_dest->sin_addr.s_addr)) {
		int ret = ::sendto(sock, buf, len, flgs, (struct sockaddr*)&saddr.addr, sizeof(sockaddr));
		if (ret < 0)
			return hleLogError(Log::sceNet, ret, "CONN_DGRAM_SOCKET sendto: Failed to send to local");
		
		dbg.sent++;
		WARN_LOG(Log::sceNet, "%d bytes send to (%s:%u);", 
			ret, ip2str(dst.virt.addr.s_addr).c_str(), ntohs(dst.virt.vport));
		return ret;
	} else {
		// DCCP must exist for P2P traffic
		auto p2p_sock = g_socketManager.GetP2PSocket();
		if (!p2p_sock) {
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(EINVAL);
#else
			socket_errno = EINVAL;
#endif
			return hleLogError(Log::sceNet, -1, "SOCK_PACKET connect: P2P_SOCK Not Present");
		}

		int ret = Send_Unrealiable(buf, len, flgs, (struct sockaddr*)&saddr.addr, sizeof(sockaddr), dest_vport);
		if (ret < 0)
			return hleLogError(Log::sceNet, ret, "CONN_DGRAM_SOCKET send: Failed to send to peer");
		dbg.sent++;
		
		std::string msg = "sendto::CONN_DGRAM " + std::to_string(ntohs(src.virt.vport)) + " -> " +
			ip2str(_dest->sin_addr) + ":" + std::to_string(ntohs(_dest->sin_port)) + 
			"{" + std::to_string(dest_vport) + "}";
		INFO_HEXLOG(Log::sceNet, msg.c_str(), buf, ret, 386);

		WARN_LOG(Log::sceNet, "%d bytes send to %s:%u(%u); [tx=%d/rx=%d]", 
			ret, ip2str(dst.virt.addr).c_str(), ntohs(dst.virt.port), ntohs(dst.virt.vport),
			tx_seq, rx_seq);
		DEBUG_LOG(Log::sceNet, "VPORT %d s(%lld/%lld) r(%lld,%lld)", ntohs(src.virt.vport), dbg.sent, dbg.send, dbg.recv, dbg.read);

		// Now shotgun-send using all peer id's
		// if (sigServer) {
		// 	std::vector<SceNpMatching2RoomMemberId> peers = sigServer->GetPeerList();
		// 	for (auto peer : peers) {
		// 		// Alter the vport to point at the peer
		// 		header.vport = htons(peer);
		// 		memcpy(packet.get(), &header, VPORT_HEADER_SIZE);
		// 		::sendto(p2p_sock->sock, packet.get(), packet_size, flags, (struct sockaddr*)&saddr.addr, sizeof(sockaddr));
		// 	}
		// }

		return ret; // Report unmodified packet size
	}

 }
int ConnDgramSocket::recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) { 
	dbg.read++;
	SockAddrIN4 saddr{};
	if (fromlen)
		*fromlen = std::min((*fromlen) > 0 ? *fromlen : 0, static_cast<socklen_t>(sizeof(saddr)));
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);

	if (has_pending_data()) {
		// Dequeue from local packet queue for virtual sockets
		VirtualPacket pkt;
		if (!dequeue_packet(pkt)) {
			// Empty Queue, try actual socket
			int ret = ::recvfrom(sock, buf, len, flgs, (struct sockaddr*)&saddr.addr, fromlen);
			if (ret < 0)
				return ret;

			dbg.recv++;

			if (from) {
				from->sa_family = saddr.addr.sa_family;
				memcpy(from->sa_data, saddr.addr.sa_data, sizeof(from->sa_data));
				from->sa_len = fromlen ? *fromlen : 0;
			}
			return ret;
		}
		
		// ===== STRICT DESTRUCTIVE FIFO SEMANTICS =====
		// 
		// If the caller's buffer is smaller than the packet:
		//   - Copy only what fits (truncate)
		//   - DISCARD THE REMAINDER (do not queue it back)
		//   - Return the truncated size
		//
		// If the caller's buffer is larger than the packet:
		//   - Copy the entire packet
		//   - Return the actual packet size (do NOT pad)
		//
		// Always preserve source address information
		
		// Copy payload (truncate if necessary)
		size_t copy_len = std::min((size_t)len, pkt.len);
		if (copy_len > 0 && buf && pkt.data) {
			memcpy(buf, pkt.data.get(), copy_len);
		}
		
		// Copy source address (only update sin_addr and sin_port, preserve other fields)
		if (from && fromlen) {
			sockaddr_in* from_in = (sockaddr_in*)from;
			// Preserve caller's structure but update only the address and port
			from_in->sin_addr = pkt.src.host.sin_addr;
			from_in->sin_port = pkt.src.host.sin_port;
			from_in->sin_zero[0] = pkt.src.host.sin_zero[0]; // Copy vport
			from_in->sin_zero[1] = pkt.src.host.sin_zero[1];
			*fromlen = sizeof(sockaddr_in);  // Always set to actual size
			
			// Log with hex dump at INFO level so we see packet pickup
			std::string msg = "recvfrom::CONN_DGRAM (vport " + std::to_string(ntohs(src.virt.vport)) + "): picked up " + 
				std::to_string(copy_len) + " bytes from " + ip2str(from_in->sin_addr.s_addr) + 
				":" + std::to_string(ntohs(from_in->sin_port));
			INFO_HEXLOG(Log::sceNet, msg.c_str(), buf, (int)copy_len, 256);
		}
		
		dbg.recv++;
		
		// Log truncation if it occurred
		if (copy_len < pkt.len) {
			DEBUG_LOG(Log::sceNet, "recvfrom: TRUNCATED packet for vport %d (buf=%zu, pkt=%zu, discarding %zu bytes)",
				ntohs(src.virt.vport), copy_len, pkt.len, pkt.len - copy_len);
		}

		DEBUG_LOG(Log::sceNet, "VPORT %d s(%lld/%lld) r(%lld,%lld)", ntohs(src.virt.vport), dbg.sent, dbg.send, dbg.recv, dbg.read);
			// Return actual bytes copied (NOT padded to requested size)
		return hleLogDebug(Log::sceNet, (int)copy_len, "RecvFrom: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));

	}

	int ret = ::recvfrom(sock, buf, len, flgs, (struct sockaddr*)&saddr.addr, fromlen);
	if (ret < 0)
		return ret; // Do not report, sceNetInetRecvfrom will handle the error reporting

	if (from) {
		from->sa_family = saddr.addr.sa_family;
		memcpy(from->sa_data, saddr.addr.sa_data, sizeof(from->sa_data));
		from->sa_len = fromlen ? *fromlen : 0;
	}
	dbg.recv++;
	std::string msg = "recv::PACKET " + ip2str(saddr.in.sin_addr) + ":" + std::to_string(ntohs(saddr.in.sin_port));
	INFO_HEXLOG(Log::sceNet, msg.c_str(), buf, ret, 386);

	DEBUG_LOG(Log::sceNet, "PORT %u s(%lld/%lld) r(%lld,%lld)", ntohs(saddr.in.sin_port), dbg.sent, dbg.send, dbg.recv, dbg.read);
		// Return actual bytes copied (NOT padded to requested size)
	return hleLogDebug(Log::sceNet, ret, "RecvFrom: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
}
int ConnDgramSocket::bind(SceNetInetSockaddr* name, int namelen) { 
	SockAddrIN4 saddr{};
	// TODO: Should've created convertSockaddrPSP2Host (and Host2PSP too) function as it's being used pretty often, thus fixing a bug on it will be tedious when scattered all over the places
	saddr.addr.sa_family = name->sa_family;
	int len = std::min(namelen > 0 ? namelen : 0, static_cast<int>(sizeof(saddr)));
	memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));
	// if (isLocalServer) {
	// 	getLocalIp(&saddr.in);
	// }
	// FIXME: On non-Windows broadcast to INADDR_BROADCAST(255.255.255.255) might not be received by the sender itself when binded to specific IP (ie. 192.168.0.2) or INADDR_BROADCAST.
	//        Meanwhile, it might be received by itself when binded to subnet (ie. 192.168.0.255) or INADDR_ANY(0.0.0.0).
	//
	// Replace INADDR_ANY (and INADDR_BROADCAST too) with a specific IP (using AdhocServer IP address as reference) in order not to send data through the wrong interface (especially during broadcast),
	// But let's do this only when using built-in Adhoc Server, otherwise UNO won't works
	// if (saddr.in.sin_addr.s_addr == INADDR_ANY || (g_Config.bEnableAdhocServer && saddr.in.sin_addr.s_addr == INADDR_BROADCAST)) {
	// 	// Get Local IP Address
	// 	sockaddr_in sockAddr{};
	// 	getLocalIp(&sockAddr);
	// 	INFO_LOG(Log::sceNet, "Bind: Address Replacement = %s => %s", ip2str(saddr.in.sin_addr).c_str(), ip2str(sockAddr.sin_addr).c_str());
	// 	saddr.in.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
	// }
	// TODO: Make use Port Offset only for PPSSPP to PPSSPP communications (ie. IP addresses available in the group/friendlist), otherwise should be considered as Online Service thus should use the port as is.
	//saddr.in.sin_port = htons(ntohs(saddr.in.sin_port) + portOffset);

	// Update socket debug metadata
	src.host = saddr.in;
	if (src.virt.vport == 0)
		src.virt.vport = user_id.load();

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(src.virt.family).c_str(), ip2str(src.virt.addr).c_str(), ntohs(src.virt.port), ntohs(src.virt.vport));

	// changeBlockingMode(sock, 0);
	int ret = ::bind(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret);
	return ret;
}

// ============================================================================
// TCP Virtual Socket with UPnP transmission capabilities
// ============================================================================
int PacketSocket::send(const char* buf, int len, int flags) { 
	VERBOSE_LOG(Log::sceNet, "SOCK_PACKET::send(buf, %d, %d): state=%d", len, flags, (int)tcp_state);

	// int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	int flgs = convertMSGFlagsPSP2Host(flags);

	std::string msg = "send::PACKET " + ip2str(dst.virt.addr.s_addr) + ":" + std::to_string(ntohs(dst.virt.port)) + 
	"[" + std::to_string(ntohs(dst.virt.vport)) + "] (" + std::to_string(dbg.send) + ", " + 
	std::to_string(dbg.recv) + "/" + std::to_string(dbg.read) + ")";
	INFO_HEXLOG(Log::sceNet, msg.c_str(), buf, len, 386);
	
	int ret = 0;
	if (isLocalTarget(dst.virt.addr.s_addr)) {
		// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
		// g_socketManager.vBroadcast(std::move(send_pkt), dst);
		// tx_seq++; // TODO: Only on ::send success?
		// MSG_NOSIGNAL: a peer that already closed this connection makes send()
		// raise SIGPIPE otherwise. PPSSPP ignores SIGPIPE process-wide at startup,
		// but a native debugger attached to the host binary traps it anyway (it
		// intercepts delivery before our handler runs) - suppress it at the
		// syscall level instead, matching every other raw send()/recv() call site
		// in this codebase.
		ret = ::send(sock, buf, len, flgs | MSG_NOSIGNAL);
		if (ret < 0) {
			return hleLogError(Log::sceNet, ret, "SOCK_PACKET send: Failed to send to local");
		}
		dbg.sent++;
		WARN_LOG(Log::sceNet, "%d bytes send to (%s:%u);", 
			ret, ip2str(dst.virt.addr.s_addr).c_str(), ntohs(dst.virt.port));
	} else {
		// For SOCK_PACKET, send() requires an established connection
		if (tcp_state != TCPState::Established) {
			ERROR_LOG(Log::sceNet, "SOCK_PACKET send: Socket not Established (state=%d)", (int)tcp_state);
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(ENOTCONN);
#else
			socket_errno = ENOTCONN;
#endif
			return -1;
		}
		// Remote delivery to vport (NAT)
		ret = Send_Reliable(buf, len, (p2ps_tcp_flags::PSH | p2ps_tcp_flags::TCP));
		if (ret < 0)
			return hleLogError(Log::sceNet, ret, "SOCK_PACKET send: Failed to send to peer");
		dbg.sent++;

		WARN_LOG(Log::sceNet, "%d bytes send to %s:%u(%u); [tx=%d/rx=%d]", 
			ret, ip2str(dst.virt.addr).c_str(), ntohs(dst.virt.port), ntohs(dst.virt.vport),
			tx_seq, rx_seq);
	}
	
	// // If this socket has broadcast enabled, replicate to other broadcast subscribers on this VPort
	// if ((so_flags & SO_FLAGS_DCCP_BROADCAST) && ret > 0) {
	// 	g_socketManager.BroadcastFromSocket(vport, this, buf, len, &peer);
	// }
	
	return ret;
}
int PacketSocket::recv(char* buf, int len, int flags) {
	VERBOSE_LOG(Log::sceNet, "SOCK_PACKET::recv(buf, %d, %d): state=%d", len, flags, (int)tcp_state);

	// int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	int flgs = convertMSGFlagsPSP2Host(flags);

	// A TCP socket has exactly one peer, held in dst - if it isn't local, this is a
	// virtual connection and data only ever arrives through the DCCP relay queue.
	// The host socket is never connected for these, so it must not be touched.
	if (!isLocalTarget(dst.virt.addr.s_addr)) {
		if (tcp_state == TCPState::SynSent || tcp_state == TCPState::SynReceived) {
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(WSAEWOULDBLOCK);
#else
			socket_errno = EWOULDBLOCK;
#endif
			return hleLogDebug(Log::sceNet, -1, "Socket waiting for Established state (state=%d)", (int)tcp_state);
		}
		if (tcp_state != TCPState::Established && tcp_state != TCPState::CloseWait) {
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(WSAENOTCONN);
#else
			socket_errno = ENOTCONN;
#endif
			return hleLogError(Log::sceNet, -1, "Socket not connected (state=%d)", (int)tcp_state);
		}
		if (!has_pending_data(true)) {
			if (tcp_state == TCPState::CloseWait)
				return 0; // Peer closed and the queue is drained - EOF
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(WSAEWOULDBLOCK);
#else
			socket_errno = EWOULDBLOCK;
#endif
			return hleLogDebug(Log::sceNet, -1, "No virtual data pending (state=%d)", (int)tcp_state);
		}

		sockaddr_in source_addr{};
		int copy_len = dequeue_stream(buf, len, &source_addr, true);

		VERBOSE_LOG(Log::sceNet, "%d bytes received from (%s:%u); [tx=%d/rx=%d]",
			copy_len, inet_ntoa(source_addr.sin_addr), ntohs(source_addr.sin_port),
			tx_seq, rx_seq);

		if (copy_len == 0 && tcp_state != TCPState::CloseWait) {
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(WSAEWOULDBLOCK);
#else
			socket_errno = EWOULDBLOCK;
#endif
			return -1;
		}

		std::string msg = "recv::PACKET " + ip2str(dst.virt.addr.s_addr) + ":" + std::to_string(ntohs(dst.virt.port)) +
		"[" + std::to_string(ntohs(dst.virt.vport)) + "] (" + std::to_string(dbg.send) + ", " +
		std::to_string(dbg.recv) + "/" + std::to_string(dbg.read) + ")";
		INFO_HEXLOG(Log::sceNet, msg.c_str(), buf, copy_len, 386);

		WARN_LOG(Log::sceNet, "%d bytes received from virtual (%s:%u);",
			copy_len, ip2str(dst.virt.addr.s_addr).c_str(), ntohs(dst.virt.port));

		dbg.recv++;
		return copy_len;
	}

	// Local connection: the host socket carries the data
	int ret = ::recv(sock, buf, len, flgs);
	if (ret < 0) {
		// While a connect is in progress the PSP's NetBSD-derived stack treats the
		// socket as SS_ISCONNECTING and recv() waits (EWOULDBLOCK when non-blocking)
		// rather than failing - the local host connect may not have completed yet.
		if (socket_errno == ENOTCONN &&
			(tcp_state == TCPState::SynSent || tcp_state == TCPState::SynReceived)) {
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(WSAEWOULDBLOCK);
#else
			socket_errno = EWOULDBLOCK;
#endif
			return hleLogDebug(Log::sceNet, -1, "Socket waiting for Established state (state=%d)", (int)tcp_state);
		}
		return ret; //return hleLogError(Log::sceNet, ret, "SOCK_PACKET recv: Failed to receive");
	}

	std::string msg = "recv::PACKET " + ip2str(dst.virt.addr.s_addr) + ":" + std::to_string(ntohs(dst.virt.port)) + 
	"[" + std::to_string(ntohs(dst.virt.vport)) + "] (" + std::to_string(dbg.send) + ", " + 
	std::to_string(dbg.recv) + "/" + std::to_string(dbg.read) + ")";
	INFO_HEXLOG(Log::sceNet, msg.c_str(), buf, ret, 386);

	WARN_LOG(Log::sceNet, "%d bytes received from (%s:%u);", 
		ret, ip2str(dst.virt.addr.s_addr).c_str(), ntohs(dst.virt.port));
	return ret;
}
int PacketSocket::connect(SceNetInetSockaddr* name, int namelen) { 
	const sockaddr_in* _dest = reinterpret_cast<const sockaddr_in*>(name);
	// Host Order
	auto _vport = (_dest->sin_zero[0] << 8) | _dest->sin_zero[1];
	INFO_LOG(Log::sceNet, "SOCK_PACKET::connect(%s:%u|%u, %d): state=%d", ip2str(_dest->sin_addr).c_str(), ntohs(_dest->sin_port), _vport, namelen, (int)tcp_state);

	// The remote branch below validates against the state from BEFORE this call
	// overwrites it - otherwise the SynSent assignment here makes that check
	// always fail with EISCONN on the first connect to a non-local peer.
	TCPState prior_state = tcp_state;

	tcp_state = TCPState::SynSent;
	rx_seq = 0;
	tx_seq = 0;

	// Store connected socket
	dst.host.sin_family = AF_INET;
	dst.host.sin_addr.s_addr = _dest->sin_addr.s_addr;
	// Flip PSP port/vports
	dst.virt.port = _dest->sin_port;
	dst.virt.vport = htons(_vport);

	INFO_LOG(Log::sceNet, "PACKET: Connecting to %s:%u on vport %u",
		ip2str(dst.virt.addr.s_addr).c_str(), ntohs(dst.virt.port), ntohs(dst.virt.vport));

	int ret = 0;
	if (isLocalTarget(dst.virt.addr.s_addr)) {
		// Linux's kernel silently rewrites a connect() target of INADDR_ANY to
		// loopback (net/ipv4/af_inet.c, inet_stream_connect); Windows has no such
		// compatibility shim, so connecting to 0.0.0.0 never reaches the listener
		// and the socket sits in SynSent indefinitely. Do the same rewrite
		// ourselves so both platforms actually connect.
		if (dst.host.sin_addr.s_addr == htonl(INADDR_ANY))
			dst.host.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		ret = ::connect(sock, reinterpret_cast<struct sockaddr*>(&dst.host), sizeof(sockaddr_in));
		// g_socketManager.vBroadcast(std::move(send_pkt), dst);
		// tx_seq++;
		// if (ret < 0) {
		// 	return -1; //return hleLogError(Log::sceNet, -1, "SOCK_PACKET connect: Failed to send SYN");
		// }

		if (socket_errno == EAGAIN || socket_errno == EINPROGRESS) {
			// Cache the socket information
			SockAddrIN4 saddr{};
			saddr.addr.sa_family = name->sa_family;
			int len = std::min(namelen > 0 ? namelen : 0, static_cast<int>(sizeof(saddr)));
			name->sa_len = len;
			memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));

			getsockname(sock, (sockaddr*)&saddr, (socklen_t*)&len);
			this->src.host.sin_family = saddr.in.sin_family;
			this->src.virt.addr = saddr.in.sin_addr;
			this->src.virt.port = saddr.in.sin_port; // Adopt the ephemeral port
			this->src.virt.vport = htons(_vport); // Adopt the vport as vport
			// getsockname resets the inet last error, so we need to swap it back
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(EAGAIN);
#else
			socket_errno = EINPROGRESS;
#endif
		}
	} else {
		// DCCP must exist for P2P traffic
		auto p2p_sock = g_socketManager.GetP2PSocket();
		if (!p2p_sock) {
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(EINVAL);
#else
			socket_errno = EINVAL;
#endif
			return hleLogError(Log::sceNet, -1, "SOCK_PACKET connect: P2P_SOCK Not Present");
		}
		// Validate socket is not already connected/connecting
		if (prior_state != TCPState::Disconnected) {
			ERROR_LOG(Log::sceNet, "SOCK_PACKET connect: Socket not in Disconnected state (state=%d)", (int)prior_state);
			tcp_state = prior_state; // undo the clobber above; the existing connection stays as it was
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(EISCONN);
#else
			socket_errno = EISCONN;
#endif
			return hleLogError(Log::sceNet, -1, "SOCK_PACKET connect: Socket not in Disconnected state (state=%d)", (int)prior_state);
		}
		// Flip PSP port/vports
		dst.virt.port = _dest->sin_port;
		dst.virt.vport = htons(_vport);
		
		// Set state to SynSent (waiting for ACK)
		tcp_state = TCPState::SynSent;
		rx_seq = 0;
		tx_seq = 0;
		
		this->src.virt.addr.s_addr = INADDR_ANY;
		this->src.virt.port = htons(g_socketManager.generateEphemeralPort()); // Adopt a unique vport
		this->src.virt.vport =  htons(_vport); // Adopt the destination port
		// this->port = ntohs(_dest->sin_port);

		auto data = std::make_unique<char[]>(2);
		memcpy(data.get(), &src.virt.vport, 2);

		// Assigns the outer ret - declaring a fresh one here shadowed it, making the
		// function return the outer 0 ("connected!") for a SynSent socket.
		// Send_Reliable increments tx_seq itself - no manual increment here.
		ret = Send_Reliable(data.get(), 2, p2ps_tcp_flags::SYN|p2ps_tcp_flags::TCP);
		// int ret = ::sendto(p2p_sock->sock, _data.get(), _len, 0, (struct sockaddr*)&dst.host, sizeof(sockaddr_in));
		if (ret < 0) {

#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(ECONNABORTED);
#else
			socket_errno = ECONNABORTED;
#endif
			return hleLogError(Log::sceNet, -1, "SOCK_PACKET connect: Failed to send SYN");
		}

#if PPSSPP_PLATFORM(WINDOWS)
		SetLastError(EAGAIN);
#else
		socket_errno = EINPROGRESS;
#endif
		ret = -1;
	}
	
	// INFO_LOG(Log::sceNet, "SOCK_PACKET: Connected vport %d to %s:%u",
	// 	vport, inet_ntoa(_dest->sin_addr), ntohs(_dest->sin_port));
	return ret;  // Non-blocking: game will check connection status later
}
int PacketSocket::listen(int backlog) { 
	VERBOSE_LOG(Log::sceNet, "SOCK_PACKET::listen(%d): state=%d", backlog, (int)tcp_state);
	// Validate socket is in correct state
	if (tcp_state != TCPState::Disconnected) {
		ERROR_LOG(Log::sceNet, "SOCK_PACKET listen: Socket not in Disconnected state (state=%d)", (int)tcp_state);
#if PPSSPP_PLATFORM(WINDOWS)
		SetLastError(EINVAL);
#else
		socket_errno = EINVAL;
#endif
		return -1;
	}
		
	// Set state to Listening
	tcp_state = TCPState::Listening;
	this->backlog = backlog;
		
	int ret = ::listen(sock, backlog);
	INFO_LOG(Log::sceNet, "SOCK_PACKET listen: port %d now accepting %d connections", ntohs(src.virt.port), this->backlog);

	return ret;
	// return 0;
}
int PacketSocket::accept(sockaddr* addr, socklen_t* addrlen) { 
	const sockaddr_in* _dest = reinterpret_cast<const sockaddr_in*>(addr);
	INFO_LOG(Log::sceNet, "SOCK_PACKET::accept(%s:%u, %d): pending=%d state=%d", ip2str(this->src.virt.addr).c_str(), ntohs(this->src.virt.port), static_cast<int>(*addrlen), (int)pending_connections.size(), (int)tcp_state);

	if (has_pending_connection()) {
		// Validate socket is listening
		if (tcp_state != TCPState::Listening) {
			ERROR_LOG(Log::sceNet, "Socket not in Listening state (state=%d)", (int)tcp_state);
	#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(EINVAL);
	#else
			socket_errno = EINVAL;
	#endif
			return hleLogError(Log::sceNet, -1, "Socket not in Listening state (state=%d)", (int)tcp_state);
		}

		// Check for pending connection (any SYN that arrived)
		InetSocket* pending_conn = get_pending_connection();
		if (!pending_conn) {
			// No virtual connections
	#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(WSAEWOULDBLOCK);
	#else
			socket_errno = EWOULDBLOCK;
	#endif
			return hleLogDebug(Log::sceNet, -1, "No pending connections.");
		}
		
		// Return the peer address to caller
		if (addr && addrlen) {
			VirtualSockAddr peer = pending_conn->dst;
			memcpy(addr, &peer.host, std::min((size_t)*addrlen, sizeof(sockaddr_in)));
			*addrlen = sizeof(sockaddr_in);
		}
		
		// Create a NEW InetSocket for the accepted connection
		// The listening socket remains in Listening state
		int new_socket_idx = -1;
		int err = 0;
		InetSocket* new_sock = g_socketManager.CreateSocket(&new_socket_idx, &err, SocketState::UsedNetInet, 
			domain, type, protocol);
		
		if (!new_sock) {
	#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(EMFILE);
	#else
			socket_errno = EMFILE;
	#endif
			return hleLogError(Log::sceNet, -1, "Failed to create new socket (errno=%d)", err);
		}
		
		// Top level copy
		new_sock->domain = this->domain;
		new_sock->type = this->type;
		new_sock->protocol = this->protocol;
		new_sock->nonblocking = this->nonblocking;  // should we inherit blocking state?
		// Copy metadata from listening socket to new socket
		new_sock->src.host = this->src.host;

		new_sock->tcp_state = pending_conn->tcp_state;
		// Store connected peer
		new_sock->dst.virt = pending_conn->dst.virt;
		// Store buffer states?
		std::swap(new_sock->rx_queue, pending_conn->rx_queue);
		std::swap(new_sock->rx_buffer, pending_conn->rx_buffer);
		new_sock->rx_seq = pending_conn->rx_seq;
		std::swap(new_sock->tx_buffer, pending_conn->tx_buffer);
		new_sock->tx_seq = pending_conn->tx_seq; // sync with ACK

		new_sock->state = SocketState::UsedNetInet;	
		
		INFO_LOG(Log::sceNet, "SOCK_PACKET accept: Accepted connection on listening socket from %s:%u on %s:%u (vport=%u), created socket %d",
			ip2str(new_sock->dst.virt.addr.s_addr).c_str(), ntohs(new_sock->dst.virt.port),
			ip2str(new_sock->src.virt.addr.s_addr).c_str(), ntohs(new_sock->src.virt.port), ntohs(new_sock->src.virt.vport),
			new_socket_idx);
		// clean-up
		remove_pending_connection(pending_conn);
		return new_socket_idx;
	} else {
		int new_socket_idx = -1;
		int err = 0;

		int ret = ::accept(sock, addr, addrlen);
		if (ret < 0)
			return ret;

		InetSocket* new_sock = g_socketManager.AdoptSocket(&new_socket_idx, ret, this);
		memcpy(&new_sock->src.host, &src.host, std::min((size_t)*addrlen, sizeof(sockaddr_in)));
		
		// Copy metadata from listening socket to new socket
		new_sock->src.host = this->src.host;

		new_sock->tcp_state = TCPState::Established;
		// Store connected peer
		memcpy(&new_sock->dst.host, addr, std::min((size_t)*addrlen, sizeof(sockaddr_in)));
		new_sock->dst.virt.vport = src.virt.vport;

		new_sock->state = SocketState::UsedNetInet;
		INFO_LOG(Log::sceNet, "SOCK_PACKET accept: Accepted connection on listening socket from %s:%u on %s:%u (vport=%u), created socket %d",
			ip2str(new_sock->dst.virt.addr.s_addr).c_str(), ntohs(new_sock->dst.virt.port),
			ip2str(new_sock->src.virt.addr.s_addr).c_str(), ntohs(new_sock->src.virt.port), ntohs(new_sock->src.virt.vport),
			new_socket_idx);
		return new_socket_idx;
	}
}
int PacketSocket::bind(SceNetInetSockaddr* name, int namelen) { 
	SockAddrIN4 saddr{};
	// TODO: Should've created convertSockaddrPSP2Host (and Host2PSP too) function as it's being used pretty often, thus fixing a bug on it will be tedious when scattered all over the places
	saddr.addr.sa_family = name->sa_family;
	int len = std::min(namelen > 0 ? namelen : 0, static_cast<int>(sizeof(saddr)));
	memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));

	VERBOSE_LOG(Log::sceNet, "SOCK_PACKET::bind(%s:%u, %d): state=%d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port), namelen, (int)tcp_state);
	// FIXME: On non-Windows broadcast to INADDR_BROADCAST(255.255.255.255) might not be received by the sender itself when binded to specific IP (ie. 192.168.0.2) or INADDR_BROADCAST.
	//        Meanwhile, it might be received by itself when binded to subnet (ie. 192.168.0.255) or INADDR_ANY(0.0.0.0).
	//
	// Replace INADDR_ANY (and INADDR_BROADCAST too) with a specific IP (using AdhocServer IP address as reference) in order not to send data through the wrong interface (especially during broadcast),
	// But let's do this only when using built-in Adhoc Server, otherwise UNO won't works
	// if (saddr.in.sin_addr.s_addr == INADDR_ANY || (g_Config.bEnableAdhocServer && saddr.in.sin_addr.s_addr == INADDR_BROADCAST)) {
	// 	// Get Local IP Address
	// 	sockaddr_in sockAddr{};
	// 	getLocalIp(&sockAddr);
	// 	INFO_LOG(Log::sceNet, "Bind: Address Replacement = %s => %s", ip2str(saddr.in.sin_addr).c_str(), ip2str(sockAddr.sin_addr).c_str());
	// 	saddr.in.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
	// }
	// TODO: Make use Port Offset only for PPSSPP to PPSSPP communications (ie. IP addresses available in the group/friendlist), otherwise should be considered as Online Service thus should use the port as is.
	//saddr.in.sin_port = htons(ntohs(saddr.in.sin_port) + portOffset);

	// Update socket debug metadata
	src.host = saddr.in;
	// Flip ports
	src.virt.port = src.virt.vport;
	src.virt.vport = saddr.in.sin_port;

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(src.virt.family).c_str(), ip2str(src.virt.addr).c_str(), ntohs(src.virt.port), htons(src.virt.vport));

	// changeBlockingMode(sock, 0);
	int ret = ::bind(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret);
	return ret;
}
int PacketSocket::shutdown(int how) { 
	VERBOSE_LOG(Log::sceNet, "SOCK_PACKET::shutdown(how=%d): state=%d", how, (int)tcp_state);
	// Only allow shutdown if connected
	if (tcp_state != TCPState::Established && tcp_state != TCPState::SynReceived) {
		INFO_LOG(Log::sceNet, "SOCK_PACKET shutdown: Socket not connected (state=%d)", (int)tcp_state);
		return 0;  // Silently ignore if not connected
	}
	// Transition to disconnected
	tcp_state = TCPState::Disconnected;
	g_socketManager.exhaustEphemeralPort(ntohs(src.virt.vport));
	
	// Get DCCP socket for sending FIN
	auto dccp_sock = g_socketManager.GetDCCP();
	if (dccp_sock) {
		// Create the transmission vpacket
		VirtualPacket vpkt;
		vpkt.len = 0;
		vpkt.header_flags = p2ps_tcp_flags::FIN|p2ps_tcp_flags::TCP;
		vpkt.src.host = src.host;
		vpkt.seq_id = tx_seq+1;
		// Add timestamp for TTL tracking
		vpkt.enqueue_time_us = (u64)(time_now_d() * 1000000.0);

		auto send_pkt = vpkt.clone();
		{
			// Add to transmit buffer
			std::lock_guard<std::mutex> lock(buffer_lock);
			// Place at end
			tx_buffer[tx_seq+1] = std::move(vpkt.clone());
		}

		INFO_LOG(Log::sceNet, "SOCK_PACKET shutdown: Sending FIN from port %d to %d", htons(src.virt.vport), htons(dst.virt.vport));
		if (isLocalTarget(dst.virt.port)) {
			// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
			g_socketManager.vBroadcast(std::move(send_pkt), dst);
		} else {
			auto [_len, _data] = send_pkt.Pack(dst.virt.vport);
			int ret = ::sendto(dccp_sock->sock, _data.get(), _len, 0, (struct sockaddr*)&dst.host, sizeof(sockaddr_in));
			if (ret < 0) {
				ERROR_LOG(Log::sceNet, "SOCK_PACKET shutdown: Failed to send FIN");
				// return -1; // Let it shut down the socket anyways
			}
		}
	}
	
	return ::shutdown(sock, how);
}