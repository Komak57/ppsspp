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

u16 SocketManager::generateEphemeralPort() {
    std::lock_guard<std::mutex> guard(g_socketMutex);
	// Start port at 49152, and be 1 higher than all other existing vports
	u16 _vport = 49152;
	auto sockets = g_socketManager.Sockets();
	for (int i = SocketManager::MIN_VALID_INET_SOCKET; i < SocketManager::VALID_INET_SOCKET_COUNT; i++) {
		if (sockets[i].state != SocketState::Unused && sockets[i].port >= _vport)
			_vport = sockets[i].port + 1;
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
		if (sockets[i].state != SocketState::Unused && sockets[i].vport >= _vport)
			_vport = sockets[i].vport + 1;
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
    addr.clear();
    port = 0;
    memset(&dbg, 0, sizeof(dbg));

    // Virtual fields
    tcp_state = TCPState::Disconnected;
    type = 0;
    vport = 0;
    dst_addr = 0;
    dst_port = 0;
    threadID = 0;

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
		switch (type) {
		case PSP_NET_INET_SOCK_STREAM:
			inetSock = new (inetSock) StreamSocket();
			break;
		case PSP_NET_INET_SOCK_DGRAM:
			inetSock = new (inetSock) DgramSocket();
			break;
		case PSP_NET_INET_SOCK_RAW:
			inetSock = new (inetSock) RawSocket();
			break;
		case PSP_NET_INET_SOCK_RDM:
			inetSock = new (inetSock) RdmSocket();
			break;
		case PSP_NET_INET_SOCK_SEQPACKET:
			inetSock = new (inetSock) SeqpacketSocket();
			break;
		case PSP_NET_INET_SOCK_DCCP:
			inetSock = new (inetSock) DccpSocket();
			break;
		case PSP_NET_INET_SOCK_CONN_DGRAM:
			inetSock = new (inetSock) ConnDgramSocket();
			break;
		case PSP_NET_INET_SOCK_PACKET:
			inetSock = new (inetSock) PacketSocket();
			break;
		default:
			inetSock = new (inetSock) InetSocket();  // Fallback to base class
			break;
		}
#pragma pop_macro("new")
		
		inetSock->clear();  // Reset to default.
		inetSock->domain = domain;
		inetSock->type = type;
		inetSock->protocol = protocol;
		inetSock->nonblocking = false;
	}

	switch (type) {
	case PSP_NET_INET_SOCK_PACKET: // Type 10
		inetSock->tcp_state = TCPState::Disconnected;
		break;
	case PSP_NET_INET_SOCK_CONN_DGRAM: // Virtual Socket
		// TODO: Enable SO_REUSEPORT / SO_REUSEADDR with SO_BROADCAST to recycle ports
		inetSock->vport = 0;
		break;
	case PSP_NET_INET_SOCK_DCCP: // Parent to all Virtual Sockets
		dccp_sock = inetSock;
	default: // Normal Socket
		break;
	}

	inetSock->sock = ::socket(hostDomain, hostType, hostProtocol);

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
		switch (type) {
		case PSP_NET_INET_SOCK_STREAM:
			inetSock = new (inetSock) StreamSocket();
			break;
		case PSP_NET_INET_SOCK_DGRAM:
			inetSock = new (inetSock) DgramSocket();
			break;
		case PSP_NET_INET_SOCK_RAW:
			inetSock = new (inetSock) RawSocket();
			break;
		case PSP_NET_INET_SOCK_RDM:
			inetSock = new (inetSock) RdmSocket();
			break;
		case PSP_NET_INET_SOCK_SEQPACKET:
			inetSock = new (inetSock) SeqpacketSocket();
			break;
		case PSP_NET_INET_SOCK_DCCP:
			inetSock = new (inetSock) DccpSocket();
			break;
		case PSP_NET_INET_SOCK_CONN_DGRAM:
			inetSock = new (inetSock) ConnDgramSocket();
			break;
		case PSP_NET_INET_SOCK_PACKET:
			inetSock = new (inetSock) PacketSocket();
			break;
		default:
			inetSock = new (inetSock) InetSocket();  // Fallback to base class
			break;
		}
#pragma pop_macro("new")
		
		inetSock->clear();  // Reset to default.
		inetSock->domain = domain;
		inetSock->type = type;
		inetSock->protocol = protocol;
		inetSock->nonblocking = false;
	}

	switch (type) {
	case PSP_NET_INET_SOCK_PACKET: // Type 10
		inetSock->tcp_state = TCPState::Disconnected;
		break;
	case PSP_NET_INET_SOCK_CONN_DGRAM: // Virtual Socket
		// TODO: Enable SO_REUSEPORT / SO_REUSEADDR with SO_BROADCAST to recycle ports
		inetSock->vport = 0;
		break;
	case PSP_NET_INET_SOCK_DCCP: // Parent to all Virtual Sockets
		dccp_sock = inetSock;
	default: // Normal Socket
		break;
	}

	inetSock->sock = ::socket(hostDomain, hostType, hostProtocol);

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
			switch (derive->type) {
			case PSP_NET_INET_SOCK_STREAM:
				inetSock = new (inetSock) StreamSocket();
				break;
			case PSP_NET_INET_SOCK_DGRAM:
				inetSock = new (inetSock) DgramSocket();
				break;
			case PSP_NET_INET_SOCK_RAW:
				inetSock = new (inetSock) RawSocket();
				break;
			case PSP_NET_INET_SOCK_RDM:
				inetSock = new (inetSock) RdmSocket();
				break;
			case PSP_NET_INET_SOCK_SEQPACKET:
				inetSock = new (inetSock) SeqpacketSocket();
				break;
			case PSP_NET_INET_SOCK_DCCP:
				inetSock = new (inetSock) DccpSocket();
				break;
			case PSP_NET_INET_SOCK_CONN_DGRAM:
				inetSock = new (inetSock) ConnDgramSocket();
				break;
			case PSP_NET_INET_SOCK_PACKET:
				inetSock = new (inetSock) PacketSocket();
				break;
			default:
				inetSock = new (inetSock) InetSocket();
				break;
			}
#pragma pop_macro("new")

			inetSock->sock = hostSocket;
			inetSock->state = derive->state;
			inetSock->domain = derive->domain;
			inetSock->type = derive->type;
			inetSock->protocol = derive->protocol;
			inetSock->nonblocking = derive->nonblocking;  // should we inherit blocking state?
			if (derive->type == PSP_NET_INET_SOCK_CONN_DGRAM)
				inetSock->port = derive->port; // We only need this if we're adopting a CONN_DGRAM (unlikely)
			return inetSock;
		}
	}

	// No space? Return nullptr and let the caller handle it. Shouldn't ever happen.
	*index = 0;
	return nullptr;
}

void SocketManager::ProcessNetStack(int* timeout) {
	// Process Remote to Local first
	while (dccp_sock->ProcessNetStack()) {
		// auto start = std::chrono::steady_clock::now();
		// bool hadPacket = ;
		// auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
		// *timeout = (*timeout > elapsed) ? (*timeout - elapsed) : 0;
		// if (!hadPacket) return;
	}
	std::vector<std::pair<VirtualPacket, uint16_t>> outbuf; // <packet, dst_port>
	// Process Each Local Once
	for (int i = MIN_VALID_INET_SOCKET; i < VALID_INET_SOCKET_COUNT; i++) {
		InetSocket* s = &inetSockets_[i];
		if (s->state != SocketState::Unused && s->type == PSP_NET_INET_SOCK_PACKET) {
			// Run the emulated protocol stack for this socket
			// s->ProcessNetStack();

			uint8_t expected_flag = 0;
			switch (s->tcp_state) {
				case TCPState::SynSent:			expected_flag = p2ps_tcp_flags::SYN; break;
				case TCPState::SynReceived:		expected_flag = (p2ps_tcp_flags::SYN|p2ps_tcp_flags::ACK); break;
				case TCPState::Disconnected:	expected_flag = p2ps_tcp_flags::FIN; break;
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
				if (!flags.empty()) flags.pop_back(); // strip trailing '|'

				WARN_LOG(Log::sceNet, "PACKET: Re-Sending %s at listening socket from %s:%u to %s:%u",
					flags.c_str(), inet_ntoa(pkt.src_addr.sin_addr), ntohs(pkt.src_addr.sin_port), s->addr.c_str(), s->port);
				if (isLocalTarget(s->dst_addr)) {
					outbuf.push_back({std::move(vpkt), s->dst_port});
					// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
					// g_socketManager.vBroadcast(std::move(vpkt), htons(s->dst_port));
					pkt.last_sent_us = now_us;
					pkt.sent_count++;
				} else {
					sockaddr_in peer{};
					peer.sin_family = AF_INET;
					peer.sin_addr.s_addr = s->dst_addr;
					peer.sin_port = htons(s->dst_port);

					auto [_len, _data] = vpkt.Pack(s->port);
					auto dccp_sock = g_socketManager.GetDCCP();
					// Skip local send
					int ret = ::sendto(dccp_sock->sock, _data.get(), _len, 0, (struct sockaddr*)&peer, sizeof(sockaddr_in));
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
					case TCPState::SynSent:			expected_flag = p2ps_tcp_flags::SYN; break;
					case TCPState::SynReceived:		expected_flag = (p2ps_tcp_flags::SYN|p2ps_tcp_flags::ACK); break;
					case TCPState::Disconnected:	expected_flag = p2ps_tcp_flags::FIN; break;
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
					if (!flags.empty()) flags.pop_back(); // strip trailing '|'

					WARN_LOG(Log::sceNet, "PACKET: Re-Sending %s at listening socket from %s:%u to %s:%u",
						flags.c_str(), inet_ntoa(pkt.src_addr.sin_addr), ntohs(pkt.src_addr.sin_port), s->addr.c_str(), s->port);
					if (isLocalTarget(conn->dst_addr)) {
						outbuf.push_back({std::move(vpkt), conn->dst_port});
						// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
						// g_socketManager.vBroadcast(std::move(vpkt), htons(conn->dst_port));
						pkt.last_sent_us = now_us;
						pkt.sent_count++;
					} else {
						sockaddr_in peer{};
						peer.sin_family = AF_INET;
						peer.sin_addr.s_addr = conn->dst_addr;
						peer.sin_port = htons(conn->dst_port);

						auto [_len, _data] = vpkt.Pack(conn->port);
						auto dccp_sock = g_socketManager.GetDCCP();
						// Skip local send
						int ret = ::sendto(dccp_sock->sock, _data.get(), _len, 0, (struct sockaddr*)&peer, sizeof(sockaddr_in));
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
	for (auto& [vpkt, dst_port] : outbuf) {
        g_socketManager.vBroadcast(std::move(vpkt), htons(dst_port));
    }
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
	if (sock < MIN_VALID_INET_SOCKET || sock >= ARRAY_SIZE(inetSockets_) || inetSockets_[sock].state == SocketState::Unused) {
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

int SocketManager::vBroadcast(VirtualPacket&& vpkt, u16 port) {
    int delivered_count = 0;
    
    // Match sockets by vport (port-based routing instead of subscriptions)
    for (int i = 0; i < SocketManager::VALID_INET_SOCKET_COUNT; i++) {
        InetSocket* target_sock = &inetSockets_[i];
        
        // Skip unused sockets
        if (!target_sock || target_sock->state == SocketState::Unused) {
            continue;
        }

        // Match only virtual socket types (PACKET and CONN_DGRAM)
        if (target_sock->type != PSP_NET_INET_SOCK_PACKET && target_sock->type != PSP_NET_INET_SOCK_CONN_DGRAM) {
            continue;
        }
        
		if (target_sock->type == PSP_NET_INET_SOCK_PACKET && target_sock->tcp_state != TCPState::Listening) {
			if ((target_sock->dst_addr != vpkt.src_addr.sin_addr.s_addr && target_sock->dst_addr != 0 && vpkt.src_addr.sin_addr.s_addr != 0) || htons(target_sock->dst_port) != vpkt.src_addr.sin_port) {
				continue;
			}
		}

		if (target_sock->port != ntohs(port)) {
			continue;
		}

        // // Match by vport (convert from network order for comparison)
        // if (target_sock->type == PSP_NET_INET_SOCK_PACKET && htons(target_sock->port) != port) {
        //     continue;  // Not subscribed to this vport
        // }
        // // if (target_sock->type == PSP_NET_INET_SOCK_CONN_DGRAM && htons(target_sock->vport) != header.vport) {
        // if (target_sock->type == PSP_NET_INET_SOCK_CONN_DGRAM && htons(target_sock->port) != port) {
        //     continue;  // Not subscribed to this vport
        // }
        
        DEBUG_LOG(Log::sceNet, "RouteDCCP: Processing socket vport %d (type=%d)", 
            target_sock->vport, target_sock->type);

		// VirtualPacket vpkt;
		// if (data_len > 0 && packet_data != nullptr) {
		// 	vpkt.data = std::make_unique<char[]>(data_len);
		// 	memcpy(vpkt.data.get(), packet_data, data_len);
		// }
		// vpkt.len = data_len;
		// vpkt.header_flags = header.flags;
		// vpkt.src_addr = _from;

		INFO_LOG(Log::sceNet, "RouteDCCP: DELIVERING %d bytes to port %s:%u (type=%d, vport=%d) from %s:%u", 
			vpkt.len, target_sock->addr.c_str(), target_sock->port, target_sock->type, target_sock->vport, inet_ntoa(vpkt.src_addr.sin_addr), ntohs(vpkt.src_addr.sin_port));
		
		target_sock->enqueue_packet(vpkt.clone());
		delivered_count++;

		// Do not immediately process the net stack
		// This will reduce unecessary network traffic


		if (target_sock->ProcessNetStack()) {
			continue;
		}

		DEBUG_LOG(Log::sceNet, "RouteDCCP: NOT delivering to vport %d (deliver_data=false)", target_sock->vport);
    }
    
    if (delivered_count > 0) {
        DEBUG_LOG(Log::sceNet, "RouteDCCP: Total delivered to %d subscribers on VPort %d", delivered_count, port);
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
int InetSocket::select(SceNetInetFdSet* readfds, SceNetInetFdSet* writefds, SceNetInetFdSet* exceptfds, SceNetInetTimeval* timeout) { errno = EOPNOTSUPP; return -1; }
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
			nonblocking = optval == 1;
			// return hleLogWarning(Log::sceNet, 0, "%s emulated", host_optname_str.c_str());
		case PSP_NET_INET_SO_REUSEADDR:// TODO: Ignoring SO_REUSEADDR flag to prevent disrupting multiple-instance feature
			return hleLogWarning(Log::sceNet, 0, "%s not supported, ignoring", host_optname_str.c_str());
		case PSP_NET_INET_SO_REUSEPORT:// TODO: Ignoring SO_REUSEPORT flag to prevent disrupting multiple-instance feature (not sure if PSP has SO_REUSEPORT or not tho, defined as 15 on Android)
			return hleLogWarning(Log::sceNet, 0, "%s not supported, ignoring", host_optname_str.c_str());
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
		DEBUG_LOG(Log::sceNet, "InetSocket::setsockopt: failed for level=%d optname=%d, accepting gracefully", level, optname);
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
			if (so_flags.size() >= sizeof(int)) {
			int flag = *reinterpret_cast<const int*>(so_flags.data());
			nonblocking = (flag != 0);
			} else if (!so_flags.empty()) {
				nonblocking = (so_flags[0] != 0);
			}
			return hleLogWarning(Log::sceNet, 0, "%s emulated", host_optname_str.c_str());
		case PSP_NET_INET_SO_BROADCAST:
			return hleLogWarning(Log::sceNet, 0, "%s not supported, ignoring", host_optname_str.c_str());
		case PSP_NET_INET_SO_REUSEADDR:
			return hleLogWarning(Log::sceNet, 0, "%s not supported, ignoring", host_optname_str.c_str());
		case PSP_NET_INET_SO_REUSEPORT:
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

	int ret = ::setsockopt(sock, host_level, host_optname, reinterpret_cast<char*>(&optval), optlen);
	if (ret < 0) {
		return hleLogWarning(Log::sceNet, 0, "InetSocket::setsockopt: failed for level=%d optname=%d, accepting gracefully", level, optname);
	}
	return ret;
}
int InetSocket::getsockopt(int level, int optname, char* optval, socklen_t* optlen) {
	if (!optval || !optlen) return -1;

    // 1. Check our Internal Shadow Registry first
    uint64_t optkey = ((uint64_t)level << 32) | (uint32_t)optname;
    
    if (so_storage.count(optkey)) {
        auto& cached_data = so_storage[optkey];
        
        // Copy only what fits in the caller's buffer to prevent overflows
        socklen_t copy_len = std::min(*optlen, (socklen_t)cached_data.size());
        memcpy(optval, cached_data.data(), copy_len);
        
        // Update the caller on how many bytes were actually written
        *optlen = copy_len;
        return 0;
    }

    // 2. Fallback: Ask the Host OS
    int host_level = convertSockoptLevelPSP2Host(level);
    int host_optname = convertSockoptNamePSP2Host(optname, level);

    if (host_optname != -1) {
        int ret = ::getsockopt(sock, host_level, host_optname, reinterpret_cast<char*>(optval), optlen);
        
        // If the host call succeeds, cache it for next time
        if (ret == 0) {
            auto& so_flags = so_storage[optkey];
            so_flags.assign(reinterpret_cast<const uint8_t*>(optval), 
                         reinterpret_cast<const uint8_t*>(optval) + *optlen);
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
bool InetSocket::ProcessNetStack() { return false; }
void InetSocket::enqueue_packet(VirtualPacket packet) {
	std::lock_guard<std::mutex> queue(queue_lock);
	// Add timestamp for TTL tracking
	packet.enqueue_time_us = (u64)(time_now_d() * 1000000.0);
	rx_queue.push_back(std::move(packet));
	DEBUG_LOG(Log::sceNet, "Enqueued packet for vport %d (queue size: %zu)", vport, rx_queue.size());
}
bool InetSocket::dequeue_packet(VirtualPacket& packet) {
	std::lock_guard<std::mutex> buffers(buffer_lock);
	const u64 MAX_PACKET_AGE_US = 30000000;  // 30 seconds
	
	while (!rx_buffer.empty()) {
		auto it = rx_buffer.begin();
		int next = it->first;
		packet = std::move(rx_buffer.begin()->second);
		rx_buffer.erase(next);
		
		// Check packet TTL
		u64 current_time_us = (u64)(time_now_d() * 1000000.0);
		u64 packet_age_us = current_time_us - packet.enqueue_time_us;
		
		if (packet_age_us > MAX_PACKET_AGE_US) {
            WARN_LOG(Log::sceNet, "dequeue_stream: Receiving stale packet (age: %.2f seconds)", (float)packet_age_us / 1000000.0f);
		}
		
		DEBUG_LOG(Log::sceNet, "Dequeued packet from vport %d (queue size: %zu)", vport, rx_buffer.size());
		return true;
	}
	
	return false;  // Queue is empty
}
int InetSocket::dequeue_stream(char* buf, int len, sockaddr_in* out_addr) {
	std::lock_guard<std::mutex> buffers(buffer_lock);
    const u64 MAX_PACKET_AGE_US = 30000000;  // 30 seconds
    u64 current_time_us = (u64)(time_now_d() * 1000000.0);
    
    int total_copied = 0;
    bool target_locked = false;
    sockaddr_in target_addr{};

	if (!rx_buffer.empty())
		WARN_LOG(Log::sceNet, "dequeue_stream: Missing next packet");
    
	auto it = rx_buffer.begin();
    while (it != rx_buffer.end()) {
        // Peek at the front packet (do NOT pop yet)
        VirtualPacket& peek_pkt = it->second;
        // Now we know we are consuming this packet (at least partially), so pop it
		rx_buffer.erase(it);
        
        // Check packet TTL
        u64 packet_age_us = current_time_us - peek_pkt.enqueue_time_us;
        if (packet_age_us > MAX_PACKET_AGE_US) {
            WARN_LOG(Log::sceNet, "dequeue_stream: Receiving stale packet (age: %.2f seconds)", (float)packet_age_us / 1000000.0f);
        }

        // Lock onto the first valid packet's source address
        if (!target_locked) {
            target_addr = peek_pkt.src_addr;
            target_locked = true;
            if (out_addr) {
                *out_addr = target_addr;
            }
        } else {
            // If we are continuing to fill the buffer, ensure this next packet is from the SAME source
            if (peek_pkt.src_addr.sin_addr.s_addr != target_addr.sin_addr.s_addr ||
                peek_pkt.src_addr.sin_port != target_addr.sin_port) {
                
                DEBUG_LOG(Log::sceNet, "dequeue_stream: Source mismatch detected. Halting coalescing. (Expected %s:%u, got %s:%u)",
                    inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port),
                    inet_ntoa(peek_pkt.src_addr.sin_addr), ntohs(peek_pkt.src_addr.sin_port));
                break; // Stop coalescing and leave this packet in the queue
            }
        }
        
		rx_seq++;
        VirtualPacket packet = std::move(rx_buffer.find(rx_seq)->second);
        rx_buffer.erase(rx_seq);
        
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
            remainder.src_addr = packet.src_addr;
            remainder.enqueue_time_us = packet.enqueue_time_us; // Preserve TTL
            
			rx_buffer[rx_seq] = std::move(remainder);
			rx_seq--; // mark this as the next packet to receive
            break; // Buffer is full
        }
    }
    
    return total_copied;
}
bool InetSocket::has_pending_data() const {
	std::lock_guard<std::mutex> buffers(buffer_lock);
	return (!rx_buffer.empty());
}
bool InetSocket::set_pending_connection(InetSocket* conn) {
	ERROR_LOG(Log::sceNet, "Socket does not support connections");
	delete conn;
	return false;
}
bool InetSocket::update_pending_connection(const sockaddr_in& peer_addr) {
	ERROR_LOG(Log::sceNet, "Socket does not support connections");
	return false;
}
InetSocket* InetSocket::get_pending_connection() {
	ERROR_LOG(Log::sceNet, "Socket does not support connections");
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
	// ERROR_LOG(Log::sceNet, "Socket does not support connections");
    return false;
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
	if (ret < 0) {
		int pspErrno = UpdateErrnoFromHost(__KernelGetCurThread(), hostErrno, __FUNCTION__);
		if (connectInProgress(hostErrno))
			return hleLogDebug(Log::sceNet, ret, "errno = %s Address = %s, Port = %d", convertInetErrno2str(pspErrno), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
		else
			return hleLogError(Log::sceNet, ret, "errno = %s Address = %s, Port = %d", convertInetErrno2str(pspErrno), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
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
	addr = ip2str(saddr.in.sin_addr);
	port = ntohs(saddr.in.sin_port);
	// The PSP is expected to provide 0, and we need to generate a vport
	// This is later "agreed" upon in the P2P handshake?
	vport = (saddr.in.sin_zero[0] << 8) | saddr.in.sin_zero[1];

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(saddr.addr.sa_family).c_str(), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port), vport);

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
int DgramSocket::select(SceNetInetFdSet* readfds, SceNetInetFdSet* writefds, SceNetInetFdSet* exceptfds, SceNetInetTimeval* timeout) {

	// First, translate the specified fd_sets to host sockets.
	fd_set rdfds, wrfds, exfds;
	FD_ZERO(&rdfds);
	FD_ZERO(&wrfds);
	FD_ZERO(&exfds);

	timeval tmout = { 5, 543210 }; // Workaround timeout value when timeout = NULL
	if (timeout) {
		tmout.tv_sec = timeout->tv_sec;
		tmout.tv_usec = timeout->tv_usec;
	}
	// TODO: Simulate blocking behaviour when timeout = NULL to prevent PPSSPP from freezing
	// Note: select can overwrite tmout.
	int retval = ::select(sock, readfds ? &rdfds : nullptr, writefds ? &wrfds : nullptr, exceptfds ? &exfds : nullptr, &tmout);


	// Convert the results back to PSP fd_sets.
	if (readfds)
		NetInetFD_ZERO(readfds);
	if (writefds)
		NetInetFD_ZERO(writefds);
	if (exceptfds)
		NetInetFD_ZERO(exceptfds);

	return retval;
}
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
	addr = ip2str(saddr.in.sin_addr);
	port = ntohs(saddr.in.sin_port);
	// The PSP is expected to provide 0, and we need to generate a vport
	// This is later "agreed" upon in the P2P handshake?
	vport = (saddr.in.sin_zero[0] << 8) | saddr.in.sin_zero[1];

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(saddr.addr.sa_family).c_str(), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port), vport);

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
	addr = ip2str(saddr.in.sin_addr);
	port = ntohs(saddr.in.sin_port);
	// The PSP is expected to provide 0, and we need to generate a vport
	// This is later "agreed" upon in the P2P handshake?
	vport = (saddr.in.sin_zero[0] << 8) | saddr.in.sin_zero[1];

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(saddr.addr.sa_family).c_str(), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port), vport);

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
	addr = ip2str(saddr.in.sin_addr);
	port = ntohs(saddr.in.sin_port);
	// The PSP is expected to provide 0, and we need to generate a vport
	// This is later "agreed" upon in the P2P handshake?
	vport = (saddr.in.sin_zero[0] << 8) | saddr.in.sin_zero[1];

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(saddr.addr.sa_family).c_str(), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port), vport);

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
	if (ret < 0) {
		int pspErrno = UpdateErrnoFromHost(__KernelGetCurThread(), hostErrno, __FUNCTION__);
		if (connectInProgress(hostErrno))
			return hleLogDebug(Log::sceNet, ret, "errno = %s Address = %s, Port = %d", convertInetErrno2str(pspErrno), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
		else
			return hleLogError(Log::sceNet, ret, "errno = %s Address = %s, Port = %d", convertInetErrno2str(pspErrno), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
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
	addr = ip2str(saddr.in.sin_addr);
	port = ntohs(saddr.in.sin_port);
	// The PSP is expected to provide 0, and we need to generate a vport
	// This is later "agreed" upon in the P2P handshake?
	vport = (saddr.in.sin_zero[0] << 8) | saddr.in.sin_zero[1];

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(saddr.addr.sa_family).c_str(), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port), vport);

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
	if (ret < 0) {
		int pspErrno = UpdateErrnoFromHost(__KernelGetCurThread(), hostErrno, __FUNCTION__);
		if (connectInProgress(hostErrno))
			return hleLogDebug(Log::sceNet, ret, "errno = %s Address = %s, Port = %d", convertInetErrno2str(pspErrno), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
		else
			return hleLogError(Log::sceNet, ret, "errno = %s Address = %s, Port = %d", convertInetErrno2str(pspErrno), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
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
	addr = ip2str(saddr.in.sin_addr);
	port = ntohs(saddr.in.sin_port);
	// The PSP is expected to provide 0, and we need to generate a vport
	// This is later "agreed" upon in the P2P handshake?
	vport = (saddr.in.sin_zero[0] << 8) | saddr.in.sin_zero[1];

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(saddr.addr.sa_family).c_str(), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port), vport);

	// changeBlockingMode(sock, 0);
	int ret = ::bind(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret);
	return ret;
}
int DccpSocket::shutdown(int how) { return ::shutdown(sock, how); }
bool DccpSocket::ProcessNetStack() {
	// Clear the error
#if PPSSPP_PLATFORM(WINDOWS)
	SetLastError(0);
#else
	socket_errno = 0;
#endif

	char data[2048];
	sockaddr_in _from{};
	socklen_t _fromlen = sizeof(_from);
	int ret = ::recvfrom(sock, data, sizeof(data), 0, reinterpret_cast<sockaddr*>(&_from), &_fromlen);
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
	if (ret - i >= sizeof(vpkt.seq_id) && header.dest != 0) {
		memcpy(&vpkt.seq_id, data, sizeof(vpkt.seq_id));
		i += sizeof(vpkt.seq_id);
	}
	vpkt.len = ret - i;
	if (vpkt.len > 0) {
		vpkt.data = std::make_unique<char[]>(vpkt.len);
		memcpy(vpkt.data.get(), data+i, vpkt.len);
	}
	vpkt.header_flags = header.flags;
	vpkt.src_addr.sin_family = AF_INET;
	// vpkt.src_addr.sin_addr.s_addr = this->addr;
	if (inet_pton(AF_INET, this->addr.c_str(), &vpkt.src_addr.sin_addr) <= 0) {
		vpkt.src_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
	}
	vpkt.src_addr = _from;
	// Add timestamp for TTL tracking
	vpkt.enqueue_time_us = (u64)(time_now_d() * 1000000.0);

	// Log incoming packet details (convert vport from network to host byte order for display)
	INFO_LOG(Log::sceNet, "RouteDCCP: Received %d bytes from %s:%u -> VPort %d (flags=0x%02x, subset=%d)", 
		ret, inet_ntoa(_from.sin_addr), ntohs(_from.sin_port), ntohs(header.dest), header.flags, header.flags & 0xFF);
	
	g_socketManager.vBroadcast(std::move(vpkt), header.dest);
	
	return true;
}

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

	// DCCP must exist for P2P traffic
	auto dccp_sock = g_socketManager.GetDCCP();
	if (!dccp_sock) {
#if PPSSPP_PLATFORM(WINDOWS)
		SetLastError(EINVAL);
#else
		socket_errno = EINVAL;
#endif
		return hleLogError(Log::sceNet, -1, "SOCK_PACKET connect: DCCP_SOCK Not Present");
	}
	
	// Create the transmission vpacket
	VirtualPacket vpkt;
	vpkt.data = std::make_unique<char[]>(len);
	memcpy(vpkt.data.get(), buf, len);
	vpkt.len = len;
	vpkt.header_flags = p2ps_tcp_flags::PSH;
	vpkt.src_addr.sin_family = AF_INET;
	// vpkt.src_addr.sin_addr.s_addr = this->addr;
	if (inet_pton(AF_INET, this->addr.c_str(), &vpkt.src_addr.sin_addr) <= 0) {
		vpkt.src_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
	}
	vpkt.src_addr.sin_port = htons(port);
	vpkt.seq_id = tx_seq+1;
	// Add timestamp for TTL tracking
	vpkt.enqueue_time_us = (u64)(time_now_d() * 1000000.0);

	// // Build packet: VPORT_HEADER + payload
	// int packet_size = VPORT_HEADER_SIZE + len;
	// std::unique_ptr<char[]> packet = std::make_unique<char[]>(packet_size);

	// // Pack DGRAM_HEADER (3 bytes): [flags][data_len]
	// VPORT_HEADER header;
	// header.flags = p2ps_tcp_flags::PSH;
	// header.dest = htons(port);
	// header.dest = (saddr.in.sin_zero[1] << 8) | saddr.in.sin_zero[0];
	// // Do not send on vport 0
	// if (header.dest == 0)
	// 	header.dest = htons(1);
	// memcpy(&header.dest, &saddr.in.sin_zero[0], 2);
	// memcpy(packet.get(), &header, VPORT_HEADER_SIZE);

	// // Pack the message body
	// if (len > 0) {
	// 	memcpy(packet.get() + VPORT_HEADER_SIZE, buf, len);
	// }

	std::string msg = "sendto::SIGN " + std::to_string(vport) + " -> " +
		ip2str(_dest->sin_addr) + ":" + std::to_string(ntohs(_dest->sin_port)) + 
		"{" + std::to_string(ntohs(dest_vport)) + "|" +std::to_string(vpkt.header_flags) + "}";
	INFO_HEXLOG(Log::sceNet, msg.c_str(), buf, len, 386);

	// Send the packet over P2P
	auto [_len, _data] = vpkt.Pack(port);
	// Send through DCCP
	int ret = ::sendto(dccp_sock->sock, _data.get(), _len, flgs, (struct sockaddr*)&saddr.addr, sizeof(sockaddr));
	if (ret > 0)
		dbg.sent++;
	tx_seq++;
	
	DEBUG_LOG(Log::sceNet, "VPORT %d s(%d/%d) r(%d,%d)", vport, dbg.sent, dbg.send, dbg.recv, dbg.read);

	// Now shotgun-send using all peer id's
	// if (sigServer) {
	// 	std::vector<SceNpMatching2RoomMemberId> peers = sigServer->GetPeerList();
	// 	for (auto peer : peers) {
	// 		// Alter the vport to point at the peer
	// 		header.vport = htons(peer);
	// 		memcpy(packet.get(), &header, VPORT_HEADER_SIZE);
	// 		::sendto(dccp_sock->sock, packet.get(), packet_size, flags, (struct sockaddr*)&saddr.addr, sizeof(sockaddr));
	// 	}
	// }

	return ret;
 }
int ConnDgramSocket::recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) { 
	dbg.read++;
	SockAddrIN4 saddr{};
	if (fromlen)
		*fromlen = std::min((*fromlen) > 0 ? *fromlen : 0, static_cast<socklen_t>(sizeof(saddr)));
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);

	// Dequeue from local packet queue for virtual sockets
	VirtualPacket pkt;
	if (!dequeue_packet(pkt)) {
		// Empty Queue, try actual socket
		int ret = ::recvfrom(sock, buf, len, flags, (struct sockaddr*)&saddr.addr, fromlen);
		if (ret > 0)
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
		from_in->sin_addr = pkt.src_addr.sin_addr;
		from_in->sin_port = pkt.src_addr.sin_port;
		*fromlen = sizeof(sockaddr_in);  // Always set to actual size
		
		// Log with hex dump at INFO level so we see packet pickup
		std::string msg = "recvfrom(vport " + std::to_string(vport) + "): picked up " + 
			std::to_string(copy_len) + " bytes from " + ip2str(from_in->sin_addr.s_addr) + 
			":" + std::to_string(ntohs(from_in->sin_port));
		INFO_HEXLOG(Log::sceNet, msg.c_str(), buf, (int)copy_len, 256);
	}
	
	dbg.recv++;
	
	// Log truncation if it occurred
	if (copy_len < pkt.len) {
		DEBUG_LOG(Log::sceNet, "recvfrom: TRUNCATED packet for vport %d (buf=%zu, pkt=%zu, discarding %zu bytes)",
			vport, copy_len, pkt.len, pkt.len - copy_len);
	}

	DEBUG_LOG(Log::sceNet, "VPORT %d s(%d/%d) r(%d,%d)", vport, dbg.sent, dbg.send, dbg.recv, dbg.read);
		// Return actual bytes copied (NOT padded to requested size)
	return hleLogDebug(Log::sceNet, (int)copy_len, "RecvFrom: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
}
int ConnDgramSocket::bind(SceNetInetSockaddr* name, int namelen) { 
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
	addr = ip2str(saddr.in.sin_addr);
	port = ntohs(saddr.in.sin_port);
	// if (port == 0)
		// port = SCE_SIGN_PORT;
	saddr.in.sin_port = 0; // Emulate SO_BROADCAST + SO_REUSEPORT
	// The PSP is expected to provide 0, and we need to generate a vport?
	// This is later "agreed" upon in the P2P handshake?
	// Alternatively, these don't have unique identifiers, and are expected to BROADCAST to all?
	vport = (saddr.in.sin_zero[0] << 8) | saddr.in.sin_zero[1];
	if (vport == 0)
		vport = user_id.load();

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, NewPort = %d, VPort = %d", inetSocketDomain2str(saddr.addr.sa_family).c_str(), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port), port, vport);

	// changeBlockingMode(sock, 0);
	int ret = ::bind(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret);
	return ret;
}
int ConnDgramSocket::select(SceNetInetFdSet* readfds, SceNetInetFdSet* writefds, SceNetInetFdSet* exceptfds, SceNetInetTimeval* timeout) {
	// First, translate the specified fd_sets to host sockets.
	fd_set rdfds, wrfds, exfds;
	FD_ZERO(&rdfds);
	FD_ZERO(&wrfds);
	FD_ZERO(&exfds);

	// Log select() calls on virtual sockets for debugging
	INFO_LOG(Log::sceNet, "select: vport %d called (type=%d, readfds=%p, timeout=%p)", 
		vport, type, readfds, timeout);
	
	if (readfds && has_pending_data()) {
		INFO_LOG(Log::sceNet, "select: vport %d HAS PENDING DATA, returning 1", vport);
		return 1;
	}
	
	// If we get here with readfds set, there's no data
	if (readfds) {
		INFO_LOG(Log::sceNet, "select: vport %d NO PENDING DATA", vport);
	}
	
	if (writefds) {
		bool writable = false;
		if (type == PSP_NET_INET_SOCK_CONN_DGRAM) {
			writable = true;  // UDP always writable
		} else if (type == PSP_NET_INET_SOCK_PACKET) {
			writable = (tcp_state == TCPState::Established || tcp_state == TCPState::SynReceived);
		}
		
		if (writable) {
			INFO_LOG(Log::sceNet, "select: vport %d is writable, returning 1", vport);
			return 1;
		}
	}
	
	// 2. Physical Socket Checks
	// Poll the underlying physical socket using a non-blocking select
	timeval tv_zero = {0, 0};
	
	// We MUST copy the fd_sets. A 0-timeout select will clear the sets if nothing is ready,
	// and we don't want to destroy the caller's sets if only virtual data becomes ready later.
	fd_set read_copy, write_copy, exc_copy;
	fd_set* p_read = nullptr;
	fd_set* p_write = nullptr;
	fd_set* p_exc = nullptr;
	
	if (readfds)   { read_copy = rdfds;   p_read = &read_copy;   }
	if (writefds)  { write_copy = wrfds; p_write = &write_copy; }
	if (exceptfds) { exc_copy = exfds;  p_exc = &exc_copy;     }
	
	// Using 'sock' mirrors your default fallback behavior
	int phys_ready = ::select(sock, p_read, p_write, p_exc, &tv_zero);
	if (phys_ready > 0) {
		DEBUG_LOG(Log::sceNet, "select: vport %d has physical data/events", vport);
		// Copy back the mutated sets so the caller knows exactly what triggered
		// if (readfds)   *readfds = read_copy;
		// if (writefds)  *writefds = write_copy;
		// if (exceptfds) *exceptfds = exc_copy;

		// Convert the results back to PSP fd_sets.
		if (readfds)
			NetInetFD_ZERO(readfds);
		if (writefds)
			NetInetFD_ZERO(writefds);
		if (exceptfds)
			NetInetFD_ZERO(exceptfds);
		return phys_ready;
	}
	
	// Nothing ready yet
	return 0;
	// Wait Logic?
}
bool ConnDgramSocket::ProcessNetStack() {
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
            WARN_LOG(Log::sceNet, "ProcessNetStack: Discarding stale packet (age: %.2f s)", 
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
// ============================================================================
// TCP Virtual Socket with UPnP transmission capabilities
// ============================================================================

int PacketSocket::send(const char* buf, int len, int flags) { 
	VERBOSE_LOG(Log::sceNet, "SOCK_PACKET::send(buf, %d, %d): state=%d", len, flags, (int)tcp_state);
	// // Delegate to sendto with peer address
	// sockaddr_in peer;
	// peer.sin_family = AF_INET;
	// peer.sin_addr.s_addr = dst_addr;
	// peer.sin_port = htons(dst_port);
	
	// DCCP must exist for P2P traffic
	auto dccp_sock = g_socketManager.GetDCCP();
	if (!dccp_sock) {
#if PPSSPP_PLATFORM(WINDOWS)
		SetLastError(EINVAL);
#else
		socket_errno = EINVAL;
#endif
		return hleLogError(Log::sceNet, -1, "SOCK_PACKET connect: DCCP_SOCK Not Present");
	}

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

	// auto next_seq = htonl(tx_seq+1);
	// // Build packet: VPORT_HEADER + payload
	// int packet_size = VPORT_HEADER_SIZE + len + sizeof(next_seq);
	// std::unique_ptr<char[]> packet = std::make_unique<char[]>(packet_size);

	// // Pack DGRAM_HEADER (3 bytes): [flags][data_len]
	// VPORT_HEADER header;
	// header.flags = p2ps_tcp_flags::PSH;
	// header.vport = htons(dst_port);
	// memcpy(packet.get(), &header, VPORT_HEADER_SIZE);
	// memcpy(packet.get() + VPORT_HEADER_SIZE, &next_seq, sizeof(next_seq));

	// // Add the message
    // if (len > 0 && buf != nullptr)
    //     memcpy(packet.get() + VPORT_HEADER_SIZE + sizeof(next_seq), buf, len);

	std::string msg = "send::PACKET " + ip2str(dst_addr) + ":" + std::to_string(dst_port) + 
	"[" + std::to_string(vport) + "] (" + std::to_string(dbg.send) + ", " + 
	std::to_string(dbg.recv) + "/" + std::to_string(dbg.read) + ")";
	INFO_HEXLOG(Log::sceNet, msg.c_str(), buf, len, 386);

	// Create the transmission vpacket
	VirtualPacket vpkt;
	vpkt.data = std::make_unique<char[]>(len);
	memcpy(vpkt.data.get(), buf, len);
	vpkt.len = len;
	vpkt.header_flags = p2ps_tcp_flags::PSH;
	vpkt.src_addr.sin_family = AF_INET;
	// vpkt.src_addr.sin_addr.s_addr = this->addr;
	if (inet_pton(AF_INET, this->addr.c_str(), &vpkt.src_addr.sin_addr) <= 0) {
		vpkt.src_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
	}
	vpkt.src_addr.sin_port = htons(port);
	vpkt.seq_id = tx_seq+1;
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
	if (isLocalTarget(dst_addr)) {
		// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
		g_socketManager.vBroadcast(std::move(send_pkt), htons(dst_port));
		tx_seq++; // TODO: Only on ::send success?
		dbg.sent++;
		WARN_LOG(Log::sceNet, "%d bytes send to (%s:%u); [tx=%d/rx=%d]", 
			send_pkt.len, ip2str(dst_addr).c_str(), ntohs(dst_port), 
			tx_seq, rx_seq);
		return len;
	} else {
		// Delegate to sendto with peer address
		sockaddr_in peer;
		peer.sin_family = AF_INET;
		peer.sin_addr.s_addr = dst_addr;
		peer.sin_port = htons(dst_port);
		
		// Remote delivery to vport (NAT)
		auto [_len, _data] = send_pkt.Pack(vport);
		int ret = ::sendto(dccp_sock->sock, _data.get(), _len, flags, (const sockaddr*)&peer, sizeof(sockaddr_in));
		if (ret < 0)
			return hleLogError(Log::sceNet, -1, "SOCK_PACKET accept: Failed to send ACK to peer");
		tx_seq++; // TODO: Only on ::send success?
		dbg.sent++;

		WARN_LOG(Log::sceNet, "%d bytes send to (%s:%u); [tx=%d/rx=%d]", 
			ret, inet_ntoa(peer.sin_addr), ntohs(peer.sin_port), 
			tx_seq, rx_seq);
		return len; // Report unmodified packet size
	}
	
	// // If this socket has broadcast enabled, replicate to other broadcast subscribers on this VPort
	// if ((so_flags & SO_FLAGS_DCCP_BROADCAST) && ret > 0) {
	// 	g_socketManager.BroadcastFromSocket(vport, this, buf, len, &peer);
	// }
	
	return 0;
}
int PacketSocket::recv(char* buf, int len, int flags) { 
	VERBOSE_LOG(Log::sceNet, "SOCK_PACKET::recv(buf, %d, %d): state=%d", len, flags, (int)tcp_state);
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
		return hleLogError(Log::sceNet, -1, "Socket not in Listening state (state=%d)", (int)tcp_state);
    }

	sockaddr_in source_addr{};
	int copy_len = dequeue_stream(buf, len, &source_addr);

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

	std::string msg = "recv::PACKET " + ip2str(source_addr.sin_addr) + ":" + std::to_string(ntohs(source_addr.sin_port));
	INFO_HEXLOG(Log::sceNet, msg.c_str(), buf, copy_len, 386);

	dbg.recv++;
	return copy_len;
}
int PacketSocket::connect(SceNetInetSockaddr* name, int namelen) { 
	const sockaddr_in* _dest = reinterpret_cast<const sockaddr_in*>(name);
	auto _vport = (_dest->sin_zero[0] << 8) | _dest->sin_zero[1];
	INFO_LOG(Log::sceNet, "SOCK_PACKET::connect(%s:%u, %d): state=%d", ip2str(_dest->sin_addr).c_str(), ntohs(_dest->sin_port), namelen, (int)tcp_state);

	// Validate socket is not already connected/connecting
	if (tcp_state != TCPState::Disconnected) {
		ERROR_LOG(Log::sceNet, "SOCK_PACKET connect: Socket not in Disconnected state (state=%d)", (int)tcp_state);
#if PPSSPP_PLATFORM(WINDOWS)
		SetLastError(EISCONN);
#else
		socket_errno = EISCONN;
#endif
		return hleLogError(Log::sceNet, -1, "SOCK_PACKET connect: Socket not in Disconnected state (state=%d)", (int)tcp_state);
	}
	// Set state to SynSent (waiting for ACK)
	tcp_state = TCPState::SynSent;
	rx_seq = 0;
	tx_seq = 0;
	
	// Store connected socket
	dst_addr = _dest->sin_addr.s_addr;
	dst_port = ntohs(_dest->sin_port);

	this->addr = ip2str(INADDR_ANY);
	this->port = g_socketManager.generateEphemeralPort();
	// this->port = ntohs(_dest->sin_port);
	this->vport = _vport;

	// Create the transmission vpacket
	VirtualPacket vpkt;
	vpkt.len = 0;
	vpkt.header_flags = p2ps_tcp_flags::SYN;
	vpkt.src_addr.sin_family = AF_INET;
	// vpkt.src_addr.sin_addr.s_addr = this->addr;
	if (inet_pton(AF_INET, this->addr.c_str(), &vpkt.src_addr.sin_addr) <= 0) {
		vpkt.src_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
	}
	vpkt.src_addr.sin_port = htons(port);
	vpkt.seq_id = tx_seq+1;
	// Add timestamp for TTL tracking
	vpkt.enqueue_time_us = (u64)(time_now_d() * 1000000.0);
	
	auto send_pkt = vpkt.clone();
	{
		// Add to transmit buffer
		std::lock_guard<std::mutex> lock(buffer_lock);
		// Place at end
		tx_buffer[tx_seq+1] = std::move(vpkt);
	}

	INFO_LOG(Log::sceNet, "PACKET: Connecting to %s:%u on vport %u",
		inet_ntoa(_dest->sin_addr), ntohs(_dest->sin_port), _vport);

	if (isLocalTarget(dst_addr)) {
		// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
		g_socketManager.vBroadcast(std::move(send_pkt), _dest->sin_port);
		tx_seq++;
	} else {
		// DCCP must exist for P2P traffic
		auto dccp_sock = g_socketManager.GetDCCP();
		if (!dccp_sock) {
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(EINVAL);
#else
			socket_errno = EINVAL;
#endif
			return hleLogError(Log::sceNet, -1, "SOCK_PACKET connect: DCCP_SOCK Not Present");
		}

		// Match the destination port for remote connections
		this->port = ntohs(_dest->sin_port);
		dst_port = _vport;

		sockaddr_in peer{};
		peer.sin_family = AF_INET;
		peer.sin_addr = _dest->sin_addr;
		peer.sin_port = htons(_vport);

		auto [_len, _data] = send_pkt.Pack(port);
		int ret = ::sendto(dccp_sock->sock, _data.get(), _len, 0, (struct sockaddr*)&peer, sizeof(sockaddr_in));
		if (ret < 0) {
			return hleLogError(Log::sceNet, -1, "SOCK_PACKET connect: Failed to send SYN");
		}
		tx_seq++;
	}
	
	// INFO_LOG(Log::sceNet, "SOCK_PACKET: Connected vport %d to %s:%u",
	// 	vport, inet_ntoa(_dest->sin_addr), ntohs(_dest->sin_port));
	
#if PPSSPP_PLATFORM(WINDOWS)
		SetLastError(EINPROGRESS);
#else
		socket_errno = EINPROGRESS;
#endif
	return -1;  // Non-blocking: game will check connection status later
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
		
	INFO_LOG(Log::sceNet, "SOCK_PACKET listen: vport %d now accepting %d connections", vport, this->backlog);

	// return ::listen(sock, backlog);
	return 0;
}
int PacketSocket::accept(sockaddr* addr, socklen_t* addrlen) { 
	const sockaddr_in* _dest = reinterpret_cast<const sockaddr_in*>(addr);
	INFO_LOG(Log::sceNet, "SOCK_PACKET::accept(%s:%u, %d): pending=%d state=%d", this->addr.c_str(), this->port, static_cast<int>(*addrlen), (int)pending_connections.size(), (int)tcp_state);

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
		sockaddr_in peer{};
		peer.sin_family = AF_INET;
		peer.sin_addr.s_addr = pending_conn->dst_addr;
		peer.sin_port = htons(pending_conn->dst_port);
		memcpy(addr, &peer, std::min((size_t)*addrlen, sizeof(sockaddr_in)));
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
	new_sock->vport = this->vport;         // Same vport
	new_sock->port = this->port;           // Same port
	new_sock->addr = this->addr;           // Same address

	new_sock->tcp_state = pending_conn->tcp_state;
	// Store connected peer
	new_sock->dst_addr = pending_conn->dst_addr;
	new_sock->dst_port = pending_conn->dst_port;
	// Store buffer states
	std::swap(new_sock->rx_queue, pending_conn->rx_queue);
	std::swap(new_sock->rx_buffer, pending_conn->rx_buffer);
	new_sock->rx_seq = pending_conn->rx_seq;
	std::swap(new_sock->tx_buffer, pending_conn->tx_buffer);
	new_sock->tx_seq = pending_conn->tx_seq; // sync with ACK

	new_sock->state = SocketState::UsedNetInet;	
	
	INFO_LOG(Log::sceNet, "SOCK_PACKET accept: Accepted connection on listening socket from %s:%u on %s:%u (vport=%u), created socket %d",
		ip2str(pending_conn->dst_addr).c_str(), pending_conn->dst_port,
		new_sock->addr.c_str(), new_sock->port, new_sock->vport,
		new_socket_idx);
	// clean-up
	remove_pending_connection(pending_conn);
	return new_socket_idx;
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
	addr = ip2str(saddr.in.sin_addr);
	port = ntohs(saddr.in.sin_port);
	// The PSP is expected to provide 0, and we need to generate a vport
	// This is later "agreed" upon in the P2P handshake?
	vport = (saddr.in.sin_zero[0] << 8) | saddr.in.sin_zero[1];

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(saddr.addr.sa_family).c_str(), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port), vport);

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
	
	// Get DCCP socket for sending FIN
	auto dccp_sock = g_socketManager.GetDCCP();
	if (dccp_sock) {
		// Create the transmission vpacket
		VirtualPacket vpkt;
		vpkt.len = 0;
		vpkt.header_flags = p2ps_tcp_flags::FIN;
		vpkt.src_addr.sin_family = AF_INET;
		// vpkt.src_addr.sin_addr.s_addr = this->addr;
		if (inet_pton(AF_INET, this->addr.c_str(), &vpkt.src_addr.sin_addr) <= 0) {
			vpkt.src_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
		}
		vpkt.src_addr.sin_port = htons(vport);
		vpkt.seq_id = tx_seq+1;
		// Add timestamp for TTL tracking
		vpkt.enqueue_time_us = (u64)(time_now_d() * 1000000.0);

		{
			// Add to transmit buffer
			std::lock_guard<std::mutex> lock(buffer_lock);
			// Place at end
			tx_buffer[tx_seq+1] = std::move(vpkt.clone());
		}

		INFO_LOG(Log::sceNet, "SOCK_PACKET shutdown: Sending FIN from port %d to %d", port, dst_port);
		if (isLocalTarget(dst_port)) {
			sockaddr_in src_addr{};
			src_addr.sin_family = AF_INET;
			src_addr.sin_port = htons(this->port);
			if (inet_pton(AF_INET, this->addr.c_str(), &src_addr.sin_addr) <= 0) {
				src_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
			}
			// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
			g_socketManager.vBroadcast(std::move(vpkt), htons(vport));
		} else {
			sockaddr_in dst_addr{};
			dst_addr.sin_family = AF_INET;
			dst_addr.sin_addr = dst_addr.sin_addr;
			dst_addr.sin_port = htons(vport);

			auto [_len, _data] = vpkt.Pack(dst_port);
			int ret = ::sendto(dccp_sock->sock, _data.get(), _len, 0, (struct sockaddr*)&dst_addr, sizeof(sockaddr_in));
			if (ret < 0) {
				ERROR_LOG(Log::sceNet, "SOCK_PACKET shutdown: Failed to send FIN");
				// return -1; // Let it shut down the socket anyways
			}
		}
	}
	
	return 0;
}
int PacketSocket::select(SceNetInetFdSet* readfds, SceNetInetFdSet* writefds, SceNetInetFdSet* exceptfds, SceNetInetTimeval* timeout) {
	// First, translate the specified fd_sets to host sockets.
	fd_set rdfds, wrfds, exfds;
	FD_ZERO(&rdfds);
	FD_ZERO(&wrfds);
	FD_ZERO(&exfds);

	timeval tmout = { 5, 543210 }; // Workaround timeout value when timeout = NULL
	if (timeout) {
		tmout.tv_sec = timeout->tv_sec;
		tmout.tv_usec = timeout->tv_usec;
	}
		// Log select() calls on virtual sockets for debugging
	INFO_LOG(Log::sceNet, "select: vport %d called (type=%d, readfds=%p, timeout=%p)", 
		vport, type, readfds, timeout);
	
	// 1. Virtual State Checks
	if (readfds && type == PSP_NET_INET_SOCK_PACKET && tcp_state == TCPState::Listening) {
		if (has_pending_connection()) {
			INFO_LOG(Log::sceNet, "select: vport %d has pending connection for accept(), returning 1", vport);
			return 1;
		}
	}
	
	if (readfds && has_pending_data()) {
		INFO_LOG(Log::sceNet, "select: vport %d HAS PENDING DATA, returning 1", vport);
		return 1;
	}
	
	// If we get here with readfds set, there's no data
	if (readfds) {
		INFO_LOG(Log::sceNet, "select: vport %d NO PENDING DATA", vport);
	}
	
	if (writefds) {
		bool writable = false;
		if (type == PSP_NET_INET_SOCK_CONN_DGRAM) {
			writable = true;  // UDP always writable
		} else if (type == PSP_NET_INET_SOCK_PACKET) {
			writable = (tcp_state == TCPState::Established || tcp_state == TCPState::SynReceived);
		}
		
		if (writable) {
			INFO_LOG(Log::sceNet, "select: vport %d is writable, returning 1", vport);
			return 1;
		}
	}
	
	// 2. Physical Socket Checks
	// Poll the underlying physical socket using a non-blocking select
	timeval tv_zero = {0, 0};
	
	// We MUST copy the fd_sets. A 0-timeout select will clear the sets if nothing is ready,
	// and we don't want to destroy the caller's sets if only virtual data becomes ready later.
	fd_set read_copy, write_copy, exc_copy;
	fd_set* p_read = nullptr;
	fd_set* p_write = nullptr;
	fd_set* p_exc = nullptr;
	
	if (readfds)   { read_copy = rdfds;   p_read = &read_copy;   }
	if (writefds)  { write_copy = wrfds; p_write = &write_copy; }
	if (exceptfds) { exc_copy = exfds;  p_exc = &exc_copy;     }
	
	// Using 'sock' mirrors your default fallback behavior
	int phys_ready = ::select(sock, p_read, p_write, p_exc, &tv_zero);
	if (phys_ready > 0) {
		DEBUG_LOG(Log::sceNet, "select: vport %d has physical data/events", vport);
		// Copy back the mutated sets so the caller knows exactly what triggered
		// if (readfds)   *readfds = read_copy;
		// if (writefds)  *writefds = write_copy;
		// if (exceptfds) *exceptfds = exc_copy;

		// Convert the results back to PSP fd_sets.
		if (readfds)
			NetInetFD_ZERO(readfds);
		if (writefds)
			NetInetFD_ZERO(writefds);
		if (exceptfds)
			NetInetFD_ZERO(exceptfds);

		return phys_ready;
	}
	
	// Nothing ready yet
	return 0;
	// Wait Logic?
}
bool PacketSocket::dequeue_packet(VirtualPacket& packet) {
	std::lock_guard<std::mutex> buffers(buffer_lock);
	const u64 MAX_PACKET_AGE_US = 30000000;  // 30 seconds
	
	while (!rx_buffer.empty() && rx_buffer.find(rx_seq + 1) != rx_buffer.end()) {
		rx_seq++;
		packet = std::move(rx_buffer.find(rx_seq)->second);
		rx_buffer.erase(rx_seq);
		
		// Check packet TTL
		u64 current_time_us = (u64)(time_now_d() * 1000000.0);
		u64 packet_age_us = current_time_us - packet.enqueue_time_us;
		
		if (packet_age_us > MAX_PACKET_AGE_US) {
            WARN_LOG(Log::sceNet, "dequeue_stream: Receiving stale packet (age: %.2f seconds)", (float)packet_age_us / 1000000.0f);
		}
		
		DEBUG_LOG(Log::sceNet, "Dequeued packet from vport %d (queue size: %zu)", vport, rx_buffer.size());
		return true;
	}
	
	return false;  // Queue is empty
}
int PacketSocket::dequeue_stream(char* buf, int len, sockaddr_in* out_addr) {
	std::lock_guard<std::mutex> buffers(buffer_lock);
    const u64 MAX_PACKET_AGE_US = 30000000;  // 30 seconds
    u64 current_time_us = (u64)(time_now_d() * 1000000.0);
    
    int total_copied = 0;
    bool target_locked = false;
    sockaddr_in target_addr{};

	if (!rx_buffer.empty() && rx_buffer.find(rx_seq + 1) == rx_buffer.end())
		WARN_LOG(Log::sceNet, "dequeue_stream: Missing next packet at %d", rx_seq+1);
    
    while (total_copied < len && !rx_buffer.empty() && rx_buffer.find(rx_seq + 1) != rx_buffer.end()) {
        // Peek at the front packet (do NOT pop yet)
        VirtualPacket& peek_pkt = rx_buffer.find(rx_seq + 1)->second;
        
        // Check packet TTL
        u64 packet_age_us = current_time_us - peek_pkt.enqueue_time_us;
        if (packet_age_us > MAX_PACKET_AGE_US) {
            WARN_LOG(Log::sceNet, "dequeue_stream: Receiving stale packet (age: %.2f seconds)", (float)packet_age_us / 1000000.0f);
        }

        // Lock onto the first valid packet's source address
        if (!target_locked) {
            target_addr = peek_pkt.src_addr;
            target_locked = true;
            if (out_addr) {
                *out_addr = target_addr;
            }
        } else {
            // If we are continuing to fill the buffer, ensure this next packet is from the SAME source
            if (peek_pkt.src_addr.sin_addr.s_addr != target_addr.sin_addr.s_addr ||
                peek_pkt.src_addr.sin_port != target_addr.sin_port) {
                
                DEBUG_LOG(Log::sceNet, "dequeue_stream: Source mismatch detected. Halting coalescing. (Expected %s:%u, got %s:%u)",
                    inet_ntoa(target_addr.sin_addr), ntohs(target_addr.sin_port),
                    inet_ntoa(peek_pkt.src_addr.sin_addr), ntohs(peek_pkt.src_addr.sin_port));
                break; // Stop coalescing and leave this packet in the queue
            }
        }
        
        // Now we know we are consuming this packet (at least partially), so pop it
		rx_seq++;
        VirtualPacket packet = std::move(rx_buffer.find(rx_seq)->second);
        rx_buffer.erase(rx_seq);
        
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
            remainder.src_addr = packet.src_addr;
            remainder.enqueue_time_us = packet.enqueue_time_us; // Preserve TTL
            
			rx_buffer[rx_seq] = std::move(remainder);
			rx_seq--; // mark this as the next packet to receive
            break; // Buffer is full
        }
    }
    
    return total_copied;
}
bool PacketSocket::has_pending_data() const {
	std::lock_guard<std::mutex> buffers(buffer_lock);
	return ((!rx_buffer.empty() && rx_buffer.find(rx_seq + 1) != rx_buffer.end()) || tcp_state == TCPState::CloseWait);
}
bool PacketSocket::set_pending_connection(InetSocket* conn) {
	std::lock_guard<std::mutex> connections(conn_lock);
	if ((int)pending_connections.size() >= backlog) {
		ERROR_LOG(Log::sceNet, "Backlog full, dropping SYN from %s:%u", ip2str(conn->dst_addr).c_str(), conn->dst_port);
		delete conn;
		return false;
	}
	// Check for an existing connection
	for (auto& existing : pending_connections) {
        if (existing->dst_addr == conn->dst_addr && 
            existing->dst_port == conn->dst_port) {
			ERROR_LOG(Log::sceNet, "Request already exists, dropping SYN from %s:%u", ip2str(conn->dst_addr).c_str(), conn->dst_port);
            delete conn; // discard the duplicate
            return false;
        }
    }

	pending_connections.push_back(conn);
	DEBUG_LOG(Log::sceNet, "Set pending connection on vport %d from %s:%u",
		vport, ip2str(conn->dst_addr).c_str(), conn->dst_port);
	return true;
}
bool PacketSocket::update_pending_connection(const sockaddr_in& peer_addr) {
	std::lock_guard<std::mutex> connections(conn_lock);
	for (auto& conn : pending_connections) {
        if (conn->dst_addr == peer_addr.sin_addr.s_addr && 
            conn->dst_port == ntohs(peer_addr.sin_port)) {
            
            if (conn->tcp_state == TCPState::SynReceived) {
                conn->tcp_state = TCPState::Established;
				{
					std::lock_guard<std::mutex> buffers(conn->buffer_lock);
					// Flag SYN|ACK as acquired
					auto psh_syn = std::find_if(conn->tx_buffer.begin(), conn->tx_buffer.end(), [](const auto& pair) { return pair.second.header_flags == (p2ps_tcp_flags::SYN|p2ps_tcp_flags::ACK); });
					if (psh_syn != conn->tx_buffer.end())
						psh_syn->second.seq_ack = true;
					conn->rx_seq++; // ACK received
				}
                DEBUG_LOG(Log::sceNet, "Promoted connection to Established for %s:%u",
                    ip2str(conn->dst_addr).c_str(), conn->dst_port);
                return true;
            }
        }
    }
	return false;
}
InetSocket* PacketSocket::get_pending_connection() {
	std::lock_guard<std::mutex> connections(conn_lock);
	// Find the first connection that has finished the 3-way handshake
    for (auto& conn : pending_connections) {
        if (conn->tcp_state == TCPState::Established) {
			return conn;
        }
    }
	return nullptr;
}
void PacketSocket::remove_pending_connection(InetSocket* conn) {
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
bool PacketSocket::has_pending_connection() const {
	std::lock_guard<std::mutex> connections(conn_lock);
	for (const auto& conn : pending_connections) {
        if (conn->tcp_state == TCPState::Established) {
            return true;
        }
    }
    return false;
}
bool PacketSocket::ProcessNetStack() {
	bool hadData = has_pending_data(); // Needs queue_lock
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
            WARN_LOG(Log::sceNet, "ProcessNetStack: Discarding stale packet (age: %.2f seconds)", (float)packet_age_us / 1000000.0f);
            continue;
        }

        // if (pkt.header_flags == (p2ps_tcp_flags::PSH | p2ps_tcp_flags::FIN)) {
		// 	INFO_LOG(Log::sceNet, "PACKET: Received PSH|FIN at listening socket from %s:%u to port %u",
		// 		inet_ntoa(pkt.src_addr.sin_addr), ntohs(pkt.src_addr.sin_port), port);
		// }
        // else 
		if (pkt.header_flags == (p2ps_tcp_flags::PSH | p2ps_tcp_flags::ACK)) {
			INFO_LOG(Log::sceNet, "PACKET: Received PSH|ACK at listening socket from %s:%u to %s:%u",
				inet_ntoa(pkt.src_addr.sin_addr), ntohs(pkt.src_addr.sin_port), addr.c_str(), port);
			// Do not increment rx_seq, this is just a confirmation

			std::lock_guard<std::mutex> buffer(buffer_lock);
			auto ack = tx_buffer.find(pkt.seq_id);
			// Safety check, should never trigger
			if (ack != tx_buffer.end()) {
				VirtualPacket& vpkt = ack->second;
				// Flag as acquired
				vpkt.seq_ack = true;
			}
		}
        else if (pkt.header_flags == p2ps_tcp_flags::PSH) {
			if (tcp_state != TCPState::Listening) {
				INFO_LOG(Log::sceNet, "PACKET: Received PSH at listening socket from %s:%u to %s:%u [seq=%d,tx=%d/rx=%d,hpd=%d]",
					inet_ntoa(pkt.src_addr.sin_addr), ntohs(pkt.src_addr.sin_port), addr.c_str(), port, pkt.seq_id, tx_seq, rx_seq, has_pending_data());
				// Do not increment rx_seq until Recv is called

				// Buffer the received packet
				auto pkt_seq = pkt.seq_id;
				rx_buffer[pkt_seq] = std::move(pkt);
				// Return PSH|ACK to notify it was received
				VirtualPacket vpkt{};
				vpkt.len = 0;
				vpkt.header_flags = (p2ps_tcp_flags::PSH|p2ps_tcp_flags::ACK);
				vpkt.src_addr.sin_family = AF_INET;
				// vpkt.src_addr.sin_addr.s_addr = this->addr;
				if (inet_pton(AF_INET, this->addr.c_str(), &vpkt.src_addr.sin_addr) <= 0) {
					vpkt.src_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
				}
				vpkt.src_addr.sin_port = htons(port);
				vpkt.seq_id = pkt_seq; // Just confirm this packet was received
				// Add timestamp for TTL tracking
				vpkt.enqueue_time_us = (u64)(time_now_d() * 1000000.0);

				// Do NOT save this for re-transmission. Wait for another PSH

				INFO_LOG(Log::sceNet, "SOCK_PACKET connect: Returning PSH-ACK from %s:%u to %s:%u",
					addr.c_str(), port, ip2str(dst_addr).c_str(), dst_port);

				if (isLocalTarget(dst_addr)) {
					g_socketManager.vBroadcast(std::move(vpkt), htons(dst_port));
				} else {
					sockaddr_in peer{};
					peer.sin_family = AF_INET;
					peer.sin_addr.s_addr = dst_addr;
					peer.sin_port = htons(dst_port);

					auto [_len, _data] = vpkt.Pack(port);
					auto dccp_sock = g_socketManager.GetDCCP();
					int ret = ::sendto(dccp_sock->sock, _data.get(), _len, 0, (struct sockaddr*)&peer, sizeof(sockaddr_in));
					if (ret < 0) {
						ERROR_LOG(Log::sceNet, "SOCK_PACKET connect: Failed to send ACK");
					}
				}
			}
        }
        // 2. Process Control Plane (The "Kernel" Logic)
        else if (pkt.header_flags == p2ps_tcp_flags::SYN) {
			if (tcp_state == TCPState::Listening) {
				InetSocket* conn = new InetSocket();
				conn->dst_addr = pkt.src_addr.sin_addr.s_addr;
				conn->dst_port = ntohs(pkt.src_addr.sin_port);
				conn->tcp_state = TCPState::SynReceived;
				conn->tx_seq = 0;
				if (!set_pending_connection(conn))
					continue;
				conn->rx_seq = 1; // Mark this packet received
				
				INFO_LOG(Log::sceNet, "PACKET: Received SYN at listening socket from %s:%u to %s:%u",
					inet_ntoa(pkt.src_addr.sin_addr), ntohs(pkt.src_addr.sin_port), addr.c_str(), port);

				VirtualPacket vpkt{};
				vpkt.len = 0;
				vpkt.header_flags = (p2ps_tcp_flags::SYN|p2ps_tcp_flags::ACK);
				vpkt.src_addr.sin_family = AF_INET;
				// vpkt.src_addr.sin_addr.s_addr = this->addr;
				if (inet_pton(AF_INET, this->addr.c_str(), &vpkt.src_addr.sin_addr) <= 0) {
					vpkt.src_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
				}
				vpkt.src_addr.sin_port = htons(port);
				vpkt.seq_id = conn->tx_seq+1;
				// Add timestamp for TTL tracking
				vpkt.enqueue_time_us = (u64)(time_now_d() * 1000000.0);
				vpkt.last_sent_us = (u64)(time_now_d() * BASE_RTO_US);

				auto send_pkt = vpkt.clone();
				{
					std::lock_guard<std::mutex> buffer(conn->buffer_lock);
					// Add to transmit buffer
					conn->tx_buffer[conn->tx_seq+1] = std::move(vpkt);
				}
				INFO_LOG(Log::sceNet, "SOCK_PACKET connect: Returning SYN-ACK from %s:%u to %s:%u",
					addr.c_str(), port, ip2str(conn->dst_addr).c_str(), conn->dst_port);
					
				if (isLocalTarget(conn->dst_addr)) {
					// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
					g_socketManager.vBroadcast(std::move(send_pkt), htons(conn->dst_port));
					conn->tx_seq++;
				} else {
					sockaddr_in peer{};
					peer.sin_family = AF_INET;
					peer.sin_addr.s_addr = conn->dst_addr;
					peer.sin_port = htons(conn->dst_port);

					auto [_len, _data] = send_pkt.Pack(port);
					auto dccp_sock = g_socketManager.GetDCCP();
					int ret = ::sendto(dccp_sock->sock, _data.get(), _len, 0, (struct sockaddr*)&peer, sizeof(sockaddr_in));
					if (ret < 0) {
						ERROR_LOG(Log::sceNet, "SOCK_PACKET connect: Failed to send ACK");
					}
					conn->tx_seq++;
				}
			}
        } 
        else if (pkt.header_flags == (p2ps_tcp_flags::SYN | p2ps_tcp_flags::ACK)) {
			if (tcp_state == TCPState::SynSent) {
				INFO_LOG(Log::sceNet, "PACKET: Received SYN-ACK at listening socket from %s:%u to %s:%u",
					inet_ntoa(pkt.src_addr.sin_addr), ntohs(pkt.src_addr.sin_port), addr.c_str(), port);
				tcp_state = TCPState::Established;
				dst_addr = pkt.src_addr.sin_addr.s_addr;
                dst_port = ntohs(pkt.src_addr.sin_port);
				rx_seq++;
				
                // Resume the thread that is currently blocked in sceNetInetConnect
                if (threadID > 0) {
                    DEBUG_LOG(Log::sceNet, "ProcessNetStack: SYN-ACK received, resuming thread %d", threadID);
                    __KernelResumeThreadFromWait(threadID, 0);
                    threadID = -1;
                }

				// TODO: Mark the tx_buffer SYN packet as acquired
				// pkt.seq_ack = true;

				VirtualPacket vpkt{};
				vpkt.len = 0;
				vpkt.header_flags = (p2ps_tcp_flags::ACK);
				vpkt.src_addr.sin_family = AF_INET;
				// vpkt.src_addr.sin_addr.s_addr = this->addr;
				if (inet_pton(AF_INET, this->addr.c_str(), &vpkt.src_addr.sin_addr) <= 0) {
					vpkt.src_addr.sin_addr.s_addr = htonl(INADDR_ANY); 
				}
				vpkt.src_addr.sin_port = htons(port);
				vpkt.seq_id = tx_seq+1;
				// Add timestamp for TTL tracking
				vpkt.enqueue_time_us = (u64)(time_now_d() * 1000000.0);

				// Do not resend. Let the peer re-send SYN|ACK if it hasn't connected yet

				INFO_LOG(Log::sceNet, "SOCK_PACKET connect: Returning ACK from %s:%u to %s:%u",
					addr.c_str(), port, inet_ntoa(pkt.src_addr.sin_addr), ntohs(pkt.src_addr.sin_port));
				
				if (isLocalTarget(dst_addr)) {
					// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
					g_socketManager.vBroadcast(std::move(vpkt), htons(dst_port));
					tx_seq++;
				} else {
					sockaddr_in peer{};
					peer.sin_family = AF_INET;
					peer.sin_addr.s_addr = dst_addr;
					peer.sin_port = htons(dst_port);

					auto [_len, _data] = vpkt.Pack(port);
					auto dccp_sock = g_socketManager.GetDCCP();
					int ret = ::sendto(dccp_sock->sock, _data.get(), _len, 0, (struct sockaddr*)&peer, sizeof(sockaddr_in));
					if (ret < 0) {
						ERROR_LOG(Log::sceNet, "SOCK_PACKET connect: Failed to send ACK");
					}
					tx_seq++;
				}
			}
		}
        else if (pkt.header_flags == p2ps_tcp_flags::ACK) {
            if (tcp_state == TCPState::Listening) {
				INFO_LOG(Log::sceNet, "PACKET: Received ACK at listening socket from %s:%u to %s:%u",
					inet_ntoa(pkt.src_addr.sin_addr), ntohs(pkt.src_addr.sin_port), addr.c_str(), port);

				// tcp_state = TCPState::Established;
				update_pending_connection(pkt.src_addr); // Increments rx_seq

                // Resume the thread that is currently blocked in sceNetInetConnect
                if (threadID > 0) {
                    DEBUG_LOG(Log::sceNet, "ProcessNetStack: ACK received, resuming thread %d", threadID);
                    __KernelResumeThreadFromWait(threadID, 0);
                    threadID = -1;
                }
            }
        } 
        else if (pkt.header_flags == p2ps_tcp_flags::FIN) {
            if (tcp_state != TCPState::Listening) {
				INFO_LOG(Log::sceNet, "PACKET: Received FIN at listening socket from %s:%u to %s:%u",
					inet_ntoa(pkt.src_addr.sin_addr), ntohs(pkt.src_addr.sin_port), addr.c_str(), port);
                tcp_state = TCPState::CloseWait;
				rx_seq++;
            }
        }
    }

	return hadData;
}
