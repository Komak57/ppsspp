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

bool isLocalTarget(const sockaddr_in* _dest) {
	sockaddr_in local_addr{};
	getLocalIp(&local_addr);
	return (_dest->sin_addr.s_addr == htonl(INADDR_LOOPBACK) || 
				_dest->sin_addr.s_addr == htonl(INADDR_ANY) ||
				(_dest->sin_addr.s_addr == local_addr.sin_addr.s_addr));
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
        std::lock_guard<std::mutex> lock(queue_lock);
        std::deque<VirtualPacket> empty;
        std::swap(rx_queue, empty);
    }
    
    // Reset pointers
    pending_connection.reset();
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

		// Destroy the old object and construct the appropriate derived type using placement new
		inetSock->~InetSocket();
		
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
			
			// Determine the type from derive and reconstruct with the correct derived class
			// This ensures the vtable matches the socket type
			inetSock->~InetSocket();
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

bool SocketManager::Close(InetSocket *inetSocket) {
	_dbg_assert_(inetSocket->state != SocketState::Unused);

	int ret = 0;
	if (inetSocket->type == PSP_NET_INET_SOCK_CONN_DGRAM)
		ret = inetSocket->closesocket();
	else
		ret = closesocket(inetSocket->sock);

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

int SocketManager::DeliverPacketToVPorts(const VPORT_HEADER& header, const char* packet_data, int data_len, const sockaddr_in& _from) {
    int delivered_count = 0;
    
    // Match sockets by vport (port-based routing instead of subscriptions)
    for (int i = SocketManager::MIN_VALID_INET_SOCKET; i < SocketManager::VALID_INET_SOCKET_COUNT; i++) {
        InetSocket* target_sock = &inetSockets_[i];
        
        // Skip unused sockets
        if (!target_sock || target_sock->state == SocketState::Unused) {
            continue;
        }
        
        // Match only virtual socket types (PACKET and CONN_DGRAM)
        if (target_sock->type != PSP_NET_INET_SOCK_PACKET && target_sock->type != PSP_NET_INET_SOCK_CONN_DGRAM) {
            continue;
        }
        
        // Match by vport (convert from network order for comparison)
        if (target_sock->type == PSP_NET_INET_SOCK_PACKET && htons(target_sock->port) != header.vport) {
            continue;  // Not subscribed to this vport
        }
        if (target_sock->type == PSP_NET_INET_SOCK_CONN_DGRAM && htons(target_sock->vport) != header.vport) {
            continue;  // Not subscribed to this vport
        }
        
        DEBUG_LOG(Log::sceNet, "RouteDCCP: Processing socket vport %d (type=%d)", 
            target_sock->vport, target_sock->type);

        // Handle TCP control packets (SYN/ACK/FIN) for SOCK_PACKET
        if (target_sock->type == PSP_NET_INET_SOCK_PACKET) {
            PacketSocket* pkt_sock = const_cast<PacketSocket*>(static_cast<const PacketSocket*>(target_sock));
            
			// Only handle SYN for listening sockets
            if (header.flags & p2ps_tcp_flags::SYN) {
                if (target_sock->tcp_state == TCPState::Listening) {
                    ConnectionRequest conn;
                    conn.peer_addr = _from;
                    conn.peer_port = ntohs(_from.sin_port);
                    pkt_sock->set_pending_connection(conn);
                    
                    INFO_LOG(Log::sceNet, "PACKET: Received SYN at listening socket from %s:%u to port %u",
                        inet_ntoa(_from.sin_addr), ntohs(_from.sin_port), target_sock->port);
                    continue; // SYN handled, don't enqueue as data
                }
            }
            
			// Incoming ACK - only handle for SynSent state
            if (header.flags & p2ps_tcp_flags::ACK) {
                if (target_sock->tcp_state == TCPState::SynSent) {
                    InetSocket* mutable_sock = const_cast<InetSocket*>(target_sock);
                    mutable_sock->tcp_state = TCPState::Established;
                    mutable_sock->dst_addr = _from.sin_addr.s_addr;
                    mutable_sock->dst_port = ntohs(_from.sin_port);
                    
                    INFO_LOG(Log::sceNet, "PACKET: Received ACK at connecting socket from %s:%u to port %u",
                        inet_ntoa(_from.sin_addr), ntohs(_from.sin_port), target_sock->port);
					// if (target_sock->threadID > 0) {
					// 	__KernelResumeThreadFromWait(target_sock->threadID, 0);
					// 	target_sock->threadID = -1;
					// }
                    continue; // ACK handled, don't enqueue as data
                }
            }
            
			// Incoming FIN (close)
            if (header.flags & p2ps_tcp_flags::FIN) {
				// Accepted sockets copy the listening socket's information. Only shut down non-listening sockets
				if (target_sock->tcp_state == TCPState::Listening)
					continue;
                const_cast<InetSocket*>(target_sock)->tcp_state = TCPState::CloseWait;
                INFO_LOG(Log::sceNet, "PACKET: Received FIN from %s:%u to port %u",
                    inet_ntoa(_from.sin_addr), ntohs(_from.sin_port), target_sock->port);
                continue; // FIN handled, don't enqueue as data
            }

			// Check if this socket should receive data packets
            if (header.flags & p2ps_tcp_flags::PSH) {
                if (target_sock->tcp_state == TCPState::Established) {
					if (target_sock->dst_addr != _from.sin_addr.s_addr || target_sock->dst_port != ntohs(_from.sin_port))
						continue;
                    
					VirtualPacket vpkt;
					if (data_len > 0 && packet_data != nullptr) {
						vpkt.data = std::make_unique<char[]>(data_len);
						memcpy(vpkt.data.get(), packet_data, data_len);
					}
					vpkt.len = data_len;
					vpkt.header_flags = header.flags;
					vpkt.src_addr = _from;
					
					DEBUG_LOG(Log::sceNet, "RouteDCCP: DELIVERING to port %d (type=%d, %d bytes from %s:%u)", 
						target_sock->port, target_sock->type, data_len, inet_ntoa(_from.sin_addr), ntohs(_from.sin_port));
					
					// Enqueue to target socket (atomic delivery) based on type
					if (target_sock->type == PSP_NET_INET_SOCK_PACKET) {
						static_cast<PacketSocket*>(target_sock)->enqueue_packet(vpkt);
					} else if (target_sock->type == PSP_NET_INET_SOCK_CONN_DGRAM) {
						static_cast<ConnDgramSocket*>(target_sock)->enqueue_packet(vpkt);
					}

                    INFO_LOG(Log::sceNet, "PACKET: Received PSH at established socket from %s:%u to port %u",
                        inet_ntoa(_from.sin_addr), ntohs(_from.sin_port), target_sock->port);
					delivered_count++;
                    continue; // Next socket
                }
            }
        } else {
			// FIXME: Should technically support non-broadcast sends
			// if (!target_sock->is_broadcast_enabled())
				// continue;
            VirtualPacket vpkt;
            if (data_len > 0 && packet_data != nullptr) {
                vpkt.data = std::make_unique<char[]>(data_len);
                memcpy(vpkt.data.get(), packet_data, data_len);
            }
            vpkt.len = data_len;
            vpkt.header_flags = header.flags;
            vpkt.src_addr = _from;
            
            INFO_LOG(Log::sceNet, "RouteDCCP: DELIVERING to vport %d (type=%d, %d bytes from %s:%u)", 
                target_sock->vport, target_sock->type, data_len, inet_ntoa(_from.sin_addr), ntohs(_from.sin_port));
            
            DEBUG_LOG(Log::sceNet, "%d=recvfrom(%s:%u) -> vport %d{%02X} (type=%d); [%lld/%lld, %lld/%lld]", 
                data_len, inet_ntoa(_from.sin_addr), ntohs(_from.sin_port), 
                target_sock->vport, header.flags, target_sock->type,
                target_sock->dbg.send, target_sock->dbg.sent, target_sock->dbg.recv, target_sock->dbg.read);
            
            // Enqueue to target socket (atomic delivery) based on type
            if (target_sock->type == PSP_NET_INET_SOCK_PACKET) {
				static_cast<PacketSocket*>(target_sock)->enqueue_packet(vpkt);
            } else if (target_sock->type == PSP_NET_INET_SOCK_CONN_DGRAM) {
                static_cast<ConnDgramSocket*>(target_sock)->enqueue_packet(vpkt);
            }
            delivered_count++;
			continue; // Next Socket
		}

		DEBUG_LOG(Log::sceNet, "RouteDCCP: NOT delivering to vport %d (deliver_data=false)", target_sock->vport);
    }
    
    if (delivered_count > 0) {
        DEBUG_LOG(Log::sceNet, "RouteDCCP: Total delivered to %d subscribers on VPort %d", delivered_count, ntohs(header.vport));
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

std::tuple<int, std::unique_ptr<char[]>> Pack(u16 vport, u8 flags, const char* data, int len) {
	// Build packet: VPORT_HEADER + payload
	int packet_size = VPORT_HEADER_SIZE + len;
	std::unique_ptr<char[]> packet = std::make_unique<char[]>(packet_size);

	// Pack DGRAM_HEADER (3 bytes): [flags][data_len]
	VPORT_HEADER header;
	header.flags = flags;
	header.vport = vport;
	memcpy(packet.get(), &header, VPORT_HEADER_SIZE);

	// Pack the message body
	if (len > 0) {
		memcpy(packet.get() + VPORT_HEADER_SIZE, data, len);
	}
	return {packet_size, std::move(packet)};
}

// ============================================================================
// Base Socket Class
// Default fallback functions for things not yet implemented by other sockets
// ============================================================================
int InetSocket::select(fd_set* readfds, fd_set* writefds, fd_set* exceptfds, timeval* timeout) { errno = EOPNOTSUPP; return -1; }
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
			return hleLogWarning(Log::sceNet, 0, "%s not supported, ignoring", host_optname_str.c_str());
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
			nonblocking = optval;
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
void InetSocket::ProcessNetStack() { /* Do nothing */ }

// Close a virtual socket
int InetSocket::closesocket() {
	return ::closesocket(sock);
}

// ============================================================================
// 
// ============================================================================
int StreamSocket::send(const char* buf, int len, int flags) { return ::send(sock, buf, len, flags); }
int StreamSocket::recv(char* buf, int len, int flags) { return ::recv(sock, buf, len, flags); }
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
			// Clear the error
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(0);
#else
			errno = 0;
#endif

// ============================================================================
// Standard P2P Comm Channel (UDP)
// ============================================================================
int ConnDgramSocket::sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) { 
		int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	SockAddrIN4 saddr{};
	int dstlen = std::min(tolen > 0 ? tolen : 0, static_cast<int>(sizeof(saddr)));
	if (to) {
		saddr.addr.sa_family = to->sa_family;
		memcpy(saddr.addr.sa_data, to->sa_data, sizeof(to->sa_data));
	}
	const sockaddr_in* _dest = reinterpret_cast<const sockaddr_in*>(&saddr.addr);
		
	// Send the packet over P2P

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
	
	// Build packet: VPORT_HEADER + payload
	int packet_size = VPORT_HEADER_SIZE + len;
	std::unique_ptr<char[]> packet = std::make_unique<char[]>(packet_size);

	// Pack DGRAM_HEADER (3 bytes): [flags][data_len]
	VPORT_HEADER header;
	header.flags = p2ps_tcp_flags::PSH;
	header.vport = (saddr.in.sin_zero[1] << 8) | saddr.in.sin_zero[0];
	// memcpy(&header.vport, &saddr.in.sin_zero[0], 2);
	memcpy(packet.get(), &header, VPORT_HEADER_SIZE);

	// Pack the message body
	if (len > 0) {
		memcpy(packet.get() + VPORT_HEADER_SIZE, buf, len);
	}

	std::string msg = "sendto::SIGN " + ip2str(_dest->sin_addr) + ":" + std::to_string(port) + 
		"{" + std::to_string(vport) + ", " + std::to_string(header.flags) + "} (" + std::to_string(dbg.send) + ", " + 
		std::to_string(dbg.recv) + "/" + std::to_string(dbg.read) + ")";
	INFO_HEXLOG(Log::sceNet, msg.c_str(), buf, len, 386);

	// Send through DCCP
	int ret = ::sendto(dccp_sock->sock, packet.get(), packet_size, flags, (struct sockaddr*)&saddr.addr, sizeof(sockaddr));
	if (ret > 0)
		dbg.sent++;
	
	return ret;
 }
int ConnDgramSocket::recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) { 
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
	if (saddr.in.sin_addr.s_addr == INADDR_ANY || (g_Config.bEnableAdhocServer && saddr.in.sin_addr.s_addr == INADDR_BROADCAST)) {
		// Get Local IP Address
		sockaddr_in sockAddr{};
		getLocalIp(&sockAddr);
		INFO_LOG(Log::sceNet, "Bind: Address Replacement = %s => %s", ip2str(saddr.in.sin_addr).c_str(), ip2str(sockAddr.sin_addr).c_str());
		saddr.in.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
	}
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

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, NewPort = %d, VPort = %d", inetSocketDomain2str(saddr.addr.sa_family).c_str(), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port), port, vport);

	changeBlockingMode(sock, 0);
	int ret = ::bind(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret);
	return ret;
}
int ConnDgramSocket::select(fd_set* readfds, fd_set* writefds, fd_set* exceptfds, timeval* timeout) {
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
	
	if (readfds)   { read_copy = *readfds;   p_read = &read_copy;   }
	if (writefds)  { write_copy = *writefds; p_write = &write_copy; }
	if (exceptfds) { exc_copy = *exceptfds;  p_exc = &exc_copy;     }
	
	// Using 'sock' mirrors your default fallback behavior
	int phys_ready = ::select(sock, p_read, p_write, p_exc, &tv_zero);
	if (phys_ready > 0) {
		DEBUG_LOG(Log::sceNet, "select: vport %d has physical data/events", vport);
		// Copy back the mutated sets so the caller knows exactly what triggered
		if (readfds)   *readfds = read_copy;
		if (writefds)  *writefds = write_copy;
		if (exceptfds) *exceptfds = exc_copy;
		return phys_ready;
	}
	
	// Nothing ready yet
	return 0;
	// Wait Logic?
}

void ConnDgramSocket::enqueue_packet(VirtualPacket& packet) {
	std::lock_guard<std::mutex> lock(queue_lock);
	// Add timestamp for TTL tracking
	packet.enqueue_time_us = (u64)(time_now_d() * 1000000.0);
	rx_queue.push_back(std::move(packet));
	packet_ready.notify_all();
	DEBUG_LOG(Log::sceNet, "Enqueued packet for vport %d (queue size: %zu)", vport, rx_queue.size());
}
bool ConnDgramSocket::dequeue_packet(VirtualPacket& packet) {
	std::lock_guard<std::mutex> lock(queue_lock);
	const u64 MAX_PACKET_AGE_US = 30000000;  // 30 seconds
	
	while (!rx_queue.empty()) {
		packet = std::move(rx_queue.front());
		rx_queue.pop_front();
		
		// Check packet TTL
		u64 current_time_us = (u64)(time_now_d() * 1000000.0);
		u64 packet_age_us = current_time_us - packet.enqueue_time_us;
		
		if (packet_age_us > MAX_PACKET_AGE_US) {
			DEBUG_LOG(Log::sceNet, "dequeue_packet: Discarding stale packet on vport %d (age: %.2f seconds)",
				vport, (float)packet_age_us / 1000000.0f);
			continue;  // Skip this packet and try the next one
		}
		
		DEBUG_LOG(Log::sceNet, "Dequeued packet from vport %d (queue size: %zu)", vport, rx_queue.size());
		return true;
	}
	
	return false;  // Queue is empty
}
bool ConnDgramSocket::has_pending_data() const {
	std::lock_guard<std::mutex> lock(queue_lock);
	return !rx_queue.empty();
}

// ============================================================================
// TCP Virtual Socket with UPnP transmission capabilities
// ============================================================================

int PacketSocket::send(const char* buf, int len, int flags) { 
	// Delegate to sendto with peer address
	sockaddr_in peer;
	peer.sin_family = AF_INET;
	peer.sin_addr.s_addr = dst_addr;
	peer.sin_port = htons(dst_port);
	
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

	// Build packet: VPORT_HEADER + payload
	int packet_size = VPORT_HEADER_SIZE + len;
	std::unique_ptr<char[]> packet = std::make_unique<char[]>(packet_size);

	// Pack DGRAM_HEADER (3 bytes): [flags][data_len]
	VPORT_HEADER header;
	header.flags = p2ps_tcp_flags::PSH;
	header.vport = htons(dst_port);
	memcpy(packet.get(), &header, VPORT_HEADER_SIZE);

	// Add the message
    if (len > 0 && buf != nullptr)
        memcpy(packet.get() + VPORT_HEADER_SIZE, buf, len);

	std::string msg = "send::PACKET " + ip2str(dst_addr) + ":" + std::to_string(dst_port) + 
	"[" + std::to_string(vport) + "] (" + std::to_string(dbg.send) + ", " + 
	std::to_string(dbg.recv) + "/" + std::to_string(dbg.read) + ")";
	INFO_HEXLOG(Log::sceNet, msg.c_str(), buf, len, 386);

	if (isLocalTarget(&peer)) {
		sockaddr_in src_addr{};
		src_addr.sin_family = AF_INET;
		src_addr.sin_port = htons(this->port);
		if (inet_pton(AF_INET, this->addr.c_str(), &src_addr.sin_addr) <= 0) {
			// Fallback if the string is empty or invalid (e.g., binds to INADDR_ANY / 0.0.0.0)
			sockaddr_in sockAddr{};
			getLocalIp(&sockAddr);
			src_addr.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
		}
		// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
		g_socketManager.DeliverPacketToVPorts(header, buf, len, src_addr);
		dbg.sent++;
		return len;
	} else {
		// Send through DCCP
		int ret = ::sendto(dccp_sock->sock, packet.get(), packet_size, flags, (const sockaddr*)&peer, sizeof(sockaddr_in));
		if (ret < 0)
			return hleLogError(Log::sceNet, -1, "SOCK_PACKET accept: Failed to send ACK to peer");
		dbg.sent++;
		return ret;
	}
	
	// // If this socket has broadcast enabled, replicate to other broadcast subscribers on this VPort
	// if ((so_flags & SO_FLAGS_DCCP_BROADCAST) && ret > 0) {
	// 	g_socketManager.BroadcastFromSocket(vport, this, buf, len, &peer);
	// }
	
	return 0;
}
int PacketSocket::recv(char* buf, int len, int flags) { 
	if (tcp_state == TCPState::SynSent || tcp_state == TCPState::SynReceived) {
#if PPSSPP_PLATFORM(WINDOWS)
        SetLastError(WSAEWOULDBLOCK);
#else
        socket_errno = EWOULDBLOCK;
#endif
		return hleLogError(Log::sceNet, -1, "Socket not in Listening state (state=%d)", (int)tcp_state);
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
	size_t copy_len = dequeue_stream(buf, len, &source_addr);
	if (copy_len == 0) {
		if (tcp_state == TCPState::CloseWait) {
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(WSAENOTCONN);
#else
			socket_errno = ENOTCONN;
#endif
		return 0;
		}
#if PPSSPP_PLATFORM(WINDOWS)
        SetLastError(WSAEWOULDBLOCK);
#else
        socket_errno = EWOULDBLOCK;
#endif
        return -1;
    }

	// // Dequeue from local packet queue for virtual sockets
	// VirtualPacket pkt;
	// if (!dequeue_packet(pkt)) {
	// 	// Empty Queue, try actual socket
	// 	int ret = ::recv(sock, buf, len, flags);
	// 	if (ret > 0)
	// 		dbg.recv++;
	// 	return ret;
	// }
	
	INFO_LOG(Log::sceNet, "%d=recv(%s:%u) -> vport %d (type=%d); [%lld/%lld, %lld/%lld]", 
		copy_len, inet_ntoa(source_addr.sin_addr), ntohs(source_addr.sin_port), 
		vport, type,
		dbg.send, dbg.sent, dbg.recv, dbg.read);
	
	// Copy packet data to caller's buffer
	// size_t copy_len = std::min((size_t)len, pkt.len);
	// if (copy_len > 0) {
	// memcpy(buf, buf, copy_len);
	// }
	
	dbg.recv++;
	return copy_len;
}
int PacketSocket::connect(SceNetInetSockaddr* name, int namelen) { 
	const sockaddr_in* _dest = reinterpret_cast<const sockaddr_in*>(name);

	if (this->addr == "0.0.0.0") {
		sockaddr_in sockAddr{};
		getLocalIp(&sockAddr);
		this->addr = inet_ntoa(sockAddr.sin_addr);
	}
	if (this->port == 0) {
		this->port = g_socketManager.generateEphemeralPort();
		this->vport = SCE_SIGN_PORT;
	}
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
	

	// Build packet: VPORT_HEADER + payload
	int packet_size = VPORT_HEADER_SIZE;
	std::unique_ptr<char[]> packet = std::make_unique<char[]>(packet_size);

	// Pack DGRAM_HEADER (3 bytes): [flags][data_len]
	VPORT_HEADER header;
	header.flags = p2ps_tcp_flags::SYN;
	header.vport = _dest->sin_port;
	memcpy(packet.get(), &header, VPORT_HEADER_SIZE);


	if (isLocalTarget(_dest)) {
		sockaddr_in src_addr{};
		src_addr.sin_family = AF_INET;
		src_addr.sin_port = htons(this->port);
		if (inet_pton(AF_INET, this->addr.c_str(), &src_addr.sin_addr) <= 0) {
			// Fallback if the string is empty or invalid (e.g., binds to LocalIp)
			sockaddr_in sockAddr{};
			getLocalIp(&sockAddr);
			src_addr.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
		}
		// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
		g_socketManager.DeliverPacketToVPorts(header, packet.get(), packet_size, src_addr);
	} else {
		int ret = ::sendto(dccp_sock->sock, packet.get(), packet_size, 0, (struct sockaddr*)_dest, sizeof(_dest));
		if (ret < 0) {
			return hleLogError(Log::sceNet, -1, "SOCK_PACKET connect: Failed to send SYN");
	}
}

	// Set state to SynSent (waiting for ACK)
	tcp_state = TCPState::SynSent;

	// Store connected socket
	dst_addr = _dest->sin_addr.s_addr;
	dst_port = ntohs(_dest->sin_port);
	
	// Store target address for when ACK arrives
	// Note: actual peer info will be set when we receive ACK
	
	INFO_LOG(Log::sceNet, "SOCK_PACKET connect: Sent SYN from vport %d to %s:%u",
		vport, inet_ntoa(_dest->sin_addr), ntohs(_dest->sin_port));
	
	return 0;  // Non-blocking: game will check connection status later
}
int PacketSocket::listen(int backlog) { 
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
		
	INFO_LOG(Log::sceNet, "SOCK_PACKET listen: vport %d now accepting connections", vport);

	// return ::listen(sock, backlog);
		return 0;
}
int PacketSocket::accept(sockaddr* addr, socklen_t* addrlen) { 
	// DCCP must exist for P2P traffic
	auto dccp_sock = g_socketManager.GetDCCP();
	if (!dccp_sock) {
#if PPSSPP_PLATFORM(WINDOWS)
        SetLastError(WSAENETDOWN);
#else
        socket_errno = ENETDOWN;
#endif
		return hleLogError(Log::sceNet, -1, "DCCP_SOCK Not Present");
	}

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
	ConnectionRequest pending_conn;
	if (!get_pending_connection(pending_conn)) {
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
		memcpy(addr, &pending_conn.peer_addr, std::min((size_t)*addrlen, sizeof(sockaddr_in)));
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
	
	// Copy metadata from listening socket to new socket
	new_sock->vport = this->vport;         // Same vport
	new_sock->port = this->port;           // Same port
	new_sock->addr = this->addr;           // Same address
	new_sock->tcp_state = TCPState::Established;
	new_sock->dst_addr = pending_conn.peer_addr.sin_addr.s_addr;
	new_sock->dst_port = pending_conn.peer_port;  // Store peer's vport
	
	DEBUG_LOG(Log::sceNet, "SOCK_PACKET accept: Created new socket %d with vport %d, peer vport %d", new_socket_idx, vport, pending_conn.peer_port);


	// Build packet: VPORT_HEADER + payload
	int packet_size = VPORT_HEADER_SIZE;
	std::unique_ptr<char[]> packet = std::make_unique<char[]>(packet_size);

	// Pack DGRAM_HEADER (3 bytes): [flags][data_len]
	VPORT_HEADER header;
	header.flags = p2ps_tcp_flags::ACK;
	header.vport = htons(pending_conn.peer_port);
	memcpy(packet.get(), &header, VPORT_HEADER_SIZE);

	if (isLocalTarget(&pending_conn.peer_addr)) {
		sockaddr_in src_addr{};
		src_addr.sin_family = AF_INET;
		src_addr.sin_port = htons(this->port);
		if (inet_pton(AF_INET, this->addr.c_str(), &src_addr.sin_addr) <= 0) {
			// Fallback if the string is empty or invalid (e.g., binds to INADDR_ANY / 0.0.0.0)
			sockaddr_in sockAddr{};
			getLocalIp(&sockAddr);
			src_addr.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
		}
		// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
		g_socketManager.DeliverPacketToVPorts(header, packet.get(), packet_size, src_addr);
	} else {
		int ret = ::sendto(dccp_sock->sock, packet.get(), packet_size, 0,
			(const sockaddr*)&pending_conn.peer_addr, sizeof(sockaddr_in));
		if (ret < 0) {
			ERROR_LOG(Log::sceNet, "SOCK_PACKET accept: Failed to send ACK to peer");
					return -1;
				}
			}
	DEBUG_LOG(Log::sceNet, "SOCK_PACKET accept: Delivered ACK to client vport %d", pending_conn.peer_port);

	INFO_LOG(Log::sceNet, "SOCK_PACKET accept: Accepted connection on listening socket vport %d from %s:%u (peer vport %u), created socket %d",
		vport, inet_ntoa(pending_conn.peer_addr.sin_addr), ntohs(pending_conn.peer_addr.sin_port),
		pending_conn.peer_port, new_socket_idx);
	
	return new_socket_idx;
}
int PacketSocket::bind(SceNetInetSockaddr* name, int namelen) { 
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
	if (saddr.in.sin_addr.s_addr == INADDR_ANY || (g_Config.bEnableAdhocServer && saddr.in.sin_addr.s_addr == INADDR_BROADCAST)) {
		// Get Local IP Address
		sockaddr_in sockAddr{};
		getLocalIp(&sockAddr);
		INFO_LOG(Log::sceNet, "Bind: Address Replacement = %s => %s", ip2str(saddr.in.sin_addr).c_str(), ip2str(sockAddr.sin_addr).c_str());
		saddr.in.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
	}
	// TODO: Make use Port Offset only for PPSSPP to PPSSPP communications (ie. IP addresses available in the group/friendlist), otherwise should be considered as Online Service thus should use the port as is.
	//saddr.in.sin_port = htons(ntohs(saddr.in.sin_port) + portOffset);

	// Update socket debug metadata
	addr = ip2str(saddr.in.sin_addr);
	port = ntohs(saddr.in.sin_port);
	// The PSP is expected to provide 0, and we need to generate a vport
	// This is later "agreed" upon in the P2P handshake?
	vport = (saddr.in.sin_zero[0] << 8) | saddr.in.sin_zero[1];

	INFO_LOG(Log::sceNet, "sceNetInetBind: Family = %s, Address = %s, Port = %d, VPort = %d", inetSocketDomain2str(saddr.addr.sa_family).c_str(), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port), vport);

	changeBlockingMode(sock, 0);
	int ret = ::bind(sock, (struct sockaddr*)&saddr.in, sizeof(saddr.in));
	if (ret < 0)
		return hleLogError(Log::sceNet, ret);
	return ret;
}
int PacketSocket::shutdown(int how) { 
	// Only allow shutdown if connected
	if (tcp_state != TCPState::Established && tcp_state != TCPState::SynReceived) {
		INFO_LOG(Log::sceNet, "SOCK_PACKET shutdown: Socket not connected (state=%d)", (int)tcp_state);
		return 0;  // Silently ignore if not connected
	}
	
	// Get DCCP socket for sending FIN
	auto dccp_sock = g_socketManager.GetDCCP();
	if (dccp_sock) {
		// Build packet: VPORT_HEADER + payload
		int packet_size = VPORT_HEADER_SIZE;
		std::unique_ptr<char[]> packet = std::make_unique<char[]>(packet_size);

		// Pack DGRAM_HEADER (3 bytes): [flags][data_len]
		VPORT_HEADER header;
		header.flags = p2ps_tcp_flags::FIN;
		header.vport = htons(dst_port);
		memcpy(packet.get(), &header, VPORT_HEADER_SIZE);

		sockaddr_in dst;
		dst.sin_family = AF_INET;
		dst.sin_addr.s_addr = dst_addr;
		dst.sin_port = htons(dst_port);
		
		if (isLocalTarget(&dst)) {
			sockaddr_in src_addr{};
			src_addr.sin_family = AF_INET;
			src_addr.sin_port = htons(this->port);
			if (inet_pton(AF_INET, this->addr.c_str(), &src_addr.sin_addr) <= 0) {
				// Fallback if the string is empty or invalid (e.g., binds to INADDR_ANY / 0.0.0.0)
				sockaddr_in sockAddr{};
				getLocalIp(&sockAddr);
				src_addr.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
			}
			// return ::connect(sock, (struct sockaddr*)_dest, sizeof(sockaddr_in));
			g_socketManager.DeliverPacketToVPorts(header, packet.get(), packet_size, src_addr);
		} else {
			int ret = ::sendto(dccp_sock->sock, packet.get(), packet_size, 0, 
				(struct sockaddr*)&dst, sizeof(dst));
			if (ret < 0) {
				ERROR_LOG(Log::sceNet, "SOCK_PACKET shutdown: Failed to send FIN");
				// return -1; // Let it shut down the socket anyways
			}
		}
	}
	// Transition to disconnected
	tcp_state = TCPState::Disconnected;
	
	INFO_LOG(Log::sceNet, "SOCK_PACKET shutdown: Sent FIN from port %d to %d", port, dst_port);
		return 0;
}
int PacketSocket::select(fd_set* readfds, fd_set* writefds, fd_set* exceptfds, timeval* timeout) {
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
	
	if (readfds)   { read_copy = *readfds;   p_read = &read_copy;   }
	if (writefds)  { write_copy = *writefds; p_write = &write_copy; }
	if (exceptfds) { exc_copy = *exceptfds;  p_exc = &exc_copy;     }

	// Using 'sock' mirrors your default fallback behavior
	int phys_ready = ::select(sock, p_read, p_write, p_exc, &tv_zero);
	if (phys_ready > 0) {
		DEBUG_LOG(Log::sceNet, "select: vport %d has physical data/events", vport);
		// Copy back the mutated sets so the caller knows exactly what triggered
		if (readfds)   *readfds = read_copy;
		if (writefds)  *writefds = write_copy;
		if (exceptfds) *exceptfds = exc_copy;
		return phys_ready;
	}
	
	// Nothing ready yet
		return 0;
	// Wait Logic?
}

void PacketSocket::ProcessNetStack() {
    std::lock_guard<std::mutex> lock(queue_lock);
    const u64 MAX_PACKET_AGE_US = 30000000; // 30 seconds
    u64 current_time_us = (u64)(time_now_d() * 1000000.0);

    auto it = rx_queue.begin();
    while (it != rx_queue.end()) {
        VirtualPacket& pkt = *it;

        // 1. Cleanup Stale Packets (Protocol Housekeeping)
        u64 packet_age_us = current_time_us - pkt.enqueue_time_us;
        if (packet_age_us > MAX_PACKET_AGE_US) {
            DEBUG_LOG(Log::sceNet, "RunProtocolStack: Discarding stale packet (age: %.2f s)", 
                (float)packet_age_us / 1000000.0f);
            it = rx_queue.erase(it);
            continue;
        }

        // 2. Process Control Plane (The "Kernel" Logic)
        if (pkt.header_flags & p2ps_tcp_flags::SYN) {
            // Handled by acceptor, but we clear it from the queue here
            it = rx_queue.erase(it);
        } 
        else if (pkt.header_flags & p2ps_tcp_flags::ACK) {
            if (tcp_state == TCPState::SynSent) {
                tcp_state = TCPState::Established;
                dst_addr = pkt.src_addr.sin_addr.s_addr;
                dst_port = ntohs(pkt.src_addr.sin_port);

                // Resume the thread that is currently blocked in sceNetInetConnect
                if (threadID != -1) {
                    DEBUG_LOG(Log::sceNet, "RunProtocolStack: ACK received, resuming thread %d", threadID);
                    __KernelResumeThreadFromWait(threadID, 0);
                    threadID = -1;
                }
            }
            it = rx_queue.erase(it);
        } 
        else if (pkt.header_flags & p2ps_tcp_flags::FIN) {
            if (tcp_state != TCPState::Listening) {
                tcp_state = TCPState::Disconnected;
            }
            it = rx_queue.erase(it);
        } 
        else if (pkt.header_flags & p2ps_tcp_flags::PSH) {
            // This is application data. Stop processing control flags 
            // and leave this (and everything after it) for the game to Recv().
            break; 
        } 
        else {
            it++;
        }
    }
}
void PacketSocket::enqueue_packet(VirtualPacket& packet) {
	std::lock_guard<std::mutex> lock(queue_lock);
	// Add timestamp for TTL tracking
	packet.enqueue_time_us = (u64)(time_now_d() * 1000000.0);
	rx_queue.push_back(std::move(packet));
	packet_ready.notify_all();
	DEBUG_LOG(Log::sceNet, "Enqueued packet for vport %d (queue size: %zu)", vport, rx_queue.size());
}
bool PacketSocket::dequeue_packet(VirtualPacket& packet) {
	std::lock_guard<std::mutex> lock(queue_lock);
	const u64 MAX_PACKET_AGE_US = 30000000;  // 30 seconds
	
	while (!rx_queue.empty()) {
		packet = std::move(rx_queue.front());
		rx_queue.pop_front();
		
		// Check packet TTL
		u64 current_time_us = (u64)(time_now_d() * 1000000.0);
		u64 packet_age_us = current_time_us - packet.enqueue_time_us;
		
		if (packet_age_us > MAX_PACKET_AGE_US) {
			DEBUG_LOG(Log::sceNet, "dequeue_packet: Discarding stale packet on vport %d (age: %.2f seconds)",
				vport, (float)packet_age_us / 1000000.0f);
			continue;  // Skip this packet and try the next one
		}
		
		DEBUG_LOG(Log::sceNet, "Dequeued packet from vport %d (queue size: %zu)", vport, rx_queue.size());
		return true;
	}
	
	return false;  // Queue is empty
}
int PacketSocket::dequeue_stream(char* buf, int len, sockaddr_in* out_addr) {
    std::lock_guard<std::mutex> lock(queue_lock);
    const u64 MAX_PACKET_AGE_US = 30000000;  // 30 seconds
    u64 current_time_us = (u64)(time_now_d() * 1000000.0);
    
    int total_copied = 0;
    bool target_locked = false;
    sockaddr_in target_addr{};
    
    while (total_copied < len && !rx_queue.empty()) {
        // Peek at the front packet (do NOT pop yet)
        VirtualPacket& peek_pkt = rx_queue.front();
        
        // Check packet TTL
        u64 packet_age_us = current_time_us - peek_pkt.enqueue_time_us;
        if (packet_age_us > MAX_PACKET_AGE_US) {
            DEBUG_LOG(Log::sceNet, "dequeue_stream: Discarding stale packet on vport %d", vport);
            rx_queue.pop_front(); // Safe to discard
            continue;
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
        VirtualPacket packet = std::move(rx_queue.front());
        rx_queue.pop_front();
        
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
            
            rx_queue.push_front(std::move(remainder));
            break; // Buffer is full
        }
    }
    
    return total_copied;
}
bool PacketSocket::has_pending_data() const {
	std::lock_guard<std::mutex> lock(queue_lock);
	return !rx_queue.empty();
}
void PacketSocket::set_pending_connection(const ConnectionRequest& conn) {
	std::lock_guard<std::mutex> lock(conn_lock);
	pending_connection = std::make_unique<ConnectionRequest>(conn);
	DEBUG_LOG(Log::sceNet, "Set pending connection on vport %d from %s:%u",
		vport, inet_ntoa(conn.peer_addr.sin_addr), ntohs(conn.peer_addr.sin_port));
}
bool PacketSocket::get_pending_connection(ConnectionRequest& conn) {
	std::lock_guard<std::mutex> lock(conn_lock);
	if (!pending_connection) {
		return false;
	}
	conn = *pending_connection;
	pending_connection.reset();
	return true;
}
bool PacketSocket::has_pending_connection() const {
	std::lock_guard<std::mutex> lock(conn_lock);
	return pending_connection != nullptr;
}
