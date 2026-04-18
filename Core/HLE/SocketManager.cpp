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

// A helper function to find an InetSocket by its port.
// Returns a pointer to the InetSocket on success, or nullptr if not found.
InetSocket* SocketManager::FindSocketByPort(int target_port) {
	std::lock_guard<std::mutex> guard(g_socketMutex);

	// Iterate through the valid range of socket indices.
	for (int i = SocketManager::MIN_VALID_INET_SOCKET; i < SocketManager::VALID_INET_SOCKET_COUNT; ++i) {
		const InetSocket& inetSocket = inetSockets_[i];

		// Check if the socket is in a valid state and its port matches.
		if (inetSocket.state != SocketState::Unused && inetSocket.port == target_port) {
			return const_cast<InetSocket*>(&inetSocket);
		}
	}

	DEBUG_LOG(Log::sceNet, "FindSocketByPort(%d) No matching Socket", target_port);
	// If no socket was found, return nullptr.
	return nullptr;
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
			// Clear the error
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(0);
#else
			errno = 0;
#endif

			// We can't receive without a master socket
			auto dccp_sock = g_socketManager.GetDCCP();
			if (!dccp_sock) {
#if PPSSPP_PLATFORM(WINDOWS)
				SetLastError(WSAEWOULDBLOCK);
#else
				errno = EWOULDBLOCK;
#endif
				return -1;
			}
			char newbuf[2048];
			int ret = ::recvfrom(dccp_sock->sock, newbuf, sizeof(newbuf), MSG_PEEK | flags, from, fromlen);
			if (ret <= 2)
				return (ret < 0 ? ret : -1); // Malformed

			// vport headers are attached to all packets for filtering
			u16 port_header = ntohs(*(u16*)newbuf);
			//u16 vport_header = ntohs(*(u16*)(newbuf+2));
			int data_len = ret - 2;

			if (port_header != port /*|| vport_header != vport*/) {
#if PPSSPP_PLATFORM(WINDOWS)
				SetLastError(WSAEWOULDBLOCK);
#else
				errno = EWOULDBLOCK;
#endif
				return -1; // Not for this vsock, wait for the next one
			}
			if (port == 3658) {
				sockaddr_in* _src = reinterpret_cast<sockaddr_in*>(from);
				auto header = "recvfrom::GAME " + ip2str(_src->sin_addr.s_addr) + ":" + std::to_string(ntohs(_src->sin_port));
				DEBUG_HEXLOG(Log::Signaling, header.c_str(), newbuf, ret, 386);
			}

			// Receive the packet and return
			ret = ::recvfrom(dccp_sock->sock, newbuf, sizeof(newbuf), flags, from, fromlen);

			memcpy(buf, newbuf + 2, data_len);
			return data_len;
		}
	default:
		return ::recvfrom(sock, buf, len, flags, from, fromlen);
	}
}

int InetSocket::select(fd_set* readfds, fd_set* writefds, fd_set* exceptfds, timeval* timeout) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
	{
		if (wait_thread != 0) {
#if PPSSPP_PLATFORM(WINDOWS)
			SetLastError(WSAEINVAL);
#else
			errno = EINVAL;
#endif
			return -1;
		}

		// Simulate a select + timeout
		wait_thread = sceKernelGetThreadId();
		u32 _timeout = 1000000;
		int retval = 0;
		__KernelWaitCurThread(WAITTYPE_ASYNCIO, wait_thread, retval, _timeout, false, "InetSocket.select()");
		wait_thread = 0;
		return retval;
	}
	default:
		return ::select(sock, readfds, writefds, exceptfds, timeout);
	}
}

int InetSocket::send(const char* buf, int len, int flags) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		_dbg_assert_msg_(false, "send not implemented for this socket type");
		return 0;
	default:
		return ::send(sock, buf, len, flags);
	}
}

int InetSocket::sendto(const char* buf, int len, int flags, const sockaddr* to, int tolen) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		{
			// We only send data when we have a master socket
			auto dccp_sock = g_socketManager.GetDCCP();
			if (!dccp_sock) {
#if PPSSPP_PLATFORM(WINDOWS)
				SetLastError(WSAEINVAL);
#else
				errno = EINVAL;
#endif
				return -1;
			}

			// Pad the packet
			int newlen = 2 + len;
			char* packet = new char[newlen];

			// Pack the port
			u16 port_header = htons(port);
			memcpy(packet, &port_header, 2);
			// Pack the vport
			/*u16 vport_header = htons(vport);
			memcpy(packet + 2, &port_header, 2);*/
			// Pack the message body
			memcpy(packet + 2, buf, len);

			if (port == 3658) {
				const sockaddr_in* _src = reinterpret_cast<const sockaddr_in*>(to);
				auto header = "sendto::GAME " + ip2str(_src->sin_addr) + ":" + std::to_string(ntohs(_src->sin_port));
				INFO_HEXLOG(Log::Signaling, header.c_str(), packet, newlen, 386);
			}

			return ::sendto(dccp_sock->sock, packet, newlen, flags, to, tolen);
		}
		return 0;
	default:
		return ::sendto(sock, buf, len, flags, to, tolen);
	}
}

int InetSocket::setsockopt(int level, int optname, const char* optval, socklen_t optlen) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		_dbg_assert_msg_(false, "setsockopt not implemented for this socket type");
		return 0;
	default:
		return ::setsockopt(sock, level, optname, optval, optlen);
	}
}

int InetSocket::getsockopt(int level, int optname, char* optval, socklen_t* optlen) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		_dbg_assert_msg_(false, "getsockopt not implemented for this socket type");
		return 0;
	default:
		return ::getsockopt(sock, level, optname, optval, optlen);
	}
}

int InetSocket::bind(sockaddr* name, int namelen) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		// vport 0 is used for P2P signaling, and would error if we actually bind it here
		if (vport == 0) {
			// Start vport at 30000, and be 1 higher than all other existing vports
			vport = 30000;
			auto sockets = g_socketManager.Sockets();
			for (int i = SocketManager::MIN_VALID_INET_SOCKET; i < SocketManager::VALID_INET_SOCKET_COUNT; i++) {
				if (sockets[i].state != SocketState::Unused && sockets[i].type == type && sockets[i].vport >= vport)
					vport = sockets[i].vport + 1;
				if (vport > 65535) {
#if PPSSPP_PLATFORM(WINDOWS)
					SetLastError(WSAEADDRINUSE);
#else
					errno = EADDRINUSE;
#endif
					return -1;
				}
			}
		}
		return 0;
	default:
		return ::bind(sock, name, namelen);
	}
}

int InetSocket::connect(sockaddr* name, int namelen) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		_dbg_assert_msg_(false, "connect not implemented for this socket type");
		return 0;
	default:
		return ::connect(sock, name, namelen);
	}
}

int InetSocket::listen(int backlog) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		_dbg_assert_msg_(false, "listen not implemented for this socket type");
		return 0;
	default:
		return ::listen(sock, backlog);
	}
}

int InetSocket::accept(sockaddr* addr, socklen_t* addrlen) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		_dbg_assert_msg_(false, "accept not implemented for this socket type");
		return 0;
	default:
		return ::accept(sock, addr, addrlen);
	}
}

int InetSocket::shutdown(int how) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		// Patapon3 will shut this socket down when you disband a party
		return 0;
	default:
		return ::shutdown(sock, how);
	}
}

// Close a virtual socket
int InetSocket::closesocket() {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		return 0;
	default:
		return ::closesocket(sock);
	}
}
