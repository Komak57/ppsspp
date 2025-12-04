#include "Common/Net/SocketCompat.h"
#include "Core/HLE/NetInetConstants.h"
#include "Core/HLE/SocketManager.h"
#include "Common/Log.h"

#include <mutex>

SocketManager g_socketManager;
static std::mutex g_socketMutex;  // TODO: Remove once the adhoc thread is gone

int SocketManager::NextUnusedSocket() {
	for (int i = MIN_VALID_INET_SOCKET; i < ARRAY_SIZE(inetSockets_); i++) {
		if (inetSockets_[i].state == SocketState::Unused) {
			return i;
		}
	}
	return -1;
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
			*inetSock = {};  // Reset to default.
			inetSock->domain = domain;
			inetSock->type = type;
			inetSock->protocol = protocol;
			inetSock->nonblocking = false;
	}

	SOCKET hostSock;
	switch (type) {
	case PSP_NET_INET_SOCK_DCCP: // Parent to all Virtual Sockets
		inetSock->sock = ::socket(hostDomain, SOCK_DGRAM, hostProtocol);
		
		if (inetSock->sock < 0) {
			*returned_errno = socket_errno;
			return nullptr;
		}

		inetSock->state = state;
		dccp_sock = inetSock;
			return inetSock;
	case PSP_NET_INET_SOCK_CONN_DGRAM: // Virtual Socket
		inetSock->sock = 0; // This helps find unhandled uses
		inetSock->state = state;
		return inetSock;
	default: // Normal Socket
		inetSock->sock = ::socket(hostDomain, hostType, hostProtocol);

		if (inetSock->sock < 0) {
			*returned_errno = socket_errno;
			return nullptr;
		}
		inetSock->state = state;
		return inetSock;
	}

	_dbg_assert_(false);

	ERROR_LOG(Log::sceNet, "Ran out of socket handles! This is BAD.");
	closesocket(hostSock);
	*index = 0;
	*returned_errno = ENOMEM; // or something..
	return nullptr;
}

InetSocket *SocketManager::AdoptSocket(int *index, SOCKET hostSocket, const InetSocket *derive) {
	std::lock_guard<std::mutex> guard(g_socketMutex);

	for (int i = MIN_VALID_INET_SOCKET; i < ARRAY_SIZE(inetSockets_); i++) {
		if (inetSockets_[i].state == SocketState::Unused) {
			*index = i;

			InetSocket *inetSock = inetSockets_ + i;
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
	if (closesocket(inetSocket->sock) != 0) {
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

int InetSocket::recvfrom(_Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR* buf, _In_ int len, _In_ int flags, _Out_writes_bytes_to_opt_(*fromlen, *fromlen) struct sockaddr FAR* from, _Inout_opt_ int FAR* fromlen) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		{
			// Clear the error
			SetLastError(0);

			// We can't receive without a master socket
			auto dccp_sock = g_socketManager.GetDCCP();
			if (!dccp_sock) {
				SetLastError(WSAEINVAL);
				return -1;
			}
			sockaddr_storage src;
			int src_len = sizeof(src);
			char newbuf[2048];
			int ret = ::recvfrom(dccp_sock->sock, newbuf, sizeof(newbuf), MSG_PEEK | flags, reinterpret_cast<sockaddr*>(&src), &src_len);
			if (ret <= 2)
				return (ret < 0 ? ret : -1); // Malformed

			// vport headers are attached to all packets for filtering
			u16 vport = ntohs(*(u16*)newbuf);
			int data_len = ret - 2;

			if (vport != port) {
				SetLastError(WSAEWOULDBLOCK);
				return -1; // Not for this vsock, wait for the next one
			}

			// Receive the packet and return
			ret = ::recvfrom(dccp_sock->sock, newbuf, sizeof(newbuf), flags, reinterpret_cast<sockaddr*>(&src), &src_len);

			memcpy(buf, newbuf + 2, data_len);
			memcpy(from, &src, src_len);
			*fromlen = src_len;
			return data_len;
		}
	default:
		return ::recvfrom(sock, buf, len, flags, from, fromlen);
	}
}

int InetSocket::select(fd_set* readfds, fd_set* writefds, fd_set* exceptfds, timeval* timeout) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		_dbg_assert_msg_(false, "select not implemented for this socket type");
		return 0;
	default:
		return ::select(sock, readfds, writefds, exceptfds, timeout);
	}
}
int InetSocket::sendto(const char* buf, int len, int flags, const sockaddr* to, int tolen) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		{
			// We only send data when we have a master socket
			auto dccp_sock = g_socketManager.GetDCCP();
			if (!dccp_sock) {
				SetLastError(WSAEINVAL);
				return -1;
			}

			// Pad the packet
			int newlen = 2 + len;
			char* packet = new char[newlen];

			// Pack the vport
			u16 net = htons(port);
			memcpy(packet, &net, 2);
			// Pack the message body
			memcpy(packet + 2, buf, len);

			return ::sendto(dccp_sock->sock, packet, newlen, flags, to, tolen);
		}
		return 0;
	default:
		return ::sendto(sock, buf, len, flags, to, tolen);
	}
}

int InetSocket::setsockopt(int level, int optname, const char* optval, int optlen) {
	switch (type) {
	case PSP_NET_INET_SOCK_CONN_DGRAM:
		_dbg_assert_msg_(false, "setsockopt not implemented for this socket type");
		return 0;
	default:
		return ::setsockopt(sock, level, optname, optval, optlen);
	}
}