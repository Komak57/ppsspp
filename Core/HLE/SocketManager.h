#pragma once

#include "Common/Net/SocketCompat.h"
#include "Common/Log.h"

// These should be safe between Windows and Linux?
#ifndef SOCK_DCCP
#define SOCK_DCCP 18
#endif
#ifndef SOCK_CONN_DGRAM
#define SOCK_CONN_DGRAM 19
#endif

// Keep track of who's using a socket.
enum class SocketState {
	Unused = 0,
	UsedNetInet,
	UsedProAdhoc,
};

const char *SocketStateToString(SocketState state);

// Internal socket state tracking
struct InetSocket {
	SOCKET sock;  // native socket
	SocketState state;
	// NOTE: These are the PSP types. Can be converted to the host types if needed.
	int domain;
	int type; // WARNING: vsocks rely on this, will break if changed
	int protocol;
	bool nonblocking;
	// Metadata for debug use only.
	std::string addr;
	int port;
	int vport; // WARNING: vsocks rely on this, will break if changed

	int recvfrom(char* buf, int len, int flags, sockaddr* from, socklen_t* fromlen);
	int select(fd_set* readfds, fd_set* writefds, fd_set* exceptfds, timeval* timeout);
	int sendto(const char* buf, int len, int flags, const sockaddr* to, int tolen);
	int setsockopt(int level, int optname, const char* optval, socklen_t optlen);
	int getsockopt(int level, int optname, char* optval, socklen_t* optlen);

	int bind(sockaddr* name, int namelen);
	int closesocket();
	int shutdown(int how);

	// These aren't normally used by this socket type
	int send(const char* buf, int len, int flags);
	int recv(char* buf, int len, int flags);
	int connect(sockaddr* name, int namelen);
	int listen(int backlog);
	int accept(sockaddr* addr, socklen_t* addrlen);

	int wait_thread = 0;
};

// Only use this for sockets whose ID are exposed to the game.
// Don't really need to bother with the others, as the game doesn't know about them.
class SocketManager {
public:
	enum {
		VALID_INET_SOCKET_COUNT = 256,
		MIN_VALID_INET_SOCKET = 1,
	};

	InetSocket *CreateSocket(int *index, int *returned_errno, SocketState state, int domain, int type, int protocol);
	// for accept()
	InetSocket *AdoptSocket(int *index, SOCKET hostSocket, const InetSocket *derive);

	bool GetInetSocket(int sock, InetSocket **inetSocket);
	SOCKET GetHostSocketFromInetSocket(int sock);
	InetSocket* FindSocketByPort(int target_port);
	bool Close(InetSocket *inetSocket);
	void CloseAll();

	// For debugger
	const InetSocket *Sockets() {
		return inetSockets_;
	}
	InetSocket* GetDCCP() { return dccp_sock; }

private:
	int NextUnusedSocket();
	// We use this array from MIN_VALID_INET_SOCKET and forward. It's probably not a good idea to return 0 as a socket.
	InetSocket inetSockets_[VALID_INET_SOCKET_COUNT];
	// SOCK_DCCP should only have 1 instance, ever. Each CONN_DGRAM should point to this for it's sock
	InetSocket* dccp_sock;
};

extern SocketManager g_socketManager;
