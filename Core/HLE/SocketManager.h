#pragma once

#include "Common/Net/SocketCompat.h"

// These should be safe between Windows and Linux?
#define SOCK_DCCP 18
#define SOCK_CONN_DGRAM 19

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
	int type;
	int protocol;
	bool nonblocking;
	// Metadata for debug use only.
	std::string addr;
	int port;
	int recvfrom(_Out_writes_bytes_to_(len, return) __out_data_source(NETWORK) char FAR* buf, _In_ int len, _In_ int flags, _Out_writes_bytes_to_opt_(*fromlen, *fromlen) struct sockaddr FAR* from, _Inout_opt_ int FAR* fromlen);
	int select(fd_set* readfds, fd_set* writefds, fd_set* exceptfds, timeval* timeout);
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
