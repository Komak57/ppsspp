#pragma once

#include <mutex>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <memory>
#include <unordered_map>
#include <vector>
#include "Common/Net/SocketCompat.h"
#include "Common/Log.h"
#include "Common/Swap.h"
#include "Core/HLE/NetInetTypes.h"
#include "Core/HLE/NetInetConstants.h"
#include <thread>
#include <cstring>

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

enum class TCPState {
	Disconnected = 0,
	SynSent = 1,      // connect() called, SYN sent, waiting for SYN-ACK
	SynReceived = 2,  // received SYN, queued as pending connection
	Listening = 3,    // listen() called, waiting for incoming SYN
	Established = 4,  // connection established (handshake complete)
	FinWait = 5,      // shutdown() called, FIN sent
	CloseWait = 6,	  // connected socket sent FIN
};
const char *SocketStateToString(SocketState state);

// RPCS3 implemented RDP stack for TCP flags
enum p2ps_tcp_flags : u8
{
	FIN = (1 << 0),
	SYN = (1 << 1),
	RST = (1 << 2),
	PSH = (1 << 3),
	ACK = (1 << 4),
	URG = (1 << 5),
	ECE = (1 << 6),
	CWR = (1 << 7),
};

struct VPORT_HEADER {
	u16 vport;
	// UDP uses SUBSET, TCP uses FLAGS
	u8 flags;
};
const int VPORT_HEADER_SIZE = 3;

// Must be exactly 3 bytes: (u8 flags) + (u16 data_len in network order)
// struct DGRAM_HEADER {
// 	u8 flags;
// 	u16 data_len;
// };
// const int DGRAM_HEADER_SIZE = 3;

struct SOCK_DBG {
	s64 send; // send/sendto packets
	s64 sent; // delivered packets
	s64 recv; // recv/recvfrom packets
	s64 read; // received packets
};

// Packet structure for virtual socket queuing
struct VirtualPacket {
	std::unique_ptr<char[]> data;  // Payload (heap allocated)
	size_t len;                     // Payload length
	sockaddr_in src_addr;           // Source address (for recvfrom)
	u8 header_flags;                // TCP flags from DGRAM_HEADER for control packets
	u64 enqueue_time_us;            // Microseconds since epoch (for TTL checking)
};

// Connection request for SOCK_PACKET listen queue
struct ConnectionRequest {
	sockaddr_in peer_addr;          // Remote address info
	u16 peer_port;                 // Remote virtual port
};

#pragma pack(push, 8)
// Internal socket state tracking
struct InetSocket {
	SOCKET sock;  // native socket
	SocketState state;
	// NOTE: These are the PSP types. Can be converted to the host types if needed.
	int domain;
	int protocol;
	bool nonblocking;

	// Metadata for debug use only.
	std::string addr;
	int port;
	SOCK_DBG dbg;

	// Virtual Socket fields
	TCPState tcp_state; // Used by SOCK_PACKET
	int type; // WARNING: vsocks rely on this, will break if changed
	int vport; // Host Order; WARNING: vsocks rely on this, will break if changed
	u32 dst_addr;
	u16 dst_port;
	int threadID = 0;
	std::thread thread;

	// Subscription and Broadcasting flags
	std::unordered_map<uint64_t, std::vector<uint8_t>> so_storage;
	u32 broadcast_mask = 0;              // Bitfield tracking which "rooms/sessions" this socket participates in

	// Packet queue for virtual sockets (SOCK_PACKET and SOCK_CONN_DGRAM)
	std::deque<VirtualPacket> rx_queue;
	mutable std::mutex queue_lock;
	std::condition_variable packet_ready;

	// Pending connection for SOCK_PACKET (simplified: one slot only)
	std::unique_ptr<ConnectionRequest> pending_connection;
	mutable std::mutex conn_lock;

	fd_set* readfds;
	fd_set* writefds;
	fd_set* exceptfds;
	// Virtual destructor for proper cleanup of derived types
	virtual ~InetSocket() = default;
	void clear();
	InetSocket() {
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
		
		so_storage.clear();
		broadcast_mask = 0;

		// Clear the queue safely
		{
			std::lock_guard<std::mutex> lock(queue_lock);
			std::deque<VirtualPacket> empty;
			std::swap(rx_queue, empty);
		}
		
		// Reset pointers
		{
			std::lock_guard<std::mutex> lock(conn_lock);
			pending_connection.reset();
		}
		readfds = nullptr;
		writefds = nullptr;
		exceptfds = nullptr;
	};
	// Virtual methods - override in derived classes for type-specific behavior
	// Base implementations return EOPNOTSUPP for unsupported operations
	virtual int select(fd_set* readfds, fd_set* writefds, fd_set* exceptfds, timeval* timeout);
	virtual int setsockopt(int level, int optname, int optval, socklen_t optlen);
	virtual int setsockopt(int level, int optname, const char* optval, socklen_t optlen);
	virtual int getsockopt(int level, int optname, char* optval, socklen_t* optlen);
	virtual bool is_broadcast_enabled() const;

	virtual int bind(SceNetInetSockaddr* name, int namelen);
	virtual int closesocket();
	virtual int shutdown(int how);

	virtual int send(const char* buf, int len, int flags);
	virtual int recv(char* buf, int len, int flags);
	virtual int sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen);
	virtual int recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen);
	virtual int connect(SceNetInetSockaddr* name, int namelen);
	virtual int listen(int backlog);
	virtual int accept(sockaddr* addr, socklen_t* addrlen);

	virtual void ProcessNetStack();
};
#pragma pack(pop)

// Derived socket type implementations - each supports only the operations for its type
// NOTE: These classes must NOT add member variables to maintain placement new compatibility

#pragma pack(push, 8)
class StreamSocket : public InetSocket {
public:
	StreamSocket() : InetSocket() {
		this->tcp_state = TCPState::Disconnected;
		this->type = PSP_NET_INET_SOCK_STREAM;
	}
	int send(const char* buf, int len, int flags) override;
	int recv(char* buf, int len, int flags) override;
	int connect(SceNetInetSockaddr* name, int namelen) override;
	int listen(int backlog) override;
	int accept(sockaddr* addr, socklen_t* addrlen) override;
	int bind(SceNetInetSockaddr* name, int namelen) override;
	int shutdown(int how) override;
};
#pragma pack(pop)
static_assert(sizeof(StreamSocket) == sizeof(InetSocket), "Socket size mismatch!");
#pragma pack(push, 8)
class DgramSocket : public InetSocket {
public:
	DgramSocket() : InetSocket() {
		this->type = PSP_NET_INET_SOCK_DGRAM;
	}
	int sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) override;
	int recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) override;
	int bind(SceNetInetSockaddr* name, int namelen) override;
	int shutdown(int how) override;
};
#pragma pack(pop)
static_assert(sizeof(DgramSocket) == sizeof(InetSocket), "Socket size mismatch!");
#pragma pack(push, 8)
class RawSocket : public InetSocket {
public:
	RawSocket() : InetSocket() {
		this->type = PSP_NET_INET_SOCK_RAW;
	}
	int send(const char* buf, int len, int flags) override;
	int recv(char* buf, int len, int flags) override;
	int sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) override;
	int recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) override;
	int bind(SceNetInetSockaddr* name, int namelen) override;
};
#pragma pack(pop)
static_assert(sizeof(RawSocket) == sizeof(InetSocket), "Socket size mismatch!");
#pragma pack(push, 8)
class RdmSocket : public InetSocket {
public:
	RdmSocket() : InetSocket() {
		this->type = PSP_NET_INET_SOCK_RDM;
	}
	int send(const char* buf, int len, int flags) override;
	int recv(char* buf, int len, int flags) override;
	int sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) override;
	int recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) override;
	int bind(SceNetInetSockaddr* name, int namelen) override;
};
#pragma pack(pop)
static_assert(sizeof(RdmSocket) == sizeof(InetSocket), "Socket size mismatch!");
#pragma pack(push, 8)
class SeqpacketSocket : public InetSocket {
public:
	SeqpacketSocket() : InetSocket() {
		this->type = PSP_NET_INET_SOCK_SEQPACKET;
	}
	int send(const char* buf, int len, int flags) override;
	int recv(char* buf, int len, int flags) override;
	int sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) override;
	int recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) override;
	int connect(SceNetInetSockaddr* name, int namelen) override;
	int listen(int backlog) override;
	int accept(sockaddr* addr, socklen_t* addrlen) override;
	int bind(SceNetInetSockaddr* name, int namelen) override;
	int shutdown(int how) override;
};
#pragma pack(pop)
static_assert(sizeof(SeqpacketSocket) == sizeof(InetSocket), "Socket size mismatch!");
#pragma pack(push, 8)
class DccpSocket : public InetSocket {
public:
	DccpSocket() : InetSocket() {
		this->type = PSP_NET_INET_SOCK_DCCP;
	}
	int send(const char* buf, int len, int flags) override;
	int recv(char* buf, int len, int flags) override;
	int sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) override;
	int recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) override;
	int connect(SceNetInetSockaddr* name, int namelen) override;
	int listen(int backlog) override;
	int accept(sockaddr* addr, socklen_t* addrlen) override;
	int bind(SceNetInetSockaddr* name, int namelen) override;
	int shutdown(int how) override;
	void ProcessNetStack() override;
};
#pragma pack(pop)
static_assert(sizeof(DccpSocket) == sizeof(InetSocket), "Socket size mismatch!");
#pragma pack(push, 8)
class ConnDgramSocket : public InetSocket {
public:
	ConnDgramSocket() : InetSocket() {
		this->type = PSP_NET_INET_SOCK_CONN_DGRAM;
	}
	int select(fd_set* readfds, fd_set* writefds, fd_set* exceptfds, timeval* timeout) override;
	int sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) override;
	int recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) override;
	int bind(SceNetInetSockaddr* name, int namelen) override;

	// Helper methods for virtual socket packet handling
	void enqueue_packet(VirtualPacket& packet);
	bool dequeue_packet(VirtualPacket& packet);
	bool has_pending_data() const;
	void clear();
};
#pragma pack(pop)
static_assert(sizeof(ConnDgramSocket) == sizeof(InetSocket), "Socket size mismatch!");
#pragma pack(push, 8)
class PacketSocket : public InetSocket {
public:
	PacketSocket() : InetSocket() {
		this->type = PSP_NET_INET_SOCK_PACKET;
	}
	int select(fd_set* readfds, fd_set* writefds, fd_set* exceptfds, timeval* timeout) override;
	int send(const char* buf, int len, int flags) override;
	int recv(char* buf, int len, int flags) override;
	int connect(SceNetInetSockaddr* name, int namelen) override;
	int listen(int backlog) override;
	int accept(sockaddr* addr, socklen_t* addrlen) override;
	int bind(SceNetInetSockaddr* name, int namelen) override;
	int shutdown(int how) override;

	void ProcessNetStack() override;
	void enqueue_packet(VirtualPacket& packet);
	bool dequeue_packet(VirtualPacket& packet);
	int dequeue_stream(char* buf, int len, sockaddr_in* out_addr);
	bool has_pending_data() const;
	void set_pending_connection(const ConnectionRequest& conn);
	bool get_pending_connection(ConnectionRequest& conn);
	bool has_pending_connection() const;
};
#pragma pack(pop)
static_assert(sizeof(PacketSocket) == sizeof(InetSocket), "Socket size mismatch!");

// VPort Bus subscription entry (replaced SwitchEntry)
struct VPortSubscriber {
	InetSocket* socket;
	std::string subscriber_id;  // For debugging: helps identify which game/module subscribes
	u8 vport_subset = 0xFF;     // For VPort 0: subset filter (0=RPCN, 1=Signaling, 0xFF=all). Ignored for other VPorts.
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
	int DeliverPacketToVPorts(const VPORT_HEADER& header, const char* packet_data, int data_len, const sockaddr_in& _from);

	bool GetInetSocket(int sock, InetSocket **inetSocket);
	u16 generateEphemeralPort();
	u16 generateVPort();
	SOCKET GetHostSocketFromInetSocket(int sock);
	bool Close(InetSocket *inetSocket);
	void CloseAll();
	void ProcessNetStack();

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
