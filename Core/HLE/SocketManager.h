#pragma once

#include <mutex>
#include <atomic>
#include <queue>
#include <map>
#include <list>
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
	UNUSED1 = (1 << 5),
	UNUSED2 = (1 << 6),
	TCP = (1 << 7), // Is using TCP protocols
};

enum p2p_type : u8
{
	DISABLED = 0xFF,
	RELIABLE = 0x00,
	UNRELIABLE = 0x01
};

struct VPORT_HEADER {
	u16 dest;
	// UDP uses SUBSET, TCP uses FLAGS
	u8 flags;
};
const int VPORT_HEADER_SIZE = 3;

// Wildcard vport for UNRELIABLE game traffic whose sender supplied no dest vport
// (games that address peers by the real IP:port from signaling). The receiver
// delivers to every game socket (vport != 0) of that peer. 0 stays reserved for
// RPCN/signaling. Byte-order invariant by construction.
const u16 VPORT_ANY = 0xFFFF;

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

struct sockaddr_vin {
	uint16_t		family;
    uint16_t		port;
    in_addr 		addr;
    uint16_t		vport;        // 2 bytes (Maps to sin_zero[0] and sin_zero[1])
    uint8_t			zero[6];
};

union VirtualSockAddr {
    sockaddr_in  host;
    sockaddr_vin virt;
};

// Extended on-wire header for RELIABLE (TCP-flagged) p2p packets, following the
// 3-byte VPORT_HEADER: [src_port u16][src_vport u16][dst_vport u16], all network
// order, then the u32 seq_id. The dest game PORT is NOT duplicated here - it is
// the VPORT_HEADER's dest key for TCP packets. RPCN/signaling packets
// (header.dest == 0) MUST stay exactly [VPORT_HEADER][payload] - the receiver
// matches vport 0 on the 3-byte header alone before ever looking for this
// extension.
const int VPKT_HEADER_SIZE = 6;

// Packet structure for virtual socket queuing
struct VirtualPacket {
	std::unique_ptr<char[]> data;  // Payload (heap allocated)
	size_t len;                     // Payload length
	VirtualSockAddr src;            // Source address (for recvfrom)
	VirtualSockAddr dst;            // Destination address (for distribution)
	u8 header_flags;                // TCP flags from DGRAM_HEADER for control packets
	uint32_t seq_id;				// key for packet order
	bool seq_ack;					// key for packet order
	u64 enqueue_time_us;			// Microseconds since received (for TTL checking)
	u64 last_sent_us;				// Microseconds since re-sent
	int sent_count;					// Number of attempts to re-send

    VirtualPacket clone() const {
        VirtualPacket new_pkt;
        new_pkt.len = len;
        new_pkt.src = src;
        new_pkt.dst = dst;
        new_pkt.header_flags = header_flags;
		new_pkt.seq_id = seq_id;
        new_pkt.enqueue_time_us = enqueue_time_us;
		new_pkt.last_sent_us = last_sent_us;
		new_pkt.sent_count = sent_count;

        if (len > 0 && data) {
            new_pkt.data = std::make_unique<char[]>(len);
            std::memcpy(new_pkt.data.get(), data.get(), len);
        }

        return new_pkt;
    }
	VPORT_HEADER GetHeader(u16 dest) {
		// Pack DGRAM_HEADER (3 bytes): [flags][data_len]
		VPORT_HEADER header;
		header.flags = header_flags;
		header.dest = dest;
		return header;
	}
	std::tuple<int, std::unique_ptr<char[]>> Pack(VirtualSockAddr dest) {
		memcpy(&dst.virt, &dest.virt, sizeof(sockaddr_vin));
		// Wire formats (selected by the receiver in the same order):
		//   key == 0 (RPCN/signaling):  [VPORT_HEADER][payload] - 3-byte header ONLY.
		//   TCP-flagged p2p:            [VPORT_HEADER][P2P_EXT_HEADER][seq_id][payload]
		//   other p2p (UDP-over-UDP):   [VPORT_HEADER][seq_id][payload]
		// The single u16 header key differs by transport: TCP routes on the dest
		// GAME PORT; UDP routes on the dest VPORT (0 = signaling - dst.virt.port
		// holds the sockaddr's real sin_port there and must NOT be used as key).
		u16 key = (header_flags & p2ps_tcp_flags::TCP) != 0 ? dst.virt.port : dst.virt.vport;
		bool tcp = (header_flags & p2ps_tcp_flags::TCP) != 0 && key != 0;
		bool has_seq = key != 0;
		int packet_size = VPORT_HEADER_SIZE + (tcp ? VPKT_HEADER_SIZE : 0) + (has_seq ? (int)sizeof(seq_id) : 0) + (int)len;
		std::unique_ptr<char[]> packet = std::make_unique<char[]>(packet_size);

		// Pack DGRAM_HEADER (3 bytes): [flags][data_len]
		VPORT_HEADER header = GetHeader(key);
		memcpy(packet.get(), &header, VPORT_HEADER_SIZE);
		int off = VPORT_HEADER_SIZE;
		if (tcp) {
			// Fields are already network order (they mirror sockaddr storage).
			// dst.virt.port is NOT written - it rides in header.dest (the key).
			memcpy(packet.get() + off, &src.virt.port, 2); off += 2;
			memcpy(packet.get() + off, &src.virt.vport, 2); off += 2;
			memcpy(packet.get() + off, &dst.virt.vport, 2); off += 2;
		}
		if (has_seq) {
			auto net_seq_id = htonl(seq_id);
			memcpy(packet.get() + off, &net_seq_id, sizeof(net_seq_id));
			off += sizeof(net_seq_id);
		}

		// Pack the message body
		if (len > 0) {
			memcpy(packet.get() + off, data.get(), len);
		}
		return {packet_size, std::move(packet)};
	}
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
	p2p_type p2p_mode;

	// Metadata for debug use only.
	VirtualSockAddr src;
	SOCK_DBG dbg;

	// Virtual Socket fields
	TCPState tcp_state; // Used by SOCK_PACKET
	int type; // WARNING: vsocks rely on this, will break if changed
	VirtualSockAddr dst;
	std::atomic<int> threadID = -1;
	std::thread thread;
	std::atomic<bool> abortPending = false;

	// Subscription and Broadcasting flags
	std::unordered_map<uint64_t, std::vector<uint8_t>> so_storage;
	u32 broadcast_mask = 0;              // Bitfield tracking which "rooms/sessions" this socket participates in

	// Packet queue for virtual sockets (SOCK_PACKET and SOCK_CONN_DGRAM)
	uint32_t rx_seq;		// Next sequential packet
	uint32_t tx_seq;		// Next sequential packet
	mutable std::mutex queue_lock;
	std::deque<VirtualPacket> rx_queue; 		// for received packets
	mutable std::mutex buffer_lock;
	std::map<uint32_t, VirtualPacket> rx_buffer; // for sent packets
	std::map<uint32_t, VirtualPacket> tx_buffer; // for sent packets

	mutable std::mutex conn_lock;
	std::list<InetSocket*> pending_connections; // Pending connection for SOCK_PACKET
	int backlog; // limit to buffered pending connections

	// Virtual destructor for proper cleanup of derived types
	virtual ~InetSocket() = default;
	void clear();
	InetSocket(int domain, int protocol) {
		// Basic types
		sock = INVALID_SOCKET;
		state = SocketState::Unused;
		this->domain = domain;
		this->protocol = protocol;
		nonblocking = false;
		p2p_mode = p2p_type::DISABLED;

		src.host = sockaddr_in{};
		memset(&dbg, 0, sizeof(dbg));

		// Virtual fields
		tcp_state = TCPState::Disconnected;
		type = 0;
		dst.host = sockaddr_in{};
		threadID = -1;
		abortPending = false;

		so_storage.clear();
		broadcast_mask = 0;

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
	}
	InetSocket() {
		// Basic types
		sock = INVALID_SOCKET;
		state = SocketState::Unused;
		domain = 0;
		protocol = 0;
		nonblocking = false;
		p2p_mode = p2p_type::DISABLED;

		src.host = sockaddr_in{};
		memset(&dbg, 0, sizeof(dbg));

		// Virtual fields
		tcp_state = TCPState::Disconnected;
		type = 0;
		dst.host = sockaddr_in{};
		threadID = -1;
		abortPending = false;
		
		so_storage.clear();
		broadcast_mask = 0;

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
	};
	// Virtual methods - override in derived classes for type-specific behavior
	// Base implementations return EOPNOTSUPP for unsupported operations
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

	// Process P2P as TCP over UDP with Sequential Ordering and Packet Loss Prevention 
	virtual int Send_Reliable(const char* buf, int len, int flags);
	virtual bool Process_Reliable();
	// Process P2P as UDP
	virtual int Send_Unrealiable(const char* buf, int len, int flags, const sockaddr* to, int tolen, u16 dest_vport);
	virtual bool Process_Unreliable();

	// Helper methods for virtual socket packet handling
	virtual void enqueue_packet(VirtualPacket packet);
	virtual bool dequeue_packet(VirtualPacket& packet, bool seq = false);
	virtual int dequeue_stream(char* buf, int len, sockaddr_in* out_addr, bool seq = false);
	virtual bool has_pending_data(bool seq = false) const;
	virtual bool set_pending_connection(InetSocket* conn);
	virtual bool update_pending_connection(const VirtualSockAddr& peer_addr);
	virtual InetSocket* get_pending_connection();
	virtual void remove_pending_connection(InetSocket* conn);
	virtual bool has_pending_connection() const;
	virtual void mark_ack(InetSocket* inetSock, int seq_id);
};
#pragma pack(pop)

// Derived socket type implementations - each supports only the operations for its type
// NOTE: These classes must NOT add member variables to maintain placement new compatibility

#pragma pack(push, 8)
class StreamSocket : public InetSocket {
public:
	StreamSocket(int domain, int protocol) : InetSocket() {
		this->clear();  // Reset to default.
		this->tcp_state = TCPState::Disconnected;
		this->type = PSP_NET_INET_SOCK_STREAM;
		this->domain = domain;
		this->protocol = protocol;

		int hostDomain = convertSocketDomainPSP2Host(domain);
		int hostType = convertSocketTypePSP2Host(PSP_NET_INET_SOCK_STREAM);
		int hostProtocol = convertSocketProtoPSP2Host(protocol);

		this->sock = ::socket(hostDomain, hostType, hostProtocol);
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
	DgramSocket(int domain, int protocol) : InetSocket() {
		this->clear();  // Reset to default.
		this->type = PSP_NET_INET_SOCK_DGRAM;
		this->domain = domain;
		this->protocol = protocol;

		int hostDomain = convertSocketDomainPSP2Host(domain);
		int hostType = convertSocketTypePSP2Host(PSP_NET_INET_SOCK_DGRAM);
		int hostProtocol = convertSocketProtoPSP2Host(protocol);

		this->sock = ::socket(hostDomain, hostType, hostProtocol);
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
	RawSocket(int domain, int protocol) : InetSocket() {
		this->clear();  // Reset to default.
		this->type = PSP_NET_INET_SOCK_RAW;
		this->domain = domain;
		this->protocol = protocol;

		int hostDomain = convertSocketDomainPSP2Host(domain);
		int hostType = convertSocketTypePSP2Host(PSP_NET_INET_SOCK_RAW);
		int hostProtocol = convertSocketProtoPSP2Host(protocol);

		this->sock = ::socket(hostDomain, hostType, hostProtocol);
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
	RdmSocket(int domain, int protocol) : InetSocket() {
		this->clear();  // Reset to default.
		this->type = PSP_NET_INET_SOCK_RDM;
		this->domain = domain;
		this->protocol = protocol;

		int hostDomain = convertSocketDomainPSP2Host(domain);
		int hostType = convertSocketTypePSP2Host(PSP_NET_INET_SOCK_RDM);
		int hostProtocol = convertSocketProtoPSP2Host(protocol);

		this->sock = ::socket(hostDomain, hostType, hostProtocol);
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
	SeqpacketSocket(int domain, int protocol) : InetSocket() {
		this->clear();  // Reset to default.
		this->type = PSP_NET_INET_SOCK_SEQPACKET;
		this->domain = domain;
		this->protocol = protocol;

		int hostDomain = convertSocketDomainPSP2Host(domain);
		int hostType = convertSocketTypePSP2Host(PSP_NET_INET_SOCK_SEQPACKET);
		int hostProtocol = convertSocketProtoPSP2Host(protocol);

		this->sock = ::socket(hostDomain, hostType, hostProtocol);
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
	DccpSocket(int domain, int protocol) : InetSocket() {
		this->clear();  // Reset to default.
		this->type = PSP_NET_INET_SOCK_DCCP;
		this->domain = domain;
		this->protocol = protocol;

		int hostDomain = convertSocketDomainPSP2Host(domain);
		int hostType = convertSocketTypePSP2Host(PSP_NET_INET_SOCK_DCCP);
		int hostProtocol = convertSocketProtoPSP2Host(protocol);

		this->sock = ::socket(hostDomain, hostType, hostProtocol);

		// This is the "kernel P2P socket" that binds port 3658 first; every
		// ConnDgramSocket that needs to share that port depends on THIS socket
		// having set SO_REUSEPORT/SO_REUSEADDR too - reuse only works if every
		// socket sharing the port opts in, not just the later ones.
		int reuse = 1;
#if defined(SO_REUSEPORT)
		::setsockopt(this->sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse));
#endif
		::setsockopt(this->sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
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
static_assert(sizeof(DccpSocket) == sizeof(InetSocket), "Socket size mismatch!");
#pragma pack(push, 8)
class ConnDgramSocket : public InetSocket {
public:
	ConnDgramSocket(int domain, int protocol) : InetSocket() {
		this->clear();  // Reset to default.
		this->type = PSP_NET_INET_SOCK_CONN_DGRAM;
		this->src.virt.vport = 0;
		this->domain = domain;
		this->protocol = protocol;
		p2p_mode = p2p_type::UNRELIABLE;

		int hostDomain = convertSocketDomainPSP2Host(domain);
		int hostType = convertSocketTypePSP2Host(PSP_NET_INET_SOCK_CONN_DGRAM);
		int hostProtocol = convertSocketProtoPSP2Host(protocol);

		this->sock = ::socket(hostDomain, hostType, hostProtocol);

		// Real hardware has no actual P2P socket: enabling signaling just redirects all
		// port-3658 traffic through a kernel-level hijack, so any number of vports can
		// share the port. Here that means multiple real sockets (one per vport, plus the
		// signaling PING/PONG listener) all need to bind the same real port, which requires
		// SO_REUSEADDR set before bind() ever happens.
		int reuse = 1;
#if defined(SO_REUSEPORT)
		::setsockopt(this->sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse));
#endif
		::setsockopt(this->sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
	}
	int sendto(const char* buf, int len, int flags, const SceNetInetSockaddr* to, int tolen) override;
	int recvfrom(char* buf, int len, int flags, SceNetInetSockaddr* from, socklen_t* fromlen) override;
	int bind(SceNetInetSockaddr* name, int namelen) override;
};
#pragma pack(pop)
static_assert(sizeof(ConnDgramSocket) == sizeof(InetSocket), "Socket size mismatch!");
#pragma pack(push, 8)
class PacketSocket : public InetSocket {
public:
	PacketSocket(int domain, int protocol) : InetSocket() {
		this->clear();  // Reset to default.
		this->type = PSP_NET_INET_SOCK_PACKET;
		this->nonblocking = false;
		this->tcp_state = TCPState::Disconnected;
		this->src.virt.vport = 0;
		this->domain = domain;
		this->protocol = protocol;
		p2p_mode = p2p_type::RELIABLE;

		int hostDomain = convertSocketDomainPSP2Host(domain);
		int hostType = convertSocketTypePSP2Host(PSP_NET_INET_SOCK_PACKET);
		int hostProtocol = convertSocketProtoPSP2Host(protocol);

		this->sock = ::socket(hostDomain, hostType, hostProtocol);
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
static_assert(sizeof(PacketSocket) == sizeof(InetSocket), "Socket size mismatch!");

#pragma push_macro("new")
#undef new

#if PPSSPP_PLATFORM(WINDOWS)
#include <new>
#endif
using SocketFactoryFn = InetSocket* (*)(void*, int, int);
const SocketFactoryFn InetSocketFactory[] = {
	[](void* p, int domain, int protocol) -> InetSocket* { return ::new (p) InetSocket(domain, protocol); },			// 0:  Default
	[](void* p, int domain, int protocol) -> InetSocket* { return ::new (p) StreamSocket(domain, protocol); },			// 1:  PSP_NET_INET_SOCK_STREAM
	[](void* p, int domain, int protocol) -> InetSocket* { return ::new (p) DgramSocket(domain, protocol); },			// 2:  PSP_NET_INET_SOCK_DGRAM
	[](void* p, int domain, int protocol) -> InetSocket* { return ::new (p) RawSocket(domain, protocol); },				// 3:  PSP_NET_INET_SOCK_RAW
	[](void* p, int domain, int protocol) -> InetSocket* { return ::new (p) InetSocket(domain, protocol); },			// 4:  PSP_NET_INET_SOCK_RDM
	[](void* p, int domain, int protocol) -> InetSocket* { return ::new (p) SeqpacketSocket(domain, protocol); },		// 5:  PSP_NET_INET_SOCK_SEQPACKET
	[](void* p, int domain, int protocol) -> InetSocket* { return ::new (p) ConnDgramSocket(domain, protocol); },		// 6:  PSP_NET_INET_SOCK_CONN_DGRAM
	[](void* p, int domain, int protocol) -> InetSocket* { return ::new (p) DccpSocket(domain, protocol); },			// 7:  PSP_NET_INET_SOCK_DCCP
	[](void* p, int domain, int protocol) -> InetSocket* { return ::new (p) InetSocket(domain, protocol); },			// 8:  UNDOCUMENTED
	[](void* p, int domain, int protocol) -> InetSocket* { return ::new (p) InetSocket(domain, protocol); },			// 9:  UNDOCUMENTED
	[](void* p, int domain, int protocol) -> InetSocket* { return ::new (p) PacketSocket(domain, protocol); }			// 10: PSP_NET_INET_SOCK_PACKET
};
#pragma pop_macro("new")

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
		VALID_INET_SOCKET_COUNT = 256,	// Maximum networking sockets
		MIN_VALID_INET_SOCKET = 3,		// Reserved system sockets
	};

	InetSocket *CreateSystemSocket(int *index, int *returned_errno, SocketState state, int domain, int type, int protocol);
	InetSocket *CreateSocket(int *index, int *returned_errno, SocketState state, int domain, int type, int protocol);
	// for accept()
	InetSocket *AdoptSocket(int *index, SOCKET hostSocket, const InetSocket *derive);
	int vBroadcast(VirtualPacket&& vpkt, VirtualSockAddr dest);

	bool GetInetSocket(int sock, InetSocket **inetSocket);
	void exhaustEphemeralPort(u16 port);
	u16 generateEphemeralPort();
	u16 generateVPort();
	SOCKET GetHostSocketFromInetSocket(int sock);
	bool Close(InetSocket *inetSocket);
	void CloseAll();
	void NetworkDemultiplexer(int* timeout);
	bool P2PRecv();

	// For debugger
	const InetSocket *Sockets() {
		return inetSockets_;
	}
	InetSocket* GetP2PSocket() { return p2p_sock; }
private:
	int NextUnusedSystemSocket();
	int NextUnusedSocket();
	
	// We use this array from MIN_VALID_INET_SOCKET and forward. It's probably not a good idea to return 0 as a socket.
	InetSocket inetSockets_[VALID_INET_SOCKET_COUNT];
	std::unordered_map<u16, u64> exhausted_ports;
	// SOCK_DCCP should only have 1 instance, ever. Each CONN_DGRAM should point to this for it's sock
	InetSocket* p2p_sock;
};

extern SocketManager g_socketManager;
