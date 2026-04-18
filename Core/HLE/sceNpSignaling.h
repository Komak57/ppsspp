// Copyright (c) 2022- PPSSPP Project.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0 or later versions.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License 2.0 for more details.

// A copy of the GPL 2.0 should have been included with the program.
// If not, see http://www.gnu.org/licenses/

// Official git repository and contact information can be found at
// https://github.com/hrydgard/ppsspp and http://www.ppsspp.org/.

#pragma once
#include "NpTypes.h"
#include "Np2Types.h"
#include "Core/HLE/sceNetInet.h"
#include "Core/HLE/SocketManager.h"

#define SCE_SIGNALING_OKAY									0x00000000

static constexpr u32 SIGNALING_SIGNATURE = (static_cast<u32>('S') << 24 | static_cast<u32>('I') << 16 | static_cast<u32>('G') << 8 | static_cast<u32>('N'));
static constexpr u32_le SIGNALING_VERSION = 4;

extern SceUID signalingThreadId;
extern SceUID signalingEchoThreadId;

/* DOCUMENTATION
SOCKETS:
	PSP_NET_INET_SOCK_DCCP is a real socket that has NAT Punchthrough enabled, performing send/recv on packed data
	PSP_NET_INET_SOCK_CONN_DGRAM are virtualized UDP sockets the game sets up for it's own internal communications. All games seem to use 1 of these.
	PSP_NET_INET_SOCK_PACKET are virtualized TCP sockets packed over P2P. Not all games use these, but PSP2i uses them heavily
PROCESS:
	SOCK_DCCP needs to ping-pong the UPnP server to keep the NAT open, and give players a way in without port forwarding
	CONN_DGRAM needs to pack a header to determine the vport destination?
*/

struct SceSignalingMemoryStat {
	int npMemSize;     // Memory allocated by the NP utility. Pool Size?
	int npMaxMemSize;  // Maximum memory used by the NP utility.
	int npFreeMemSize; // Free memory available to use by the NP utility.
	u32 priority;
};

enum class SignalingState {
    IDLE,
    WAIT_INITIAL_HANDSHAKE, // Sent SYN, waiting for peer ACK
    HANDSHAKE_RECEIVED,      // Received peer SYN, sending ACK
    MUTUAL_ACTIVATION,       // Both peers ready
    DISCONNECTING,           // Sent FIN
    CLOSED
};

enum SceNpSignalingCommand : u32_le {
	type_0x1 = 0x1, // Exit
	type_0x5 = 0x5,
	type_0x6 = 0x6,
	type_0x7 = 0x7, // Processes SCE_NP_MATCHING2_SIGNALING_EVENT_Established; Send Pipe 0x15
	type_0x8 = 0x8, // Processes SCE_NP_MATCHING2_SIGNALING_EVENT_Dead; Send Pipe 0x15
	type_0x9 = 0x9,
	type_0xa = 0xa,
	type_0xb = 0xb,
	type_0xc = 0xc,
	type_0xd = 0xd,
	type_0xe = 0xe,
	type_0x10 = 0x10, // Initializes Peer Connection Information in 0x24 byte struct
	type_0x11 = 0x11, // Processes Peer Connection Keep-Alive and Latency; Can Trigger PEER_UNREACHABLE || TIMEOUT
	type_0x14 = 0x14, // Triggers a loop that can exit with TERMINATED_BY_PEER
	type_0x15 = 0x15, // builds the connection based on information received, determines the host, and agrees on 4+ vports
	type_0x16 = 0x16,
	type_0x18 = 0x18, // Does some weird disconnect sanitation stuff
	type_0x19 = 0x19,
	type_0x1a = 0x1a, // Initialization when thread starts; Triggers multiple RecvFrom
	type_0x1e = 0x1e,
	type_0x1f = 0x1f,
	type_0x20 = 0x20,
	type_0x21 = 0x21,
	type_0x22 = 0x22,
	Ping = 0x23,
	Pong = 0x24,
	Connect = 0x25,
	ConnectAck = 0x26,
	Confirm = 0x27,
	Finished = 0x28,
	FinishedAck = 0x29,
	Info = 0x2a
};
inline const char *SceNpSignalingCommand_string(SceNpSignalingCommand cmd) {
	switch(cmd) {
		case Ping: return "PING";
		case Pong: return "PONG";
		case Connect: return "CONNECT";
		case ConnectAck: return "CONNECT_ACK";
		case Confirm: return "CONFIRM";
		case Finished: return "FINISHED";
		case FinishedAck: return "FINISHED_ACK";
		case Info: return "INFO";
		default: return "UNHANDLED";
	}
};

struct SceSignalingPeer
{
	SceNpSignalingState sig_status = SCE_NP_SIGNALING_EVENT_DEAD;
	SceNpSignalingConnectionState conn_status = SCE_NP_SIGNALING_CONN_STATUS_INACTIVE;
	// Network Order NAT bypass address for this Peer
	u32 addr = 0;
	// Host Order NAT bypass port for this Peer
	u16 port = 0;

	// Network Order address the Peer sends from
	u32 mapped_addr = 0;
	// Host Order port the Peer sends from
	u16 mapped_port = 0;

	// Calculated NAT type for this Peer
	u8 nat_type = 0;

	// For handler
	std::chrono::steady_clock::time_point time_last_msg_recvd = std::chrono::steady_clock::now();
	bool self = false;
	SceNpId npid{};

	// Signaling
	u32 conn_id = 0;
	bool op_activated = false;
	u32 info_counter = 10;

	// Matching2
	SceNpMatching2RoomId room_id = 0;
	SceNpMatching2RoomMemberId member_id = 0;

	// Stats
	u64 last_rtts[6] = {};
	std::size_t rtt_counters = 0;
	u32 rtt = 0;
	u32 pings_sent = 1, lost_pings = 0;
	u32 packet_loss = 0;
};

struct PipeType {
	u32 unk1;
	u32 unk2;
	u32 unk3;
	u32 unk4;
	PSPPointer<SceUID> uid;
};

struct SignalingPacket {
	u32_be signature = SIGNALING_SIGNATURE;
	u32_le version = SIGNALING_VERSION;
	u64_le timestamp_sender;
	u64_le timestamp_receiver;
	SceNpSignalingCommand command;
	u32_le sent_addr;
	u16_le sent_port;
	SceNpId npid;
};

// 16 || 0x10 bytes
struct PipePacket {
	SceNpSignalingCommand type;
	u32 conn_id;
	PSPPointer<SignalingPacket> sig_packet;
	PSPPointer<SceNetInetSockaddr> unk4;
};

int sceNpSignalingInit(int threadStackSize, u32 theadPriority);
int sceNpSignalingStop();

int sceNpSignalingGetConnectionFromNpId(u32 ctxId, SceNpId npId, u32 conn_id);
InetSocket* CreateSignalingSocket(u16 port, u16 vport, int domain, int type, int protocol);

void __NpSignalingInit();
void __NpSignalingShutdown();

int __StartSignalingThread(int threadStackSize, u32 priority);
int __StartSignalingEchoThread(u32 priority);

void Register_sceNpSignaling();
