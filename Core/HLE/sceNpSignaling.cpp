
#include "Core/HLE/sceNpSignaling.h"
#include "Core/HLE/HLE.h"
#include "Core/HLE/FunctionWrappers.h"
#include "Core/Util/BlockAllocator.h"
#include "Core/HLE/sceKernelMsgPipe.h"
#include "Core/HLE/sceKernelThread.h"
#include "Core/HLE/sceNet.h"
#include "Core/HLE/sceNp2.h"
#include <Core/Util/PortManager.h>
#include <Core/Config.h>
#include <Core/Net/SIGAgent.h>
#include <Core/HLE/sceKernelMemory.h>
#include <Core/HLE/ErrorCodes.h>

bool signalingInit = false;
u32 sigPoolAddr = 0;
BlockAllocator signaling_memory;
SceNpAuthMemoryStat signalingMemStat = {};

u32 signalingThreadAddr;
u32_le signalingThreadCode[3];
int signalingThreadId;
u32 signalingEchoThreadAddr;
u32_le signalingEchoThreadCode[3];
int signalingEchoThreadId;

PSPPointer<u8> optionalAddr;
std::unique_ptr<net::SIGAgent> sigServer = nullptr;

/* We register the HLE Loop functions when initializing the emulator here.
*    This is safe enough, as the functions are small, clean, and do not auto-start
*    But, these should be registered when the module is loaded instead.
*/
void __NpSignalingInit() {
	signalingThreadAddr = __CreateHLELoop(signalingThreadCode, "sceNpSignaling", "SceNpSignalingMain", "signalingThreadAddrHack");
	signalingEchoThreadAddr = __CreateHLELoop(signalingEchoThreadCode, "sceNpSignaling", "SceNpSignalingEcho", "signalingEchoThreadAddrHack");
}

void __NpSignalingShutdown() {
}

// Peer Information Generator, PSN starts this after receiving a message from EchoThread, and should only run on-demand (currently a loop)
int SceNpSignalingMainThread() // u32 param_1, u32 param_2 {+0x20 = MsgPipe_UID}
{
	// WARN_LOG(Log::Signaling, "UNIMPL %s()", __FUNCTION__);
	int ret = sigServer->MainThreadTick(&signaling_memory);

	// hleCall(ThreadManForUser, int, sceKernelDelayThread, 25000);
	return 0;
}

// P2P Listener / Distributor
int SceNpSignalingEchoThread()
{
	// WARN_LOG(Log::Signaling, "UNIMPL %s()", __FUNCTION__);
	int ret = sigServer->EchoThreadTick(&signaling_memory);
	int delayus = 25000;
	g_socketManager.NetworkDemultiplexer(&delayus);
	sigServer->UpnpThreadTick();
	// hleCall(ThreadManForUser, int, sceKernelDelayThread, 25000);
	return 0;
}

int __StartSignalingThread(int threadStackSize, u32 priority) {
	WARN_LOG(Log::Signaling, "UNIMPL %s(0x%04x, 0x%02x)", __FUNCTION__, threadStackSize, priority);
	int ret = 0;

	// signalingMemStat->npFreeMemSize = threadStackSize;
	// signalingMemStat->priority = priority;

	// ret = sceKernelCreateMbx("SceNpSignaling",0,0);
	// if (ret < 0)
	// 	return ret;

	// int sock = sceNetInetSocket(2, 6, 0);
	// if (sock < 0)
	// 	return sceNetInetGetPspError();

	//ret = sceNetInet_lib_0xAEE60F84(sock, 0x200050c8, 0);
	// sceNetInetClose(sock);
	// if (ret <= 0)
	// 	return ret;

	// u32 n = 8;
	// optionalAddr = PSPPointer<u8>::Create(signaling_memory.Alloc(n));
	//memset(optionalAddr, 0, 8);

	// ret = __KernelCreateThread("SceNpSignalingMain", __KernelGetCurThreadModuleId(), signalingThreadAddr, priority, 0x1000, PSP_THREAD_ATTR_USER, 0, true);
	ret = sceKernelCreateThread("SceNpSignalingMain", signalingThreadAddr, priority, threadStackSize, 0, 0); // would normally be the entire threadStackSize, but only because PSN allocates the entire peer system in here?
	if (ret < 0)
		return ret;
	signalingThreadId = ret;

	ret = sceKernelStartThread(signalingThreadId, 0, 0); // ret = hleCall(ThreadManForUser, int, sceKernelStartThread, signalingThreadId, 0, 0);
	if (ret < 0) {
		sceKernelTerminateThread(signalingThreadId);
		sceKernelDeleteThread(signalingThreadId);
		sceNetFreeThreadinfo(signalingThreadId);
		signalingThreadId = 0;
	}
	return ret;
}

// Handles the STUN / NAT systems
int __StartSignalingEchoThread(int threadStackSize, u32 priority) {
	WARN_LOG(Log::Signaling, "UNIMPL %s(0x%02x)", __FUNCTION__, priority);

	// int ret = __KernelCreateThread("SceNpSignalingEcho", __KernelGetCurThreadModuleId(), signalingEchoThreadAddr, priority, 0x1000, PSP_THREAD_ATTR_USER, 0, true);
	// u32* option = [8, 0, 0, 0]
	int ret = sceKernelCreateThread("SceNpSignalingEcho", signalingEchoThreadAddr, priority, threadStackSize, 0, 0);

	if (-1 < ret) {
		signalingEchoThreadId = ret;
		// Create the Virtual Socket for p2p handshakes
		// WARN_LOG(Log::Signaling, "Creating new socket for vport %d", SCE_INTERNAL_PORT);
		// SCE_INTERNAL_SOCK = sigServer->CreateSignalingSocket(SCE_SIGN_PORT, PSP_NET_INET_AF_INET, PSP_NET_INET_SOCK_CONN_DGRAM, PSP_NET_INET_IPPROTO_UNSPEC);

		ret = sceKernelStartThread(signalingEchoThreadId, 0, 0); // ret = hleCall(ThreadManForUser, int, sceKernelStartThread, signalingEchoThreadId, 0, 0);
		if (ret < 0) {
			sceKernelTerminateThread(signalingEchoThreadId);
			sceKernelDeleteThread(signalingEchoThreadId);
			sceNetFreeThreadinfo(signalingEchoThreadId);
			signalingEchoThreadId = 0;
		}
		else {
			//sceNet_lib_0xA8B6205A(this, 200000, FUN_08828fec, 0); // Send type_0x1a
		}
	}

	return ret;
}

static inline u32 AllocUser(u32 size, bool fromTop, const char* name) {
	u32 addr = userMemory.Alloc(size, fromTop, name);
	if (addr == -1)
		return 0;
	return addr;
}

// Note: Not actually a system call
int sceNpSignalingInit(int threadStackSize, u32 theadPriority) {
	WARN_LOG(Log::Signaling, "UNIMPL %s(0x%04x, 0x%04x, 0x%04x)", __FUNCTION__, threadStackSize, theadPriority);

	u32 ret = SCE_NP_MATCHING2_SIGNALING_ERROR_ALREADY_INITIALIZED;
	if ((!signalingInit) && ((ret = __StartSignalingThread(threadStackSize, theadPriority)) >= 0) && ((ret = __StartSignalingEchoThread(threadStackSize, theadPriority)) >= 0)) {
		signalingInit = true;
	}
	if (!signalingInit || ret < 0)
		return hleLogError(Log::sceNet, ret, "Unable to initialize");
	return ret;
}

int sceNpSignalingStop() {
	WARN_LOG(Log::Signaling, "UNIMPL %s()", __FUNCTION__);
	int ret = SCE_NP_MATCHING2_SIGNALING_ERROR_NOT_INITIALIZED;

	if (signalingInit) {
		// FIXME: sceKernelExitThread throws exceptions when it tries to kill these on PPSSPP exit; use __KernelStopThread() instead?
		/*if (((ret = sceKernelExitThread(signalingThreadId)) >= 0) && ((ret = sceKernelExitThread(signalingEchoThreadId)) >= 0)) {
			// TODO: retire packets
		}*/
		__KernelStopThread(signalingThreadId, SCE_KERNEL_ERROR_THREAD_TERMINATED, "thread terminated");
		__KernelStopThread(signalingEchoThreadId, SCE_KERNEL_ERROR_THREAD_TERMINATED, "thread terminated");
		// TODO: retire packets

	}
	if (ret < 0)
		return hleLogError(Log::sceNet, ret, "Error stopping Signagling Threads");
	return hleLogWarning(Log::sceNet, ret);
}

int sceNpSignalingTerm() {
	WARN_LOG(Log::Signaling, "UNIMPL %s()", __FUNCTION__);
	int ret = SCE_NP_MATCHING2_SIGNALING_ERROR_NOT_INITIALIZED;

	if (signalingInit) {
		if ((ret = sceKernelTerminateThread(signalingThreadId), -1 < ret) && (ret = sceKernelTerminateThread(signalingEchoThreadId), -1 < ret)) {
			if ((ret = sceKernelDeleteThread(signalingThreadId), -1 < ret) && (ret = sceKernelDeleteThread(signalingEchoThreadId), -1 < ret)) {
				if ((ret = sceNetFreeThreadinfo(signalingThreadId), -1 < ret) && (ret = sceNetFreeThreadinfo(signalingEchoThreadId), -1 < ret)) {
					signalingThreadId = 0;
					signalingEchoThreadId = 0;
				}
			}
		}
		signalingInit = false;
	}
	if (ret < 0)
		return hleLogError(Log::sceNet, ret, "Error terminating Signagling Threads");
	return hleLogWarning(Log::sceNet, ret);
}

int sceNpSignalingActivateConnection(u32 ctxId, PSPPointer<SceNpId> npId, PSPPointer<u32> conn_id)
{
	ERROR_LOG(Log::sceNp2, "UNIMPL %s(%d, %08x, %08x) at %08x", __FUNCTION__, ctxId, npId.ptr, conn_id.ptr, currentMIPS->pc);
	return 0;
}

int sceNpSignalingDeactivateConnection(u32 ctxId, u32 conn_id)
{
	ERROR_LOG(Log::sceNp2, "UNIMPL %s(%d, %d) at %08x", __FUNCTION__, ctxId, conn_id, currentMIPS->pc);
	return 0;
}

int sceNpSignalingTerminateConnection(u32 ctxId, u32 conn_id)
{
	ERROR_LOG(Log::sceNp2, "UNIMPL %s(%d, %d) at %08x", __FUNCTION__, ctxId, conn_id, currentMIPS->pc);
	return 0;
}

int sceNpSignalingGetConnectionFromNpId(u32 ctxId, SceNpId npId, u32 conn_id)
{
	ERROR_LOG(Log::sceNp2, "UNIMPL %s(%d, %s, %d) at %08x", __FUNCTION__, ctxId, npId.handle.data, conn_id, currentMIPS->pc);
	return 0;
}

int sceNpSignalingGetConnectionFromPeerAddress(u32 ctxId, np_in_addr_t peer_addr, np_in_port_t peer_port, PSPPointer<u32> conn_id)
{
	ERROR_LOG(Log::sceNp2, "UNIMPL %s(%d, %s, %d, %08x) at %08x", __FUNCTION__, ctxId, ip2str(peer_addr).c_str(), peer_port, conn_id.ptr, currentMIPS->pc);
	return 0;
}

InetSocket* CreateSignalingSocket(u16 port, u16 vport, int domain, int type, int protocol) {
	int index;
	int hostErrno = 0;

	// Create the master socket
	InetSocket* inetSocket = g_socketManager.CreateSystemSocket(&index, &hostErrno, SocketState::UsedNetInet, domain, type, protocol);
	if (!inetSocket) {
		ERROR_LOG(Log::Signaling, "Unable to create new socket: %08X", hostErrno);
		return nullptr;
	}

	// Bind socket for listening
	getLocalIp(&inetSocket->src.host);
	inetSocket->src.host.sin_family = AF_INET;
	inetSocket->src.virt.port = htons(port); // P2P Socket
	inetSocket->src.virt.vport = htons(vport); // Reachable Socket

	// Bypass the Registration
	int ret = ::bind(inetSocket->sock, (sockaddr*)&inetSocket->src.host, sizeof(sockaddr_in));
	if (ret < 0) {
		ERROR_LOG(Log::Signaling, "Unable to bind new socket for listening");
		return nullptr;
	}

	inetSocket->state = SocketState::UsedNetInet;

	// Ignore SIGPIPE when supported (ie. BSD/MacOS)
	// setSockNoSIGPIPE(inetSocket->sock, 1);
	// TODO: We should always use non-blocking mode and simulate blocking mode
	changeBlockingMode(inetSocket->sock, 1);
	// Enable Port Re-use, required for multiple-instance
	// setSockReuseAddrPort(inetSocket->sock);
	// Disable Connection Reset error on UDP to avoid strange behavior
	// setUDPConnReset(inetSocket->sock, false);

	if (type == PSP_NET_INET_SOCK_DCCP) {
		if (g_Config.bEnableUPnP)
			bool ok = g_PortManager.Add("UDP", port, port);
	}
	return inetSocket;
}

const HLEFunction sceNpSignaling[] = {
	// Fake function for PPSSPP's use.
	{0X756E6F2C, &WrapI_V<SceNpSignalingMainThread>,					"SceNpSignalingMain",					'i', ""		  },
	{0X756E6F30, &WrapI_V<SceNpSignalingEchoThread>,					"SceNpSignalingEcho",					'i', ""		  },
};

void Register_sceNpSignaling()
{
	RegisterHLEModule("sceNpSignaling", ARRAY_SIZE(sceNpSignaling), sceNpSignaling);
}
