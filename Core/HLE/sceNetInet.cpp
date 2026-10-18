#include <algorithm>
#include <functional>
#include "Common/StringUtils.h"
#include "Common/TimeUtil.h"
#include "Common/Net/SocketCompat.h"
#include "Common/Data/Text/Parsers.h"
#include "Common/Serialize/Serializer.h"
#include "Common/Serialize/SerializeFuncs.h"
#include "Common/Serialize/SerializeMap.h"

#include "Core/HLE/SocketManager.h"
#include "Core/HLE/HLE.h"
#include "Core/HLE/ErrorCodes.h"
#include "Core/HLE/FunctionWrappers.h"
#include "Core/HLE/KernelWaitHelpers.h"
#include "Core/HLE/sceNet.h"
#include "Core/HLE/sceNetAdhoc.h"
#include "Core/HLE/sceNetInet.h"
#include "Core/HLE/NetInetConstants.h"
#include "Core/CoreTiming.h"
#include "Core/MIPS/MIPS.h"
#include "Core/Config.h"
#include "Core/System.h"
#include "Core/ELF/ParamSFO.h"
#include "Core/MemMapHelpers.h"
#include "Core/Util/PortManager.h"
#include "Core/Instance.h"
#ifdef __MINGW32__
#include <mswsock.h>
#endif

// This is the PSP networking errno.
// It has a separate value per-thread, hence the map.

static std::map<int, int> g_inetLastErrno;

// Functions should only call this on error, NOT on success.
// Returns a PSP errno (ERROR_INET_*), in case it's needed.
/*int UpdateErrnoFromHost(int threadID, int hostErrno, const char *func)
{
	int newErrno = convertInetErrnoHost2PSP(hostErrno);
#if defined(_WIN32)
	if (newErrno == ERROR_INET_EAGAIN && (func && strcmp(func, "sceNetInetConnect") == 0))
		newErrno = ERROR_INET_EINPROGRESS;
#endif

	// This will do the right thing if not already present - insert a zero value.
	int lastErrno = g_inetLastErrno[threadID];

	if (lastErrno == 0 && newErrno == 0)
	{
		WARN_LOG(Log::sceNet, "BAD: errno set to 0 in %s. Functions should not clear errno.", func);
	}
	else if (lastErrno != 0 && newErrno == 0)
	{
		ERROR_LOG(Log::sceNet, "BAD: errno cleared (previously %s) in %s. Functions should not clear errno.", convertInetErrno2str(lastErrno), func);
		lastErrno = 0;
	}
	else if (lastErrno == newErrno)
	{
		VERBOSE_LOG(Log::sceNet, "errno remained %s in %s (host: %d)", convertInetErrno2str(newErrno), func, hostErrno);
	}
	else
	{
		DEBUG_LOG(Log::sceNet, "errno set to %s in %s (host: %d)", convertInetErrno2str(newErrno), func, hostErrno);
		lastErrno = newErrno;
	}

	g_inetLastErrno[threadID] = lastErrno;
	return lastErrno;
}*/


/* Sets PSPError for the related PSP Thread ID
 * @param error PSP Inet Error Code
 * @param threadID Optional target thread
 * @note When using a lambda thread with KernalWaitCurThread, KernelGetCurThread can report unrelated thread id's
 */
int _sce_pspnet_set_thread_errno(int error, int thread_id = -1) {
	int threadID = thread_id;
	if (thread_id == -1)
		threadID = __KernelGetCurThread();
	g_inetLastErrno[threadID] = error;
	return error;
}

// ============================================================================
// Emu-thread network op scheduler. Replaces the old per-socket std::thread
// worker: every host socket call now runs ON the emu thread, in issue order,
// paced by emulated time - so a blocking op can no longer complete on wall-
// clock time and let sibling PSP threads race ahead of it (the cross-socket
// reordering seen in PSP2i's load/lobby flow). This mirrors adhoc's fully-
// simulated blocking (WaitBlockingAdhocSocket) and the sceNetInetPoll tick.
//
// A NON-blocking call runs inline (__NetInetRunInline) and never parks. A
// BLOCKING call parks its PSP thread (WAITTYPE_NET) and registers a NetInetOp;
// __NetInetOpTick re-attempts it every NETINET_RESUME_POLL_US of EMULATED time
// (always as a non-blocking host call, so it can never stall the core) until it
// completes, errors, or is canceled, then resumes the thread - on the emu
// thread, the only context where touching kernel/scheduler state is safe.
// ============================================================================
static const int NETINET_RESUME_POLL_US = 200;

// Emulated-time charged to a completed inline op (adhoc-matched pacing) vs an
// inline non-blocking op that found nothing. The old worker model implicitly
// put EVERY op on the 200us resume grid, which throttled busy-poll loops; the
// inline path lost that, so a spinning recv/poll loop stormed host syscalls and
// starved weak hardware (lobby-load and signaling deadlines overran). Charging
// the idle 200us only on EWOULDBLOCK restores that throttle while keeping data
// delivery immediate (50us), so packet ordering is unaffected. Tunable: raise
// NETINET_IDLE_POLL_US if a weak device still storms.
static const int NETINET_OP_PACING_US = 50;
static const int NETINET_IDLE_POLL_US = 200;

// Sentinel a park op's run() returns to mean "made progress but not done, keep
// polling" (e.g. a MSG_WAITALL recv that got a partial chunk). The tick treats
// it as not-ready without touching socket_errno; the PSP thread never sees it.
static const int NETINET_OP_PENDING = -2;

struct NetInetOp {
	SceUID threadID = -1;
	int socket = -1;
	std::function<int()> run;  // one non-blocking host attempt; sets socket_errno; returns host retval
	bool active = false;
};
static std::vector<NetInetOp> g_netOps; // emu-thread only, serviced in FIFO (issue) order
static int netInetOpEvent = -1;

// ---- Per-PSP-thread net op profiler (diagnostic) --------------------------
// Flip g_netProfile to true and rebuild to log, once per host second, how many
// inet syscalls each PSP thread issued and the host time they cost. A thread
// busy-polling recv/select stands out as an outsized call count. Zero cost when
// false: every accounting site is gated on the flag, so the body is elided.
static const bool g_netProfile = false;
struct NetThreadStat { double hostUs = 0.0; u64 calls = 0; };
static std::unordered_map<SceUID, NetThreadStat> g_netThreadStats;
static double g_netProfileLastDump = 0.0;

static void __NetProfileAccount(SceUID tid, double hostUs) {
	NetThreadStat &s = g_netThreadStats[tid];
	s.hostUs += hostUs;
	s.calls++;
	const double now = time_now_d();
	if (g_netProfileLastDump == 0.0) {
		g_netProfileLastDump = now;
		return;
	}
	if (now - g_netProfileLastDump < 1.0)
		return;
	u64 totalCalls = 0;
	double totalUs = 0.0;
	for (auto &kv : g_netThreadStats) { totalCalls += kv.second.calls; totalUs += kv.second.hostUs; }
	NOTICE_LOG(Log::sceNet, "[netprof] %.2f ms host / %llu inet calls in the last second:", totalUs / 1000.0, (unsigned long long)totalCalls);
	for (auto &kv : g_netThreadStats) {
		NOTICE_LOG(Log::sceNet, "[netprof]   %-18s (0x%08x): %8llu calls  %7.2f ms",
			__KernelGetThreadName(kv.first), kv.first, (unsigned long long)kv.second.calls, kv.second.hostUs / 1000.0);
	}
	g_netThreadStats.clear();
	g_netProfileLastDump = now;
}

// A host result maps to one of these PSP errnos while the op is still pending.
static inline bool __NetInetWouldBlock(int pspErrno) {
	return pspErrno == ERROR_INET_EAGAIN || pspErrno == ERROR_INET_EWOULDBLOCK ||
	       pspErrno == ERROR_INET_EINPROGRESS || pspErrno == ERROR_INET_EALREADY;
}

static void __NetInetOpTick(u64 userdata, int cyclesLate) {
	bool anyActive = false;
	// FIFO: a socket's op completes in the order it was issued, so simultaneous
	// completions resume their PSP threads in single-core issue order.
	for (size_t i = 0; i < g_netOps.size(); i++) {
		NetInetOp &op = g_netOps[i];
		if (!op.active)
			continue;
		if (!HLEKernel::VerifyWait(op.threadID, WAITTYPE_NET, op.threadID)) {
			// Thread was released some other way (abort/close/delete) - drop it.
			op.active = false;
			continue;
		}
		const double t0 = g_netProfile ? time_now_d() : 0.0;
		int retval = op.run();
		if (g_netProfile) __NetProfileAccount(op.threadID, (time_now_d() - t0) * 1.0e6);
		if (retval == NETINET_OP_PENDING) {
			anyActive = true; // progressed (e.g. partial WAITALL) but not done - retry
			continue;
		}
		int pspErrno = (retval < 0) ? convertInetErrnoHost2PSP(socket_errno) : 0;
		if (retval < 0 && __NetInetWouldBlock(pspErrno)) {
			anyActive = true; // not ready yet - retry next tick
			continue;
		}
		op.active = false;
		SceUID tid = op.threadID;
		InetSocket *owner = nullptr;
		if (g_socketManager.GetInetSocket(op.socket, &owner))
			owner->threadID.store(-1);
		if (pspErrno != 0)
			_sce_pspnet_set_thread_errno(pspErrno, tid);
		__KernelResumeThreadFromWait(tid, retval);
	}
	if (anyActive)
		CoreTiming::ScheduleEvent(usToCycles(NETINET_RESUME_POLL_US), netInetOpEvent, 0);
}

// Run a non-blocking op inline on the emu thread (HW-faithful: no park, no
// thread switch), paced like adhoc. Returns the host retval; sets PSP errno.
static int __NetInetRunInline(const std::function<int()> &run) {
	const double t0 = g_netProfile ? time_now_d() : 0.0;
	int retval = run();
	if (g_netProfile) __NetProfileAccount(__KernelGetCurThread(), (time_now_d() - t0) * 1.0e6);
	int pace = NETINET_OP_PACING_US;
	if (retval < 0) {
		int pe = convertInetErrnoHost2PSP(socket_errno);
		_sce_pspnet_set_thread_errno(pe);
		if (__NetInetWouldBlock(pe))
			pace = NETINET_IDLE_POLL_US; // nothing there - throttle the spin like the old resume grid
	}
	hleEatMicro(pace);
	// Balance this HLE call's func-desc push with a single guarded pop. The
	// socket method may itself have logged (and popped); hleNoLog's pop then
	// no-ops. Using hleNoLog (not hleLogDebug) avoids a spurious "stack
	// mismatch" line when the inner method already logged.
	return hleNoLog(retval);
}

// Park the calling PSP thread and queue a blocking op for the retry tick. The
// returned value is ignored by the HLE layer; the real result reaches the
// thread via __KernelResumeThreadFromWait when the op completes.
static int __NetInetParkOp(InetSocket *inetSock, int socket, std::function<int()> run, const char *reason) {
	SceUID tid = __KernelGetCurThread();
	inetSock->threadID = tid;
	NetInetOp *op = nullptr;
	for (auto &candidate : g_netOps) {
		if (!candidate.active) { op = &candidate; break; }
	}
	if (!op) {
		g_netOps.emplace_back();
		op = &g_netOps.back();
	}
	op->threadID = tid;
	op->socket = socket;
	op->run = std::move(run);
	op->active = true;
	__KernelWaitCurThread(WAITTYPE_NET, tid, 0, 0, false, reason);
	if (!CoreTiming::IsScheduled(netInetOpEvent))
		CoreTiming::ScheduleEvent(usToCycles(NETINET_RESUME_POLL_US), netInetOpEvent, 0);
	return -1;
}

// Cancel any queued blocking op on this socket. If resumeThread, wake the
// parked PSP thread with EINTR; otherwise just drop it (the caller already
// resumed/aborted the thread itself).
static void __NetInetCancelOp(int socket, bool resumeThread) {
	for (auto &op : g_netOps) {
		if (!op.active || op.socket != socket)
			continue;
		op.active = false;
		if (resumeThread && HLEKernel::VerifyWait(op.threadID, WAITTYPE_NET, op.threadID)) {
			_sce_pspnet_set_thread_errno(ERROR_INET_EINTR, op.threadID);
			__KernelResumeThreadFromWait(op.threadID, -1);
		}
	}
}

// Called from __NetInetShutdown (emu thread): release any thread still parked on a net op.
static void __NetInetOpShutdown() {
	for (auto &op : g_netOps) {
		if (op.active && HLEKernel::VerifyWait(op.threadID, WAITTYPE_NET, op.threadID)) {
			_sce_pspnet_set_thread_errno(ERROR_INET_EINTR, op.threadID);
			__KernelResumeThreadFromWait(op.threadID, -1);
		}
		op.active = false;
	}
	g_netOps.clear();
}

// ============================================================================
// Blocking poll support. sceNetInetPoll parks the calling PSP thread in a
// WAITTYPE_NET wait and this recurring tick - on the emu thread, where both
// kernel and socket state are safe to touch - re-evaluates each outstanding
// poll set until an fd becomes ready, the timeout lapses, or a socket dies.
// Virtual (P2P) sockets report readiness from their queues; real host fds are
// checked with a zero-timeout select inside the tick, so no worker threads or
// cross-thread signaling are involved and wakeups can't be lost.
// ============================================================================
struct NetInetPollOp {
	SceUID threadID = -1;
	u32 fdsPtr = 0;
	u32 nfds = 0;
	s64 deadlineUs = -1; // -1 = infinite (firmware treats timeout == -1 as no deadline)
	bool active = false;
};
static std::vector<NetInetPollOp> g_pollOps; // emu-thread only, no locking needed
static int netInetPollEvent = -1;
static const int NETINET_POLL_TICK_US = 200;

// Per-socket receive arrival delay.
static const s64 RX_ARRIVAL_DELAY_US = 50000; // 50 ms (~3 frames)

// Evaluate one poll set: fills revents, returns the number of fds with events.
// Same hybrid rules as sceNetInetSelect: a P2P-capable socket reports readiness
// from its virtual queues, not the host fd (which may never signal).
static int __NetInetPollScan(SceNetInetPollfd *fdarray, u32 nfds) {
	auto virtRead = [](InetSocket *s) {
		bool r = false;
		s->select(&r, nullptr, nullptr);
		return r;
	};
	auto virtWrite = [](InetSocket *s) {
		bool w = false;
		s->select(nullptr, &w, nullptr);
		return w;
	};

	fd_set readfds{}, writefds{}, exceptfds{};
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
	int maxHostFd = 0;
	int realfds = 0;
	InetSocket *inetSock = nullptr;

	for (u32 i = 0; i < nfds; i++) {
		fdarray[i].revents = 0;
		if (fdarray[i].fd < 0)
			continue;
		if (!g_socketManager.GetInetSocket(fdarray[i].fd, &inetSock) || inetSock->sock == 0) {
			// A socket closed mid-poll must wake its waiters so their error paths run.
			fdarray[i].revents = INET_POLLNVAL;
			continue;
		}
		if (inetSock->abortPending.load()) {
			fdarray[i].revents = INET_POLLERR | INET_POLLHUP;
			continue;
		}
		// Skip host checks on virtual sockets
		if ((fdarray[i].events & (INET_POLLRDNORM | INET_POLLIN)) && !virtRead(inetSock)) {
			FD_SET(inetSock->sock, &readfds);
			realfds++;
		}
		if ((fdarray[i].events & (INET_POLLWRNORM | INET_POLLOUT)) && !virtWrite(inetSock)) {
			FD_SET(inetSock->sock, &writefds);
			realfds++;
		}
		FD_SET(inetSock->sock, &exceptfds);
		if (inetSock->sock > maxHostFd)
			maxHostFd = inetSock->sock;
	}

	int selReady = 0;
	if (realfds > 0) { // Windows returns EINVAL when you select with no FDs
		timeval zero = {0, 0};
		selReady = select(maxHostFd + 1, &readfds, &writefds, &exceptfds, &zero);
		if (selReady < 0)
			selReady = 0;
	}

	int count = 0;
	for (u32 i = 0; i < nfds; i++) {
		if (fdarray[i].fd < 0)
			continue;
		if (!fdarray[i].revents) { // not already marked NVAL/ERR above
			if (!g_socketManager.GetInetSocket(fdarray[i].fd, &inetSock) || inetSock->sock == 0)
				continue;
			if ((fdarray[i].events & (INET_POLLRDNORM | INET_POLLIN)) && (virtRead(inetSock) || (selReady > 0 && FD_ISSET(inetSock->sock, &readfds))))
				fdarray[i].revents |= (INET_POLLRDNORM | INET_POLLIN); // POLLIN_SET
			if ((fdarray[i].events & (INET_POLLWRNORM | INET_POLLOUT)) && (virtWrite(inetSock) || (selReady > 0 && FD_ISSET(inetSock->sock, &writefds))))
				fdarray[i].revents |= (INET_POLLWRNORM | INET_POLLOUT); // POLLOUT_SET
			fdarray[i].revents &= fdarray[i].events;
			if (selReady > 0 && FD_ISSET(inetSock->sock, &exceptfds))
				fdarray[i].revents |= (INET_POLLRDBAND | INET_POLLPRI | INET_POLLERR); // POLLEX_SET
		}
		if (fdarray[i].revents)
			count++;
	}
	return count;
}

static void __NetInetPollTick(u64 userdata, int cyclesLate) {
	bool anyActive = false;
	const s64 now = (s64)CoreTiming::GetGlobalTimeUs();
	for (auto &op : g_pollOps) {
		if (!op.active)
			continue;
		if (!HLEKernel::VerifyWait(op.threadID, WAITTYPE_NET, op.threadID)) {
			// The thread was released some other way (deleted, wait canceled).
			op.active = false;
			continue;
		}
		SceNetInetPollfd *fdarray = (SceNetInetPollfd *)Memory::GetPointerUnchecked(op.fdsPtr);
		if (!fdarray) {
			op.active = false;
			_sce_pspnet_set_thread_errno(ERROR_INET_EFAULT, op.threadID);
			__KernelResumeThreadFromWait(op.threadID, -1);
			continue;
		}
		int count = __NetInetPollScan(fdarray, op.nfds);
		const bool expired = op.deadlineUs >= 0 && now >= op.deadlineUs;
		if (count != 0 || expired) {
			// Timeout expiry is a clean 0-events result with no errno - firmware
			// swallows the internal EWOULDBLOCK the same way.
			op.active = false;
			__KernelResumeThreadFromWait(op.threadID, count);
			continue;
		}
		anyActive = true;
	}
	if (anyActive)
		CoreTiming::ScheduleEvent(usToCycles(NETINET_POLL_TICK_US), netInetPollEvent, 0);
}

// Called from __NetInetShutdown (emu thread): release any thread still parked in poll.
static void __NetInetPollShutdown() {
	for (auto &op : g_pollOps) {
		if (op.active && HLEKernel::VerifyWait(op.threadID, WAITTYPE_NET, op.threadID)) {
			_sce_pspnet_set_thread_errno(ERROR_INET_EINTR, op.threadID);
			__KernelResumeThreadFromWait(op.threadID, -1);
		}
		op.active = false;
	}
	g_pollOps.clear();
}

void __NetInetRegisterEvents() {
	netInetOpEvent = CoreTiming::RegisterEvent("__NetInetOpTick", __NetInetOpTick);
	netInetPollEvent = CoreTiming::RegisterEvent("__NetInetPollTick", __NetInetPollTick);
}

void __NetInetRestoreEvents() {
	CoreTiming::RestoreRegisterEvent(netInetOpEvent, "__NetInetOpTick", __NetInetOpTick);
	CoreTiming::RestoreRegisterEvent(netInetPollEvent, "__NetInetPollTick", __NetInetPollTick);
}

bool netInetInited = false;

// ---- P2P session table (see sceNetInet.h) --------------------------------
// The firmware kept its peer registry as a module global fed by ioctl; we keep
// ours as a module global fed by RegisterSessionPeer(). addr->port, network
// order, port 0 = wildcard. A socket routes P2P when its destination is here
// (InetSocket::IsP2P), replacing the old up-call into sceNpSignaling.
static std::mutex g_sessionPeerLock;
static std::unordered_map<u32, u16> g_sessionPeers;  // addr -> port (0 = any)

void RegisterSessionPeer(u32 addr, u16 port) {
	if (!addr)
		return;
	std::lock_guard<std::mutex> guard(g_sessionPeerLock);
	g_sessionPeers[addr] = port;
}

void UnregisterSessionPeer(u32 addr) {
	std::lock_guard<std::mutex> guard(g_sessionPeerLock);
	g_sessionPeers.erase(addr);
}

bool IsSessionPeer(u32 addr) {
	if (!addr)
		return false;
	std::lock_guard<std::mutex> guard(g_sessionPeerLock);
	return g_sessionPeers.find(addr) != g_sessionPeers.end();
}

void __NetInetShutdown()
{
	if (!netInetInited)
	{
		return;
	}

	netInetInited = false;
	__NetInetPollShutdown();
	__NetInetOpShutdown();
	g_socketManager.CloseAll();
	g_inetLastErrno.clear();
	{
		std::lock_guard<std::mutex> guard(g_sessionPeerLock);
		g_sessionPeers.clear();
	}
}

void __NetInetWakeCheck(bool checkDeadlines) {
	const s64 now = checkDeadlines ? (s64)CoreTiming::GetGlobalTimeUs() : 0;
	for (auto &op : g_pollOps) {
		if (!op.active)
			continue;
		if (!HLEKernel::VerifyWait(op.threadID, WAITTYPE_NET, op.threadID)) {
			op.active = false;   // thread released some other way
			continue;
		}
		SceNetInetPollfd *fdarray = (SceNetInetPollfd *)Memory::GetPointerUnchecked(op.fdsPtr);
		if (!fdarray) {
			op.active = false;
			_sce_pspnet_set_thread_errno(ERROR_INET_EFAULT, op.threadID);
			__KernelResumeThreadFromWait(op.threadID, -1);
			continue;
		}
		int count = __NetInetPollScan(fdarray, op.nfds);
		const bool expired = checkDeadlines && op.deadlineUs >= 0 && now >= op.deadlineUs;
		if (count != 0 || expired) {
			op.active = false;
			__KernelResumeThreadFromWait(op.threadID, count);  // 0 on expiry, no errno
		}
	}
}

static int sceNetInetInit()
{
	if (netInetInited)
		return hleLogError(Log::sceNet, SCE_NET_INET_ERROR_ALREADY_INITIALIZED);
	g_inetLastErrno.clear();
	netInetInited = true;
	return hleLogDebug(Log::sceNet, 0);
}

static int sceNetInetTerm()
{
	INFO_LOG(Log::sceNet, "sceNetInetTerm()");
	__NetInetShutdown();
	return hleLogDebug(Log::sceNet, 0);
}

static int sceNetInetGetErrno()
{
	int threadID = __KernelGetCurThread();
	const int lastErrno = g_inetLastErrno[threadID];

	if (lastErrno == ERROR_INET_EAGAIN)
	{
		return hleLogVerbose(Log::sceNet, lastErrno, "returning %s at %08x", convertInetErrno2str(lastErrno), currentMIPS->pc);
	}
	else
	{
		return hleLogDebug(Log::sceNet, lastErrno, "returning %s at %08x", convertInetErrno2str(lastErrno), currentMIPS->pc);
	}
}

int sceNetInetGetPspError()
{
	if (sceKernelCheckThreadStack() < 0xff0)
		return hleLogError(Log::sceNet, 0x80410005, "Socket Stack Error");
	int threadID = __KernelGetCurThread();
	const int errorno = g_inetLastErrno[threadID];
	if (errorno == 0)
		return hleLogVerbose(Log::sceNet, 0, "Success");
	const int psp_error_code = 0x80010000 | (errorno & 0xFFFF); // Correct convertInetErrno2PSPError conversion
	// Official firmware uses 

	// uint32_t error = convertInetErrno2PSPError(lastErrno);
	if (errorno == ERROR_INET_EAGAIN || errorno == ERROR_INET_EINPROGRESS || errorno == ERROR_INET_EWOULDBLOCK)
		return hleLogVerbose(Log::sceNet, psp_error_code, "returning %s converted to %08x at %08x", convertInetErrno2str(errorno), psp_error_code, currentMIPS->pc);
	return hleLogInfo(Log::sceNet, psp_error_code, "returning %s converted to %08x at %08x", convertInetErrno2str(errorno), psp_error_code, currentMIPS->pc);
}

static int sceNetInetInetPton(int af, const char *hostname, u32 inAddrPtr)
{
	_sce_pspnet_set_thread_errno(0);
	if (!Memory::IsValidAddress(inAddrPtr))
	{
		return hleLogError(Log::sceNet, 0, "invalid arg"); //-1
	}

	int retval = inet_pton(convertSocketDomainPSP2Host(af), hostname, (void*)Memory::GetPointerOrException(inAddrPtr));
	// Note that inet_pton can set errno!
	if (retval < 0)
	{
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(socket_errno));
		// UpdateErrnoFromHost(__KernelGetCurThread(), socket_errno, __FUNCTION__);
		return hleLogError(Log::sceNet, retval);
	}
	return hleLogDebug(Log::sceNet, retval);
}

static int sceNetInetInetAton(const char *hostname, u32 inAddrPtr)
{
	_sce_pspnet_set_thread_errno(0);
	if (!Memory::IsValidAddress(inAddrPtr))
	{
		return hleLogError(Log::sceNet, 0, "invalid arg"); //-1
	}

	// TODO: Wait what, we're calling pton in aton?
	int retval = inet_pton(AF_INET, hostname, (void*)Memory::GetPointerOrException(inAddrPtr));
	// inet_aton() returns nonzero if the address is valid, zero if not.
	return hleLogDebug(Log::sceNet, retval);
}

// TODO: Need to find out whether it's possible to get partial output or not, since Coded Arms Contagion is using a small bufsize(4)
static u32 sceNetInetInetNtop(int af, u32 srcInAddrPtr, u32 dstBufPtr, u32 bufsize)
{
	WARN_LOG(Log::sceNet, "UNTESTED sceNetInetInetNtop(%i, %08x, %08x, %d)", af, srcInAddrPtr, dstBufPtr, bufsize);
	_sce_pspnet_set_thread_errno(0);
	if (!Memory::IsValidAddress(srcInAddrPtr))
	{
		return hleLogError(Log::sceNet, 0, "invalid arg");
	}
	if (!Memory::IsValidAddress(dstBufPtr) || bufsize < 1 /*8*/)
	{ // usually 8 or 16, but Coded Arms Contagion is using bufsize = 4
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(ENOSPC));
		// UpdateErrnoFromHost(__KernelGetCurThread(), ENOSPC, __FUNCTION__);
		return hleLogError(Log::sceNet, 0, "invalid arg");
	}

	// Full temporary buffer (large enough for IPv6)
	char temp[64] = {0};
	if (inet_ntop(convertSocketDomainPSP2Host(af), Memory::GetCharPointer(srcInAddrPtr), temp, sizeof(temp)) == NULL)
	{
		// if (inet_ntop(convertSocketDomainPSP2Host(af), Memory::GetCharPointer(srcInAddrPtr), (char*)Memory::GetCharPointer(dstBufPtr), bufsize) == NULL) {
		return hleLogDebug(Log::sceNet, 0, "invalid arg?"); // Temporarily commented out in case it's allowed to have partial output
	}

	size_t copyLen = std::min<size_t>(strlen(temp), bufsize - 1);
	memcpy((char *)Memory::GetCharPointer(dstBufPtr), temp, copyLen);
	memset((char *)Memory::GetCharPointer(dstBufPtr) + copyLen, '\0', 1);

	INFO_LOG(Log::sceNet, "sceNetInetInetNtop -> '%s'", safe_string(Memory::GetCharPointer(dstBufPtr)));

	return hleLogDebug(Log::sceNet, dstBufPtr, "-> '%s'", safe_string(Memory::GetCharPointer(dstBufPtr)));
}

static u32_le sceNetInetInetAddr(const char *hostname)
{
	_sce_pspnet_set_thread_errno(0);
	if (hostname == nullptr || hostname[0] == '\0')
	{
		return hleLogError(Log::sceNet, INADDR_NONE, "invalid arg");
	}

	u32 retval = INADDR_NONE;			   // inet_addr(hostname); // deprecated?
	inet_pton(AF_INET, hostname, &retval); // Alternative to the deprecated inet_addr

	return hleLogDebug(Log::sceNet, retval);
}

static int sceNetInetGetpeername(int socket, u32 namePtr, u32 namelenPtr)
{
	_sce_pspnet_set_thread_errno(0);
	if (!Memory::IsValidAddress(namePtr) || !Memory::IsValidAddress(namelenPtr))
	{
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(EFAULT));
		return hleLogError(Log::sceNet, -1, "invalid arg");
	}

	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		return hleLogError(Log::sceNet, ERROR_INET_EBADF, "Bad socket #%d", socket);
	}

	SceNetInetSockaddr* name = (SceNetInetSockaddr*)Memory::GetPointerOrException(namePtr);
	int* namelen = (int*)Memory::GetPointerOrException(namelenPtr);
	SockAddrIN4 saddr{};
	// TODO: Should've created convertSockaddrPSP2Host (and Host2PSP too) function as it's being used pretty often, thus fixing a bug on it will be tedious when scattered all over the places
	saddr.addr.sa_family = name->sa_family;
	int len = std::min(*namelen > 0 ? *namelen : 0, static_cast<int>(sizeof(saddr)));
	name->sa_len = len;
	memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));

	int retval = getpeername(inetSock->sock, (sockaddr *)&saddr, (socklen_t *)&len);
	DEBUG_LOG(Log::sceNet, "Getpeername: Family = %s, Address = %s, Port = %d", inetSocketDomain2str(saddr.addr.sa_family).c_str(), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
	*namelen = len;
	if (retval < 0)
	{
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(socket_errno));
		// UpdateErrnoFromHost(__KernelGetCurThread(), socket_errno, __FUNCTION__);
		return hleLogError(Log::sceNet, retval);
	}

	// We shouldn't use the returned len here, because the returned len is the actual size needed, which can be larger than the inputted len
	memcpy(name->sa_data, saddr.addr.sa_data, name->sa_len - (sizeof(name->sa_len) + sizeof(name->sa_family)));
	name->sa_family = saddr.addr.sa_family;
	return hleLogInfo(Log::sceNet, 0);
}

static int sceNetInetGetsockname(int socket, u32 namePtr, u32 namelenPtr)
{
	_sce_pspnet_set_thread_errno(0);
	if (!Memory::IsValidAddress(namePtr) || !Memory::IsValidAddress(namelenPtr))
	{
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(EFAULT));
		// UpdateErrnoFromHost(__KernelGetCurThread(), , __FUNCTION__);
		return hleLogError(Log::sceNet, -1, "invalid arg");
	}

	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, ERROR_INET_EBADF, "Bad socket #%d", socket);
	}

	SceNetInetSockaddr* name = (SceNetInetSockaddr*)Memory::GetPointerOrException(namePtr);
	int* namelen = (int*)Memory::GetPointerOrException(namelenPtr);
	SockAddrIN4 saddr{};
	saddr.addr.sa_family = name->sa_family;
	int len = std::min(*namelen > 0 ? *namelen : 0, static_cast<int>(sizeof(saddr)));
	name->sa_len = len;
	memcpy(saddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));

	int retval = getsockname(inetSock->sock, (sockaddr *)&saddr, (socklen_t *)&len);
	DEBUG_LOG(Log::sceNet, "Getsockname: Family = %s, Address = %s, Port = %d", inetSocketDomain2str(saddr.addr.sa_family).c_str(), ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
	*namelen = len;
	if (retval < 0)
	{
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(socket_errno));
		// UpdateErrnoFromHost(__KernelGetCurThread(), socket_errno, __FUNCTION__);
		return hleLogError(Log::sceNet, retval);
	}

	// We shouldn't use the returned len here, because the returned len is the actual size needed, which can be larger than the inputted len
	memcpy(name->sa_data, saddr.addr.sa_data, name->sa_len - (sizeof(name->sa_len) + sizeof(name->sa_family)));
	name->sa_family = saddr.addr.sa_family;
	return hleLogInfo(Log::sceNet, 0);
}

class SelectTarget
{
public:
	SOCKET sock = 0;
	bool wantsRead = false;
	bool wantsWrite = false;
	bool wantsExcept = false;
};
// FIXME: select is being used here without an inetSocket pointer
// FIXME: nfds is number of fd(s) as in posix poll, or was it maximum fd value as in posix select? Star Wars Battlefront Renegade seems to set the nfds to 64, while Coded Arms Contagion is using 256
int sceNetInetSelect(int nfds, u32 readfdsPtr, u32 writefdsPtr, u32 exceptfdsPtr, u32 timeoutPtr) {
	SceNetInetFdSet	*readfds = readfdsPtr ? (SceNetInetFdSet*)Memory::GetPointerWriteOrException(readfdsPtr) : nullptr;
	SceNetInetFdSet	*writefds = writefdsPtr ? (SceNetInetFdSet*)Memory::GetPointerWriteOrException(writefdsPtr) : nullptr;
	SceNetInetFdSet	*exceptfds = exceptfdsPtr ? (SceNetInetFdSet*)Memory::GetPointerWriteOrException(exceptfdsPtr) : nullptr;
	SceNetInetTimeval *timeout = timeoutPtr ? (SceNetInetTimeval*)Memory::GetPointerWriteOrException(timeoutPtr) : nullptr;

	timeval tmout = {5, 543210}; // Workaround timeout value when timeout = NULL
	if (timeout)
	{
		tmout.tv_sec = timeout->tv_sec;
		tmout.tv_usec = timeout->tv_usec;
	}
	// First, translate the specified fd_sets to host sockets.

	fd_set rdfds, wrfds, exfds;
	FD_ZERO(&rdfds);
	FD_ZERO(&wrfds);
	FD_ZERO(&exfds);

	if (nfds > 256)
	{
		// Probably never happens, just for safety.
		ERROR_LOG(Log::sceNet, "Bad nfds value, resetting to 256: %d", nfds);
		nfds = 256;
	}

	int rdcnt = 0, wrcnt = 0, excnt = 0;
	int realfds = 0; // Windows compatibility for virtual sockets

	int maxHostSocket = 0;
	// Save the mapping during setup.
	SelectTarget hostSockets[256]{};

	InetSocket *inetSock = nullptr;
	for (int i = SocketManager::MIN_VALID_INET_SOCKET; i < nfds; i++)
	{
		// Ignore invalid sockets
		if (!g_socketManager.GetInetSocket(i, &inetSock))
			continue;
		// Dead socket
		if (inetSock->sock == 0)
			continue;
		hostSockets[i].sock = inetSock->sock;
		if (inetSock->sock > maxHostSocket)
			maxHostSocket = inetSock->sock;

		bool virtReadReady = false;
		bool virtWriteReady = false;
		inetSock->select(&virtReadReady, &virtWriteReady, nullptr);
		if (readfds && (NetInetFD_ISSET(i, readfds)))
		{
			hostSockets[i].wantsRead = true;
			VERBOSE_LOG(Log::sceNet, "Input Read FD #%i (host: %d)", i, inetSock->sock);
			if (rdcnt < FD_SETSIZE)
			{
				// Skip host checks on virtual sockets: the socket reports its own
				// virtual read-readiness
				if (virtReadReady)
				{
					// We have existing data on one of the virtual sockets. Force an instant return for any other host sockets
					tmout.tv_sec = 0;
					tmout.tv_usec = 0;
				}
				else
				{
					FD_SET(inetSock->sock, &rdfds); // This might pointed to a non-existing socket or sockets belonged to other programs on Windows, because most of the time Windows socket have an id above 1k instead of 0-255
					realfds++;
				}
				rdcnt++;
			}
			else
			{
				ERROR_LOG(Log::sceNet, "Hit set size (rd)");
			}
		}
		if (writefds && (NetInetFD_ISSET(i, writefds)))
		{
			hostSockets[i].wantsWrite = true;
			VERBOSE_LOG(Log::sceNet, "Input Write FD #%i (host: %d)", i, inetSock->sock);
			if (wrcnt < FD_SETSIZE)
			{
				// Skip host checks on virtual sockets: the socket reports its own
				// virtual write-readiness
				if (virtWriteReady)
				{
					// We have existing data on one of the virtual sockets. Force an instant return for any other host sockets
					tmout.tv_sec = 0;
					tmout.tv_usec = 0;
				}
				else
				{
					FD_SET(inetSock->sock, &wrfds);
					realfds++;
				}
				wrcnt++;
			}
			else
			{
				ERROR_LOG(Log::sceNet, "Hit set size (wr)");
			}
		}
		if (exceptfds && (NetInetFD_ISSET(i, exceptfds)))
		{
			hostSockets[i].wantsExcept = true;
			VERBOSE_LOG(Log::sceNet, "Input Except FD #%i (host: %d)", i, inetSock->sock);
			if (excnt < FD_SETSIZE)
			{
				// Skip host checks on virtual sockets
				// if (inetSock->protocol == PSP_NET_INET_IPPROTO_TCP && (inetSock->has_pending_data(true) || inetSock->has_pending_connection())) {
				// 	// skip
				// } else if (inetSock->protocol == PSP_NET_INET_IPPROTO_UDP && inetSock->has_pending_data()) {
				// 	// skip
				// } else {
				FD_SET(inetSock->sock, &exfds);
				realfds++;
				// }
				excnt++;
			}
			else
			{
				ERROR_LOG(Log::sceNet, "Hit set size (exc)");
			}
		}
	}

	// Unlikely to hit these.
	_dbg_assert_(rdcnt < FD_SETSIZE);
	_dbg_assert_(wrcnt < FD_SETSIZE);
	_dbg_assert_(excnt < FD_SETSIZE);

	VERBOSE_LOG(Log::sceNet, "Select(host: %d): Read count: %d, Write count: %d, Except count: %d, TimeVal: %u.%u", maxHostSocket + 1, rdcnt, wrcnt, excnt, (int)tmout.tv_sec, (int)tmout.tv_usec);
	// TODO: Simulate blocking behaviour when timeout = NULL to prevent PPSSPP from freezing
	// Note: select can overwrite tmout.
	int retval = 0;
	if (realfds > 0) // Windows returns EINVAL when you select with no FDS
		retval = select(maxHostSocket + 1, readfds ? &rdfds : nullptr, writefds ? &wrfds : nullptr, exceptfds ? &exfds : nullptr, /*(timeout == NULL) ? NULL :*/ &tmout);
	int ready_count = 0; // Number of waiting FD's
	// Convert the results back to PSP fd_sets.
	if (readfds)
		NetInetFD_ZERO(readfds);
	if (writefds)
		NetInetFD_ZERO(writefds);
	if (exceptfds)
		NetInetFD_ZERO(exceptfds);

	// Don't need to loop through and set any bits if the sum total returned is 0.
	// But we do need to check any virtual buffers

	std::string _log = "";
	const s64 nowUs = (s64)CoreTiming::GetGlobalTimeUs();
	for (int i = SocketManager::MIN_VALID_INET_SOCKET; i < nfds; i++)
	{
		// Skip sockets that weren't requested
		if (!hostSockets[i].wantsRead && !hostSockets[i].wantsWrite && !hostSockets[i].wantsExcept)
			continue;
		if (!g_socketManager.GetInetSocket(i, &inetSock))
		{
			// _sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
			// retval = -1;
			continue; // Should we break here? Or populate all known data first?
		}
		_log += std::to_string(i) + "[";
		// Each socket reports its own virtual readiness; OR it with the host fd result.
		bool virtRead = false, virtWrite = false;
		inetSock->select(&virtRead, &virtWrite, nullptr);
		// Linger supports recv on CloseWait
		if (readfds && hostSockets[i].wantsRead)
		{
			const bool rdy = FD_ISSET(hostSockets[i].sock, &rdfds) || virtRead;
			if (!rdy)
			{
				inetSock->readReadySinceUs = -1; // nothing pending: reset the timer
			}
			else
			{
				if (inetSock->readReadySinceUs < 0)
					inetSock->readReadySinceUs = nowUs; // first moment data became available
				if (nowUs - inetSock->readReadySinceUs >= RX_ARRIVAL_DELAY_US)
				{
					NetInetFD_SET(i, readfds);
					ready_count++;
					_log += "R";
				}
				else
					_log += "d"; // held back, simulating arrival latency
			}
		}
		if (writefds && hostSockets[i].wantsWrite && (FD_ISSET(hostSockets[i].sock, &wrfds) || virtWrite))
		{
			NetInetFD_SET(i, writefds);
			ready_count++;
			_log += "W";
		}
		if (exceptfds && hostSockets[i].wantsExcept && FD_ISSET(hostSockets[i].sock, &exfds))
		{
			NetInetFD_SET(i, exceptfds);
			ready_count++;
			_log += "E";
		}
		_log += "] ";
	}
	DEBUG_LOG(Log::sceNet, "Select(host: %d): %s", maxHostSocket + 1, _log.c_str());

	if (retval < 0)
	{
		// UpdateErrnoFromHost(__KernelGetCurThread(), socket_errno, __FUNCTION__);
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(socket_errno));
		return hleLogDebug(Log::sceNet, retval);
	}
	// if (retval == 0)
	// return hleDelayResult(hleLogDebug(Log::sceNet, retval), "workaround until blocking-socket", 500); // Using hleDelayResult as a workaround for games that need blocking-socket to be implemented (ie. Coded Arms Contagion)
	return hleLogDebug(Log::sceNet, ready_count);
}

int sceNetInetPoll(u32 fdsPtr, u32 nfds, int timeout)
{ // timeout is in MILLISECONDS - firmware multiplies it by 1000 into its u32 microsecond sleep
	DEBUG_LOG(Log::sceNet, "sceNetInetPoll(%08x, %d, %i) at %08x", fdsPtr, nfds, timeout, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);

	if (nfds > FD_SETSIZE)
		nfds = FD_SETSIZE;
	if (!Memory::IsValidRange(fdsPtr, nfds * sizeof(SceNetInetPollfd))) {
		_sce_pspnet_set_thread_errno(ERROR_INET_EFAULT);
		return hleLogError(Log::sceNet, -1, "invalid fd array");
	}
	SceNetInetPollfd *fdarray = (SceNetInetPollfd *)Memory::GetPointerOrException(fdsPtr); // SceNetInetPollfd/pollfd, sceNetInetPoll() have similarity to BSD poll() but pollfd have different size on 64bit
	for (u32 i = 0; i < nfds; i++) {
		fdarray[i].revents = 0;
		if (fdarray[i].fd < 0) {
			// In Unix, this is OK and means the fd should be ignored (revents zeroed), but
			// keep the established EINVAL behavior here.
			_sce_pspnet_set_thread_errno(ERROR_INET_EINVAL);
			return hleLogError(Log::sceNet, -1, "invalid socket id");
		}
	}
	// Firmware rejects any timeout whose microsecond form doesn't fit in u32
	// (>= 0x418938 ms, ~49.7 days). -1 (and, leniently, other negatives) = infinite.
	if (timeout >= 0x418938) {
		_sce_pspnet_set_thread_errno(ERROR_INET_EINVAL);
		return hleLogError(Log::sceNet, -1, "timeout out of range");
	}

	int count = __NetInetPollScan(fdarray, nfds);
	if (count != 0 || timeout == 0) {
		// Something is already ready (or this is a pure status poll) - no need to park.
		return hleLogDebug(Log::sceNet, count);
	}

	// Nothing ready: park the PSP thread. The recurring tick resumes it when an fd
	// becomes ready, the timeout lapses (result 0, no errno), or a socket dies.
	NetInetPollOp *op = nullptr;
	for (auto &candidate : g_pollOps) {
		if (!candidate.active) {
			op = &candidate;
			break;
		}
	}
	if (!op) {
		g_pollOps.emplace_back();
		op = &g_pollOps.back();
	}
	op->threadID = __KernelGetCurThread();
	op->fdsPtr = fdsPtr;
	op->nfds = nfds;
	op->deadlineUs = timeout < 0 ? -1 : (s64)CoreTiming::GetGlobalTimeUs() + (s64)timeout * 1000;
	op->active = true;

	__KernelWaitCurThread(WAITTYPE_NET, op->threadID, 0, 0, false, "sceNetInetPoll");
	if (!CoreTiming::IsScheduled(netInetPollEvent))
		CoreTiming::ScheduleEvent(usToCycles(NETINET_POLL_TICK_US), netInetPollEvent, 0);
	return 0;
}

static int sceNetInetRecv(int socket, u32 bufPtr, u32 bufLen, u32 flags)
{
	DEBUG_LOG(Log::sceNet, "%s(%i, %08x, %i, %i) at %08x", __FUNCTION__, socket, bufPtr, bufLen, flags, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, ERROR_INET_EBADF, "Bad socket #%d", socket);
	}

	if (inetSock->threadID > 0) {
		_sce_pspnet_set_thread_errno(ERROR_INET_EINTR);
		_dbg_assert_msg_(false, "Socket currently running an operation in another thread.")
		return hleLogError(Log::sceNet, -1, "Socket is busy with previous operation");
    }

	// The socket self-routes: its recv() picks the virtual (relay) or host path
	// from the session table. The host read is forced non-blocking (DONTWAIT) so
	// it can never stall the emu thread; blocking is simulated by the op tick.
	const bool blocking = !inetSock->nonblocking && !(flags & PSP_NET_INET_MSG_DONTWAIT);
	const u32 hostFlags = flags | PSP_NET_INET_MSG_DONTWAIT;
	auto run = [bufPtr, bufLen, hostFlags, inetSock]() -> int {
		return inetSock->recv((char*)Memory::GetPointerOrException(bufPtr), bufLen, hostFlags);
	};
	if (!blocking)
		return __NetInetRunInline(run);

	// A BLOCKING MSG_WAITALL recv must return the FULL requested length - that's
	// how a length-framed reader (PSP2i's HTTPS/ComSize thread) pulls an exact
	// frame. The single-shot tick would resume on the first partial chunk and
	// desync the reader (it lands its next length read on image/GIM payload), so
	// accumulate across tick retries until full, EOF, or a hard error. Each
	// attempt is non-blocking (DONTWAIT, WAITALL stripped) so it can't stall.
	if (flags & PSP_NET_INET_MSG_WAITALL) {
		auto got = std::make_shared<int>(0);
		const u32 pollFlags = (flags & ~PSP_NET_INET_MSG_WAITALL) | PSP_NET_INET_MSG_DONTWAIT;
		auto waitall = [bufPtr, bufLen, pollFlags, inetSock, got]() -> int {
			int r = inetSock->recv((char*)Memory::GetPointerOrException(bufPtr) + *got, (int)bufLen - *got, pollFlags);
			if (r > 0) {
				*got += r;
				return (*got >= (int)bufLen) ? *got : NETINET_OP_PENDING; // full, else need more
			}
			if (r == 0)
				return *got; // peer closed: return what we have (0 = clean EOF)
			return r; // <0: EWOULDBLOCK keeps waiting (real errno), hard error completes
		};
		return __NetInetParkOp(inetSock, socket, std::move(waitall), "sceNetInetRecv");
	}
	return __NetInetParkOp(inetSock, socket, std::move(run), "sceNetInetRecv");
}

static int sceNetInetSend(int socket, u32 bufPtr, u32 bufLen, u32 flags)
{
	INFO_LOG(Log::sceNet, "%s(%i, %08x, %i, %i) at %08x", __FUNCTION__, socket, bufPtr, bufLen, flags, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, ERROR_INET_EBADF, "Bad socket #%d", socket);
	}

	// Only build the hex dump when VERBOSE sceNet logging is actually on - this
	// runs on every send on the emu thread, so unconditionally formatting the
	// whole buffer is wasted work (and host CPU) during normal play.
	if (GenericLogEnabled(Log::sceNet, LogLevel::LVERBOSE)) {
		std::string datahex;
		DataToHexString(10, 0, Memory::GetPointerOrException(bufPtr), bufLen, &datahex);
		VERBOSE_LOG(Log::sceNet, "Data Dump (%d bytes):\n%s", bufLen, datahex.c_str());
	}

	if (inetSock->threadID > 0) {
		_sce_pspnet_set_thread_errno(ERROR_INET_EINTR);
		_dbg_assert_msg_(false, "Socket currently running an operation in another thread.")
		return hleLogError(Log::sceNet, -1, "Socket is busy with previous operation");
    }

	// The socket self-routes via its send() (virtual relay vs host) and carries
	// the REAL caller flags into Send_Reliable. The host write is forced non-
	// blocking (DONTWAIT) so a full send buffer can never stall the emu thread;
	// a blocking send is retried on the op tick.
	const bool blocking = !inetSock->nonblocking && !(flags & PSP_NET_INET_MSG_DONTWAIT);
	const u32 hostFlags = flags | PSP_NET_INET_MSG_DONTWAIT;
	auto run = [bufPtr, bufLen, hostFlags, inetSock]() -> int {
		return inetSock->send((char*)Memory::GetPointerOrException(bufPtr), bufLen, hostFlags);
	};
	if (!blocking)
		return __NetInetRunInline(run);
	return __NetInetParkOp(inetSock, socket, std::move(run), "sceNetInetSend");
}

int sceNetInetSocket(int domain, int type, int protocol)
{
	INFO_LOG(Log::sceNet, "sceNetInetSocket(%d, %d, %d) at %08x - Socket: Domain = %s, Type = %s, Protocol = %s",
			 domain, type, protocol, currentMIPS->pc, inetSocketDomain2str(domain).c_str(), inetSocketType2str(type).c_str(), inetSocketProto2str(protocol).c_str());
	_sce_pspnet_set_thread_errno(0);

	int socket;
	int hostErrno = 0;
	InetSocket *inetSock = g_socketManager.CreateSocket(&socket, &hostErrno, SocketState::UsedNetInet, domain, type, protocol);
	if (!inetSock)
	{
		// UpdateErrnoFromHost(__KernelGetCurThread(), hostErrno, __FUNCTION__);
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(hostErrno));
		return hleLogError(Log::sceNet, -1);
	}
	// Ignore SIGPIPE when supported (ie. BSD/MacOS)
	// setSockNoSIGPIPE(inetSock->sock, 1);
	// TODO: We should always use non-blocking mode and simulate blocking mode
	// changeBlockingMode(inetSock->sock, 1);
	// Enable Port Re-use, required for multiple-instance
	// setSockReuseAddrPort(inetSock->sock);
	// Disable Connection Reset error on UDP to avoid strange behavior
	// setUDPConnReset(inetSock->sock, false);
	return hleLogDebug(Log::sceNet, socket);
}

static int sceNetInetSetsockopt(int socket, int level, int optname, u32 optvalPtr, int optlen)
{
	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}

	const u32 optval = Memory::IsValid4AlignedAddress(optvalPtr) ? Memory::ReadUnchecked_U32(optvalPtr) : 0;
	INFO_LOG(Log::sceNet, "sceNetInetSetsockopt(%i, %i, %i, %08x, %i) at %08x: Level = %s, OptName = %s, OptValue = %d",
			 socket, level, optname, optvalPtr, optlen, currentMIPS->pc,
			 inetSockoptLevel2str(level).c_str(), inetSockoptName2str(optname, level).c_str(), optval);

	timeval tval{};

	int retval = inetSock->setsockopt(level, optname, optval, optlen);
	if (retval < 0)
	{
		// UpdateErrnoFromHost(__KernelGetCurThread(), socket_errno, __FUNCTION__);
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(socket_errno));
		return hleLogError(Log::sceNet, retval);
	}
	return hleLogDebug(Log::sceNet, retval);
}

static int sceNetInetGetsockopt(int socket, int level, int optname, u32 optvalPtr, u32 optlenPtr)
{
	WARN_LOG(Log::sceNet, "sceNetInetGetsockopt(%i, %i, %i, %08x, %08x) at %08x", socket, level, optname, optvalPtr, optlenPtr, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);

	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}

	u32_le* optval = (u32_le*)Memory::GetPointerOrException(optvalPtr);
	socklen_t* optlen = (socklen_t*)Memory::GetPointerOrException(optlenPtr);
	DEBUG_LOG(Log::sceNet, "SockOpt: Level = %s, OptName = %s", inetSockoptLevel2str(level).c_str(), inetSockoptName2str(optname, level).c_str());
	timeval tval{};

	int retval = inetSock->getsockopt(level, optname, (char *)optval, optlen);
	if (retval < 0)
	{
		// UpdateErrnoFromHost(__KernelGetCurThread(), socket_errno, __FUNCTION__);
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(socket_errno));
		return hleLogError(Log::sceNet, retval);
	}
	DEBUG_LOG(Log::sceNet, "SockOpt: OptValue = %d", *optval);
	return hleLogDebug(Log::sceNet, retval);
}

static int sceNetInetBind(int socket, u32 namePtr, int namelen)
{
	INFO_LOG(Log::sceNet, "%s(%i, %08x, %i) at %08x", __FUNCTION__, socket, namePtr, namelen, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);

	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}

	SceNetInetSockaddr *name = (SceNetInetSockaddr *)Memory::GetPointerOrException(namePtr);

	// Port 3658 (SCE_SIGN_PORT) is the P2P/signaling convention port. On real hardware it's a
	// kernel-level hijack that any number of sockets share via vports; here that means multiple
	// real host sockets must bind the same port, so 3658 must ALWAYS be reusable. Apply this to
	// ANY socket binding 3658 - a game re-binding a port it already owns just to probe whether
	// it's taken would be an absurd counter-measure to something the SDK made impossible.
	if (name && inetSock->sock != INVALID_SOCKET) {
		SockAddrIN4 baddr{};
		baddr.addr.sa_family = name->sa_family;
		memcpy(baddr.addr.sa_data, name->sa_data, sizeof(name->sa_data));
		if (ntohs(baddr.in.sin_port) == SCE_SIGN_PORT) {
			int reuse = 1;
#if defined(SO_REUSEPORT)
			::setsockopt(inetSock->sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&reuse, sizeof(reuse));
#endif
			::setsockopt(inetSock->sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
		}
	}

	int retval = inetSock->bind(name, namelen);
	// retval = bind(inetSock->sock, (struct sockaddr*)&saddr, len);
	if (retval < 0)
	{
		// UpdateErrnoFromHost(__KernelGetCurThread(), socket_errno, __FUNCTION__);
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(socket_errno));
		// changeBlockingMode(inetSock->sock, 1);
		return hleLogError(Log::sceNet, retval);
	}

	// FIXME: Not all ports require port forwarding, especially in Infra P2P
	// Check the socket type/protocol for SOCK_STREAM/SOCK_DGRAM or IPPROTO_TCP/IPPROTO_UDP instead of forwarding both protocols like in ANR2ME's original change.
	// unsigned short port = ntohs(saddr.in.sin_port);
	if (inetSock->src.host.sin_port != htons(SCE_SIGN_PORT))
		// Reliable (TCP-family) socket types map TCP; datagram types map UDP.
		{
			const int t = inetSock->type;
			const bool tcpLike = (t == PSP_NET_INET_SOCK_STREAM || t == PSP_NET_INET_SOCK_RAW ||
			                      t == PSP_NET_INET_SOCK_RDM || t == PSP_NET_INET_SOCK_SEQPACKET ||
			                      t == PSP_NET_INET_SOCK_PACKET);
			UPnP_Add(tcpLike ? IP_PROTOCOL_TCP : IP_PROTOCOL_UDP, ntohs(inetSock->src.virt.port), ntohs(inetSock->src.virt.port));
		}

	// Workaround: Send a dummy 0 size message to AdhocServer IP to make sure the socket actually bound to an address when binded with INADDR_ANY before using getsockname, seems to fix sending DGRAM from incorrect port issue on Android
	/*saddr.in.sin_addr.s_addr = g_adhocServerIP.in.sin_addr.s_addr;
	saddr.in.sin_port = 0;
	sendto(socket, dummyPeekBuf64k, 0, MSG_NOSIGNAL, (struct sockaddr*)&saddr, sizeof(saddr));
	*/
	return hleLogInfo(Log::sceNet, retval);
}

static int sceNetInetConnect(int socket, u32 sockAddrPtr, int sockAddrLen)
{
	INFO_LOG(Log::sceNet, "sceNetInetConnect(%i, %08x, %i) at %08x", socket, sockAddrPtr, sockAddrLen, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}

	// Still using warn log here so it stands out in the log

	SceNetInetSockaddr *dst = (SceNetInetSockaddr *)Memory::GetPointerOrException(sockAddrPtr);

	if (inetSock->threadID > 0) {
		_sce_pspnet_set_thread_errno(ERROR_INET_EINTR);
		_dbg_assert_msg_(false, "Socket currently running an operation in another thread.")
		return hleLogError(Log::sceNet, -1, "Socket is busy with previous operation");
    }

	// Copy the sockaddr by value: a parked blocking connect re-polls on the op
	// tick after this frame, and connect() may write back into it (sa_len).
	SceNetInetSockaddr addrCopy = *dst;
	const bool blocking = !inetSock->nonblocking;

	// The socket self-routes: its connect() runs the virtual TCP-over-UDP
	// handshake for a peer destination, or a real host connect otherwise. Both
	// are poll-safe - re-calling while in progress returns EINPROGRESS/EALREADY,
	// and EISCONN once it lands - so the retry tick can drive completion.
	auto run = [addrCopy, sockAddrLen, inetSock]() mutable -> int {
		int r = inetSock->connect(&addrCopy, sockAddrLen);
		if (r >= 0)
			return r;
		// A re-polled connect reports EISCONN once it lands - that's success.
		// Return 0 without clearing socket_errno: callers only read it when the
		// result is < 0, so the stale value is never consumed (and socket_errno
		// is WSAGetLastError() on Windows - not assignable).
		if (convertInetErrnoHost2PSP(socket_errno) == ERROR_INET_EISCONN)
			return 0;
		return r;
	};

	if (!blocking) {
		int r = run();
		if (r < 0) {
			int pe = convertInetErrnoHost2PSP(socket_errno);
			if (pe == ERROR_INET_EAGAIN)
				pe = ERROR_INET_EINPROGRESS; // POSIX/Windows parity for non-blocking connect
			_sce_pspnet_set_thread_errno(pe);
		}
		hleEatMicro(50);
		return hleNoLog(r);
	}

	WARN_LOG(Log::sceNet, "%s: BLOCKING connect on socket #%d", __FUNCTION__, socket);
	return __NetInetParkOp(inetSock, socket, std::move(run), "sceNetInetConnect");
}

static int sceNetInetListen(int socket, int backlog)
{
	INFO_LOG(Log::sceNet, "%s(%i, %i) at %08x", __FUNCTION__, socket, backlog, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}

	int retval = inetSock->listen((backlog == PSP_NET_INET_SOMAXCONN ? SOMAXCONN : backlog));
	// retval = listen(inetSock->sock, (backlog == PSP_NET_INET_SOMAXCONN ? SOMAXCONN : backlog));
	if (retval < 0)
	{
		// UpdateErrnoFromHost(__KernelGetCurThread(), socket_errno, __FUNCTION__);
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(socket_errno));
		return hleLogError(Log::sceNet, retval);
	}

	return hleLogInfo(Log::sceNet, retval);
}

static int sceNetInetAccept(int socket, u32 addrPtr, u32 addrLenPtr)
{
	INFO_LOG(Log::sceNet, "%s(%i, %08x, %08x) at %08x", __FUNCTION__, socket, addrPtr, addrLenPtr, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}

	SceNetInetSockaddr *src = (SceNetInetSockaddr *)Memory::GetCharPointer(addrPtr);
	socklen_t *srclen = (socklen_t *)Memory::GetCharPointer(addrLenPtr);
	SockAddrIN4 saddr{};
	if (srclen)
		*srclen = std::min((*srclen) > 0 ? *srclen : 0, static_cast<socklen_t>(sizeof(saddr)));

	auto _vport = (saddr.in.sin_zero[0] << 8) | saddr.in.sin_zero[1];

	// Accept runs directly on the emu thread - a BLOCKING host accept with no
	// pending connection would stall the whole emulator, not just this PSP thread
	if (!inetSock->nonblocking)
		WARN_LOG(Log::sceNet, "%s: BLOCKING accept on socket #%d", __FUNCTION__, socket);

	// A pending virtual (relayed) SYN is promoted through Accept_Reliable; otherwise real accept.
	// Gate on the pending connection itself, NOT merely on signaling being up - otherwise a plain
	// host TCP listener could never accept a real connection while signaling runs.
	int newHostSocket = inetSock->has_pending_connection()
		? inetSock->Accept_Reliable((struct sockaddr *)&saddr.addr, srclen)
		: inetSock->accept((struct sockaddr *)&saddr.addr, srclen);
	// newHostSocket = accept(inetSock->sock, (struct sockaddr*)&saddr.addr, srclen);
	if (newHostSocket < 0)
	{
		int errorno = convertInetErrnoHost2PSP(socket_errno);
		_sce_pspnet_set_thread_errno(errorno);
		if (errorno == ERROR_INET_EAGAIN)
		{
			return hleLogDebug(Log::sceNet, -1, "EAGAIN");
		}
		else
		{
			return hleLogError(Log::sceNet, -1);
		}
	}

	// int newSocketId;
	// InetSocket *newInetSocket = g_socketManager.AdoptSocket(&newSocketId, newHostSocket, inetSock);
	// if (!newInetSocket) {
	// 	// Ran out of space. Shouldn't really happen.
	// 	UpdateErrnoFromHost(__KernelGetCurThread(), ENOMEM, __FUNCTION__);
	// 	return hleLogError(Log::sceNet, -1, "Out of socket IDs");;
	// }

	if (src)
	{
		src->sa_family = saddr.addr.sa_family;
		memcpy(src->sa_data, saddr.addr.sa_data, sizeof(src->sa_data));
		src->sa_len = srclen ? *srclen : 0;
	}
	INFO_LOG(Log::sceNet, "Accept: Address = %s, Port = %u, VPort = %u", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port), _vport);

	return hleLogInfo(Log::sceNet, newHostSocket);
}

static int sceNetInetShutdown(int socket, int how)
{
	INFO_LOG(Log::sceNet, "%s(%i, %i) at %08x", __FUNCTION__, socket, how, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}

	// Convert HOW from PSP to Host
	int hostHow = how;
	switch (how)
	{
	case PSP_NET_INET_SHUT_RD:
		hostHow = SHUT_RD;
		break;
	case PSP_NET_INET_SHUT_WR:
		hostHow = SHUT_WR;
		break;
	case PSP_NET_INET_SHUT_RDWR:
		hostHow = SHUT_RDWR;
		break;
	}

	// The socket self-routes: its shutdown() tears down the virtual connection or
	// the host socket. (NOTE: the per-type override preserves the pre-existing
	// inverted gate - Shutdown_Reliable for NON-peer dsts - flagged for review.)
	int retVal = inetSock->shutdown(hostHow);
	// retVal = shutdown(inetSock->sock, hostHow);  // no translation
	if (retVal < 0)
	{
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(socket_errno));
/*#ifdef PPSSPP_PLATFORM_WINDOWS
		auto err = WSAGetLastError();
		switch (err)
		{
		case WSANOTINITIALISED:
			return hleLogError(Log::sceNet, ERROR_NET_WLAN_DEVICE_NOT_READY, "Socket Not Initialized");
		case WSAENETDOWN:
			return hleLogError(Log::sceNet, ERROR_NET_WLAN_INTERNAL_FAIL, "Network Failure");
		case WSAENOTSOCK:
			return hleLogError(Log::sceNet, ERROR_NET_WLAN_INVALID_ARG, "Invalid Argument");
		case WSAEINPROGRESS:
			return hleLogError(Log::sceNet, ERROR_NET_WLAN_DEVICE_NOT_READY, "Socket Is Busy");
		case WSAEINTR:
			return hleLogWarning(Log::sceNet, 0, "Socket Interrupted");
		case WSAEWOULDBLOCK:
			return hleLogWarning(Log::sceNet, 0, "Non-Blocking Socket");
		case WSAENOTCONN:
			return hleLogWarning(Log::sceNet, 0, "Socket Not Connected");
		default:
			return hleLogWarning(Log::sceNet, 0, "Unhandled Error: %d", err);
		}
#else
		int err = errno;
		switch (err)
		{
		case EBADF:
		case EINVAL:
		case ENOTSOCK:
			return hleLogError(Log::sceNet, ERROR_NET_WLAN_INVALID_ARG, "Invalid Argument");
		case ENOTCONN:
			return hleLogError(Log::sceNet, ERROR_NET_WLAN_DEVICE_NOT_READY, "Socket Not Initialized");
		default:
			return hleLogWarning(Log::sceNet, 0, "Unhandled Error: %d", err);
		}
#endif*/
	}
	return hleLogInfo(Log::sceNet, 0);
}

// This function should never touch a connection directly.
// It's purpose is to stop the target sockets blocking actions, and report ERROR_INET_EINTR for that socket's actions
// This function will only report Bad Thread Stack, Bad Socket, or 0 (success)
static int sceNetInetSocketAbort(int socket)
{
	INFO_LOG(Log::sceNet, "%s(%i) at %08x", __FUNCTION__, socket, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}

	inetSock->abortPending = true;
	int tid = inetSock->threadID.exchange(-1);
	if (tid > 0) {
		_sce_pspnet_set_thread_errno(ERROR_INET_EINTR, tid);
		__KernelResumeThreadFromWait(tid, -1);
	}
	// Drop the queued op entry (the parked thread was just resumed above).
	__NetInetCancelOp(socket, false);

	// FIXME: either using shutdown/close or select? probably using select if blocking mode is being simulated with non-blocking
	// int retval = inetSock->shutdown(SHUT_RDWR);
	// if (retval < 0) {
	// 	_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(socket_errno));
	// 	return hleLogError(Log::sceNet, retval);
	// }
	// retVal = shutdown(inetSock->sock, SHUT_RDWR);
	return hleLogInfo(Log::sceNet, 0);
}

int sceNetInetClose(int socket)
{
	INFO_LOG(Log::sceNet, "%s(%i) at %08x", __FUNCTION__, socket, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}
	// Wake (with EINTR) any PSP thread still parked on a blocking op for this
	// socket before it goes away, so it can't hang waiting for a dead socket.
	__NetInetCancelOp(socket, true);
	g_socketManager.Close(inetSock);
	return hleLogInfo(Log::sceNet, 0);
}

// TODO: How is this different than just sceNetInetClose?
static int sceNetInetCloseWithRST(int socket)
{
	INFO_LOG(Log::sceNet, "%s(%i) at %08x", __FUNCTION__, socket, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}

	// Based on http://deepix.github.io/2016/10/21/tcprst.html
	struct linger sl{};
	sl.l_onoff = 1;	 // non-zero value enables linger option in kernel
	sl.l_linger = 0; // timeout interval in seconds
	inetSock->setsockopt(SOL_SOCKET, SO_LINGER, (const char *)&sl, sizeof(sl));
	// setsockopt(inetSock->sock, SOL_SOCKET, SO_LINGER, (const char*)&sl, sizeof(sl));
	__NetInetCancelOp(socket, true);
	g_socketManager.Close(inetSock);
	return hleLogInfo(Log::sceNet, 0);
}

static int sceNetInetRecvfrom(int socket, u32 bufferPtr, int len, int flags, u32 fromPtr, u32 fromlenPtr)
{
	DEBUG_LOG(Log::sceNet, "%s(%i, %08x, %i, %i, %08x, %08x) at %08x", __FUNCTION__, socket, bufferPtr, len, flags, fromPtr, fromlenPtr, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}

	if (inetSock->threadID > 0) {
		_sce_pspnet_set_thread_errno(ERROR_INET_EINTR);
		_dbg_assert_msg_(false, "Socket currently running an operation in another thread.")
		return hleLogError(Log::sceNet, -1, "Socket is busy with previous operation");
    }

	// The socket self-routes: its recvfrom() drains the virtual relay queue when
	// bound to the signaling port, else the host recvfrom. Forced non-blocking
	// (DONTWAIT) so it can never stall the emu thread. The from/fromlen pointers
	// live in the (parked, therefore frozen) caller stack, so they stay valid.
	const bool blocking = !inetSock->nonblocking && !(flags & PSP_NET_INET_MSG_DONTWAIT);
	const u32 hostFlags = flags | PSP_NET_INET_MSG_DONTWAIT;
	auto run = [bufferPtr, len, hostFlags, fromPtr, fromlenPtr, inetSock]() -> int {
		SceNetInetSockaddr *src = (SceNetInetSockaddr *)Memory::GetCharPointer(fromPtr);
		socklen_t *srclen = (socklen_t *)Memory::GetCharPointer(fromlenPtr);
		return inetSock->recvfrom((char *)Memory::GetPointerOrException(bufferPtr), len, hostFlags, src, srclen);
	};
	if (!blocking)
		return __NetInetRunInline(run);
	return __NetInetParkOp(inetSock, socket, std::move(run), "sceNetInetRecvfrom");
}

static int sceNetInetSendto(int socket, u32 bufferPtr, int len, int flags, u32 toPtr, int tolen)
{
	INFO_LOG(Log::sceNet, "%s(%i, %08x, %i, %i, %08x, %i) at %08x", __FUNCTION__, socket, bufferPtr, len, flags, toPtr, tolen, currentMIPS->pc);
	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}

	if (inetSock->threadID > 0) {
		_sce_pspnet_set_thread_errno(ERROR_INET_EINTR);
		_dbg_assert_msg_(false, "Socket currently running an operation in another thread.")
		return hleLogError(Log::sceNet, -1, "Socket is busy with previous operation");
    }

	// The socket self-routes: its sendto() relays to a peer destination (or the
	// signaling port) via Send_Reliable/Unreliable, else a real host sendto.
	// Forced non-blocking (DONTWAIT) so it can never stall the emu thread; the
	// to-address lives in the (parked, frozen) caller stack and stays valid.
	const bool blocking = !inetSock->nonblocking && !(flags & PSP_NET_INET_MSG_DONTWAIT);
	const u32 hostFlags = flags | PSP_NET_INET_MSG_DONTWAIT;
	auto run = [bufferPtr, len, hostFlags, toPtr, tolen, inetSock]() -> int {
		SceNetInetSockaddr *dst = (SceNetInetSockaddr *)Memory::GetCharPointer(toPtr);
		return inetSock->sendto((char *)Memory::GetPointerOrException(bufferPtr), len, hostFlags, dst, tolen);
	};
	if (!blocking)
		return __NetInetRunInline(run);
	return __NetInetParkOp(inetSock, socket, std::move(run), "sceNetInetSendto");
}

// Similar to POSIX's sendmsg or Winsock2's WSASendMsg? Are their packets compatible one another?
// Games using this: The Warrior's Code
static int sceNetInetSendmsg(int socket, u32 msghdrPtr, int flags)
{
	INFO_LOG(Log::sceNet, "%s(%i, %08x, %i) at %08x", __FUNCTION__, socket, msghdrPtr, flags, currentMIPS->pc);
	// Note: sendmsg is concatenating iovec buffers before sending it, and send/sendto is just a wrapper for sendmsg according to https://stackoverflow.com/questions/4258834/how-sendmsg-works
	int retval = -1;
	if (!Memory::IsValidAddress(msghdrPtr))
	{
		// UpdateErrnoFromHost(__KernelGetCurThread(), , __FUNCTION__);
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(EFAULT));
		return hleLogError(Log::sceNet, retval);
	}

	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}

	InetMsghdr *pspMsghdr = (InetMsghdr *)Memory::GetPointerUnchecked(msghdrPtr);
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	SockAddrIN4 saddr{};
#if defined(_WIN32)
	WSAMSG hdr;
	WSACMSGHDR *chdr = NULL;
	size_t iovecsize = sizeof(WSABUF);
	WSABUF *iov = (WSABUF *)malloc(pspMsghdr->msg_iovlen * iovecsize);
#else
	msghdr hdr;
	cmsghdr *chdr = nullptr;
	size_t iovecsize = sizeof(iovec);
	iovec *iov = (iovec *)malloc(pspMsghdr->msg_iovlen * iovecsize);
#endif
	if (iov == NULL)
	{
		// UpdateErrnoFromHost(__KernelGetCurThread(), , __FUNCTION__);
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(ENOBUFS));
		return hleLogError(Log::sceNet, retval);
	}
	memset(iov, 0, pspMsghdr->msg_iovlen * iovecsize);
	memset(&hdr, 0, sizeof(hdr));
	if (pspMsghdr->msg_name != 0) {
		SceNetInetSockaddr* pspSaddr = (SceNetInetSockaddr*)Memory::GetPointerOrException(pspMsghdr->msg_name);
		saddr.addr.sa_family = pspSaddr->sa_family;
		size_t datalen = std::min(pspMsghdr->msg_namelen - (sizeof(pspSaddr->sa_len) + sizeof(pspSaddr->sa_family)), sizeof(saddr.addr.sa_data));
		memcpy(saddr.addr.sa_data, pspSaddr->sa_data, datalen);
		DEBUG_LOG(Log::sceNet, "SendMsg: Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
#if defined(_WIN32)
		hdr.name = &saddr.addr;
		hdr.namelen = static_cast<int>(datalen + sizeof(saddr.addr.sa_family));
#else
		hdr.msg_name = &saddr.addr;
		hdr.msg_namelen = static_cast<int>(datalen + sizeof(saddr.addr.sa_family));
#endif
	}
#if defined(_WIN32)
	hdr.lpBuffers = iov;
	hdr.dwBufferCount = pspMsghdr->msg_iovlen;
#else
	hdr.msg_iov = iov;
	hdr.msg_iovlen = pspMsghdr->msg_iovlen;
#endif
	if (pspMsghdr->msg_iov != 0) {
		SceNetIovec* pspIov = (SceNetIovec*)Memory::GetPointerOrException(pspMsghdr->msg_iov);
		for (int i = 0; i < pspMsghdr->msg_iovlen; i++) {
			if (pspIov[i].iov_base != 0) {
#if defined(_WIN32)
				iov[i].buf = (char*)Memory::GetPointerOrException(pspIov[i].iov_base);
				iov[i].len = pspIov[i].iov_len;
#else
				iov[i].iov_base = (char*)Memory::GetPointerOrException(pspIov[i].iov_base);
				iov[i].iov_len = pspIov[i].iov_len;
#endif
			}
		}
	}
	// Control's Level (ie. host's SOL_SOCKET to/from psp's PSP_NET_INET_SOL_SOCKET) and Type (ie. SCM_RIGHTS) might need to be converted to be cross-platform
	if (pspMsghdr->msg_control != 0)
	{
#if defined(_WIN32)
		chdr = (WSACMSGHDR *)malloc(pspMsghdr->msg_controllen);
#else
		chdr = (cmsghdr *)malloc(pspMsghdr->msg_controllen);
#endif
		if (chdr == NULL)
		{
			// UpdateErrnoFromHost(__KernelGetCurThread(), , __FUNCTION__);
		_sce_pspnet_set_thread_errno(convertInetErrnoHost2PSP(ENOBUFS));
			free(iov);
			return hleLogError(Log::sceNet, retval);
		}
		InetCmsghdr* pspCmsghdr = (InetCmsghdr*)Memory::GetPointerOrException(pspMsghdr->msg_control);
		// TODO: Convert InetCmsghdr into platform-specific struct as they're affected by 32/64bit
		memcpy(chdr, pspCmsghdr, pspMsghdr->msg_controllen);
#if defined(_WIN32)
		hdr.Control.buf = (char *)chdr; // (char*)pspCmsghdr;
		hdr.Control.len = pspMsghdr->msg_controllen;
		// Note: Many existing implementations of CMSG_FIRSTHDR never look at msg_controllen and just return the value of cmsg_control.
		if (pspMsghdr->msg_controllen >= sizeof(InetCmsghdr))
		{
			// TODO: Creates our own CMSG_* macros (32-bit version of it, similar to the one on PSP) to avoid alignment/size issue that can lead to memory corruption/out of bound issue.
			for (WSACMSGHDR *cmsgptr = WSA_CMSG_FIRSTHDR(&hdr); cmsgptr != NULL; cmsgptr = WSA_CMSG_NXTHDR(&hdr, cmsgptr))
			{
				cmsgptr->cmsg_type = convertCMsgTypePSP2Host(cmsgptr->cmsg_type, cmsgptr->cmsg_level);
				cmsgptr->cmsg_level = convertSockoptLevelPSP2Host(cmsgptr->cmsg_level);
			}
		}
#else
		hdr.msg_control = (char *)chdr; // (char*)pspCmsghdr;
		hdr.msg_controllen = pspMsghdr->msg_controllen;
		// Note: Many existing implementations of CMSG_FIRSTHDR never look at msg_controllen and just return the value of cmsg_control.
		if (pspMsghdr->msg_controllen >= sizeof(InetCmsghdr))
		{
			for (cmsghdr *cmsgptr = CMSG_FIRSTHDR(&hdr); cmsgptr != NULL; cmsgptr = CMSG_NXTHDR(&hdr, cmsgptr))
			{
				cmsgptr->cmsg_type = convertCMsgTypePSP2Host(cmsgptr->cmsg_type, cmsgptr->cmsg_level);
				cmsgptr->cmsg_level = convertSockoptLevelPSP2Host(cmsgptr->cmsg_level);
			}
		}
#endif
	}
	// Flags (ie. PSP_NET_INET_MSG_OOB) might need to be converted to be cross-platform
#if defined(_WIN32)
	hdr.dwFlags = convertMSGFlagsPSP2Host(pspMsghdr->msg_flags & ~PSP_NET_INET_MSG_DONTWAIT) | MSG_NOSIGNAL;
#else
	hdr.msg_flags = convertMSGFlagsPSP2Host(pspMsghdr->msg_flags & ~PSP_NET_INET_MSG_DONTWAIT) | MSG_NOSIGNAL;
#endif
	unsigned long sent = 0;
	bool isBcast = isBroadcastIP(saddr.in.sin_addr.s_addr);
	// Broadcast/Multicast, use real broadcast/multicast if there is no one in peerlist
	if (isBcast && getActivePeerCount() > 0)
	{
		// Acquire Peer Lock
		peerlock.lock();
		SceNetAdhocctlPeerInfo *peer = friends;
		for (; peer != NULL; peer = peer->next)
		{
			// Does Skipping sending to timed out friends could cause desync when players moving group at the time MP game started?
			if (peer->last_recv == 0)
				continue;

			saddr.in.sin_addr.s_addr = peer->ip_addr;
#if defined(_WIN32)
			int result = WSASendMsg(inetSock->sock, &hdr, flgs | MSG_NOSIGNAL, &sent, NULL, NULL);
			if (static_cast<int>(sent) > retval)
				retval = sent;
#else
			size_t result = sendmsg(inetSock->sock, &hdr, flgs | MSG_NOSIGNAL);
			if (static_cast<int>(result) > retval)
				retval = result;
#endif
			if (retval != SOCKET_ERROR)
			{
				DEBUG_LOG(Log::sceNet, "SendMsg(BC): Address = %s, Port = %d", ip2str(saddr.in.sin_addr).c_str(), ntohs(saddr.in.sin_port));
			}
			else
			{
				DEBUG_LOG(Log::sceNet, "SendMsg(BC): Socket error %d", socket_errno);
			}
		}
		// Free Peer Lock
		peerlock.unlock();
		// TODO: Calculate number of bytes supposed to be sent
		retval = std::max(retval, 0); // Broadcast always success?
	}
	// Unicast or real broadcast/multicast
	else
	{
		// FIXME: On non-Windows(including PSP too?) broadcast to INADDR_BROADCAST(255.255.255.255) might not be received by the sender itself when binded to specific IP (ie. 192.168.0.2) or INADDR_BROADCAST.
		//        Meanwhile, it might be received by itself when binded to subnet (ie. 192.168.0.255) or INADDR_ANY(0.0.0.0).
		/*if (isBcast) {
			// TODO: Replace Broadcast with Multicast to be more consistent across platform
			// Replace Limited Broadcast(255.255.255.255) with Direct Broadcast(ie. 192.168.0.255) for accurate targetting when there are multiple interfaces, to avoid receiving it's own broadcasted data through IP 169.254.x.x on Windows (which is not recognized as it's own IP by the game)
			// Get Local IP Address
			sockaddr_in sockAddr{};
			getLocalIp(&sockAddr);
			// Change the last number to 255 to indicate a common broadcast address (the accurate way should be: ip | (~subnetmask))
			((u8*)&sockAddr.sin_addr.s_addr)[3] = 255;
			saddr.in.sin_addr.s_addr = sockAddr.sin_addr.s_addr;
			DEBUG_LOG(Log::sceNet, "SendMsg(BC): Address Replacement = %s", ip2str(saddr.in.sin_addr).c_str());
		}*/
#if defined(_WIN32)
		int result = WSASendMsg(inetSock->sock, &hdr, flgs | MSG_NOSIGNAL, &sent, NULL, NULL);
		if (result != SOCKET_ERROR)
			retval = sent;
#else
		retval = sendmsg(inetSock->sock, &hdr, flgs | MSG_NOSIGNAL);
#endif
	}
	free(chdr);
	free(iov);
	/*  // Example with 1 Msg buffer and without CMsg
		msghdr msg;
		iovec iov[1];
		int buflen = pspMsghdr->msg_iovlen;
		char* buf = (char*)malloc(buflen);

		memset(&msg, 0, sizeof(msg));
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		iov[0].iov_base = buf;
		iov[0].iov_len = buflen;

		retval = sendmsg(inetSock->sock, &msg, flags);
		free(buf);
	*/
	if (retval < 0)
	{
		int errorno = convertInetErrnoHost2PSP(socket_errno);
		_sce_pspnet_set_thread_errno(errorno);
		if (errorno == ERROR_INET_EAGAIN)
		{
			return hleLogDebug(Log::sceNet, retval, "EAGAIN");
		}
		else
		{
			return hleLogError(Log::sceNet, retval);
		}
	}
	return hleLogInfo(Log::sceNet, retval); // returns number of bytes sent?
}

// Similar to POSIX's recvmsg or Mswsock's WSARecvMsg? Are their packets compatible one another?
// Games using this: World of Poker
static int sceNetInetRecvmsg(int socket, u32 msghdrPtr, int flags)
{
	ERROR_LOG(Log::sceNet, "UNIMPL %s(%i, %08x, %08x) at %08x", __FUNCTION__, socket, msghdrPtr, flags, currentMIPS->pc);

	_sce_pspnet_set_thread_errno(0);
	InetSocket *inetSock;
	if (!g_socketManager.GetInetSocket(socket, &inetSock))
	{
		_sce_pspnet_set_thread_errno(ERROR_INET_EBADF);
		return hleLogError(Log::sceNet, -1, "Bad socket #%d", socket);
	}

	// Reference: http://www.masterraghu.com/subjects/np/introduction/unix_network_programming_v1.3/ch14lev1sec5.html
	int retval = -1;
	if (!Memory::IsValidAddress(msghdrPtr))
	{
		// UpdateErrnoFromHost(__KernelGetCurThread(), , __FUNCTION__);
		_sce_pspnet_set_thread_errno(ERROR_INET_EFAULT);
		return hleLogError(Log::sceNet, retval);
	}
	InetMsghdr* pspMsghdr = (InetMsghdr*)Memory::GetPointerOrException(msghdrPtr);
	int flgs = flags & ~PSP_NET_INET_MSG_DONTWAIT; // removing non-POSIX flag, which is an alternative way to use non-blocking mode
	flgs = convertMSGFlagsPSP2Host(flgs);
	SockAddrIN4 saddr{};
#if defined(_WIN32)
	WSAMSG hdr;
	WSACMSGHDR *chdr = NULL;
	size_t iovecsize = sizeof(WSABUF);
	WSABUF *iov = (WSABUF *)malloc(pspMsghdr->msg_iovlen * iovecsize);
#else
	msghdr hdr;
	cmsghdr *chdr = nullptr;
	size_t iovecsize = sizeof(iovec);
	iovec *iov = (iovec *)malloc(pspMsghdr->msg_iovlen * iovecsize);
#endif
	if (iov == NULL)
	{
		// UpdateErrnoFromHost(__KernelGetCurThread(), , __FUNCTION__);
		_sce_pspnet_set_thread_errno(ERROR_INET_ENOBUFS);
		return hleLogError(Log::sceNet, retval);
	}
	memset(iov, 0, pspMsghdr->msg_iovlen * iovecsize);
	memset(&hdr, 0, sizeof(hdr));

	// TODO: Do similar to the already working sceNetInetSendmsg but in reverse
	// if (pspMsghdr->msg_name != 0) { ... }

	// UNFINISHED
	free(iov);

	return hleLogError(Log::sceNet, retval); // returns number of bytes received?
}

// cbStatLenPtr = NULL causes null-pointer dereference; else inputs an element count, and outputs a byte-length
// cbStatPtr = NULL generates a count-only probe;
int sceNetInetGetUdpcbstat(u32 cbStatLenPtr, u32 cbStatPtr) {
    const int cap = (Memory::IsValidAddress(cbStatLenPtr)? (int)Memory::ReadUnchecked_U32(cbStatLenPtr) : 0);
	WARN_LOG(Log::sceNet, "UNTESTED %s(%08x[%i], %08x) at %08x", __FUNCTION__, cbStatLenPtr, cap, cbStatPtr, currentMIPS->pc);
	if (!Memory::IsValidAddress(cbStatLenPtr) && !Memory::IsValidAddress(cbStatPtr))
		return hleLogError(Log::sceNet, SCE_NET_INET_ERROR_INVALID_ARG, "No request provided");
	PSPPointer<PSPList<SceNetInetUdpCbStat>> stat_list;

	int count = 0;
	InetSocket *inetSock = nullptr;
	PSPPointer<PSPList<SceNetInetUdpCbStat>> lastCbStat;
	for (int i = SocketManager::MIN_VALID_INET_SOCKET; i <= SocketManager::VALID_INET_SOCKET_COUNT; i++)
	{
		if (!g_socketManager.GetInetSocket(i, &inetSock))
			continue;
		if (inetSock->type != PSP_NET_INET_SOCK_DGRAM)
			continue;
		
		// Format space as another linked-list UdpCbStat
		// Only write if the request is asking for data
        if (cbStatPtr != 0) {
			// Have we reached the limit of allowed elements?
			if ((count+1) > cap) break;
			stat_list = PSPPointer<PSPList<SceNetInetUdpCbStat>>::Create(cbStatPtr + (count * SceNetInetUdpCbStatSize));
			if (lastCbStat.ptr != 0)
				lastCbStat->next.ptr = stat_list.ptr;
            stat_list->next = 0;

			// FIXME: netintr is suppose to be allowed to modify this data? this lock prevents that.
    		std::lock_guard<std::mutex> buffers(inetSock->buffer_lock);
			u32 tx_count = 0;
			// Count all packets that haven't received an ACK (retranmissions still occuring)
			for (const auto& [seq, pkt] : inetSock->tx_buffer)
				if (!pkt.seq_ack) tx_count += pkt.len;
			stat_list->data.sndCc = tx_count;
			u32 rx_count = 0;
			// Count all data not yet received
			for (const auto& [seq, pkt] : inetSock->rx_buffer)
				rx_count += pkt.len;
			stat_list->data.rcvCc = rx_count;

			stat_list->data.local_ip = inetSock->src.host.sin_addr.s_addr;
			stat_list->data.local_port = inetSock->src.host.sin_port;
			stat_list->data.dest_ip = inetSock->dst.host.sin_addr.s_addr;	// Should naturally default to 0 for UDP/Unreliable sockets
			stat_list->data.dest_port = inetSock->dst.host.sin_port;		// Should naturally default to 0 for UDP/Unreliable sockets
        }
        count++;
		lastCbStat = stat_list; // Cache shit stat_list for next InetSock
    }
	// Only write if the request is asking for size
	if (cbStatLenPtr)
	    Memory::WriteUnchecked_U32(cbStatLenPtr, count * SceNetInetUdpCbStatSize);  // OUT: total bytes
    return hleLogDebug(Log::sceNet, 0);
}

// cbStatLenPtr = NULL causes null-pointer dereference; else inputs an element count, and outputs a byte-length
// cbStatPtr = NULL generates a count-only probe;
int sceNetInetGetTcpcbstat(u32 cbStatLenPtr, u32 cbStatPtr) {
    const int cap = (Memory::IsValidAddress(cbStatLenPtr)? (int)Memory::ReadUnchecked_U32(cbStatLenPtr) : 0);
	WARN_LOG(Log::sceNet, "UNTESTED %s(%08x[%i], %08x) at %08x", __FUNCTION__, cbStatLenPtr, cap, cbStatPtr, currentMIPS->pc);
	if (!Memory::IsValidAddress(cbStatLenPtr) && !Memory::IsValidAddress(cbStatPtr))
		return hleLogError(Log::sceNet, SCE_NET_INET_ERROR_INVALID_ARG, "No request provided");
	PSPPointer<PSPList<SceNetInetTcpCbStat>> stat_list;

	int count = 0;
	InetSocket *inetSock = nullptr;
	PSPPointer<PSPList<SceNetInetTcpCbStat>> lastCbStat;
	for (int i = SocketManager::MIN_VALID_INET_SOCKET; i <= SocketManager::VALID_INET_SOCKET_COUNT; i++)
	{
		if (!g_socketManager.GetInetSocket(i, &inetSock))
			continue;
		if (inetSock->type != PSP_NET_INET_SOCK_STREAM && inetSock->type != PSP_NET_INET_SOCK_PACKET)
			continue;
		
		// Format space as another linked-list TcpCbStat
        if (cbStatPtr != 0) {
			// Have we reached the limit of allowed elements?
			if ((count+1) > cap) break;
			stat_list = PSPPointer<PSPList<SceNetInetTcpCbStat>>::Create(cbStatPtr + (count * SceNetInetTcpCbStatSize));
			if (lastCbStat.ptr != 0)
				lastCbStat->next.ptr = stat_list.ptr;
            stat_list->next = 0;
			
			// FIXME: netintr is suppose to be allowed to modify this data? this lock prevents that.
    		std::lock_guard<std::mutex> buffers(inetSock->buffer_lock);
			u32 tx_count = 0;
			// Count all packets that haven't received an ACK (retranmissions still occuring)
			for (const auto& [seq, pkt] : inetSock->tx_buffer)
				if (!pkt.seq_ack) tx_count += pkt.len;
			stat_list->data.sndCc = tx_count;
			u32 rx_count = 0;
			// Count all data not yet received
			for (const auto& [seq, pkt] : inetSock->rx_buffer)
				rx_count += pkt.len;
			stat_list->data.rcvCc = rx_count;

			stat_list->data.local_ip = inetSock->src.host.sin_addr.s_addr;
			stat_list->data.local_port = inetSock->src.host.sin_port;
			stat_list->data.dest_ip = inetSock->dst.host.sin_addr.s_addr;	// Should naturally default to 0
			stat_list->data.dest_port = inetSock->dst.host.sin_port;		// Should naturally default to 0
			stat_list->data.tcp_state = (u16)inetSock->tcp_state;
        }
        count++;
		lastCbStat = stat_list; // Cache shit stat_list for next InetSock
    }
	if (cbStatLenPtr)
    	Memory::WriteUnchecked_U32(cbStatLenPtr, count * SceNetInetTcpCbStatSize);  // OUT: total bytes
    return hleLogDebug(Log::sceNet, 0);
}

// TODO: fix retmasks
const HLEFunction sceNetInet[] = {
	{0X17943399, &WrapI_V<sceNetInetInit>,           "sceNetInetInit",                  'i', ""       },
	{0X4CFE4E56, &WrapI_II<sceNetInetShutdown>,      "sceNetInetShutdown",              'i', "ii"     },
	{0XA9ED66B9, &WrapI_V<sceNetInetTerm>,           "sceNetInetTerm",                  'i', ""       },
	{0X8B7B220F, &WrapI_III<sceNetInetSocket>,       "sceNetInetSocket",                'i', "iii"    },
	{0X2FE71FE7, &WrapI_IIIUI<sceNetInetSetsockopt>, "sceNetInetSetsockopt",            'i', "iiixi"  },
	{0X4A114C7C, &WrapI_IIIUU<sceNetInetGetsockopt>, "sceNetInetGetsockopt",            'i', "iiixx"  },
	{0X410B34AA, &WrapI_IUI<sceNetInetConnect>,      "sceNetInetConnect",               'i', "ixi"    },
	{0X805502DD, &WrapI_I<sceNetInetCloseWithRST>,   "sceNetInetCloseWithRST",          'i', "i"      },
	{0XD10A1A7A, &WrapI_II<sceNetInetListen>,        "sceNetInetListen",                'i', "ii"     },
	{0XDB094E1B, &WrapI_IUU<sceNetInetAccept>,       "sceNetInetAccept",                'i', "ixx"    },
	{0XFAABB1DD, &WrapI_UUI<sceNetInetPoll>,         "sceNetInetPoll",                  'i', "xxi"    },
	{0X5BE8D595, &WrapI_IUUUU<sceNetInetSelect>,     "sceNetInetSelect",                'i', "ixxxx"  },
	{0X8D7284EA, &WrapI_I<sceNetInetClose>,          "sceNetInetClose",                 'i', "i"      },
	{0XCDA85C99, &WrapI_IUUU<sceNetInetRecv>,        "sceNetInetRecv",                  'i', "ixxx"   },
	{0XC91142E4, &WrapI_IUIIUU<sceNetInetRecvfrom>,  "sceNetInetRecvfrom",              'i', "ixiixx" },
	{0XEECE61D2, &WrapI_IUI<sceNetInetRecvmsg>,      "sceNetInetRecvmsg",               'i', "ixi"    },
	{0X7AA671BC, &WrapI_IUUU<sceNetInetSend>,        "sceNetInetSend",                  'i', "ixxx"   },
	{0X05038FC7, &WrapI_IUIIUI<sceNetInetSendto>,	 "sceNetInetSendto",                'i', "ixiixi" },
	{0X774E36F4, &WrapI_IUI<sceNetInetSendmsg>,      "sceNetInetSendmsg",               'i', "ixi"    },
	{0XFBABE411, &WrapI_V<sceNetInetGetErrno>,       "sceNetInetGetErrno",              'i', ""       },
	{0X1A33F9AE, &WrapI_IUI<sceNetInetBind>,         "sceNetInetBind",                  'i', "ixi"    },
	{0XB75D5B0A, &WrapU_C<sceNetInetInetAddr>,       "sceNetInetInetAddr",              'x', "s"      },
	{0X1BDF5D13, &WrapI_CU<sceNetInetInetAton>,      "sceNetInetInetAton",              'i', "sx"     },
	{0XD0792666, &WrapU_IUUU<sceNetInetInetNtop>,    "sceNetInetInetNtop",              'x', "ixxx"   },
	{0XE30B8C19, &WrapI_ICU<sceNetInetInetPton>,     "sceNetInetInetPton",              'i', "isx"    },
	{0X8CA3A97E, &WrapI_V<sceNetInetGetPspError>,    "sceNetInetGetPspError",           'i', ""       },
	{0XE247B6D6, &WrapI_IUU<sceNetInetGetpeername>,  "sceNetInetGetpeername",           'i', "ixx"    },
	{0X162E6FD5, &WrapI_IUU<sceNetInetGetsockname>,  "sceNetInetGetsockname",           'i', "ixx"    },
	{0X80A21ABD, &WrapI_I<sceNetInetSocketAbort>,    "sceNetInetSocketAbort",           'i', "i"      },
	{0X39B0C7D3, &WrapI_UU<sceNetInetGetUdpcbstat>,  "sceNetInetGetUdpcbstat",          'i', "xx"     },
	{0XB3888AD4, &WrapI_UU<sceNetInetGetTcpcbstat>,  "sceNetInetGetTcpcbstat",          'i', "xx"     },
	{0X2D5868C0, nullptr,                            "sceNetInetDelArp",                '?', ""       },
	{0XCCC18C45, nullptr,                            "sceNetInetAddArp",                '?', ""       }
};

void Register_sceNetInet()
{
	RegisterHLEModule("sceNetInet", std::size(sceNetInet), sceNetInet);
}
