#pragma once

#include "ppsspp_config.h"

#include "Core/HLE/HLE.h"

#include "Common/Net/SocketCompat.h"

#include <memory>
#include "Core/HLE/NetInetTypes.h"

// Using constants instead of numbers for readability reason, since PSP_THREAD_ATTR_KERNEL/USER is located in sceKernelThread.cpp instead of sceKernelThread.h
#ifndef PSP_THREAD_ATTR_KERNEL
#define PSP_THREAD_ATTR_KERNEL 0x00001000
#endif
#ifndef PSP_THREAD_ATTR_USER
#define PSP_THREAD_ATTR_USER 0x80000000
#endif

class PointerWrap;

extern bool g_netInited;
extern bool netInetInited;
extern bool g_netApctlInited;
extern u32 netApctlState;
extern SceNetApctlInfoInternal netApctlInfo;
extern const char *const defaultNetConfigName;
extern const char *const defaultNetSSID;

void Register_sceNetInet();

void __NetInetShutdown();

int NetApctl_GetState();

int sceNetApctlConnect(int connIndex);
int sceNetInetPoll(u32 fdsPtr, u32 nfds, int timeout);
int sceNetApctlDisconnect();
