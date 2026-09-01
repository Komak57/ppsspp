// Copyright (c) 2012- PPSSPP Project.

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

/** Event flag creation attributes */
enum PspEventFlagAttributes {
	/** Allow the event flag to be waited upon by multiple threads */
	PSP_EVENT_WAITMULTIPLE = 0x200
};

/** Event flag wait types */
enum PspEventFlagWaitTypes {
	/** Wait for all bits in the pattern to be set */
	PSP_EVENT_WAITAND = 0x00,
	/** Wait for one or more bits in the pattern to be set */
	PSP_EVENT_WAITOR = 0x01,
	/** Clear the entire pattern when it matches. */
	PSP_EVENT_WAITCLEARALL = 0x10,
	/** Clear the wait pattern when it matches */
	PSP_EVENT_WAITCLEAR = 0x20,

	PSP_EVENT_WAITANY = PSP_EVENT_WAITCLEAR | PSP_EVENT_WAITOR,
	PSP_EVENT_WAITKNOWN = PSP_EVENT_WAITCLEAR | PSP_EVENT_WAITCLEARALL | PSP_EVENT_WAITOR,
};

int sceKernelCreateEventFlag(const char *name, u32 flag_attr, u32 flag_initPattern, u32 optPtr);
u32 sceKernelClearEventFlag(SceUID id, u32 bits);
u32 sceKernelDeleteEventFlag(SceUID uid);
u32 sceKernelSetEventFlag(SceUID id, u32 bitsToSet);
int sceKernelWaitEventFlag(SceUID id, u32 bits, u32 wait, u32 outBitsPtr, u32 timeoutPtr);
int sceKernelWaitEventFlagCB(SceUID id, u32 bits, u32 wait, u32 outBitsPtr, u32 timeoutPtr);
int sceKernelPollEventFlag(SceUID id, u32 bits, u32 wait, u32 outBitsPtr);
u32 sceKernelReferEventFlagStatus(SceUID id, u32 statusPtr);
u32 sceKernelCancelEventFlag(SceUID uid, u32 pattern, u32 numWaitThreadsPtr);

void __KernelEventFlagInit();
void __KernelEventFlagDoState(PointerWrap &p);
KernelObject *__KernelEventFlagObject();
