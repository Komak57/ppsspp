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

#include <mutex>
#include <deque>
#include <map>
#include "Core/HLE/sceRtc.h"
#include "Common/Net/HTTPClient.h"
#include "Common/Net/Resolve.h"
#include "Common/Net/URL.h"
#include "Core/HLE/NpTypes.h"

#define	PARENTAL_CONTROL_DISABLED	0
#define	PARENTAL_CONTROL_ENABLED	1

#define	STATUS_ACCOUNT_SUSPENDED					0x80
#define	STATUS_ACCOUNT_CHAT_RESTRICTED				0x100
#define	STATUS_ACCOUNT_PARENTAL_CONTROL_ENABLED		0x200

#define NP_SIGNIN_STATUS_NONE		0 // SIGNEDOUT?
#define NP_SIGNIN_STATUS_SUCCESS	1
#define NP_SIGNIN_STATUS_CANCELED	2
#define NP_SIGNIN_STATUS_FAILED		3 // ERROR/ABORTED/SIGNEDOUT?

// Used by PSPNpSigninDialog.cpp
extern int npSigninState;
extern PSPTimeval npSigninTimestamp;

// Used by sceNet.cpp since we're borrowing Apctl's PSPThread to process NP events & callbacks.
// TODO: NP events should be processed on it's own PSPThread
extern std::recursive_mutex npAuthEvtMtx;

// Used by sceNp2.cpp
extern SceNpCommunicationId npTitleId;

void __NpInit();

int NpGetNpId(SceNpId* npid);
bool NpAuthProcessEvents();

int sceNpAuthGetMemoryStat(u32 memStatAddr);
int sceNpAuthCreateStartRequest(u32 paramAddr);
int sceNpAuthGetTicket(u32 requestId, u32 bufferAddr, u32 length);
int sceNpAuthGetEntitlementById(u32 ticketBufferAddr, u32 ticketLength, u32 entitlementIdAddr, u32 arg4);
int sceNpAuthAbortRequest(int requestId);
int sceNpAuthDestroyRequest(int requestId);

void Register_sceNp();
void Register_sceNpService();
void Register_sceNpAuth();
void Register_sceNpCommerce2();
