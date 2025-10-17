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

#include <cstdint>

#include "Common/CommonTypes.h"
#include "Common/Swap.h"

class PointerWrap;

struct PSPTimeval {
	s32_le tv_sec;
	s32_le tv_usec;
};

#define TICKS_PER_SECOND 1000000ULL
#define TICKS_PER_MILLI 1000ULL
#define TICKS_PER_MICRO 1ULL

#ifdef HAVE_LIBNX
// I guess that works...
#define setenv(x, y, z) (void*)0
#define tzset() (void*)0
#define unsetenv(x) (void*)0
#endif // HAVE_LIBNX

// This is a base time that everything is relative to.
// This way, time doesn't move strangely with savestates, turbo speed, etc.
static PSPTimeval rtcBaseTime;
static u64 rtcBaseTicks;

// Grabbed from JPSCP
// This is the # of microseconds between January 1, 0001 and January 1, 1970.
const u64 rtcMagicOffset = 62135596800000000ULL;
// This is the # of microseconds between January 1, 0001 and January 1, 1601 (for Win32 FILETIME.)
const u64 rtcFiletimeOffset = 50491123200000000ULL;

// 400 years is a convenient number, since leap days and everything cycle every 400 years.
// 400 years is in other words 20871 full weeks.
const u64 rtc400YearTicks = (u64)20871 * 7 * 24 * 3600 * 1000000ULL;

// This is the last moment the clock was adjusted.
// It's possible games may not like the clock being adjusted in the past hour (cheating?)
// So this returns a static time.
const u64 rtcLastAdjustedTicks = rtcMagicOffset + 41 * 365 * 24 * 3600 * 1000000ULL;
// The reincarnated time seems related to the battery or manufacturing date.
// On a test PSP, it was over 3 years in the past, so we again pick a fixed date.
const u64 rtcLastReincarnatedTicks = rtcMagicOffset + 40 * 365 * 24 * 3600 * 1000000ULL;

const int PSP_TIME_INVALID_YEAR = -1;
const int PSP_TIME_INVALID_MONTH = -2;
const int PSP_TIME_INVALID_DAY = -3;
const int PSP_TIME_INVALID_HOUR = -4;
const int PSP_TIME_INVALID_MINUTES = -5;
const int PSP_TIME_INVALID_SECONDS = -6;
const int PSP_TIME_INVALID_MICROSECONDS = -7;

// One Second Drift
#define CLOCK_DRIFT_LIMIT_USECS 1000000ULL

void __RtcTimeOfDay(PSPTimeval *tv);
int32_t RtcBaseTime(int32_t *micro = nullptr);
void RtcSetBaseTime(int32_t seconds, int32_t micro = 0);
u64 __RtcGetCurrentTick();

void Register_sceRtc();
void __RtcInit();
void __RtcDoState(PointerWrap &p);

struct ScePspDateTime {
	s16_le year;
	s16_le month;
	s16_le day;
	s16_le hour;
	s16_le minute;
	s16_le second;
	u32_le microsecond;
};
