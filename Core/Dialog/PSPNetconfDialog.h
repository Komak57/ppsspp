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

#include "Core/Dialog/PSPDialog.h"
#include "Core/MemMapHelpers.h"

struct SceUtilityNetconfData {
	char groupName[8];
	int timeout;
};

struct SceUtilityNetconfParam {
	pspUtilityDialogCommon common;
	int netAction;				// sets how to connect
	PSPPointer<SceUtilityNetconfData> NetconfData;
	int netHotspot;				// Flag to allow hotspot connections
	int netHotspotConnected;	// Flag to check if a hotspot connection is active
	int netWifiSpot;			// Flag to allow WIFI connections
};

// Stage machine, modeled after PSPNpSigninDialog. Each stage owns one screen (or
// one wait), INIT routes by netAction, and every exit funnels through SUCCESS /
// CANCELLED / FAIL so the finish bookkeeping lives in exactly one place each.
enum class NetconfStage {
	INIT,              // param parsed; route by netAction and WLAN switch
	NO_WLAN,           // "The Wireless switch is off" error screen (infra only)
	SELECT_CONNECTION, // reserved: interface/connection picker (currently pass-through)
	APNET_CONNECT,     // issue sceNetApctlConnect, "Connecting to the access point..."
	APNET_GETTING_IP,  // "Obtaining IP address..." until GOT_IP (and infra json ready)
	ADHOC_CONNECT,     // create/scan+join/connect adhocctl group, "Connecting..."
	SUCCESS,           // finish the dialog with the current (OK) result
	FAIL,              // timeout/internal error screen, Back -> CANCELLED
	CANCELLED,         // finish the dialog with SCE_UTILITY_DIALOG_RESULT_ABORT
};

class PSPNetconfDialog : public PSPDialog {
public:
	PSPNetconfDialog(UtilityDialogType type) : PSPDialog(type) {}

	int Init(u32 paramAddr);
	int Update(int animSpeed) override;
	int Shutdown(bool force = false) override;
	void DoState(PointerWrap &p) override;
	pspUtilityDialogCommon* GetCommonParam() override;

protected:
	bool UseAutoStatus() override {
		return false;
	}

private:
	void DrawBanner();
	void DrawIndicator();
	void Transition(NetconfStage next);
	void FinishDialog();
	void FreeScanInfos();

	// Stage handlers (one per drawing/waiting stage).
	void UpdateNoWlan();
	void UpdateSelectConnection();
	void UpdateApnetConnect(u64 now);
	void UpdateApnetGettingIP(u64 now);
	void UpdateAdhocConnect(u64 now);
	void UpdateFail();

	SceUtilityNetconfParam request{};
	u32 requestAddr = 0;
	int connResult = -1;

	u32 scanInfosAddr = 0;
	int scanStep = 0;
	u64 startTime = 0;

	NetconfStage stage = NetconfStage::INIT;
	bool stageEntered_ = false;  // one-shot work guard, armed by Transition()
	bool jsonReady_ = false;

	// Select Connection screen: row 0 = [New Connection], rows 1..N = confIds.
	int selectedRow_ = -1;   // -1 = initialize from the session's latest on entry
	int chosenConfId_ = 1;   // what APNET_CONNECT hands to sceNetApctlConnect
};
