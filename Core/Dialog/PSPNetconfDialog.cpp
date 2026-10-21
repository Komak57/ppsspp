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

#include <algorithm>
#include "Common/TimeUtil.h"
#include "Common/Data/Text/I18n.h"
#include "Common/Serialize/Serializer.h"
#include "Common/Serialize/SerializeFuncs.h"
#include "Core/Config.h"
#include "Core/MemMapHelpers.h"
#include "Core/Util/PPGeDraw.h"
#include "Core/HLE/HLE.h"
#include "Core/HLE/HLEUtil.h"
#include "Core/HLE/ErrorCodes.h"
#include "Core/HLE/sceKernelMemory.h"
#include "Core/HLE/sceCtrl.h"
#include "Core/HLE/sceUtility.h"
#include "Core/HLE/sceNet.h"
#include "Core/HLE/sceNetAdhoc.h"
#include "Core/HLE/sceNetApctl.h"
#include "Core/Dialog/PSPNetconfDialog.h"
#include "Common/Data/Encoding/Utf8.h"


#define NETCONF_CONNECT_APNET 0
#define NETCONF_STATUS_APNET 1
#define NETCONF_CONNECT_ADHOC 2
#define NETCONF_CONNECT_APNET_LAST 3
#define NETCONF_CREATE_ADHOC 4
#define NETCONF_JOIN_ADHOC 5

static const float FONT_SCALE = 0.65f;

// Needs testing.
const static int NET_INIT_DELAY_US = 200000;
const static int NET_SHUTDOWN_DELAY_US = 200000;
const static int NET_CONNECT_TIMEOUT = 15000000; // Using 15 secs to match the timeout on Adhoc Server side (SERVER_USER_TIMEOUT)

struct ScanInfos {
	s32_le sz;
	SceNetAdhocctlScanInfoEmu si;
} PACK;

int PSPNetconfDialog::Init(u32 paramAddr) {
	// Already running
	if (ReadStatus() != SCE_UTILITY_STATUS_NONE)
		return SCE_ERROR_UTILITY_INVALID_STATUS;

	jsonReady_ = false;
	// Kick off a request to the infra-dns.json since we'll need it later.
	StartInfraJsonDownload();

	requestAddr = paramAddr;
	if (!ReadVariableSizedStruct(paramAddr, &request)) {
		return SCE_KERNEL_ERROR_BAD_ARGUMENT;  // untested
	}
	NOTICE_LOG(Log::sceUtility, "PSPNetconfDialog Init (netAction=%d)", request.netAction);

	ChangeStatusInit(NET_INIT_DELAY_US);

	// Eat any keys pressed before the dialog inited.
	InitCommon();
	UpdateButtons();

	connResult = -1;
	scanInfosAddr = 0;
	scanStep = 0;
	startTime = (u64)(time_now_d() * 1000000.0);
	stage = NetconfStage::INIT;
	stageEntered_ = false;
	selectedRow_ = -1;
	chosenConfId_ = 1;

	StartFade(true);
	return 0;
}

void PSPNetconfDialog::DrawBanner() {
	PPGeDrawRect(0, 0, 480, 22, CalcFadedColor(0x65636358));

	PPGeStyle textStyle = FadedStyle(PPGeAlign::BOX_VCENTER, 0.6f);
	textStyle.hasShadow = false;

	// TODO: Draw a hexagon icon
	PPGeDrawImage(10, 5, 11.0f, 10.0f, 1, 10, 1, 10, 10, 10, FadedImageStyle());
	auto di = GetI18NCategory(I18NCat::DIALOG);
	PPGeDrawText(di->T("Network Connection"), 31, 10, textStyle);
}

void PSPNetconfDialog::DrawIndicator() {
	// TODO: Draw animated circle as processing indicator
	PPGeDrawImage(456, 248, 20.0f, 20.0f, 1, 10, 1, 10, 10, 10, FadedImageStyle());
}

void PSPNetconfDialog::Transition(NetconfStage next) {
	stage = next;
	stageEntered_ = false;  // arm the next stage's one-shot work
}

void PSPNetconfDialog::FreeScanInfos() {
	if (Memory::IsValidAddress(scanInfosAddr))
		userMemory.Free(scanInfosAddr);
	scanInfosAddr = 0;
}

// Fade out and schedule the FINISHED status; the caller has already set
// request.common.result as appropriate.
void PSPNetconfDialog::FinishDialog() {
	// Checking pendingStatus to make sure ChangeStatus not to continously extending the delay ticks on every call for eternity
	if (pendingStatus != SCE_UTILITY_STATUS_FINISHED) {
		StartFade(false);
		ChangeStatus(SCE_UTILITY_STATUS_FINISHED, NET_SHUTDOWN_DELAY_US);
	}
	FreeScanInfos();
}

// "A connection error has occurred. The Wireless switch on the PSP system is
// off." - infra actions with WLAN disabled in settings.
void PSPNetconfDialog::UpdateNoWlan() {
	auto di = GetI18NCategory(I18NCat::DIALOG);
	auto err = GetI18NCategory(I18NCat::ERRORS);
	const float WRAP_WIDTH = 254.0f;

	PPGeStyle textStyle = FadedStyle(PPGeAlign::BOX_CENTER, 0.5f);
	PPGeStyle buttonStyle = FadedStyle(PPGeAlign::BOX_LEFT, 0.5f);

	PPGeDrawRect(0, 0, 480, 272, CalcFadedColor(0x63636363));
	DrawBanner();
	PPGeDrawTextWrapped(err->T("WirelessSwitchOffError", "A connection error has occurred.\nThe Wireless switch on the PSP system is off (network is disabled)."), 241, 132, WRAP_WIDTH, 0, textStyle);
	// Glyph and input follow the game's buttonSwap (set in UpdateCommon).
	PPGeDrawImage(cancelButtonImg, 255, 240, 20, 20, buttonStyle);
	PPGeDrawText(di->T("Cancel"), 285, 243, buttonStyle);

	// Let the player read the message and choose to bail out (ie. for testing networks API)
	if (IsButtonPressed(cancelButtonFlag)) {
		Transition(NetconfStage::CANCELLED);
	}
}

// The Select Connection screen, laid out to match the OFW netconf dialog:
// transparent background (the game stays visible behind it), centered heading,
// left-aligned rows at x=180 starting y=105 with 23px spacing, [New Connection]
// first, and a thin focus outline hugging the selected entry's text. The row
// list is the net config list generated from host adapters at sceNetApctlInit.
void PSPNetconfDialog::UpdateSelectConnection() {
	auto di = GetI18NCategory(I18NCat::DIALOG);
	const int confCount = NetApctlConfCount();
	const int rowCount = confCount + 1;  // row 0 = [New Connection]

	if (selectedRow_ < 0) {
		// Initial focus: the session's last-used connection, like the OFW
		// (which highlighted latest_id), else the first real config.
		const int latest = NetApctlGetLatestConf();
		selectedRow_ = (latest >= 1 && latest <= confCount) ? latest : (confCount >= 1 ? 1 : 0);
	}
	if (selectedRow_ >= rowCount)
		selectedRow_ = rowCount - 1;

	// No background rect: this screen is fully transparent on hardware. The
	// banner strip and button bar carry their own translucency.
	DrawBanner();

	// Font scales follow PSPNpSigninDialog's forms (0.5 for rows/labels).
	const float TEXT_SCALE = 0.5f;
	PPGeStyle headingStyle = FadedStyle(PPGeAlign::BOX_HCENTER, TEXT_SCALE);
	PPGeDrawText(di->T("Select connection."), 240, 62, headingStyle);

	PPGeStyle rowStyle = FadedStyle(PPGeAlign::BOX_LEFT, TEXT_SCALE);
	const float listX = 180.0f, listY = 105.0f, rowH = 23.0f;
	for (int row = 0; row < rowCount; row++) {
		const float y = listY + row * rowH;
		std::string label;
		if (row == 0) {
			label = di->T("New Connection");
			label = "[" + label + "]";
		} else {
			const NetApctlConfig *conf = NetApctlGetConf(row);  // row index == confId
			label = conf ? conf->cnf_name : "?";
		}

		if (row == selectedRow_) {
			// Focus is an opaque fill BEHIND the selected entry's text (drawn
			// first), hugging the text like the OFW selector.
			float w = 0.0f, h = 0.0f;
			PPGeMeasureText(&w, &h, label, TEXT_SCALE);
			PPGeDrawRect(listX - 6.0f, y - 3.0f, listX + w + 6.0f, y + h + 3.0f, CalcFadedColor(0xFF666666));
		}
		PPGeDrawText(label, listX, y, rowStyle);
	}

	// Default captions are "Enter"/"Back". Both the glyphs and the input flags
	// (okButtonFlag/cancelButtonFlag, set in UpdateCommon) follow the GAME's
	// requested buttonSwap - a JP title like PSP2i gets circle=Enter - so input
	// must use those flags, never GetConfirmButton()/GetCancelButton() (those
	// read the emulator's Button Preference and can contradict the labels).
	DisplayButtons(DS_BUTTON_OK | DS_BUTTON_CANCEL);

	// "(triangle) Options" in the lower right, like the OFW (edit/delete there).
	// Not wired to anything yet - our configs are generated, nothing to edit.
	{
		PPGeStyle buttonStyle = FadedStyle(PPGeAlign::BOX_LEFT, FONT_SCALE);
		PPGeDrawImage(ImageID("I_TRIANGLE"), 402, 256, 11.5f, 11.5f, buttonStyle);
		PPGeDrawText(di->T("Options"), 416.5f, 252, buttonStyle);
	}

	if (IsButtonPressed(CTRL_UP)) {
		if (selectedRow_ > 0)
			selectedRow_--;
	} else if (IsButtonPressed(CTRL_DOWN)) {
		if (selectedRow_ < rowCount - 1)
			selectedRow_++;
	} else if (IsButtonPressed(okButtonFlag)) {
		if (selectedRow_ == 0) {
			// [New Connection]: on OFW this opens the connection wizard. Our
			// configs come from the host, so the closest analog is a rescan for
			// newly available adapters.
			NetApctlGenerateConfigs();
		} else {
			chosenConfId_ = selectedRow_;
			NetApctlSetLatestConf(chosenConfId_);
			StartFade(true);
			Transition(NetconfStage::APNET_CONNECT);
		}
	} else if (IsButtonPressed(cancelButtonFlag)) {
		Transition(NetconfStage::CANCELLED);
	}
}

// DISCONNECTED -> fire sceNetApctlConnect once, then wait for the apctl state
// machine to start moving. "Connecting to the access point. Please wait..."
void PSPNetconfDialog::UpdateApnetConnect(u64 now) {
	auto di = GetI18NCategory(I18NCat::DIALOG);
	int state = NetApctl_GetState();

	PPGeDrawRect(0, 0, 480, 272, CalcFadedColor(0xC0C8B2AC));
	DrawBanner();
	DrawIndicator();
	DisplayMessage2(di->T("ConnectingAP", "Connecting to the access point.\nPlease wait..."), di->T("ConnectionName", "Connection Name"), netApctlInfo.name, di->T("SSID"), netApctlInfo.ssid);
	DisplayButtons(DS_BUTTON_CANCEL, di->T("Cancel"));

	if (state == PSP_NET_APCTL_STATE_DISCONNECTED && connResult < 0) {
		// Connect with the config chosen on the Select Connection screen (or
		// the session's latest for NETCONF_CONNECT_APNET_LAST).
		connResult = hleCall(sceNetApctl, int, sceNetApctlConnect, chosenConfId_);
	}

	if (state == PSP_NET_APCTL_STATE_JOINING) {
		// Switch to the next message
		StartFade(true);
	} else if (state == PSP_NET_APCTL_STATE_GETTING_IP || state == PSP_NET_APCTL_STATE_GOT_IP) {
		Transition(NetconfStage::APNET_GETTING_IP);
	}
}

// "Obtaining IP address. Please wait..." - the dialog stays visible until the
// network reaches PSP_NET_APCTL_STATE_GOT_IP *AND* we have the infra json.
void PSPNetconfDialog::UpdateApnetGettingIP(u64 now) {
	auto di = GetI18NCategory(I18NCat::DIALOG);
	int state = NetApctl_GetState();

	PPGeDrawRect(0, 0, 480, 272, CalcFadedColor(0xC0C8B2AC));
	DrawBanner();
	DrawIndicator();
	DisplayMessage2(di->T("ObtainingIP", "Obtaining IP address.\nPlease wait..."), di->T("ConnectionName", "Connection Name"), netApctlInfo.name, di->T("SSID"), netApctlInfo.ssid);
	DisplayButtons(DS_BUTTON_CANCEL, di->T("Cancel"));

	if (state == PSP_NET_APCTL_STATE_GOT_IP && jsonReady_) {
		Transition(NetconfStage::SUCCESS);
	}
}

// Adhocctl group create/scan+join/connect flow. "Connecting. Please wait..."
void PSPNetconfDialog::UpdateAdhocConnect(u64 now) {
	auto di = GetI18NCategory(I18NCat::DIALOG);
	int state = NetAdhocctl_GetState();

	if (state == ADHOCCTL_STATE_DISCONNECTED && now - startTime > NET_CONNECT_TIMEOUT) {
		Transition(NetconfStage::FAIL);
		return;
	}

	PPGeDrawRect(0, 0, 480, 272, CalcFadedColor(0xC0C8B2AC));
	DrawBanner();
	DrawIndicator();

	std::string channel = std::to_string(g_Config.iWlanAdhocChannel);
	if (g_Config.iWlanAdhocChannel == PSP_SYSTEMPARAM_ADHOC_CHANNEL_AUTOMATIC)
		channel = "Automatic";

	DisplayMessage2(di->T("ConnectingPleaseWait", "Connecting.\nPlease wait..."), std::string(di->T("Channel:")) + std::string(" ") + std::string(di->T(channel)));

	// Only Join mode is showing Cancel button on KHBBS and the button will fade out before the dialog is fading out, probably because it's already connected thus can't be canceled anymore
	if (request.netAction == NETCONF_JOIN_ADHOC)
		DisplayButtons(DS_BUTTON_CANCEL, di->T("Cancel"));

	// KHBBS will first enter the arena using NETCONF_CONNECT_ADHOC (auto-create group when not exist yet?), but when the event started the event's creator use NETCONF_CREATE_ADHOC while the joining players use NETCONF_JOIN_ADHOC
	if (request.NetconfData.IsValid() && state == ADHOCCTL_STATE_DISCONNECTED) {
		switch (request.netAction)
		{
		case NETCONF_CREATE_ADHOC:
			if (connResult < 0) {
				connResult = hleCall(sceNetAdhocctl, int, sceNetAdhocctlCreate, request.NetconfData->groupName);
			}
			break;
		case NETCONF_JOIN_ADHOC:
			// FIXME: Should we Scan for a matching group first before Joining a Group (like adhoc games normally do)? Or Is it really allowed to join non-existing group?
			if (scanStep == 0) {
				if (hleCall(sceNetAdhocctl, int, sceNetAdhocctlScan) >= 0) {
					u32 structsz = sizeof(ScanInfos);
					FreeScanInfos();
					scanInfosAddr = userMemory.Alloc(structsz, false, "NetconfScanInfo");
					// TODO: What if scanInfosAddr is not valid?
					Memory::WriteOrException_U32(sizeof(SceNetAdhocctlScanInfoEmu), scanInfosAddr);
					scanStep = 1;
				}
			}
			else if (scanStep == 1) {
				s32 sz = Memory::ReadOrException_U32(scanInfosAddr);
				// Get required buffer size
				if (hleCall(sceNetAdhocctl, int, sceNetAdhocctlGetScanInfo, scanInfosAddr, 0) >= 0) {
					s32 reqsz = Memory::ReadOrException_U32(scanInfosAddr);
					if (reqsz > sz) {
						sz = reqsz;
						userMemory.Free(scanInfosAddr);
						u32 structsz = sz + sizeof(s32);
						scanInfosAddr = userMemory.Alloc(structsz, false, "NetconfScanInfo");
						// TODO: What if scanInfosAddr is not valid?
						Memory::WriteOrException_U32(sz, scanInfosAddr);
					}
					if (reqsz > 0) {
						if (hleCall(sceNetAdhocctl, int, sceNetAdhocctlGetScanInfo, scanInfosAddr, scanInfosAddr + (u32)sizeof(s32)) >= 0) {
							ScanInfos* scanInfos = (ScanInfos*)Memory::GetPointerOrException(scanInfosAddr);
							int n = scanInfos->sz / sizeof(SceNetAdhocctlScanInfoEmu);
							// Assuming returned SceNetAdhocctlScanInfoEmu(s) are contiguous where next is pointing to current addr + sizeof(SceNetAdhocctlScanInfoEmu)
							while (n > 0) {
								SceNetAdhocctlScanInfoEmu* si = (SceNetAdhocctlScanInfoEmu*)Memory::GetPointerOrException(scanInfosAddr + sizeof(s32) + sizeof(SceNetAdhocctlScanInfoEmu) * (n - 1LL));
								if (memcmp(si->group_name.data, request.NetconfData->groupName, ADHOCCTL_GROUPNAME_LEN) == 0) {
									// Moving found group info to the front so we can use it on sceNetAdhocctlJoin easily
									memcpy((char*)scanInfos + sizeof(s32), si, sizeof(SceNetAdhocctlScanInfoEmu));
									scanStep = 2;
									break;
								}
								n--;
							}
							// Target group not found, try to scan again later
							if (n <= 0) {
								scanStep = 0;
							}
						}
					}
					// No group found, try to scan again later
					else {
						scanStep = 0;
					}
				}
			}
			else if (scanStep == 2) {
				if (connResult < 0) {
					connResult = hleCall(sceNetAdhocctl, int, sceNetAdhocctlJoin, scanInfosAddr + (u32)sizeof(s32));
					if (connResult >= 0) {
						// We are done!
						FreeScanInfos();
					}
				}
			}
			break;
		default:
			if (connResult < 0) {
				connResult = hleCall(sceNetAdhocctl, int, sceNetAdhocctlConnect, request.NetconfData->groupName);
			}
			break;
		}
	}

	// The Netconf dialog stays visible until the network reaches the state ADHOCCTL_STATE_CONNECTED.
	if (state == ADHOCCTL_STATE_CONNECTED) {
		Transition(NetconfStage::SUCCESS);
		return;
	}

	if (request.netAction == NETCONF_JOIN_ADHOC && IsButtonPressed(cancelButtonFlag)) {
		Transition(NetconfStage::CANCELLED);
	}
}

// Adhoc connect timed out. "An internal error has occurred." + Back.
void PSPNetconfDialog::UpdateFail() {
	auto di = GetI18NCategory(I18NCat::DIALOG);

	// A connection that lands late still completes the dialog (the original code
	// kept checking for ADHOCCTL_STATE_CONNECTED even on the timeout screen).
	if (NetAdhocctl_GetState() == ADHOCCTL_STATE_CONNECTED) {
		Transition(NetconfStage::SUCCESS);
		return;
	}

	PPGeDrawRect(0, 0, 480, 272, CalcFadedColor(0xC0C8B2AC));
	DrawBanner();
	DrawIndicator();

	// FIXME: Do we need to show error message?
	std::string message(di->T("InternalError", "An internal error has occurred."));
	DisplayMessage2(message + StringFromFormat("\n(%08X)", connResult));
	DisplayButtons(DS_BUTTON_CANCEL, di->T("Back"));

	if (IsButtonPressed(cancelButtonFlag)) {
		Transition(NetconfStage::CANCELLED);
	}
}

int PSPNetconfDialog::Update(int animSpeed) {
	if (ReadStatus() != SCE_UTILITY_STATUS_RUNNING) {
		return SCE_ERROR_UTILITY_INVALID_STATUS;
	}

	UpdateButtons();
	UpdateCommon();
	u64 now = (u64)(time_now_d() * 1000000.0);

	// The infra json download runs alongside whatever stage is active.
	std::string json;
	if (!jsonReady_ && PollInfraJsonDownload(&json)) {
		if (!json.empty()) {
			if (!LoadAutoDNS(json)) {
				// If the JSON parse fails, throw away the cache file at least.
				ERROR_LOG(Log::sceNet, "Failed to parse bad json. Deleting cache file.");
				DeleteAutoDNSCacheFile();
			} else {
				DEBUG_LOG(Log::sceNet, "Got and processed the AutoDNS json.");
			}
		} else {
			// TODO: Show a notice?
			WARN_LOG(Log::sceNet, "Failed to get json file. Autoconfig will not work.");
		}
		jsonReady_ = true;
	}

	UpdateFade(animSpeed);
	StartDraw();

	switch (stage) {
	case NetconfStage::INIT:
		// Route by requested action. It seems JPCSP doesn't check for NETCONF_STATUS_APNET.
		switch (request.netAction) {
		case NETCONF_CONNECT_APNET:
		case NETCONF_STATUS_APNET:
		case NETCONF_CONNECT_APNET_LAST:
			if (!g_Config.bEnableWlan) {
				Transition(NetconfStage::NO_WLAN);
			} else if (request.netAction == NETCONF_CONNECT_APNET_LAST && NetApctlGetLatestConf() > 0) {
				// "Connect to the last-used config": silent once something has
				// actually been picked this session; until then there is no
				// meaningful "last", so the picker shows.
				chosenConfId_ = NetApctlGetLatestConf();
				Transition(NetconfStage::APNET_CONNECT);
			} else {
				Transition(NetconfStage::SELECT_CONNECTION);
			}
			break;
		case NETCONF_CONNECT_ADHOC:
		case NETCONF_CREATE_ADHOC:
		case NETCONF_JOIN_ADHOC:
			Transition(NetconfStage::ADHOC_CONNECT);
			break;
		default:
			WARN_LOG(Log::sceUtility, "PSPNetconfDialog: unknown netAction %d", request.netAction);
			Transition(NetconfStage::CANCELLED);
			break;
		}
		break;

	case NetconfStage::NO_WLAN:
		UpdateNoWlan();
		break;

	case NetconfStage::SELECT_CONNECTION:
		UpdateSelectConnection();
		break;

	case NetconfStage::APNET_CONNECT:
		UpdateApnetConnect(now);
		break;

	case NetconfStage::APNET_GETTING_IP:
		UpdateApnetGettingIP(now);
		break;

	case NetconfStage::ADHOC_CONNECT:
		UpdateAdhocConnect(now);
		break;

	case NetconfStage::FAIL:
		UpdateFail();
		break;

	case NetconfStage::SUCCESS:
		FinishDialog();
		break;

	case NetconfStage::CANCELLED:
		// TODO: When the dialog is aborted, does it really set the result to this?
		// It seems to make Phantasy Star Portable 2 happy, so it should be okay for now.
		request.common.result = SCE_UTILITY_DIALOG_RESULT_ABORT;
		FinishDialog();
		break;
	}

	EndDraw();

	if (ReadStatus() == SCE_UTILITY_STATUS_FINISHED || pendingStatus == SCE_UTILITY_STATUS_FINISHED)
		Memory::Memcpy(requestAddr, &request, request.common.size, "NetConfDialogParam");

	return 0;
}

int PSPNetconfDialog::Shutdown(bool force) {
	if (ReadStatus() != SCE_UTILITY_STATUS_FINISHED && !force)
		return SCE_ERROR_UTILITY_INVALID_STATUS;

	PSPDialog::Shutdown(force);
	if (!force) {
		ChangeStatusShutdown(NET_SHUTDOWN_DELAY_US);
	}

	return 0;
}

void PSPNetconfDialog::DoState(PointerWrap &p) {
	PSPDialog::DoState(p);

	auto s = p.Section("PSPNetconfigDialog", 0, 4);
	if (!s)
		return;

	Do(p, request);
	if (s >= 2) {
		Do(p, scanInfosAddr);
		Do(p, scanStep);
		Do(p, connResult);
	}
	else {
		scanInfosAddr = 0;
		scanStep = 0;
		connResult = -1;
	}
	if (s >= 3) {
		Do(p, stage);
	} else {
		// Old save: INIT re-routes by netAction, and the connect stages only act
		// on the live apctl/adhocctl state, so recovery is natural.
		stage = NetconfStage::INIT;
	}
	if (s >= 4) {
		Do(p, selectedRow_);
		Do(p, chosenConfId_);
	} else {
		selectedRow_ = -1;
		chosenConfId_ = 1;
	}

	if (p.mode == p.MODE_READ) {
		startTime = 0;
	}
}

pspUtilityDialogCommon* PSPNetconfDialog::GetCommonParam()
{
	return &request.common;
}
