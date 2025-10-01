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
#include "Core/MemMapHelpers.h"
#include "Core/Util/PPGeDraw.h"
#include "Core/HLE/sceKernelMemory.h"
#include "Core/HLE/sceCtrl.h"
#include "Core/HLE/sceUtility.h"
#include "Core/HLE/sceNp.h"
#include "Core/HLE/ErrorCodes.h"
#include "Core/Dialog/PSPNpSigninDialog.h"
#include "Common/Data/Encoding/Utf8.h"
#include "Core/Reporting.h"
#include <Core/Config.h>
#include <System/Request.h>
#include "Common/StringUtils.h"

// Needs testing.
const static int NP_INIT_DELAY_US = 200000; 
const static int NP_SHUTDOWN_DELAY_US = 501000; 
const static int NP_RUNNING_DELAY_US = 1000000; // faked delay to simulate signin process to give chance for players to read the text on the dialog
const static int NP_TRANSITION_SPEED = 500;

std::map<u8, u8> selected;
std::string npid = "";
std::string email = "";
bool validEmail = false;
std::string online_name = "";
std::string avatar_url = "";
std::string password = "";
std::string password_confirm = "";
std::string token = "";

std::string failMessage = "";
double deltaTime = 0;
bool runOnce = false;

void PSPNpSigninDialog::InitForms() {
	npid = "";
	email = "";
	bool validEmail = false;
	online_name = "";
	avatar_url = "";
	password = "";
	password_confirm = "";
	token = "";

	selected[(u8)SigninStage::LOGIN_FORM] = (u8)SigninSelected::SIGNIN;
	selected[(u8)SigninStage::PASSWORD_FORM] = (u8)PasswordSelected::LOGIN;
	selected[(u8)SigninStage::PASSWORD_TOKEN_FORM] = (u8)PasswordTokenSelected::TOKEN;
	selected[(u8)SigninStage::REGISTRATION_FORM] = (u8)RegisterSelected::LOGIN;
	selected[(u8)SigninStage::REGISTRATION_INFO_FORM] = (u8)RegisterInfoSelected::ONLINE_NAME;
}

int PSPNpSigninDialog::Init(u32 paramAddr) {
	// Already running
	if (ReadStatus() != SCE_UTILITY_STATUS_NONE)
		return SCE_ERROR_UTILITY_INVALID_STATUS;

	requestAddr = paramAddr;
	int size = Memory::Read_U32(paramAddr);
	memset(&request, 0, sizeof(request));
	// Only copy the right size to support different request format
	Memory::Memcpy(&request, paramAddr, size);
	
	WARN_LOG_REPORT_ONCE(PSPNpSigninDialogInit, Log::sceNet, "NpSignin Init Params: %08x, %08x, %08x, %08x", request.npSigninStatus, request.unknown1, request.unknown2, request.unknown3);

	ChangeStatusInit(NP_INIT_DELAY_US);

	// Eat any keys pressed before the dialog inited.
	UpdateButtons();
	InitCommon();

	//npSigninResult = -1;
	startTime = (u64)(time_now_d() * 1000000.0);
	lastTime = startTime;
	deltaTime = (startTime / 1000000.0f);
	stage = SigninStage::INIT;
	transitionStage = SigninStage::INIT;
	// Initialize default selection pointers
	InitForms();
	server = net::CreateNPAuthAgent(net::NPAgentType::RPCN, "rpcn.revurb.us", 31313);
	StartFade(true);
	return 0;
}

void PSPNpSigninDialog::DrawBanner() {
	PPGeDrawRect(0, 0, 480, 22, CalcFadedColor(0x65636358));

	PPGeStyle textStyle = FadedStyle(PPGeAlign::BOX_VCENTER, 0.6f);
	textStyle.hasShadow = false;

	// TODO: Draw a hexagon icon
	PPGeDrawImage(10, 5, 11.0f, 10.0f, 1, 10, 1, 10, 10, 10, FadedImageStyle());
	auto di = GetI18NCategory(I18NCat::DIALOG);
	PPGeDrawText(di->T("Sign In"), 31, 10, textStyle);
}

void PSPNpSigninDialog::DrawIndicator() {
	// TODO: Draw animated circle as processing indicator
	PPGeDrawImage(456, 248, 20.0f, 20.0f, 1, 10, 1, 10, 10, 10, FadedImageStyle());
}

void PSPNpSigninDialog::DrawLogo() {
	// TODO: Draw OpenDNAS logo
	PPGeDrawImage(416, 22, 64.0f, 64.0f, 1, 10, 1, 10, 64, 64, FadedImageStyle());
}

void PSPNpSigninDialog::DrawFormBG() {
	// TODO: Draw PSP wave background?
	PPGeDrawRect(0, 0, 480, 272, CalcFadedColor(0xFF3D282C));
}
void PSPNpSigninDialog::Transition(SigninStage next, bool forced) {
	lastTime = (u64)(time_now_d() * 1000000.0);
	transitioning = true;	// Continues animating out and in for transition
	transitionStage = next; // Will move here half way through the transition
	fadeTimer = 0;
	runOnce = true; // Used for tasks that need to execute in the new stage
	// Skip animation
	if (forced) {
		transitioning = false;
		stage = next;
	}
	// Safety Disconnect
	if (next == SigninStage::FAIL || next == SigninStage::SHUTDOWN || next == SigninStage::CANCELLED)
		server->Disconnect();
}

int PSPNpSigninDialog::Update(int animSpeed) {
	if (ReadStatus() != SCE_UTILITY_STATUS_RUNNING) {
		return SCE_ERROR_UTILITY_INVALID_STATUS;
	}
	UpdateButtons();
	UpdateCommon();

	auto err = GetI18NCategory(I18NCat::ERRORS);

	if (request.npSigninStatus == NP_SIGNIN_STATUS_NONE) {

		u64 now = (u64)(time_now_d() * 1000000.0);
		deltaTime = (time_now_d() - deltaTime);
		auto di = GetI18NCategory(I18NCat::DIALOG);
		UpdateFade(animSpeed);
		StartDraw();

		// Transition between scenes
		if (transitioning) {
			if (stage != transitionStage) {
				// Fade Out
				fadeTimer += deltaTime * animSpeed; // Probably need a more real value of delta time
				if (fadeTimer < NP_TRANSITION_SPEED / 2) {
					fadeValue = 255 - (u32)(fadeTimer / (NP_TRANSITION_SPEED / 2) * 255);
				}
				else {
					fadeValue = 0;
					fadeTimer = 0;
					// Transition to new stage
					stage = transitionStage;
				}
			}
			else {
				// Fade In
				fadeTimer += deltaTime * animSpeed; // Probably need a more real value of delta time
				if (fadeTimer < NP_TRANSITION_SPEED / 2) {
					fadeValue = (u32)(fadeTimer / (NP_TRANSITION_SPEED / 2) * 255);
				}
				else {
					fadeValue = 255;
					transitioning = false;
				}
			}
		}

		switch (stage) {
		case SigninStage::INIT:
			// Check Flags for AutoLogin
			if (g_Config.infraNpId.empty() || g_Config.infraPassword.empty() || g_Config.infraToken.empty() || !g_Config.infraAutoSignIn)
				Transition(SigninStage::LOGIN_FORM, true);
			else
				Transition(SigninStage::AUTO_LOGIN, true);
			break;
		case SigninStage::AUTO_LOGIN:
			Transition(SigninStage::CONNECT_REQUEST, true);
			break;
		case SigninStage::LOGIN_FORM:
			UpdateSigninForm(animSpeed);
			break;
		case SigninStage::PASSWORD_FORM:
			UpdatePasswordRecoveryForm(animSpeed);
			break;
		case SigninStage::PASSWORD_TOKEN_REQUEST:
			PPGeDrawRect(0, 0, 480, 272, CalcFadedColor(0xC0C8B2AC));
			DrawBanner();
			DrawIndicator();
			DisplayMessage2(di->T("SigninPleaseWait", "Requesting Verification."));
			DisplayButtons(DS_BUTTON_CANCEL, di->T("Cancel"));
			if (IsButtonPressed(cancelButtonFlag)) {
				Transition(SigninStage::CANCELLED);
				break;
			}
			if (now - lastTime > NP_RUNNING_DELAY_US) {
				if (runOnce) {
					runOnce = false;
					if (!server->Resolve()) {
						failMessage = "Unable to find server. Retry?";
						Transition(SigninStage::FAIL);
						break;
					}
					if (!server->Connect()) {
						failMessage = "Connection Failed. Retry?";
						Transition(SigninStage::FAIL);
						break;
					}
					int ret = server->SendResetToken(npid.c_str(), email.c_str());
					if (ret != 0) {
						switch ((ErrorType)ret) {
						case ErrorType::Blocked:
							failMessage = "Server Disconnected before request.";
							break;
						case ErrorType::Invalid:
							failMessage = "The server has no email verification and doesn't support password changes!";
							break;
						case ErrorType::DbFail:
							failMessage = "A database related error happened on the server!";
							break;
						case ErrorType::TooSoon:
							failMessage = "You can only ask for a token mail once every 24 hours!";
							break;
						case ErrorType::EmailFail:
							failMessage = "The mail couldn't be sent successfully!";
							break;
						case ErrorType::LoginError:
							failMessage = "The username/email pair is invalid!";
							break;
						default:
							failMessage = "Unknown error sending the token. (" + std::to_string(ret) + ")";
							break;
						}
						// This specific error does not constitute a failure
						if (ret != (u8)ErrorType::TooSoon) {
							Transition(SigninStage::FAIL);
							break;
						}
					}
				}
			}
			if (now - lastTime > NP_RUNNING_DELAY_US * 2 && !transitioning) {
				Transition(SigninStage::PASSWORD_TOKEN_FORM);
			}
			break;
		case SigninStage::PASSWORD_TOKEN_FORM:
			UpdatePasswordRecoveryTokenForm(animSpeed);
			break;
		case SigninStage::PASSWORD_REQUEST:
			PPGeDrawRect(0, 0, 480, 272, CalcFadedColor(0xC0C8B2AC));
			DrawBanner();
			DrawIndicator();
			DisplayMessage2(di->T("SigninPleaseWait", "Requesting Password Reset."));
			DisplayButtons(DS_BUTTON_CANCEL, di->T("Cancel"));
			if (IsButtonPressed(cancelButtonFlag)) {
				Transition(SigninStage::CANCELLED);
				break;
			}
			if (now - lastTime > NP_RUNNING_DELAY_US) {
				if (runOnce) {
					runOnce = false;
					if (!server->Resolve()) {
						failMessage = "Unable to find server. Retry?";
						Transition(SigninStage::FAIL);
						break;
					}
					if (!server->Connect()) {
						failMessage = "Connection Failed. Retry?";
						Transition(SigninStage::FAIL);
						break;
					}
					int ret = server->ResetPassword(npid.c_str(), token.c_str(), password.c_str());
					if (ret != 0) {
						switch ((ErrorType)ret) {
						case ErrorType::Invalid:
							failMessage = "The server has no email verification and doesn't support password changes!";
							break;
						case ErrorType::DbFail:
							failMessage = "A database related error happened on the server!";
							break;
						case ErrorType::TooSoon:
							failMessage = "You can only reset your password once every 24 hours!";
							break;
						case ErrorType::EmailFail:
							failMessage = "The mail couldn't be sent!";
							break;
						case ErrorType::LoginError:
							failMessage = "The username/password pair is invalid!";
							break;
						default:
							failMessage = "Failed to reset the password. (" + std::to_string(ret) + ")";
							break;
						}
						Transition(SigninStage::FAIL);
						break;
					}
				}
			}
			if (now - lastTime > NP_RUNNING_DELAY_US * 2 && !transitioning) {
				Transition(SigninStage::LOGIN_FORM);
			}
			break;
		case SigninStage::REGISTRATION_FORM:
			UpdateRegistrationForm(animSpeed);
			break;
		case SigninStage::REGISTRATION_INFO_FORM:
			UpdateRegistrationInfoForm(animSpeed);
			break;
		case SigninStage::REGISTRATION_REQUEST:
			PPGeDrawRect(0, 0, 480, 272, CalcFadedColor(0xC0C8B2AC));
			DrawBanner();
			DrawIndicator();
			DisplayMessage2(di->T("SigninPleaseWait", "Registerring your new account..."));
			DisplayButtons(DS_BUTTON_CANCEL, di->T("Cancel"));
			if (IsButtonPressed(cancelButtonFlag)) {
				Transition(SigninStage::CANCELLED);
				break;
			}
			if (now - lastTime > NP_RUNNING_DELAY_US) {
				if (runOnce) {
					runOnce = false;
					if (!server->Resolve()) {
						failMessage = "Unable to find server. Retry?";
						Transition(SigninStage::FAIL);
						break;
					}
					if (!server->Connect()) {
						failMessage = "Connection Failed. Retry?";
						Transition(SigninStage::FAIL);
						break;
					}
					int ret = server->CreateAccount(npid.c_str(), password.c_str(), online_name.c_str(), avatar_url.c_str(), email.c_str());
					if (ret != 0) {
						switch ((ErrorType)ret) {
						case ErrorType::CreationExistingUsername:
							failMessage = "An account with that username already exists!";
							break;
						case ErrorType::CreationBannedEmailProvider:
							failMessage = "This email provider is unsupported!";
							break;
						case ErrorType::CreationExistingEmail:
							failMessage = "An account with that email already exists!";
							break;
						case ErrorType::CreationError:
							failMessage = "Could not Create Account.";
							break;
						default:
							failMessage = "Could not Create Account. (" + std::to_string(ret) + ")";
							break;
						}
						Transition(SigninStage::FAIL);
						break;
					}
				}
			}
			if (now - lastTime > NP_RUNNING_DELAY_US * 2 && !transitioning) {
				Transition(SigninStage::LOGIN_FORM);
			}
			break;
		case SigninStage::CONNECT_REQUEST:
			PPGeDrawRect(0, 0, 480, 272, CalcFadedColor(0xC0C8B2AC));
			DrawBanner();
			DrawIndicator();
			DisplayMessage2(di->T("SigninPleaseWait", "You are currently signing in.\nPlease wait for a moment."));
			DisplayButtons(DS_BUTTON_CANCEL, di->T("Cancel"));
			if (IsButtonPressed(cancelButtonFlag)) {
				Transition(SigninStage::CANCELLED);
				break;
			}
			if (now - lastTime > NP_RUNNING_DELAY_US) {
				if (runOnce) {
					if (!server->Resolve()) {
						failMessage = "Unable to find server. Retry?";
						Transition(SigninStage::FAIL);
						break;
					}
					if (!server->Connect()) {
						failMessage = "Connection Failed. Retry?";
						Transition(SigninStage::FAIL);
						break;
					}
					runOnce = false;
				}
			}
			if (now - lastTime > NP_RUNNING_DELAY_US * 2 && !transitioning) {
				Transition(SigninStage::AUTH_REQUEST);
			}
			break;
		case SigninStage::AUTH_REQUEST:
			PPGeDrawRect(0, 0, 480, 272, CalcFadedColor(0xC0C8B2AC));
			DrawBanner();
			DrawIndicator();
			DrawLogo();
			DisplayMessage2(di->T("SigninPleaseWait", "Please wait for a moment."));
			DisplayButtons(DS_BUTTON_CANCEL, di->T("Cancel"));
			if (IsButtonPressed(cancelButtonFlag)) {
				Transition(SigninStage::CANCELLED);
				break;
			}
			if (now - lastTime > NP_RUNNING_DELAY_US) {
				if (runOnce) {
					runOnce = false;
					std::string* creds = NpGetLogin();
					if (server->Login(creds[0].c_str(), creds[2].c_str(), creds[1].c_str()) != 0) {
						g_Config.infraToken = ""; // Reset the Token to force re-entry
						failMessage = "Authentication Failed. Retry?";
						Transition(SigninStage::FAIL);
						break;
					}
				}
			}
			if (now - lastTime > NP_RUNNING_DELAY_US * 2 && !transitioning) {
				NOTICE_LOG(Log::sceNet, " - Login Successful");
				Transition(SigninStage::SUCCESS);
			}
			break;
		case SigninStage::SUCCESS:
			request.common.result = SCE_UTILITY_DIALOG_RESULT_SUCCESS;
			request.npSigninStatus = NP_SIGNIN_STATUS_SUCCESS;
			ChangeStatus(SCE_UTILITY_STATUS_FINISHED, NP_SHUTDOWN_DELAY_US);
			break;
		case SigninStage::FAIL:
			// Disable Token to force re-aquire ?
			//g_Config.infraToken = "";
			// Reset all forms
			InitForms();
			DrawLogo();
			DisplayMessage2(di->T("PleaseWait", failMessage));
			DisplayButtons(DS_BUTTON_OK, di->T("Confirm"));
			DisplayButtons(DS_BUTTON_CANCEL, di->T("Cancel"));
			if (IsButtonPressed(okButtonFlag)) {
				Transition(SigninStage::LOGIN_FORM);
				break;
			}
			if (IsButtonPressed(cancelButtonFlag)) {
				Transition(SigninStage::SHUTDOWN);
				break;
			}
			break;
		case SigninStage::CANCELLED:
			DisplayMessage2(di->T("PleaseWait", "Cancelling..."));
			if (now - lastTime > NP_RUNNING_DELAY_US) {
				request.common.result = SCE_UTILITY_DIALOG_RESULT_ABORT;
				request.npSigninStatus = NP_SIGNIN_STATUS_CANCELED;
				ChangeStatus(SCE_UTILITY_STATUS_FINISHED, NP_SHUTDOWN_DELAY_US);
			}
			break;
		case SigninStage::SHUTDOWN:
			DisplayMessage2(di->T("PleaseWait", "Exiting..."));
			request.common.result = SCE_UTILITY_DIALOG_RESULT_ABORT;
			request.npSigninStatus = NP_SIGNIN_STATUS_FAILED;
			ChangeStatus(SCE_UTILITY_STATUS_FINISHED, NP_SHUTDOWN_DELAY_US);
			break;
		}

		EndDraw();
	}

	if (ReadStatus() == SCE_UTILITY_STATUS_FINISHED || pendingStatus == SCE_UTILITY_STATUS_FINISHED) {
		npSigninState = NP_SIGNIN_STATUS_SUCCESS;
		__RtcTimeOfDay(&npSigninTimestamp);
		request.npSigninStatus = npSigninState;
	}
	return 0;
}

void PSPNpSigninDialog::UpdateSigninForm(int animSpeed) {
	u64 now = (u64)(time_now_d() * 1000000.0);
	auto di = GetI18NCategory(I18NCat::DIALOG);

	const int confirmBtn = GetConfirmButton();
	const int cancelBtn = GetCancelButton();
	const ImageID confirmBtnImage = confirmBtn == CTRL_CROSS ? ImageID("I_CROSS") : ImageID("I_CIRCLE");
	const ImageID cancelBtnImage = cancelBtn == CTRL_CIRCLE ? ImageID("I_CIRCLE") : ImageID("I_CROSS");

	PPGeStyle leftAligned = FadedStyle(PPGeAlign::BOX_LEFT, 0.6f);
	PPGeStyle centerAligned = FadedStyle(PPGeAlign::BOX_HCENTER, 0.6f);

	switch ((SigninSelected)selected[(u8)stage]) {
	case SigninSelected::LOGIN:
		PPGeDrawRect(70, 70, 405, 90, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(downButtonFlag))
			selected[(u8)stage] = (u8)SigninSelected::PASSWORD;
		if (IsButtonPressed(okButtonFlag)) {
			std::string LoginType = "Username";
			if (server->GetAuthType() == net::NPAgentType::PSN)
				LoginType = "E-mail Address";
			System_InputBoxGetString(NON_EPHEMERAL_TOKEN, LoginType, g_Config.infraNpId, false,
				[&](const std::string& value, int) {
				// TODO: Alert the user that some characters are not allowed
				g_Config.infraNpId = SanitizeString(value, StringRestriction::AlphaNumUnderscore, 3, 16);
				g_Config.infraToken = "";
			},
				[&]() {
				// Failure callback
			}
			);
		}
		break;
	case SigninSelected::PASSWORD:
		PPGeDrawRect(70, 115, 405, 135, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)SigninSelected::LOGIN;
		if (IsButtonPressed(downButtonFlag))
			selected[(u8)stage] = (u8)SigninSelected::AUTOLOGIN;
		if (IsButtonPressed(okButtonFlag)) {
			System_InputBoxGetString(NON_EPHEMERAL_TOKEN, "Password", g_Config.infraPassword, true,
				[&](const std::string& value, int) {
				// Success callback
				g_Config.infraPassword = value;
				g_Config.infraToken = "";
			},
				[&]() {
				// Failure callback
			}
			);
		}
		break;
	case SigninSelected::AUTOLOGIN:
		PPGeDrawRect(70, 145, 300, 165, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)SigninSelected::PASSWORD;
		if (IsButtonPressed(downButtonFlag))
			selected[(u8)stage] = (u8)SigninSelected::REMEMBERME;
		if (IsButtonPressed(okButtonFlag)) {
			g_Config.infraAutoSignIn = !g_Config.infraAutoSignIn;
			if (g_Config.infraAutoSignIn)
				g_Config.infraRememberPwd = true;
		}
		break;
	case SigninSelected::REMEMBERME:
		PPGeDrawRect(70, 170, 200, 190, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)SigninSelected::AUTOLOGIN;
		if (IsButtonPressed(downButtonFlag))
			selected[(u8)stage] = (u8)SigninSelected::SIGNIN;
		if (IsButtonPressed(okButtonFlag)) {
			g_Config.infraRememberPwd = !g_Config.infraRememberPwd;
			if (!g_Config.infraRememberPwd)
				g_Config.infraAutoSignIn = false;
		}
		break;
	case SigninSelected::SIGNIN:
		PPGeDrawRect(200, 200, 280, 220, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)SigninSelected::REMEMBERME;
		if (IsButtonPressed(downButtonFlag))
			selected[(u8)stage] = (u8)SigninSelected::FORGOTPSWD;
		if (IsButtonPressed(okButtonFlag)) {
			// Sanity Check
			if (g_Config.infraNpId.empty() || g_Config.infraPassword.empty())
				break;
			if (g_Config.infraToken.empty()) {
				System_InputBoxGetString(NON_EPHEMERAL_TOKEN, "Token", g_Config.infraToken, true,
					[&](const std::string& value, int) {
					// Success callback
					g_Config.infraToken = value;
					startTime = now;
					Transition(SigninStage::CONNECT_REQUEST);
				},
					[&]() {
					// Failure callback
				}
				);
			}
			else {
				startTime = now;
				Transition(SigninStage::CONNECT_REQUEST);
			}
		}
		break;
	case SigninSelected::FORGOTPSWD:
		PPGeDrawRect(170, 230, 310, 250, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)SigninSelected::SIGNIN;
		if (IsButtonPressed(okButtonFlag))
			Transition(SigninStage::PASSWORD_FORM);
		break;
	}
	if (server->GetAuthType() == net::NPAgentType::RPCN) {
		PPGeDrawText(di->T("RPCN"), 240, 5, centerAligned);
		PPGeDrawText(di->T("Sign-In ID (Username)"), 70, 50, leftAligned);
	}
	else {
		PPGeDrawText(di->T("PSN"), 240, 5, centerAligned);
		PPGeDrawText(di->T("Sign-In ID (E-mail Address)"), 70, 50, leftAligned);
	}
	DrawInputBox(g_Config.infraNpId, 70, 70, 405, 90, CalcFadedColor(0x40000000), leftAligned);
	PPGeDrawText(di->T("Password"), 70, 95, leftAligned);
	DrawInputBox(g_Config.infraPassword, 70, 115, 405, 135, CalcFadedColor(0x40000000), leftAligned, true);
	{
		ImageID autoSignInChkBox = g_Config.infraAutoSignIn ? ImageID("I_CROSS") : ImageID("I_SQUARE");
		PPGeDrawImage(autoSignInChkBox, 70, 145, 20, 20, leftAligned);
	}
	PPGeDrawText(di->T("Sign In Automatically (Auto Sign-In)"), 90, 145, leftAligned);
	{
		ImageID savePswdChkBox = g_Config.infraRememberPwd ? ImageID("I_CROSS") : ImageID("I_SQUARE");
		PPGeDrawImage(savePswdChkBox, 70, 170, 20, 20, leftAligned);
	}
	PPGeDrawText(di->T("Save Password"), 90, 170, leftAligned);

	PPGeDrawText(di->T("Sign In"), 240, 200, centerAligned);
	PPGeDrawText(di->T("Forgot Password"), 240, 230, centerAligned);
	DisplayButtons(DS_BUTTON_OK, di->T("Confirm"));
	DisplayButtons(DS_BUTTON_CANCEL, di->T("Cancel"));
	if (IsButtonPressed(cancelButtonFlag)) {
		Transition(SigninStage::CANCELLED);
	}
}

void PSPNpSigninDialog::UpdatePasswordRecoveryForm(int animSpeed) {
	u64 now = (u64)(time_now_d() * 1000000.0);
	auto di = GetI18NCategory(I18NCat::DIALOG);

	const int confirmBtn = GetConfirmButton();
	const int cancelBtn = GetCancelButton();
	const ImageID confirmBtnImage = confirmBtn == CTRL_CROSS ? ImageID("I_CROSS") : ImageID("I_CIRCLE");
	const ImageID cancelBtnImage = cancelBtn == CTRL_CIRCLE ? ImageID("I_CIRCLE") : ImageID("I_CROSS");

	PPGeStyle centerAligned = FadedStyle(PPGeAlign::BOX_HCENTER, 0.6f);
	PPGeStyle formText = FadedStyle(PPGeAlign::BOX_RIGHT, 0.5f);
	PPGeStyle header = FadedStyle(PPGeAlign::BOX_LEFT, 0.7f);
	PPGeStyle descText = FadedStyle(PPGeAlign::BOX_LEFT, 0.6f);
	PPGeStyle inputBox = FadedStyle(PPGeAlign::BOX_LEFT, 0.58f);
	// Window Color: 0x40000000
	// Button Color: 0xFF884300

	DrawFormBG();
	switch ((PasswordSelected)selected[(u8)stage]) {
	case PasswordSelected::LOGIN:
		PPGeDrawRect(243, 115, 413, 132, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(downButtonFlag))
			selected[(u8)stage] = (u8)RegisterSelected::EMAIL;
		if (IsButtonPressed(okButtonFlag)) {
			System_InputBoxGetString(NON_EPHEMERAL_TOKEN, "Login ID", npid, false,
				[&](const std::string& value, int) {
				// TODO: Alert the user that some characters are not allowed
				npid = SanitizeString(value, StringRestriction::AlphaNumUnderscore, 3, 16);
			},
				[&]() {
				// Failure callback
			}
			);
		}
		break;
	case PasswordSelected::EMAIL:
		PPGeDrawRect(243, 135, 413, 152, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)RegisterSelected::LOGIN;
		if (IsButtonPressed(downButtonFlag)) {
			// Simple logic for default selection
			if (validEmail)
				selected[(u8)stage] = (u8)PasswordSelected::CONTINUE;
			else
				selected[(u8)stage] = (u8)PasswordSelected::CANCEL;
		}
		if (IsButtonPressed(okButtonFlag)) {
			System_InputBoxGetString(NON_EPHEMERAL_TOKEN, "E-mail Address", email, false,
				[&](const std::string& value, int) {
					validEmail = true;
					// TODO: Alert the user that some characters are not allowed
					if (value != SanitizeString(value, StringRestriction::EmailSanity, 5, (64 + 1 + 255)))
						validEmail = false;
					// TODO: Alert the user that the email is invalid
					if (!IsValidEmail(value))
						validEmail = false;
					email = value;
				},
				[&]() {
					// Failure callback
				}
			);
		}
		break;
	case PasswordSelected::CANCEL:
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)PasswordSelected::EMAIL;
		if (IsButtonPressed(rightButtonFlag)) {
			// Skip Continue if email is empty
			if (validEmail)
				selected[(u8)stage] = (u8)PasswordSelected::CONTINUE;
			else
				selected[(u8)stage] = (u8)PasswordSelected::REGISTER;
		}
		if (IsButtonPressed(okButtonFlag))
			Transition(SigninStage::LOGIN_FORM);
		break;
	case PasswordSelected::CONTINUE:
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)PasswordSelected::EMAIL;
		if (IsButtonPressed(leftButtonFlag))
			selected[(u8)stage] = (u8)PasswordSelected::CANCEL;
		if (IsButtonPressed(rightButtonFlag))
			selected[(u8)stage] = (u8)PasswordSelected::REGISTER;
		if (IsButtonPressed(okButtonFlag))
			Transition(SigninStage::PASSWORD_TOKEN_REQUEST, true);
		break;
	case PasswordSelected::REGISTER:
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)PasswordSelected::EMAIL;
		if (IsButtonPressed(leftButtonFlag)) {
			// Skip Continue if email is empty
			if (validEmail)
				selected[(u8)stage] = (u8)PasswordSelected::CONTINUE;
			else
				selected[(u8)stage] = (u8)PasswordSelected::CANCEL;
		}
		if (IsButtonPressed(okButtonFlag))
			Transition(SigninStage::REGISTRATION_FORM, true);
		break;
	}
	// Draw window
	PPGeDrawRect(44, 42, 434, 230, CalcFadedColor(0x40000000));
	// Header
	PPGeDrawRect(48, 46, 430, 82, CalcFadedColor(0x40000000));

	PPGeDrawText(di->T("Forgot your password?"), 44, 20, header);
	PPGeDrawText(di->T("Enter the following information."), 65, 54, descText);

	PPGeDrawText(di->T("Login ID"), 235, 115, formText);
	DrawInputBox(npid, 243, 115, 413, 132, CalcFadedColor(0x40000000), inputBox);

	PPGeDrawText(di->T("Sign-In ID"), 235, 141, formText);
	PPGeDrawText(di->T("(E-mail Address)"), 235, 151, formText);

	DrawInputBox(email, 243, 135, 413, 152, CalcFadedColor(0x40000000), inputBox);

	DrawButton(di->T("Cancel"), 50, 210, 120, 225, CalcFadedColor(0xFF884300), 0.5f, (PasswordSelected)selected[(u8)stage] == PasswordSelected::CANCEL);
	DrawButton(di->T("Continue"), 205, 210, 275, 225, CalcFadedColor(0xFF884300), 0.5f, (PasswordSelected)selected[(u8)stage] == PasswordSelected::CONTINUE);
	DrawButton(di->T("Register"), 358, 210, 428, 225, CalcFadedColor(0xFF884300), 0.5f, (PasswordSelected)selected[(u8)stage] == PasswordSelected::REGISTER);
}

void PSPNpSigninDialog::UpdatePasswordRecoveryTokenForm(int animSpeed) {
	u64 now = (u64)(time_now_d() * 1000000.0);
	auto di = GetI18NCategory(I18NCat::DIALOG);

	const int confirmBtn = GetConfirmButton();
	const int cancelBtn = GetCancelButton();
	const ImageID confirmBtnImage = confirmBtn == CTRL_CROSS ? ImageID("I_CROSS") : ImageID("I_CIRCLE");
	const ImageID cancelBtnImage = cancelBtn == CTRL_CIRCLE ? ImageID("I_CIRCLE") : ImageID("I_CROSS");

	PPGeStyle centerAligned = FadedStyle(PPGeAlign::BOX_HCENTER, 0.6f);
	PPGeStyle formText = FadedStyle(PPGeAlign::BOX_RIGHT, 0.5f);
	PPGeStyle header = FadedStyle(PPGeAlign::BOX_LEFT, 0.7f);
	PPGeStyle descText = FadedStyle(PPGeAlign::BOX_LEFT, 0.6f);
	PPGeStyle inputBox = FadedStyle(PPGeAlign::BOX_LEFT, 0.58f);
	// Window Color: 0x40000000
	// Button Color: 0xFF884300

	DrawFormBG();
	switch ((PasswordTokenSelected)selected[(u8)stage]) {
	case PasswordTokenSelected::TOKEN:
		PPGeDrawRect(243, 115, 413, 132, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(downButtonFlag))
			selected[(u8)stage] = (u8)PasswordTokenSelected::PASSWORD;
		if (IsButtonPressed(okButtonFlag)) {
			System_InputBoxGetString(NON_EPHEMERAL_TOKEN, "TOKEN", token, false,
				[&](const std::string& value, int) {
				// TODO: Alert the user that some characters are not allowed
				token = SanitizeString(value, StringRestriction::AlphaNumUnderscore, 1, 20);
			},
				[&]() {
				// Failure callback
			}
			);
		}
		break;
	case PasswordTokenSelected::PASSWORD:
		PPGeDrawRect(243, 135, 413, 152, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)PasswordTokenSelected::TOKEN;
		if (IsButtonPressed(downButtonFlag))
			selected[(u8)stage] = (u8)PasswordTokenSelected::PASSCONFIRM;
		if (IsButtonPressed(okButtonFlag)) {
			System_InputBoxGetString(NON_EPHEMERAL_TOKEN, "Password", password, false,
				[&](const std::string& value, int) {
				// TODO: Alert the user that some characters are not allowed
				password = value;
			},
				[&]() {
				// Failure callback
			}
			);
		}
		break;
	case PasswordTokenSelected::PASSCONFIRM:
		PPGeDrawRect(243, 155, 413, 172, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)PasswordTokenSelected::PASSWORD;
		if (IsButtonPressed(downButtonFlag)) {
			// Simple logic for default selection
			if (!token.empty() && token.length() == 16)
				selected[(u8)stage] = (u8)PasswordTokenSelected::CONTINUE;
			else
				selected[(u8)stage] = (u8)PasswordTokenSelected::CANCEL;
		}
		if (IsButtonPressed(okButtonFlag)) {
			System_InputBoxGetString(NON_EPHEMERAL_TOKEN, "Confirm Password", password_confirm, false,
				[&](const std::string& value, int) {
				// TODO: Alert the user that some characters are not allowed
				password_confirm = value;
			},
				[&]() {
				// Failure callback
			}
			);
		}
		break;
	case PasswordTokenSelected::CANCEL:
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)PasswordTokenSelected::PASSCONFIRM;
		if (IsButtonPressed(rightButtonFlag)) {
			// Skip Continue if email is empty
			if (!token.empty() && token.length() == 16)
				selected[(u8)stage] = (u8)PasswordTokenSelected::CONTINUE;
		}
		if (IsButtonPressed(okButtonFlag))
			Transition(SigninStage::LOGIN_FORM);
		break;
	case PasswordTokenSelected::CONTINUE:
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)PasswordTokenSelected::PASSCONFIRM;
		if (IsButtonPressed(leftButtonFlag))
			selected[(u8)stage] = (u8)PasswordTokenSelected::CANCEL;
		if (IsButtonPressed(okButtonFlag))
			Transition(SigninStage::PASSWORD_REQUEST, true);
		break;
	}
	// Draw window
	PPGeDrawRect(44, 42, 434, 230, CalcFadedColor(0x40000000));
	// Header
	PPGeDrawRect(48, 46, 430, 82, CalcFadedColor(0x40000000));

	PPGeDrawText(di->T("Forgot your password?"), 44, 20, header);
	PPGeDrawText(di->T("Enter the following information."), 65, 54, descText);

	PPGeDrawText(di->T("Token"), 235, 111, formText);
	PPGeDrawText(di->T("(Check your E-mail)"), 235, 122, formText);
	DrawInputBox(token, 243, 115, 413, 132, CalcFadedColor(0x40000000), inputBox);

	PPGeDrawText(di->T("New Password"), 235, 135, formText);
	DrawInputBox(password, 243, 135, 413, 152, CalcFadedColor(0x40000000), inputBox, true);

	PPGeDrawText(di->T("Confirm Password"), 235, 155, formText);
	DrawInputBox(password_confirm, 243, 155, 413, 172, CalcFadedColor(0x40000000), inputBox, true);

	DrawButton(di->T("Cancel"), 50, 210, 120, 225, CalcFadedColor(0xFF884300), 0.5f, (PasswordTokenSelected)selected[(u8)stage] == PasswordTokenSelected::CANCEL);
	DrawButton(di->T("Continue"), 205, 210, 275, 225, CalcFadedColor(0xFF884300), 0.5f, (PasswordTokenSelected)selected[(u8)stage] == PasswordTokenSelected::CONTINUE);
}

void PSPNpSigninDialog::UpdateRegistrationForm(int animSpeed) {
	u64 now = (u64)(time_now_d() * 1000000.0);
	auto di = GetI18NCategory(I18NCat::DIALOG);

	const int confirmBtn = GetConfirmButton();
	const int cancelBtn = GetCancelButton();
	const ImageID confirmBtnImage = confirmBtn == CTRL_CROSS ? ImageID("I_CROSS") : ImageID("I_CIRCLE");
	const ImageID cancelBtnImage = cancelBtn == CTRL_CIRCLE ? ImageID("I_CIRCLE") : ImageID("I_CROSS");

	PPGeStyle centerAligned = FadedStyle(PPGeAlign::BOX_HCENTER, 0.6f);
	PPGeStyle formText = FadedStyle(PPGeAlign::BOX_RIGHT, 0.5f);
	PPGeStyle header = FadedStyle(PPGeAlign::BOX_LEFT, 0.7f);
	PPGeStyle descText = FadedStyle(PPGeAlign::BOX_LEFT, 0.6f);
	PPGeStyle inputBox = FadedStyle(PPGeAlign::BOX_LEFT, 0.58f);
	// Window Color: 0x40000000
	// Button Color: 0xFF884300

	DrawFormBG();
	switch ((RegisterSelected)selected[(u8)stage]) {
	case RegisterSelected::LOGIN:
		PPGeDrawRect(243, 115, 413, 132, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(downButtonFlag))
			selected[(u8)stage] = (u8)RegisterSelected::EMAIL;
		if (IsButtonPressed(okButtonFlag)) {
			System_InputBoxGetString(NON_EPHEMERAL_TOKEN, "Login ID", npid, false,
				[&](const std::string& value, int) {
				// TODO: Alert the user that some characters are not allowed
				npid = SanitizeString(value, StringRestriction::AlphaNumUnderscore, 3, 16);
			},
				[&]() {
				// Failure callback
			}
			);
		}
		break;
	case RegisterSelected::EMAIL:
		PPGeDrawRect(243, 135, 413, 152, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)RegisterSelected::LOGIN;
		if (IsButtonPressed(downButtonFlag))
			selected[(u8)stage] = (u8)RegisterSelected::PASSWORD;
		if (IsButtonPressed(okButtonFlag)) {
			System_InputBoxGetString(NON_EPHEMERAL_TOKEN, "E-mail Address", email, false,
				[&](const std::string& value, int) {
					validEmail = true;
					// TODO: Alert the user that some characters are not allowed
					if (value != SanitizeString(value, StringRestriction::EmailSanity, 5, (64 + 1 + 255)))
						validEmail = false;
					// TODO: Alert the user that the email is invalid
					if (!IsValidEmail(value))
						validEmail = false;
					email = value;
				},
					[&]() {
					// Failure callback
				}
			);
		}
		break;
	case RegisterSelected::PASSWORD:
		PPGeDrawRect(243, 155, 413, 172, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)RegisterSelected::EMAIL;
		if (IsButtonPressed(downButtonFlag))
			selected[(u8)stage] = (u8)RegisterSelected::PASSCONFIRM;
		if (IsButtonPressed(okButtonFlag)) {
			System_InputBoxGetString(NON_EPHEMERAL_TOKEN, "Password", password, false,
				[&](const std::string& value, int) {
				// TODO: Alert the user that some characters are not allowed
				password = value;
			},
				[&]() {
				// Failure callback
			}
			);
		}
		break;
	case RegisterSelected::PASSCONFIRM:
		PPGeDrawRect(243, 175, 413, 192, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)RegisterSelected::PASSWORD;
		if (IsButtonPressed(downButtonFlag)) {
			if (!npid.empty() && (!email.empty() && IsValidEmail(email)) && !password.empty() && !password_confirm.empty() && password == password_confirm)
				selected[(u8)stage] = (u8)RegisterSelected::CONTINUE;
			else
				selected[(u8)stage] = (u8)RegisterSelected::CANCEL;
		}
		if (IsButtonPressed(okButtonFlag)) {
			System_InputBoxGetString(NON_EPHEMERAL_TOKEN, "Confirm Password", password_confirm, false,
				[&](const std::string& value, int) {
				// TODO: Alert the user that some characters are not allowed
				password_confirm = value;
			},
				[&]() {
				// Failure callback
			}
			);
		}
		break;
	case RegisterSelected::CANCEL:
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)RegisterSelected::PASSCONFIRM;
		if (IsButtonPressed(rightButtonFlag)) {
			// Skip Continue if email is empty
			if (!npid.empty() && (!email.empty() && IsValidEmail(email)) && !password.empty() && !password_confirm.empty() && password == password_confirm)
				selected[(u8)stage] = (u8)RegisterSelected::CONTINUE;
		}
		if (IsButtonPressed(okButtonFlag))
			Transition(SigninStage::LOGIN_FORM);
		break;
	case RegisterSelected::CONTINUE:
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)RegisterSelected::PASSCONFIRM;
		if (IsButtonPressed(leftButtonFlag))
			selected[(u8)stage] = (u8)RegisterSelected::CANCEL;
		if (IsButtonPressed(okButtonFlag))
			Transition(SigninStage::REGISTRATION_INFO_FORM, true);
		break;
	}
	// Draw window
	PPGeDrawRect(44, 42, 434, 230, CalcFadedColor(0x40000000));
	// Header
	PPGeDrawRect(48, 46, 430, 82, CalcFadedColor(0x40000000));

	PPGeDrawText(di->T("Need a new account?"), 44, 20, header);
	PPGeDrawText(di->T("Enter the following information."), 65, 54, descText);

	PPGeDrawText(di->T("Login ID"), 235, 115, formText);
	DrawInputBox(npid, 243, 115, 413, 132, CalcFadedColor(0x40000000), inputBox);

	PPGeDrawText(di->T("E-mail"), 235, 135, formText);
	DrawInputBox(email, 243, 135, 413, 152, CalcFadedColor(0x40000000), inputBox);

	PPGeDrawText(di->T("Password"), 235, 155, formText);
	DrawInputBox(password, 243, 155, 413, 172, CalcFadedColor(0x40000000), inputBox, true);

	PPGeDrawText(di->T("Confirm Password"), 235, 175, formText);
	DrawInputBox(password_confirm, 243, 175, 413, 192, CalcFadedColor(0x40000000), inputBox, true);

	DrawButton(di->T("Cancel"), 50, 210, 120, 225, CalcFadedColor(0xFF884300), 0.5f, (RegisterSelected)selected[(u8)stage] == RegisterSelected::CANCEL);
	DrawButton(di->T("Continue"), 205, 210, 275, 225, CalcFadedColor(0xFF884300), 0.5f, (RegisterSelected)selected[(u8)stage] == RegisterSelected::CONTINUE);
}

void PSPNpSigninDialog::UpdateRegistrationInfoForm(int animSpeed) {
	u64 now = (u64)(time_now_d() * 1000000.0);
	auto di = GetI18NCategory(I18NCat::DIALOG);

	const int confirmBtn = GetConfirmButton();
	const int cancelBtn = GetCancelButton();
	const ImageID confirmBtnImage = confirmBtn == CTRL_CROSS ? ImageID("I_CROSS") : ImageID("I_CIRCLE");
	const ImageID cancelBtnImage = cancelBtn == CTRL_CIRCLE ? ImageID("I_CIRCLE") : ImageID("I_CROSS");

	PPGeStyle centerAligned = FadedStyle(PPGeAlign::BOX_HCENTER, 0.6f);
	PPGeStyle formText = FadedStyle(PPGeAlign::BOX_RIGHT, 0.5f);
	PPGeStyle header = FadedStyle(PPGeAlign::BOX_LEFT, 0.7f);
	PPGeStyle descText = FadedStyle(PPGeAlign::BOX_LEFT, 0.6f);
	PPGeStyle inputBox = FadedStyle(PPGeAlign::BOX_LEFT, 0.58f);
	// Window Color: 0x40000000
	// Button Color: 0xFF884300

	DrawFormBG();
	switch ((RegisterInfoSelected)selected[(u8)stage]) {
	case RegisterInfoSelected::ONLINE_NAME:
		PPGeDrawRect(243, 115, 413, 132, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(downButtonFlag))
			selected[(u8)stage] = (u8)RegisterInfoSelected::AVATAR_URL;
		if (IsButtonPressed(okButtonFlag)) {
			System_InputBoxGetString(NON_EPHEMERAL_TOKEN, "Online Nickname", online_name, false,
				[&](const std::string& value, int) {
				// TODO: Alert the user that some characters are not allowed
				online_name = SanitizeString(value, StringRestriction::AlphaNumUnderscore, 3, 16);
			},
				[&]() {
				// Failure callback
			}
			);
		}
		break;
	case RegisterInfoSelected::AVATAR_URL:
		PPGeDrawRect(243, 135, 413, 152, CalcFadedColor(0xC0C8B2AC));
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)RegisterInfoSelected::ONLINE_NAME;
		if (IsButtonPressed(downButtonFlag)) {
			if (!online_name.empty() && !avatar_url.empty())
				selected[(u8)stage] = (u8)RegisterInfoSelected::CONTINUE;
			else
				selected[(u8)stage] = (u8)RegisterInfoSelected::CANCEL;
		}
		if (IsButtonPressed(okButtonFlag)) {
			System_InputBoxGetString(NON_EPHEMERAL_TOKEN, "Avatar URL", avatar_url, false,
				[&](const std::string& value, int) {
				avatar_url = value;
			},
				[&]() {
				// Failure callback
			}
			);
		}
		break;
	case RegisterInfoSelected::CANCEL:
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)RegisterInfoSelected::AVATAR_URL;
		if (IsButtonPressed(rightButtonFlag)) {
			// Skip Continue if email is empty
			if (!online_name.empty() && !avatar_url.empty())
				selected[(u8)stage] = (u8)RegisterInfoSelected::CONTINUE;
		}
		if (IsButtonPressed(okButtonFlag))
			Transition(SigninStage::LOGIN_FORM);
		break;
	case RegisterInfoSelected::CONTINUE:
		if (IsButtonPressed(upButtonFlag))
			selected[(u8)stage] = (u8)RegisterInfoSelected::AVATAR_URL;
		if (IsButtonPressed(leftButtonFlag))
			selected[(u8)stage] = (u8)RegisterInfoSelected::CANCEL;
		if (IsButtonPressed(okButtonFlag))
			Transition(SigninStage::REGISTRATION_REQUEST, true);
		break;
	}
	// Draw window
	PPGeDrawRect(44, 42, 434, 230, CalcFadedColor(0x40000000));
	// Header
	PPGeDrawRect(48, 46, 430, 82, CalcFadedColor(0x40000000));

	PPGeDrawText(di->T("Need a new account?"), 44, 20, header);
	PPGeDrawText(di->T("Enter the following information."), 65, 54, descText);

	PPGeDrawText(di->T("Online Name"), 235, 111, formText);
	DrawInputBox(online_name, 243, 115, 413, 132, CalcFadedColor(0x40000000), inputBox);

	PPGeDrawText(di->T("Avatar URL"), 235, 135, formText);
	DrawInputBox(avatar_url, 243, 135, 413, 152, CalcFadedColor(0x40000000), inputBox);

	DrawButton(di->T("Cancel"), 50, 210, 120, 225, CalcFadedColor(0xFF884300), 0.5f, (PasswordSelected)selected[(u8)stage] == PasswordSelected::CANCEL);
	DrawButton(di->T("Continue"), 205, 210, 275, 225, CalcFadedColor(0xFF884300), 0.5f, (PasswordSelected)selected[(u8)stage] == PasswordSelected::CONTINUE);
}

int PSPNpSigninDialog::Shutdown(bool force) {
	if (ReadStatus() != SCE_UTILITY_STATUS_FINISHED && !force)
		return SCE_ERROR_UTILITY_INVALID_STATUS;

	PSPDialog::Shutdown(force);
	if (!force) {
		ChangeStatusShutdown(NP_SHUTDOWN_DELAY_US);
	}

	// FIXME: This should probably be done within FinishShutdown to prevent some games (ie. UNO) from progressing further while the Dialog is still being faded-out, since we can't override non-virtual method... so here is the closes one to FinishShutdown.
	if (Memory::IsValidAddress(requestAddr)) // Need to validate first to prevent Invalid address when the game is being Shutdown/Exited to menu
		Memory::Memcpy(requestAddr, &request, request.common.size, "NpSigninDialogParam");

	return 0;
}

void PSPNpSigninDialog::DoState(PointerWrap &p) {
	PSPDialog::DoState(p);

	auto s = p.Section("PSPNpSigninDialog", 1, 1);
	if (!s)
		return;

	Do(p, request);
	Do(p, stage);
	//Do(p, npSigninResult);

	if (p.mode == p.MODE_READ) {
		startTime = 0;
	}
}

pspUtilityDialogCommon* PSPNpSigninDialog::GetCommonParam()
{
	return &request.common;
}
