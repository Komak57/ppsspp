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
#include <Core/Net/NPAgent.h>

struct SceUtilityNpSigninParam {
	pspUtilityDialogCommon common;
	// Initially all zero? Or is there a possibility for one of these unknown to be a buffer to a packet data if it wasn't null?
	int npSigninStatus;
	int unknown1; // Pointer to struct
	int unknown2; // flags? 0x00300000
	int unknown3;
};

enum class SigninStage {
	INIT,           // param copied, heap allocated
	AUTO_LOGIN,     // if saved credentials + auto-login flag
	LOGIN_FORM,   // show input fields for NP ID + password
	PASSWORD_FORM,
	PASSWORD_TOKEN_REQUEST,
	PASSWORD_TOKEN_FORM,
	PASSWORD_REQUEST,
	REGISTRATION_FORM,
	REGISTRATION_INFO_FORM,
	REGISTRATION_REQUEST,
	CONNECT_REQUEST,// "Signing in... Please wait"
	AUTH_REQUEST,   // talk to RPCNAuthAgent/PSNAuthAgent
	SUCCESS,        // finished, result OK
	FAIL,           // failed, show error + retry option
	CANCELLED,      // user pressed cancel
	SHUTDOWN,       // fade out + cleanup
};

enum class SigninSelected {
	LOGIN,
	PASSWORD,
	AUTOLOGIN,
	REMEMBERME,
	SIGNIN,
	FORGOTPSWD
};

enum class PasswordSelected {
	LOGIN,
	EMAIL,

	CANCEL,
	CONTINUE,
	REGISTER
};

enum class PasswordTokenSelected {
	TOKEN,
	PASSWORD,
	PASSCONFIRM,

	CANCEL,
	CONTINUE,
	REGISTER
};

enum class RegisterSelected {
	LOGIN,
	EMAIL,
	PASSWORD,
	PASSCONFIRM,

	CANCEL,
	CONTINUE
};

enum class RegisterInfoSelected {
	ONLINE_NAME,
	AVATAR_URL,

	CANCEL,
	CONTINUE
};

class PSPNpSigninDialog : public PSPDialog {
public:
	PSPNpSigninDialog(UtilityDialogType type) : PSPDialog(type) {}

	int Init(u32 paramAddr);
	void InitForms();
	int Update(int animSpeed) override;
	int Shutdown(bool force = false) override;
	void DoState(PointerWrap &p) override;
	pspUtilityDialogCommon* GetCommonParam() override;

	std::unique_ptr<net::NPAuthAgent> GetServer() {
		return std::move(server);
	}

protected:
	bool UseAutoStatus() override {
		return false;
	}

private:
	void DrawBanner();
	void DrawIndicator();
	void DrawLogo();
	void DrawFormBG();

	void UpdateSigninForm(int animSpeed);
	void UpdatePasswordRecoveryForm(int animSpeed);
	void UpdatePasswordRecoveryTokenForm(int animSpeed);
	void UpdateRegistrationForm(int animSpeed);
	void UpdateRegistrationInfoForm(int animSpeed);

	SceUtilityNpSigninParam request = {};
	u32 requestAddr = 0;
	//int npSigninResult = -1;

	u64 startTime = 0;
	SigninStage stage = SigninStage::INIT;
	//SigninSelected selected = SigninSelected::SIGNIN;

	std::unique_ptr<net::NPAuthAgent> server;
};
