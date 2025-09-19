#pragma once

#include "Core/Dialog/PSPDialog.h"
#include "Core/MemMapHelpers.h"

struct SceUtilityHtmlViewerParam {
	pspUtilityDialogCommon common;
	// Initially all zero? Or is there a possibility for one of these unknown to be a buffer to a packet data if it wasn't null?
	int dataPtr;  // Pointer to formatted space
	int dataSize; // size? 0x00800000
	int unknown2;
	int unknown3;
};


class PSPHtmlViewer : public PSPDialog {
public:
	PSPHtmlViewer(UtilityDialogType type) : PSPDialog(type) {}

	int Init(u32 paramAddr);
	int Update(int animSpeed) override;
	int Shutdown(bool force = false) override;
	void DoState(PointerWrap& p) override;
	pspUtilityDialogCommon* GetCommonParam() override;

protected:
	bool UseAutoStatus() override {
		return false;
	}

private:
	void DrawBanner();
	void DrawIndicator();
	void DrawLogo();

	SceUtilityHtmlViewerParam request = {};
	u32 requestAddr = 0;
	//int npSigninResult = -1;

	u64 startTime = 0;

};
