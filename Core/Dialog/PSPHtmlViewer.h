#pragma once

#include "Core/Dialog/PSPDialog.h"
#include "Core/MemMapHelpers.h"

// "Html Viewer" (browser) utility parameter struct, as used by the PSP2/PSP2i host.
// Ground truth from the host EBOOT (PSP2 sample, "PSPP2"):
//   +0x00  size          = 0xA8
//   +0x00-0x2F pspUtilityDialogCommon
//                        (language=0, buttonSwap=0, graphicsThread=0x11, accessThread=0x13,
//                          fontThread=0x12, soundThread=0x10, result written by the utility at +0x1C)
//   +0x30  vplHeapPtr    (from sceKernelAllocateVpl, must be non-zero)
//   +0x34  vplHeapSize   (must be >= 0x400000; host uses 0x800000)
//   +0x44  1..3
//   +0x48  0..2
//   +0x4C  model         (e.g. 0x9C6; must be < 0x100000)
//   +0x50  savePathPtr   (e.g. "/PSP/SAVEDATA/NPJH50043DL")
//   +0x60  0..3
//   +0x64  urlBufSize    (<= 0x800)
//   +0x68  urlPtr        (C-string, e.g. "http://www.sega-psp2.jp/psp/")
//   +0x80  userAgentPtr  (C-string, e.g. "Phantasy Star Portable 2/1.0.0 (NPJH50043)")
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
	enum class PageState {
		LOADING,
		LOADED,
		ERROR_STATE,
	};
	void DrawBanner();
	void DrawIndicator();
	void DrawLogo();

	u64 startTime = 0;
	SceUtilityHtmlViewerParam request = {};
	u32 requestAddr = 0;
	//int npSigninResult = -1;


	// Page data
	std::string url;
	std::string userAgent;
	std::string pageText;
	std::vector<std::string> wrappedLines;
	std::string statusText;
	std::string errorText;
	PageState state = PageState::LOADING;
	float scrollY = 0.0f;
	float lineHeight = 10.0f;
	int httpStatus = 0;
	bool wrapped = false;
	bool fetched = false;

	// In-flight download; driven by g_DownloadManager.Update() from the main loop.
	std::shared_ptr<http::Request> request_;
};
