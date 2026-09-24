#pragma once

#include <condition_variable>
#include <string>
#include <thread>
#include <vector>

#include "Common/UI/View.h"
#include "Common/UI/PopupScreens.h"
#include "Common/UI/Notice.h"
#include "Core/Net/InfraServerList.h"

// Infra (RPCN) server picker, modeled after AdhocServerScreen. Differences:
// - a single custom server list (no relay/post-office split)
// - entries carry the RPCN protocol version they speak
// - localhost keeps its "multiple instance" hint

// Simple metadata viewer for a public infra server entry.
class InfraServerInfoScreen : public UI::PopupScreen {
public:
	InfraServerInfoScreen(const InfraServerListEntry &entry);

	const char *tag() const override { return "InfraServerInfo"; }

protected:
	bool FillVertical() const override { return false; }
	UI::Size PopupWidth() const override { return 650; }
	bool ShowButtons() const override { return true; }

	void CreatePopupContents(UI::ViewGroup *parent) override;

private:
	InfraServerListEntry entry_;
};

class InfraServerScreen : public UI::PopupScreen {
public:
	InfraServerScreen(std::string *value, std::string_view title);
	~InfraServerScreen();

	void CreatePopupContents(UI::ViewGroup *parent) override;

	const char *tag() const override { return "InfraServer"; }

	bool RecreateParent() const {
		return recreateParent_;
	}

protected:
	void OnCompleted(DialogResult result) override;
	bool CanComplete(DialogResult result) override;
	virtual UI::Size PopupWidth() const override { return 650; }

	void sendMessage(UIMessage message, const char *value) override;

	void dialogFinished(const Screen *screen, DialogResult result) override {
		RecreateViews();
	}

private:
	void ResolverThread();

	enum class ResolverState {
		WAITING,
		QUEUED,
		PROGRESS,
		READY,
		QUIT,
	};

	std::string *value_;
	std::string editValue_;
	NoticeView *progressView_ = nullptr;

	std::thread resolver_;
	ResolverState resolverState_ = ResolverState::WAITING;
	std::mutex resolverLock_;
	std::condition_variable resolverCond_;
	std::string toResolve_ = "";
	bool toResolveResult_ = false;
	std::string lastResolved_ = "";
	bool lastResolvedResult_ = false;
	bool recreateParent_ = false;
};

bool InfraServerNameIsCustom();
