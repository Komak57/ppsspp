#include "ppsspp_config.h"

#include "Common/Data/Text/I18n.h"
#include "Common/Net/Resolve.h"
#include "Common/StringUtils.h"
#include "Common/System/System.h"
#include "Common/UI/Context.h"
#include "Common/UI/PopupScreens.h"
#include "Common/UI/Root.h"
#include "Core/Config.h"
#include "Core/Net/InfraServerList.h"
#include "UI/InfraServerScreen.h"
#include "UI/MiscViews.h"

// Infra (RPCN) server picker, modeled after AdhocServerScreen. See the header
// for the deliberate differences from the adhoc version.

static std::string DefaultInfraServer() {
	// The first non-hidden public entry is the sensible reset target.
	std::vector<InfraServerListEntry> entries = InfraGetServerList(InfraLoadListMode::CacheOnlySync);
	for (const auto &entry : entries) {
		if (!entry.hidden) {
			return entry.host;
		}
	}
	return "rpcn.revurb.us";
}

class InfraAddServerPopupScreen : public UI::PopupScreen {
public:
	InfraAddServerPopupScreen(std::string *outEditValue) : PopupScreen(T(I18NCat::NETWORKING, "Add server"), T(I18NCat::DIALOG, "Add"), T(I18NCat::DIALOG, "Cancel")), outEditValue_(outEditValue) {
	}

	void CreatePopupContents(UI::ViewGroup *parent) override {
		using namespace UI;
		auto ni = GetI18NCategory(I18NCat::NETWORKING);

		PopupTextInputChoice *textInputChoice = parent->Add(new PopupTextInputChoice(GetRequesterToken(), &editValue_, ni->T("Hostname or IP"), "", 450, screenManager()));
		textInputChoice->SetShadowText(ni->T("Hostname or IP"));
	}

	virtual void OnCompleted(DialogResult result) override {
		if (result == DialogResult::DR_OK) {
			std::vector<InfraServerListEntry> servers = InfraGetServerList(InfraLoadListMode::CacheOnlySync);
			bool preset = false;
			for (auto &iter : servers) {
				if (equalsNoCase(editValue_, iter.host)) {
					// We have this predefined.
					preset = true;
				}
			}
			if (!preset && !ContainsNoCase(g_Config.vCustomInfraServerList, editValue_)) {
				// Insert at the start of the vector.
				g_Config.vCustomInfraServerList.insert(g_Config.vCustomInfraServerList.begin(), editValue_);
			}
			*outEditValue_ = editValue_;
		}
	}
	virtual bool CanComplete(DialogResult result) override { return result == DR_OK ? !editValue_.empty() : true; }

	const char *tag() const override { return "InfraAddServerPopup"; }

private:
	std::string editValue_;
	std::string *outEditValue_;
};

// Same as the file-local helper in AdhocServerScreen.cpp.
static UI::View *CreateInfraLinkButton(std::string url, std::string_view title = "") {
	using namespace UI;

	// steal strings from all over the place
	auto cr = GetI18NCategory(I18NCat::PSPCREDITS);
	auto st = GetI18NCategory(I18NCat::STORE);

	ImageID icon = ImageID("I_LINK_OUT_QUESTION");
	if (startsWith(url, "https://discord")) {
		icon = ImageID("I_LOGO_DISCORD");
		if (title.empty())
			title = cr->T("Discord");
	} else {
		icon = ImageID("I_LINK_OUT");
		if (title.empty())
			title = st->T("Website");
	}

	Choice *choice = new Choice(title, icon, new LinearLayoutParams(WRAP_CONTENT, WRAP_CONTENT));
	choice->OnClick.Add([url](UI::EventParams &) {
		System_LaunchUrl(LaunchUrlType::BROWSER_URL, url);
	});
	return choice;
}

InfraServerInfoScreen::InfraServerInfoScreen(const InfraServerListEntry &entry)
	: UI::PopupScreen(entry.name, T(I18NCat::DIALOG, "OK"), ""), entry_(entry) {
}

void InfraServerInfoScreen::CreatePopupContents(UI::ViewGroup *parent) {
	using namespace UI;
	auto ni = GetI18NCategory(I18NCat::NETWORKING);

	Margins contentMargins(12, 0);

	LinearLayout *content = new LinearLayout(ORIENT_VERTICAL);
	content->SetSpacing(6.0f);

	content->Add(new InfoItem(entry_.host, ""));
	if (entry_.rpcnVersion != 0) {
		content->Add(new InfoItem(ni->T("RPCN protocol"), StringFromFormat("v%d", entry_.rpcnVersion)));
	}
	if (!entry_.location.empty()) {
		content->Add(new InfoItem(ni->T("Location"), entry_.location));
	}
	if (!entry_.description.empty()) {
		TextView *desc = content->Add(new TextView(entry_.description, new LinearLayoutParams(FILL_PARENT, WRAP_CONTENT, contentMargins)));
		desc->SetTextSize(TextSize::Small);
		desc->SetWordWrap();
	}

	LinearLayout *buttonStrip = content->Add(new LinearLayout(ORIENT_HORIZONTAL, new LinearLayoutParams(FILL_PARENT, WRAP_CONTENT, contentMargins)));
	buttonStrip->SetSpacing(8);
	if (!entry_.web.empty()) {
		buttonStrip->Add(CreateInfraLinkButton(entry_.web));
	}
	if (!entry_.discord.empty()) {
		buttonStrip->Add(CreateInfraLinkButton(entry_.discord));
	}

	parent->Add(content);
}

static void AddInfraDeleteButton(std::string *editValue, ScreenManager *screenManager, UI::ViewGroup *viewGroup, const InfraServerListEntry &entry) {
	using namespace UI;
	Choice *deleteButton = viewGroup->Add(new Choice(ImageID("I_TRASHCAN"), new LinearLayoutParams(WRAP_CONTENT, WRAP_CONTENT, Gravity::G_VCENTER, Margins(0, 0, 10, 0))));
	deleteButton->OnClick.Add([host = entry.host, screenManager, editValue](UI::EventParams &e) {
		auto di = GetI18NCategory(I18NCat::DIALOG);
		const std::string quotedHost = "\"" + host + "\"";
		const std::string message = ApplySafeSubstitutions(di->T("Are you sure you want to delete %1?"), quotedHost);
		screenManager->push(new UI::MessagePopupScreen(di->T("Delete"), message, di->T("Delete"), di->T("Cancel"), [host, editValue](bool confirmed) {
			if (confirmed) {
				RemoveNoCase(g_Config.vCustomInfraServerList, host);
				if (*editValue == host) {
					*editValue = DefaultInfraServer();
				}
			}
			}));
		});
}

class InfraServerRow : public UI::LinearLayout {
public:
	InfraServerRow(std::string *value, const InfraServerListEntry &entry, bool showDeleteButton, ScreenManager *screenManager, UI::LayoutParams *layoutParams = nullptr);

	void GetContentDimensions(const UIContext &dc, float &w, float &h) const override {
		w = 500; h = 90;
	}

	void Draw(UIContext &dc) override {
		dc.FillRect(dc.GetTheme().itemStyle.background, bounds_);
		if (*value_ == entry_.host) {
			// TODO: Make this highlight themable
			dc.FillRect(UI::Drawable(0x48FFFFFF), GetBounds());
		}
		LinearLayout::Draw(dc);
	}

	bool Touch(const TouchInput &input) override {
		using namespace UI;
		if (UI::LinearLayout::Touch(input)) {
			return true;
		}
		if (input.flags & TouchInputFlags::DOWN) {
			if (bounds_.Contains(input.x, input.y)) {
				dragging_ = true;
				return true;
			}
		}
		if (dragging_ && (input.flags & TouchInputFlags::UP)) {
			dragging_ = false;
			if (!(input.flags & TouchInputFlags::CANCEL) && bounds_.Contains(input.x, input.y)) {
				EventParams e;
				e.v = this;
				OnSelected.Trigger(e);
				return true;
			}
		}
		return false;
	}

	UI::Event OnSelected;

private:
	bool dragging_ = false;
	std::string *value_;
	InfraServerListEntry entry_;
};

InfraServerRow::InfraServerRow(std::string *editValue, const InfraServerListEntry &entry, bool showDeleteButton, ScreenManager *screenManager, UI::LayoutParams *layoutParams)
	: UI::LinearLayout(ORIENT_HORIZONTAL, new UI::LinearLayoutParams(UI::FILL_PARENT, UI::WRAP_CONTENT, UI::Margins(5.0f, 0.0f))), value_(editValue), entry_(entry) {
	using namespace UI;

	SetSpacing(5.0f);
	// Show as radio button to make it really clear that selection actually is the choice.
	Add(new ImageView([editValue, host = entry.host]() { return host == *editValue ? ImageID("I_RADIO_SELECTED") : ImageID("I_RADIO_EMPTY"); },
		new LinearLayoutParams(WRAP_CONTENT, WRAP_CONTENT, Gravity::G_VCENTER, Margins(5, 0, 0, 0))));

	LinearLayout *lines = Add(new LinearLayout(ORIENT_VERTICAL, new LinearLayoutParams(Margins(5, 5))));
	lines->SetSpacing(0.0f);
	ClickableTextView *name = lines->Add(new ClickableTextView(entry.name));
	name->SetFocusable(true);
	name->OnClick.Add([this](UI::EventParams &e) {
		EventParams e2;
		e2.v = this;
		OnSelected.Trigger(e2);
	});

	std::string secondLine = entry.host;
	auto n = GetI18NCategory(I18NCat::NETWORKING);
	if (entry.host == "localhost") {
		// Special case this to add a hint - localhost allows multiple instances
		// on the same machine to talk to one local RPCN. Same key the adhoc
		// screen uses; the value is generic: "(localhost = multiple instances)".
		secondLine = n->T("Ad hoc server address hint");
	}
	if (!entry.location.empty()) {
		secondLine += ": " + entry.location;
	}

	lines->Add(new TextView(secondLine))->SetTextSize(TextSize::Small)->SetWordWrap();

	Add(new Spacer(0.0f, new LinearLayoutParams(1.0f, Margins(0.0f, 5.0f))));

	if (entry.rpcnVersion != 0) {
		// Show the protocol version so users can spot servers newer than this build supports.
		Add(new TextView(StringFromFormat("RPCN v%d", entry.rpcnVersion), new LinearLayoutParams(WRAP_CONTENT, WRAP_CONTENT, Gravity::G_VCENTER, Margins(10.0))));
	}
	if (showDeleteButton) {
		AddInfraDeleteButton(editValue, screenManager, this, entry);
	}

	if (!entry.description.empty()) {
		Choice *infoButton = Add(new Choice(ImageID("I_INFO"), new LinearLayoutParams(WRAP_CONTENT, WRAP_CONTENT, Gravity::G_VCENTER, Margins(0, 0, 10, 0))));
		InfraServerListEntry copy = entry;
		infoButton->OnClick.Add([this, copy, screenManager](UI::EventParams &e) {
			e.v = this;
			screenManager->push(new InfraServerInfoScreen(copy));
		});
	}
}

InfraServerScreen::InfraServerScreen(std::string *value, std::string_view title)
	: UI::PopupScreen(title, T(I18NCat::DIALOG, "OK"), T(I18NCat::DIALOG, "Cancel")), value_(value) {
	resolver_ = std::thread([](InfraServerScreen *thiz) {
		thiz->ResolverThread();
	}, this);
	editValue_ = *value;
	InfraLoadServerList(InfraLoadListMode::AllSourcesAsync);
}

InfraServerScreen::~InfraServerScreen() {
	{
		std::unique_lock<std::mutex> guard(resolverLock_);
		resolverState_ = ResolverState::QUIT;
		resolverCond_.notify_one();
	}
	resolver_.join();
}

void InfraServerScreen::sendMessage(UIMessage message, const char *value) {
	if (message == UIMessage::INFRA_SERVER_LIST_CHANGED) {
		RecreateViews();
	}
}

void InfraServerScreen::CreatePopupContents(UI::ViewGroup *parent) {
	using namespace UI;
	auto n = GetI18NCategory(I18NCat::NETWORKING);

	// The list load was kicked off in the constructor; grab whatever is cached
	// now, and INFRA_SERVER_LIST_CHANGED recreates us when an async load lands.
	std::vector<InfraServerListEntry> entries = InfraGetServerList(InfraLoadListMode::CacheOnlySync);

	Choice *addServer = parent->Add(new Choice(n->T("Add server"), ImageID("I_PLUS")));
	addServer->OnClick.Add([this](UI::EventParams &e) {
		screenManager()->push(new InfraAddServerPopupScreen(&editValue_));
	});

	parent->Add(new Spacer(5.0f));

	// editValue_ has the currently selected server. On closing the dialog, we copy that to settings.

	std::vector<InfraServerListEntry> localEntries;
	std::vector<InfraServerListEntry> customEntries;

	bool currentServerFound = false;  // If the current server is not found, we'll have to add it to one of the lists.

	for (const auto &iter : entries) {
		if (iter.host == editValue_) {
			currentServerFound = true;
		}
	}

	// Add localhost and local IPs - common for self-hosted RPCN.
	{
		InfraServerListEntry localhostEntry;
		localhostEntry.name = "localhost";
		localhostEntry.host = "localhost";
		localEntries.push_back(localhostEntry);

		std::vector<std::string> listIP;
		net::GetLocalIP4List(listIP);

		for (const auto &ipAddress : listIP) {
			if (startsWith(ipAddress, "127.") || startsWith(ipAddress, "169.254.") || startsWith(ipAddress, "0.")) {
				continue;
			}
			InfraServerListEntry entry;
			entry.name = ipAddress;
			entry.host = ipAddress;
			localEntries.push_back(entry);

			if (ipAddress == editValue_) {
				currentServerFound = true;
			}
		}
	}

	auto hostInEntries = [&entries](const std::string &host) {
		for (const auto &entry : entries) {
			if (entry.host == host) {
				return true;
			}
		}
		return false;
	};

	for (auto iter = g_Config.vCustomInfraServerList.begin(); iter != g_Config.vCustomInfraServerList.end();) {
		// Remove things that duplicate the public list, or that are empty. This
		// also migrates away the old defaults that used to live in this key.
		if (hostInEntries(*iter) || iter->empty()) {
			iter = g_Config.vCustomInfraServerList.erase(iter);
			recreateParent_ = true;
			continue;
		}
		InfraServerListEntry entry;
		entry.name = *iter;
		entry.host = *iter;
		customEntries.push_back(entry);

		if (*iter == editValue_) {
			currentServerFound = true;
		}
		iter++;
	}

	ScrollView *scrollView = new ScrollView(ORIENT_VERTICAL, new LinearLayoutParams(1.0f));
	LinearLayout *innerView = new LinearLayout(ORIENT_VERTICAL, new LinearLayoutParams(FILL_PARENT, WRAP_CONTENT));
	innerView->SetSpacing(5.0f);

	auto AddButtonFromEntry = [this](UI::ViewGroup *parent, const InfraServerListEntry &entry, bool showDeleteButton) {
		InfraServerRow *row = new InfraServerRow(&editValue_, entry, showDeleteButton, screenManager());
		parent->Add(row);
		row->OnSelected.Add([this](UI::EventParams &e) {
			std::string value = e.v->Tag();
			if (!value.empty()) {
				editValue_ = value;
			}
		});
		row->SetTag(entry.host);
	};

	if (!customEntries.empty() || !currentServerFound) {
		CollapsibleSection *customSection = innerView->Add(new CollapsibleSection(n->T("Custom server list"), new LinearLayoutParams(FILL_PARENT, WRAP_CONTENT)));

		if (!currentServerFound && !editValue_.empty()) {
			// Persist the currently selected but unknown server as a custom entry.
			InfraServerListEntry entry;
			entry.name = editValue_;
			entry.host = editValue_;
			g_Config.vCustomInfraServerList.insert(g_Config.vCustomInfraServerList.begin(), editValue_);
			recreateParent_ = true;
			AddButtonFromEntry(customSection, entry, true);
		}

		for (const auto &entry : customEntries) {
			AddButtonFromEntry(customSection, entry, true);
		}
	}

	CollapsibleSection *publicSection = innerView->Add(new CollapsibleSection(n->T("Public server list"), new LinearLayoutParams(FILL_PARENT, WRAP_CONTENT)));
	for (const auto &entry : entries) {
		// Show even hidden entries, as long as they are chosen currently.
		if (entry.hidden && entry.host != g_Config.proInfraServer)
			continue;
		AddButtonFromEntry(publicSection, entry, false);
	}

	CollapsibleSection *localSection = innerView->Add(new CollapsibleSection(n->T("Local network addresses"), new LinearLayoutParams(FILL_PARENT, WRAP_CONTENT)));
	for (const auto &entry : localEntries) {
		AddButtonFromEntry(localSection, entry, false);
	}

	scrollView->Add(innerView);
	parent->Add(scrollView);

	progressView_ = parent->Add(new NoticeView(NoticeLevel::INFO, n->T("Validating address..."), "", new LinearLayoutParams(Margins(0, 5, 0, 0))));
	progressView_->SetVisibility(UI::V_GONE);
}

void InfraServerScreen::ResolverThread() {
	std::unique_lock<std::mutex> guard(resolverLock_);

	while (resolverState_ != ResolverState::QUIT) {
		resolverCond_.wait(guard);

		if (resolverState_ == ResolverState::QUEUED) {
			resolverState_ = ResolverState::PROGRESS;

			addrinfo *resolved = nullptr;
			std::string err;
			toResolveResult_ = net::DNSResolve(toResolve_, "80", &resolved, err);
			if (resolved)
				net::DNSResolveFree(resolved);

			resolverState_ = ResolverState::READY;
		}
	}
}

bool InfraServerScreen::CanComplete(DialogResult result) {
	auto n = GetI18NCategory(I18NCat::NETWORKING);

	if (result != DR_OK)
		return true;

	std::string value = editValue_;
	if (lastResolved_ == value) {
		return true;
	}

	// Currently running.
	if (resolverState_ == ResolverState::PROGRESS)
		return false;

	std::lock_guard<std::mutex> guard(resolverLock_);
	switch (resolverState_) {
	case ResolverState::PROGRESS:
	case ResolverState::QUIT:
		return false;

	case ResolverState::QUEUED:
	case ResolverState::WAITING:
		break;

	case ResolverState::READY:
		if (toResolve_ == value) {
			// Reset the state, nothing there now.
			resolverState_ = ResolverState::WAITING;
			toResolve_.clear();
			lastResolved_ = value;
			lastResolvedResult_ = toResolveResult_;

			if (lastResolvedResult_) {
				progressView_->SetVisibility(UI::V_GONE);
			} else {
				progressView_->SetText(n->T("Invalid IP or hostname"));
				progressView_->SetLevel(NoticeLevel::ERROR);
				progressView_->SetVisibility(UI::V_VISIBLE);
			}
			return true;
		}

		// Throw away that last result, it was for a different value.
		break;
	}

	resolverState_ = ResolverState::QUEUED;
	toResolve_ = value;
	resolverCond_.notify_one();

	progressView_->SetText(n->T("Validating address..."));
	progressView_->SetLevel(NoticeLevel::INFO);
	progressView_->SetVisibility(UI::V_VISIBLE);

	return false;
}

void InfraServerScreen::OnCompleted(DialogResult result) {
	if (result == DR_OK) {
		*value_ = StripSpaces(editValue_);
	}
}

bool InfraServerNameIsCustom() {
	for (const auto &iter : g_Config.vCustomInfraServerList) {
		if (iter == g_Config.proInfraServer) {
			return true;
		}
	}
	return false;
}
