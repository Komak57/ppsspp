#pragma once

#include <string_view>
#include <functional>

#include "Common/UI/View.h"
#include "Common/UI/ViewGroup.h"
#include "Common/UI/Tween.h"

namespace UI {

class ChoiceStrip;
class ScrollView;

enum class TabHolderFlags {
	Default = 0,
	BackButton = 1,
	HorizontalOnlyIcons = 2,
	VerticalShowIcons = 4,
};
ENUM_CLASS_BITOPS(TabHolderFlags);

struct TabGroup {
    int choiceIndex = -1;
    int defaultTab = -1;
    std::vector<int> tabs;
};

class TabHolder : public LinearLayout {
public:
	TabHolder(Orientation orientation, float stripSize, TabHolderFlags flags, View *bannerView, std::function<void()> contextMenuCallback, LayoutParams *layoutParams);

	// Creates a group whose header is itself a real tab (with createCb contents).
	// Tabs later added with this group index are only visible while a tab
	// belonging to the group (the header included) is selected.
	int AddTabGroup(std::string_view title, ImageID imageId, std::function<ViewGroup *()> createCb);
	int AddTabDeferred(std::string_view title, ImageID imageId,
					std::function<ViewGroup *()> createCb,
					int group = -1);

	void SetTabGroupVisible(int group, bool visible);
	int GetTabGroupForTab(int tab) const;

	template <class T>
	T *AddTab(std::string_view title, ImageID imageId, T *tabContents) {
		AddTabContents(title, imageId, tabContents);
		return tabContents;
	}
	void EnableTab(int tab, bool enabled);

	void AddBack(UIScreen *parent);

	// Returns true if the tab wasn't created before (but is now).
	bool SetCurrentTab(int tab, bool skipTween = false);
	void SetInitialTab(int tab);

	int GetCurrentTab() const { return currentTab_; }
	std::string DescribeLog() const override { return "TabHolder: " + View::DescribeLog(); }

	void PersistData(PersistStatus status, std::string anonId, PersistMap &storage) override;

	void EnsureAllCreated();

	LinearLayout *Container() { return tabContainer_; }

	const std::vector<ViewGroup *> &GetTabContentViews() const {
		return tabs_;
	}
	bool EnsureTab(int index);  // return true if it actually created a tab.

	Event OnChangeTab;

private:
	void AddTabContents(std::string_view title, ImageID imageId, ViewGroup *tabContents);
	void OnTabClick(EventParams &e);
	void UpdateGroupVisibility();

	View *bannerView_ = nullptr;
	std::vector<int> tabToChoice_;
	std::vector<int> choiceToTab_;
	std::vector<int> tabGroups_;
	std::vector<TabGroup> tabGroupsList_;

	LinearLayout *tabContainer_ = nullptr;
	ChoiceStrip *tabStrip_ = nullptr;
	ScrollView *tabScroll_ = nullptr;
	ViewGroup *contents_ = nullptr;
	Orientation tabOrientation_ = ORIENT_HORIZONTAL;

	TabHolderFlags flags_ = TabHolderFlags::Default;
	int currentTab_ = 0;
	std::vector<ViewGroup *> tabs_;
	std::vector<AnchorTranslateTween *> tabTweens_;  // NOTE: The tweens are actually owned by the tabs.
	std::vector<std::function<ViewGroup *()>> createFuncs_;
};

class ChoiceStrip : public LinearLayout {
public:
	ChoiceStrip(Orientation orientation, LayoutParams *layoutParams = 0);
	
	void AddChoice(std::string_view title, ImageID imageId = ImageID::invalid());
	void AddChoice(ImageID buttonImage);
	void SetChoiceVisibility(int choice, bool visible);

	int GetSelection() const { return selected_; }
	void SetSelection(int sel, bool triggerClick);

	void EnableChoice(int choice, bool enabled);

	bool Key(const KeyInput &input) override;

	void SetTopTabs(bool tabs) { topTabs_ = tabs; }

	std::string DescribeLog() const override { return "ChoiceStrip: " + View::DescribeLog(); }
	std::string DescribeText() const override;

	Event OnChoice;

private:
	void OnChoiceClick(EventParams &e);

	std::vector<UI::StickyChoice *> choices_;
	int selected_ = 0;   // Can be controlled with L/R.
	bool topTabs_ = false;
};

}  // namespace
