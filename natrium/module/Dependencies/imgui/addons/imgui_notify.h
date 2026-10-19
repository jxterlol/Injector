


#ifndef IMGUI_NOTIFY
#define IMGUI_NOTIFY

#pragma once
#include <vector>
#include <string>
#include <chrono>
#include <mutex>
#include "../imgui.h"

#define NOTIFY_MAX_MSG_LENGTH			4096
#define NOTIFY_PADDING_X				20.f
#define NOTIFY_PADDING_Y				20.f
#define NOTIFY_PADDING_MESSAGE_Y		10.f
#define NOTIFY_FADE_IN_OUT_TIME			150
#define NOTIFY_DEFAULT_DISMISS			3000
#define NOTIFY_OPACITY					1.0f
#define NOTIFY_TOAST_FLAGS				ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoFocusOnAppearing

#define NOTIFY_USE_SEPARATOR

#define NOTIFY_INLINE					inline
#define NOTIFY_NULL_OR_EMPTY(str)		(!str ||! strlen(str))
#define NOTIFY_FORMAT(fn, format, ...)	if (format) { va_list args; va_start(args, format); fn(format, args, ##__VA_ARGS__); va_end(args); }

typedef int ImGuiToastType;
typedef int ImGuiToastPhase;
typedef int ImGuiToastPos;

enum ImGuiToastType_
{
	ImGuiToastType_None,
	ImGuiToastType_Success,
	ImGuiToastType_Warning,
	ImGuiToastType_Error,
	ImGuiToastType_Info,
	ImGuiToastType_COUNT
};

enum ImGuiToastPhase_
{
	ImGuiToastPhase_FadeIn,
	ImGuiToastPhase_Wait,
	ImGuiToastPhase_FadeOut,
	ImGuiToastPhase_Expired,
	ImGuiToastPhase_COUNT
};

enum ImGuiToastPos_
{
	ImGuiToastPos_TopLeft,
	ImGuiToastPos_TopCenter,
	ImGuiToastPos_TopRight,
	ImGuiToastPos_BottomLeft,
	ImGuiToastPos_BottomCenter,
	ImGuiToastPos_BottomRight,
	ImGuiToastPos_Center,
	ImGuiToastPos_COUNT
};

class ImGuiToast
{
private:
	ImGuiToastType	type = ImGuiToastType_None;
	char			title[NOTIFY_MAX_MSG_LENGTH];
	char			content[NOTIFY_MAX_MSG_LENGTH];
	int				dismiss_time = NOTIFY_DEFAULT_DISMISS;
	uint64_t		creation_time = 0;

private:


	NOTIFY_INLINE auto set_title(const char* format, va_list args) { vsnprintf(this->title, sizeof(this->title), format, args); }

	NOTIFY_INLINE auto set_content(const char* format, va_list args) { vsnprintf(this->content, sizeof(this->content), format, args); }

public:

	NOTIFY_INLINE auto set_title(const char* format, ...) -> void { NOTIFY_FORMAT(this->set_title, format); }

	NOTIFY_INLINE auto set_content(const char* format, ...) -> void { NOTIFY_FORMAT(this->set_content, format); }

	NOTIFY_INLINE auto set_type(const ImGuiToastType& type) -> void { IM_ASSERT(type < ImGuiToastType_COUNT); this->type = type; };

public:


	NOTIFY_INLINE auto get_title() -> char* { return this->title; };

	NOTIFY_INLINE auto get_default_title() -> const char*
	{
		if (!strlen(this->title))
		{
			switch (this->type)
			{
			case ImGuiToastType_None:
				return NULL;
			case ImGuiToastType_Success:
				return "Lunar";
			case ImGuiToastType_Warning:
				return "Lunar";
			case ImGuiToastType_Error:
				return "Lunar";
			case ImGuiToastType_Info:
				return "Lunar";
			default:
				return NULL;
			}
		}

		return this->title;
	};

	NOTIFY_INLINE auto get_type() -> const ImGuiToastType& { return this->type; };

	NOTIFY_INLINE auto get_color() -> const ImVec4
	{
		switch (this->type)
		{
		case ImGuiToastType_None:
			return { 1.f, 1.f, 1.f, 1.f };
		case ImGuiToastType_Success:
			return { 0.2f, 0.9f, 0.35f, 1.f };
		case ImGuiToastType_Warning:
			return { 1.f, 0.85f, 0.2f, 1.f };
		case ImGuiToastType_Error:
			return { 1.f, 0.3f, 0.3f, 1.f };
		case ImGuiToastType_Info:
			return { 0.25f, 0.65f, 1.f, 1.f };
		default:
			return { 1.f, 1.f, 1.f, 1.f };
		}
	}

	NOTIFY_INLINE auto get_icon() -> const char*
	{

		return NULL;
	}

	NOTIFY_INLINE auto get_content() -> char* { return this->content; };

	NOTIFY_INLINE auto get_dismiss_time() -> const int { return this->dismiss_time; };

	NOTIFY_INLINE auto get_elapsed_time() { return get_tick_count() - this->creation_time; }

	NOTIFY_INLINE auto get_phase() -> const ImGuiToastPhase
	{
		const auto elapsed = get_elapsed_time();

		if (elapsed > NOTIFY_FADE_IN_OUT_TIME + this->dismiss_time + NOTIFY_FADE_IN_OUT_TIME)
		{
			return ImGuiToastPhase_Expired;
		}
		else if (elapsed > NOTIFY_FADE_IN_OUT_TIME + this->dismiss_time)
		{
			return ImGuiToastPhase_FadeOut;
		}
		else if (elapsed > NOTIFY_FADE_IN_OUT_TIME)
		{
			return ImGuiToastPhase_Wait;
		}
		else
		{
			return ImGuiToastPhase_FadeIn;
		}
	}

	NOTIFY_INLINE auto get_fade_percent() -> const float
	{
		const auto phase = get_phase();
		const auto elapsed = get_elapsed_time();

		if (phase == ImGuiToastPhase_FadeIn)
		{
			return ((float)elapsed / (float)NOTIFY_FADE_IN_OUT_TIME) * NOTIFY_OPACITY;
		}
		else if (phase == ImGuiToastPhase_FadeOut)
		{
			return (1.f - (((float)elapsed - (float)NOTIFY_FADE_IN_OUT_TIME - (float)this->dismiss_time) / (float)NOTIFY_FADE_IN_OUT_TIME)) * NOTIFY_OPACITY;
		}

		return 1.f * NOTIFY_OPACITY;
	}

	NOTIFY_INLINE static auto get_tick_count() -> const unsigned long long
	{
		using namespace std::chrono;
		return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
	}

public:


	ImGuiToast(ImGuiToastType type, int dismiss_time = NOTIFY_DEFAULT_DISMISS)
	{
		IM_ASSERT(type < ImGuiToastType_COUNT);

		this->type = type;
		this->dismiss_time = dismiss_time;
		this->creation_time = get_tick_count();

		memset(this->title, 0, sizeof(this->title));
		memset(this->content, 0, sizeof(this->content));
	}

	ImGuiToast(ImGuiToastType type, const char* format, ...) : ImGuiToast(type) { NOTIFY_FORMAT(this->set_content, format); }

	ImGuiToast(ImGuiToastType type, int dismiss_time, const char* format, ...) : ImGuiToast(type, dismiss_time) { NOTIFY_FORMAT(this->set_content, format); }
};

namespace ImGui
{
	NOTIFY_INLINE std::vector<ImGuiToast> notifications;


	NOTIFY_INLINE std::mutex notifications_mutex;




	NOTIFY_INLINE void InsertNotification(const ImGuiToast& toast)
	{
		std::lock_guard<std::mutex> lock(notifications_mutex);
		notifications.push_back(toast);
	}





	NOTIFY_INLINE void RemoveNotification(int index)
	{
		std::lock_guard<std::mutex> lock(notifications_mutex);
		if (index >= 0 && index < static_cast<int>(notifications.size()))
			notifications.erase(notifications.begin() + index);
	}




	NOTIFY_INLINE void RenderNotifications()
	{


		std::lock_guard<std::mutex> lock(notifications_mutex);

		const auto vp_size = GetMainViewport()->Size;

		float height = 0.f;

		for (auto i = 0; i < (int)notifications.size(); i++)
		{
			auto* current_toast = &notifications[i];



			if (current_toast->get_phase() == ImGuiToastPhase_Expired)
			{
				notifications.erase(notifications.begin() + i);
				i--;
				continue;
			}


			const auto title = current_toast->get_title();
			const auto content = current_toast->get_content();
			const auto default_title = current_toast->get_default_title();
			const auto opacity = current_toast->get_fade_percent();
			const auto accent = current_toast->get_color();
			const auto phase = current_toast->get_phase();


			float slide = 0.f;
			if (phase == ImGuiToastPhase_FadeIn)
				slide = (1.f - (float)current_toast->get_elapsed_time() / (float)NOTIFY_FADE_IN_OUT_TIME) * 20.f;

			const int accent_r = (int)(accent.x * 255.f);
			const int accent_g = (int)(accent.y * 255.f);
			const int accent_b = (int)(accent.z * 255.f);
			const ImU32 accent32 = IM_COL32(accent_r, accent_g, accent_b, (int)(255.f * opacity));


			char window_name[50]{};
			snprintf(window_name, sizeof(window_name), "##TOAST%d", i);

			PushStyleColor(ImGuiCol_WindowBg, ImVec4(0.047f, 0.049f, 0.058f, 0.97f * opacity));
			PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(46.f, 10.f));
			PushStyleVar(ImGuiStyleVar_WindowRounding, 10.f);
			SetNextWindowPos(ImVec2(vp_size.x - NOTIFY_PADDING_X, vp_size.y - (NOTIFY_PADDING_Y + height) + slide), ImGuiCond_Always, ImVec2(1.0f, 1.0f));
			const bool visible = Begin(window_name, NULL, NOTIFY_TOAST_FLAGS);

			if (visible)
			{
				const ImVec2 pos = GetWindowPos();
				const ImVec2 size = GetWindowSize();
				ImDrawList* dl = GetWindowDrawList();

				PushClipRect(pos, ImVec2(pos.x + size.x, pos.y + size.y), false);


				dl->AddRect(pos, ImVec2(pos.x + size.x, pos.y + size.y),
					IM_COL32(accent_r, accent_g, accent_b, (int)(110.f * opacity)), 10.f, 0, 1.f);


				dl->AddRectFilled(ImVec2(pos.x + 2.f, pos.y + 8.f), ImVec2(pos.x + 5.f, pos.y + size.y - 8.f),
					accent32, 1.5f);


				const ImVec2 badge(pos.x + 26.f, pos.y + 11.f + GetFontSize() * 0.5f);
				dl->AddCircleFilled(badge, 10.f, IM_COL32(accent_r, accent_g, accent_b, (int)(55.f * opacity)));
				dl->AddCircle(badge, 10.f, IM_COL32(accent_r, accent_g, accent_b, (int)(170.f * opacity)), 16, 1.f);



				const ImU32 glyph = IM_COL32(255, 255, 255, (int)(245.f * opacity));
				switch (current_toast->get_type())
				{
				case ImGuiToastType_Success:
				{
					ImVec2 check[3] = {
						ImVec2(badge.x - 4.5f, badge.y + 0.5f),
						ImVec2(badge.x - 1.4f, badge.y + 3.6f),
						ImVec2(badge.x + 5.0f, badge.y - 3.6f) };
					dl->AddPolyline(check, 3, glyph, 0, 2.f);
					break;
				}
				case ImGuiToastType_Error:
					dl->AddLine(ImVec2(badge.x - 4.f, badge.y - 4.f), ImVec2(badge.x + 4.f, badge.y + 4.f), glyph, 2.f);
					dl->AddLine(ImVec2(badge.x + 4.f, badge.y - 4.f), ImVec2(badge.x - 4.f, badge.y + 4.f), glyph, 2.f);
					break;
				case ImGuiToastType_Warning:
					dl->AddLine(ImVec2(badge.x, badge.y - 5.f), ImVec2(badge.x, badge.y + 1.f), glyph, 2.f);
					dl->AddCircleFilled(ImVec2(badge.x, badge.y + 4.5f), 1.4f, glyph);
					break;
				default:
					dl->AddCircleFilled(ImVec2(badge.x, badge.y - 3.6f), 1.4f, glyph);
					dl->AddLine(ImVec2(badge.x, badge.y - 0.4f), ImVec2(badge.x, badge.y + 4.5f), glyph, 2.f);
					break;
				}


				const char* title_text = NOTIFY_NULL_OR_EMPTY(title) ? default_title : title;
				const bool has_title = !NOTIFY_NULL_OR_EMPTY(title_text);
				const bool has_content = !NOTIFY_NULL_OR_EMPTY(content);



				PushTextWrapPos(vp_size.x - NOTIFY_PADDING_X - 14.f);

				if (has_title)
					TextColored(ImVec4(0.97f, 0.97f, 0.98f, opacity), "%s", title_text);

				if (has_content)
				{
					if (has_title)
						SetCursorPosY(GetCursorPosY() + 2.f);
					TextColored(ImVec4(0.74f, 0.76f, 0.80f, 0.95f * opacity), "%s", content);
				}

				PopTextWrapPos();


				float remain = 1.f;
				if (phase == ImGuiToastPhase_Wait)
				{
					remain = 1.f - ((float)current_toast->get_elapsed_time() - (float)NOTIFY_FADE_IN_OUT_TIME)
						/ (float)current_toast->get_dismiss_time();
				}
				else if (phase == ImGuiToastPhase_FadeOut)
				{
					remain = 0.f;
				}
				if (remain < 0.f) remain = 0.f;
				else if (remain > 1.f) remain = 1.f;

				const float bar_left = pos.x + 12.f;
				const float bar_right = pos.x + size.x - 12.f;
				const float bar_y = pos.y + size.y - 5.f;
				dl->AddRectFilled(ImVec2(bar_left, bar_y), ImVec2(bar_right, bar_y + 2.5f),
					IM_COL32(255, 255, 255, (int)(20.f * opacity)), 1.25f);
				dl->AddRectFilled(ImVec2(bar_left, bar_y), ImVec2(bar_left + (bar_right - bar_left) * remain, bar_y + 2.5f),
					accent32, 1.25f);

				PopClipRect();
			}


			height += GetWindowHeight() + NOTIFY_PADDING_MESSAGE_Y;


			End();
			PopStyleVar(2);
			PopStyleColor(1);
		}
	}
}

#endif