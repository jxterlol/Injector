#pragma once

// Moon anti-afk.
// Two families of action:
//   - virtual input (Roblox VirtualInputManager) -> works while unfocused, touches nothing outside the game
//   - OS input (F13 / mouse jiggle) -> needs the game focused
// Header only - safe to include from any translation unit.

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>

#include <globals.h>
#include <Utilitys/Log.hpp>

namespace antiafk
{
    enum Mode : int
    {
        Mode_VimAlt = 0,
        Mode_VimJump,
        Mode_OsF13,
        Mode_OsJiggle,
        Mode_Count
    };

    inline std::atomic<bool> enabled{ false };
    inline std::atomic<int> mode{ Mode_VimAlt };
    inline std::atomic<int> interval{ 120 };      // seconds
    inline std::atomic<bool> os_needs_focus{ true };
    inline std::atomic<bool> log_actions{ true };
    inline std::atomic<long long> total_actions{ 0 };
    inline std::atomic<long long> next_due_ms{ 0 };
    inline std::atomic<bool> started{ false };

    inline const char* mode_name(int m)
    {
        switch (m)
        {
        case Mode_VimAlt:   return "Virtual Input - RightAlt";
        case Mode_VimJump:  return "Virtual Input - Jump";
        case Mode_OsF13:    return "OS Key - F13";
        case Mode_OsJiggle: return "OS Mouse Jiggle";
        default:            return "unknown";
        }
    }

    inline bool is_virtual_mode(int m)
    {
        return m == Mode_VimAlt || m == Mode_VimJump;
    }

    inline bool game_focused()
    {
        HWND fg = GetForegroundWindow();
        if (!fg) return false;
        DWORD pid = 0;
        GetWindowThreadProcessId(fg, &pid);
        return pid == GetCurrentProcessId();
    }

    inline void queue_lua(const std::string& src)
    {
        std::lock_guard<std::mutex> lk(Shared::ExecutionRequestsMutex);
        Shared::ExecutionRequests.push_back(src);
    }

    inline void push_vim(const char* key)
    {
        char buf[512];
        std::snprintf(buf, sizeof(buf),
            "pcall(function() local v = game:GetService(\"VirtualInputManager\") "
            "v:SendKeyEvent(true, Enum.KeyCode.%s, false, game) "
            "v:SendKeyEvent(false, Enum.KeyCode.%s, false, game) end)",
            key, key);
        queue_lua(buf);
    }

    inline void os_key(BYTE vk)
    {
        keybd_event(vk, 0, 0, 0);
        Sleep(12);
        keybd_event(vk, 0, KEYEVENTF_KEYUP, 0);
    }

    inline void os_jiggle()
    {
        static LONG dir = 1;
        INPUT in[2]{};
        in[0].type = INPUT_MOUSE;
        in[0].mi.dx = dir;
        in[0].mi.dy = dir;
        in[0].mi.dwFlags = MOUSEEVENTF_MOVE;
        in[1] = in[0];
        in[1].mi.dx = -dir;
        in[1].mi.dy = -dir;
        SendInput(2, in, sizeof(INPUT));
        dir = (dir == 1) ? -1 : 1;
    }

    inline void perform()
    {
        const int m = mode.load();
        const bool virtual_mode = is_virtual_mode(m);

        if (virtual_mode)
        {
            if (m == Mode_VimAlt)  push_vim("RightAlt");
            if (m == Mode_VimJump) push_vim("Space");
        }
        else
        {
            if (os_needs_focus.load() && !game_focused()) return;
            if (m == Mode_OsF13)    os_key(0x7C);   // VK_F13
            if (m == Mode_OsJiggle) os_jiggle();
        }

        total_actions.fetch_add(1);
        if (log_actions.load())
            LOGF("AntiAFK", "tick #%lld - %s", total_actions.load(), mode_name(m));
    }

    inline long long seconds_until_next()
    {
        long long due = next_due_ms.load();
        if (due == 0) return -1;
        long long left = due - (long long)GetTickCount64();
        return left < 0 ? 0 : (left + 999) / 1000;
    }

    inline void start()
    {
        static std::once_flag once;
        std::call_once(once, []()
        {
            started.store(true);
            std::thread([]()
            {
                for (;;)
                {
                    Sleep(250);
                    if (!enabled.load())
                    {
                        next_due_ms.store(0);
                        continue;
                    }

                    long long now = (long long)GetTickCount64();
                    long long due = next_due_ms.load();
                    if (due == 0)
                    {
                        due = now + (long long)interval.load() * 1000;
                        next_due_ms.store(due);
                        continue;
                    }

                    if (now < due) continue;

                    perform();
                    next_due_ms.store(now + (long long)interval.load() * 1000);
                }
            }).detach();
        });
    }

    inline void set_enabled(bool on)
    {
        if (on) start();
        enabled.store(on);
        if (on)
            LOGF("AntiAFK", "enabled - %s every %ds", mode_name(mode.load()), interval.load());
        else
            LOGF("AntiAFK", "disabled");
    }
}
