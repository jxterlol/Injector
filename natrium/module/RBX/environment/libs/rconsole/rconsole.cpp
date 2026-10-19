#include "rconsole.hpp"

#include <RBX/environment/env.hpp>
#include <Utilitys/Globals.hpp>

#include <string>
#include <thread>
#include <mutex>
#include <queue>
#include <functional>

namespace RConsole
{
    static std::mutex ConsoleMutex;
    static std::queue<std::function<void()>> PendingOps;

    // ── Color token parser ──
    // Supports @@RED@@, @@BLUE@@, @@GREEN@@, @@YELLOW@@, @@WHITE@@, @@BLACK@@,
    // @@CYAN@@, @@MAGENTA@@, @@RESET@@, @@GRAY@@, @@BROWN@@, @@ORANGE@@, @@LIGHT_BLUE@@,
    // @@LIGHT_GREEN@@, @@LIGHT_CYAN@@, @@LIGHT_RED@@, @@LIGHT_MAGENTA@@

    static const struct { const char* name; WORD attr; } ColorTokens[] = {
        {"@@RESET@@",       FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE},
        {"@@RED@@",         FOREGROUND_RED},
        {"@@GREEN@@",       FOREGROUND_GREEN},
        {"@@BLUE@@",        FOREGROUND_BLUE},
        {"@@WHITE@@",       FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE},
        {"@@BLACK@@",       0},
        {"@@YELLOW@@",      FOREGROUND_RED | FOREGROUND_GREEN},
        {"@@CYAN@@",        FOREGROUND_GREEN | FOREGROUND_BLUE},
        {"@@MAGENTA@@",     FOREGROUND_RED | FOREGROUND_BLUE},
        {"@@GRAY@@",        FOREGROUND_INTENSITY},
        {"@@BROWN@@",       FOREGROUND_RED | FOREGROUND_INTENSITY},
        {"@@ORANGE@@",      FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY},
        {"@@LIGHT_BLUE@@",  FOREGROUND_BLUE | FOREGROUND_INTENSITY},
        {"@@LIGHT_GREEN@@", FOREGROUND_GREEN | FOREGROUND_INTENSITY},
        {"@@LIGHT_CYAN@@",  FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY},
        {"@@LIGHT_RED@@",   FOREGROUND_RED | FOREGROUND_INTENSITY},
        {"@@LIGHT_MAGENTA@@", FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY},
        {nullptr, 0}
    };

    DWORD ParseColorToken(const char*& text, DWORD& currentColor)
    {
        for (int i = 0; ColorTokens[i].name; ++i)
        {
            size_t len = strlen(ColorTokens[i].name);
            if (strncmp(text, ColorTokens[i].name, len) == 0)
            {
                currentColor = ColorTokens[i].attr;
                text += len;
                return currentColor;
            }
        }
        return currentColor;
    }

    bool EnsureConsole()
    {
        if (ConsoleHandle != INVALID_HANDLE_VALUE)
            return true;

        if (!AllocConsole())
            return false;

        ConsoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);
        ConsoleInputHandle = GetStdHandle(STD_INPUT_HANDLE);

        SetConsoleTitleA("Sodium");
        SetConsoleOutputCP(CP_UTF8);

        // Enable VT processing for ANSI if possible
        DWORD mode = 0;
        if (GetConsoleMode(ConsoleHandle, &mode))
            SetConsoleMode(ConsoleHandle, mode | ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);

        return true;
    }

    void WriteToConsole(const char* text, WORD color)
    {
        if (!EnsureConsole() || ConsoleHandle == INVALID_HANDLE_VALUE)
            return;

        const char* cursor = text;
        DWORD written = 0;

        while (*cursor)
        {
            // Check for color tokens
            if (*cursor == '@' && *(cursor + 1) == '@')
            {
                const char* before = cursor;
                DWORD dummy = color;
                DWORD newColor = ParseColorToken(cursor, dummy);
                if (cursor != before)
                {
                    // Flush text before token
                    if (before > text)
                        WriteConsoleA(ConsoleHandle, text, (DWORD)(before - text), &written, nullptr);
                    SetConsoleTextAttribute(ConsoleHandle, (WORD)newColor);
                    text = cursor;
                    color = (WORD)newColor;
                    continue;
                }
            }
            ++cursor;
        }

        // Flush remaining text
        if (cursor > text)
            WriteConsoleA(ConsoleHandle, text, (DWORD)(cursor - text), &written, nullptr);

        // Newline
        WriteConsoleA(ConsoleHandle, "\n", 1, &written, nullptr);
    }

    // ── Lua Functions ──

    int rconsolecreate(lua_State* L)
    {
        std::lock_guard<std::mutex> lock(ConsoleMutex);

        if (ConsoleHandle != INVALID_HANDLE_VALUE)
            return 0;

        EnsureConsole();
        return 0;
    }

    int rconsoledestroy(lua_State* L)
    {
        std::lock_guard<std::mutex> lock(ConsoleMutex);

        if (ConsoleHandle != INVALID_HANDLE_VALUE)
        {
            FreeConsole();
            ConsoleHandle = INVALID_HANDLE_VALUE;
            ConsoleInputHandle = INVALID_HANDLE_VALUE;
        }

        ConsoleVisible = true;
        ConsoleTopmost = false;
        return 0;
    }

    int rconsoleclear(lua_State* L)
    {
        std::lock_guard<std::mutex> lock(ConsoleMutex);

        if (!EnsureConsole())
            return 0;

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(ConsoleHandle, &csbi))
        {
            DWORD written = 0;
            DWORD cells = csbi.dwSize.X * csbi.dwSize.Y;
            COORD origin = {0, 0};
            FillConsoleOutputCharacterA(ConsoleHandle, ' ', cells, origin, &written);
            FillConsoleOutputAttribute(ConsoleHandle, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE, cells, origin, &written);
            SetConsoleCursorPosition(ConsoleHandle, origin);
        }

        return 0;
    }

    int rconsoleprint(lua_State* L)
    {
        std::lock_guard<std::mutex> lock(ConsoleMutex);

        if (!EnsureConsole())
            return 0;

        luaL_checkany(L, 1);

        std::string text;
        if (lua_isstring(L, 1) || lua_isnumber(L, 1))
        {
            const char* str = lua_tostring(L, 1);
            if (str) text = str;
        }
        else
        {
            lua_getglobal(L, "tostring");
            lua_pushvalue(L, 1);
            lua_call(L, 1, 1);
            const char* str = lua_tostring(L, -1);
            if (str) text = str;
            lua_pop(L, 1);
        }

        // Check if third arg is false -> don't escape
        bool escape = true;
        if (!lua_isnone(L, 3))
            escape = lua_toboolean(L, 3) != 0;

        WriteToConsole(text.c_str(), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        return 0;
    }

    int rconsoleinfo(lua_State* L)
    {
        std::lock_guard<std::mutex> lock(ConsoleMutex);

        if (!EnsureConsole())
            return 0;

        luaL_checkany(L, 1);

        std::string text;
        lua_getglobal(L, "tostring");
        lua_pushvalue(L, 1);
        lua_call(L, 1, 1);
        const char* str = lua_tostring(L, -1);
        if (str) text = str;
        lua_pop(L, 1);

        // Prefix with [INFO] in cyan
        std::string output = "@@CYAN@@@@LIGHT_BLUE@@[INFO]@@RESET@@ " + text;
        WriteToConsole(output.c_str(), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        return 0;
    }

    int rconsolewarn(lua_State* L)
    {
        std::lock_guard<std::mutex> lock(ConsoleMutex);

        if (!EnsureConsole())
            return 0;

        luaL_checkany(L, 1);

        std::string text;
        lua_getglobal(L, "tostring");
        lua_pushvalue(L, 1);
        lua_call(L, 1, 1);
        const char* str = lua_tostring(L, -1);
        if (str) text = str;
        lua_pop(L, 1);

        std::string output = "@@YELLOW@@@@LIGHT_GREEN@@[WARN]@@RESET@@ " + text;
        WriteToConsole(output.c_str(), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        return 0;
    }

    int rconsoleerr(lua_State* L)
    {
        std::lock_guard<std::mutex> lock(ConsoleMutex);

        if (!EnsureConsole())
        {
            // Still return the error string even if no console
            luaL_checkany(L, 1);
            lua_getglobal(L, "tostring");
            lua_pushvalue(L, 1);
            lua_call(L, 1, 1);
            return 1;
        }

        luaL_checkany(L, 1);

        std::string text;
        lua_getglobal(L, "tostring");
        lua_pushvalue(L, 1);
        lua_call(L, 1, 1);
        const char* str = lua_tostring(L, -1);
        if (str) text = str;
        lua_pop(L, 1);

        std::string output = "@@RED@@@@LIGHT_RED@@[ERROR]@@RESET@@ " + text;
        WriteToConsole(output.c_str(), FOREGROUND_RED | FOREGROUND_INTENSITY);

        // Also return the string
        lua_pushstring(L, text.c_str());
        return 1;
    }

    int rconsoleinput(lua_State* L)
    {
        std::lock_guard<std::mutex> lock(ConsoleMutex);

        if (!EnsureConsole())
        {
            lua_pushstring(L, "");
            return 1;
        }

        // Flush any pending output
        if (ConsoleHandle != INVALID_HANDLE_VALUE)
        {
            // Show prompt
            DWORD written = 0;
            WriteConsoleA(ConsoleHandle, "> ", 2, &written, nullptr);
        }

        char buffer[4096] = {0};
        DWORD read = 0;

        if (ConsoleInputHandle != INVALID_HANDLE_VALUE)
        {
            // Use ReadConsoleA for proper line input
            ReadConsoleA(ConsoleInputHandle, buffer, sizeof(buffer) - 1, &read, nullptr);

            // Remove trailing \r\n
            while (read > 0 && (buffer[read - 1] == '\n' || buffer[read - 1] == '\r'))
                buffer[--read] = '\0';
        }

        lua_pushstring(L, buffer);
        return 1;
    }

    int rconsolename(lua_State* L)
    {
        std::lock_guard<std::mutex> lock(ConsoleMutex);

        size_t len = 0;
        const char* name = luaL_checklstring(L, 1, &len);

        if (EnsureConsole() && name)
        {
            // Truncate to reasonable length
            char title[256] = {0};
            strncpy_s(title, name, min(len, (size_t)255));
            SetConsoleTitleA(title);
        }

        return 0;
    }

    int rconsoleshow(lua_State* L)
    {
        std::lock_guard<std::mutex> lock(ConsoleMutex);

        if (EnsureConsole())
        {
            HWND hwnd = GetConsoleWindow();
            if (hwnd)
            {
                ShowWindow(hwnd, SW_SHOW);
                ConsoleVisible = true;
            }
        }

        return 0;
    }

    int rconsolehide(lua_State* L)
    {
        std::lock_guard<std::mutex> lock(ConsoleMutex);

        HWND hwnd = GetConsoleWindow();
        if (hwnd)
        {
            ShowWindow(hwnd, SW_HIDE);
            ConsoleVisible = false;
        }

        return 0;
    }

    int rconsoletoggle(lua_State* L)
    {
        std::lock_guard<std::mutex> lock(ConsoleMutex);

        HWND hwnd = GetConsoleWindow();
        if (hwnd)
        {
            if (ConsoleVisible)
            {
                ShowWindow(hwnd, SW_HIDE);
                ConsoleVisible = false;
            }
            else
            {
                ShowWindow(hwnd, SW_SHOW);
                ConsoleVisible = true;
            }
        }

        return 0;
    }

    int rconsoletop(lua_State* L)
    {
        std::lock_guard<std::mutex> lock(ConsoleMutex);

        bool topmost = lua_isnone(L, 1) ? true : lua_toboolean(L, 1) != 0;

        HWND hwnd = GetConsoleWindow();
        if (hwnd)
        {
            HWND insertAfter = topmost ? HWND_TOPMOST : HWND_NOTOPMOST;
            SetWindowPos(hwnd, insertAfter, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            ConsoleTopmost = topmost;
        }

        return 0;
    }

    // ── Reset / Register ──

    void ResetLibraryState()
    {
        // Don't destroy the console on reset — just clear state flags
        ConsoleVisible = true;
        ConsoleTopmost = false;
    }

    void register_lib(lua_State* L)
    {
        funcnameinc = 0;

        // rconsolecreate / consolecreate
        Environment->make_aliases(L, rconsolecreate, funcnameinc++, {
            "rconsolecreate", "consolecreate"
            });

        // rconsoledestroy / consoledestroy
        Environment->make_aliases(L, rconsoledestroy, funcnameinc++, {
            "rconsoledestroy", "consoledestroy"
            });

        // rconsoleclear / consoleclear
        Environment->make_aliases(L, rconsoleclear, funcnameinc++, {
            "rconsoleclear", "consoleclear"
            });

        // rconsoleprint / consoleprint
        Environment->make_aliases(L, rconsoleprint, funcnameinc++, {
            "rconsoleprint", "consoleprint"
            });

        // rconsoleinfo
        Environment->make_global(L, "rconsoleinfo", rconsoleinfo, funcnameinc++);

        // rconsolewarn
        Environment->make_global(L, "rconsolewarn", rconsolewarn, funcnameinc++);

        // rconsoleerr
        Environment->make_global(L, "rconsoleerr", rconsoleerr, funcnameinc++);

        // rconsoleinput / consoleinput
        Environment->make_aliases(L, rconsoleinput, funcnameinc++, {
            "rconsoleinput", "consoleinput"
            });

        // rconsolename / rconsolesettitle / consolesettitle
        Environment->make_aliases(L, rconsolename, funcnameinc++, {
            "rconsolename", "rconsolesettitle", "consolesettitle"
            });

        // rconsoleshow
        Environment->make_global(L, "rconsoleshow", rconsoleshow, funcnameinc++);

        // rconsolehide
        Environment->make_global(L, "rconsolehide", rconsolehide, funcnameinc++);

        // rconsoletoggle
        Environment->make_global(L, "rconsoletoggle", rconsoletoggle, funcnameinc++);

        // rconsoletop
        Environment->make_global(L, "rconsoletop", rconsoletop, funcnameinc++);

        // rconsolehidden (alias for rconsolehide)
        Environment->make_global(L, "rconsolehidden", rconsolehide, funcnameinc++);
    }
}
