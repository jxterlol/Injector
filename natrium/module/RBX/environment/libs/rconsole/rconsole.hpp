#pragma once

#include <lstate.h>
#include <lualib.h>
#include <Windows.h>

namespace RConsole
{
    static int funcnameinc = 0;

    // State
    inline HANDLE ConsoleHandle = INVALID_HANDLE_VALUE;
    inline HANDLE ConsoleInputHandle = INVALID_HANDLE_VALUE;
    inline HMENU ConsoleMenu = nullptr;
    inline bool ConsoleVisible = true;
    inline bool ConsoleTopmost = false;

    // Registration
    int rconsolecreate(lua_State* L);
    int rconsoledestroy(lua_State* L);
    int rconsoleclear(lua_State* L);
    int rconsoleprint(lua_State* L);
    int rconsoleinfo(lua_State* L);
    int rconsolewarn(lua_State* L);
    int rconsoleerr(lua_State* L);
    int rconsoleinput(lua_State* L);
    int rconsolename(lua_State* L);
    int rconsoleshow(lua_State* L);
    int rconsolehide(lua_State* L);
    int rconsoletoggle(lua_State* L);
    int rconsoletop(lua_State* L);

    // Helpers
    void WriteToConsole(const char* text, WORD color);
    DWORD ParseColorToken(const char*& text, DWORD& currentColor);
    bool EnsureConsole();

    void register_lib(lua_State* L);
    void ResetLibraryState();
}
