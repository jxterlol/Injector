#pragma once
#include <queue>
#include <string>
#include <vector>
#include <lstate.h>
#include <lgc.h>
#include <functional>
#include <lstate.h>
#include <string>
#include <queue>
#include <functional>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <mutex>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <unordered_set>

#define lua_pushoclosure(L, C) setclvalue(L, L->top, C); incr_top(L)
#define lua_tomutclosure(L, idx) const_cast<Closure*>(reinterpret_cast<const Closure*>(lua_topointer(L, idx)))
inline uintptr_t MaxCapabilities = 0xFFFFFFFFFFFFFFFF;

inline std::string GenerateRandomName(int len = 12)
{
    static const char* charset = ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    std::string result;
    result.reserve(len);
    unsigned int seed = static_cast<unsigned int>(__rdtsc()) ^ static_cast<unsigned int>(GetTickCount64());
    for (int i = 0; i < len; ++i)
    {
        seed = seed * 1664525u + 1013904223u;
        result += charset[(seed >> 16) % 62];
    }
    return result;
}
namespace Shared
{
    inline uintptr_t LastDataModel;
    inline uintptr_t ScriptContext;
    inline lua_State* ExploitThread;
    inline lua_State* RobloxState;
    inline int RobloxPcallRef = LUA_NOREF;

    inline std::atomic<uint64_t> StateGeneration{ 0 };
    inline std::vector<std::string> ExecutionRequests;
    inline std::mutex ExecutionRequestsMutex;
    inline std::vector<std::string> TeleportQueue;

    inline std::mutex TeleportQueueMutex;

    inline std::queue<std::function<void()>> YieldQueue;
    inline std::mutex YieldQueueMutex;

    inline std::filesystem::path workspace_folder;
    inline std::filesystem::path autoexecute_folder;
    inline std::unordered_set<Closure*> ExecutorClosures;

    inline std::unordered_set<lua_State*> ExecutorThreads;

    inline std::atomic_bool JobStepLocked{ true };
    inline std::mutex JobHookMutex;
    inline std::atomic_bool IsInitializedOnGame{ false };

    using JobStep_t = uintptr_t(__fastcall*)(uintptr_t Job, uintptr_t Stats);
    inline JobStep_t OriginalStepFunction = nullptr;
    inline uintptr_t LastWaitingHybridScriptsJob = 0;
    inline uintptr_t* OriginalHybridJobVtable = nullptr;
    inline uintptr_t* HybridJobVtable = nullptr;
    inline uintptr_t MaxCapabilities = 0xFFFFFFFFFFFFFFFF;
}

static LuaTable* getcurrenv(lua_State* L)
{
    if (L->ci == L->base_ci)
        return L->gt;
    else
        return curr_func(L)->env;
}

static LUAU_NOINLINE TValue* pseudo2addr(lua_State* L, int idx)
{
    api_check(L, lua_ispseudo(idx));
    switch (idx)
    {
    case LUA_REGISTRYINDEX:
        return registry(L);
    case LUA_ENVIRONINDEX:
    {
        sethvalue(L, &L->global->pseudotemp, getcurrenv(L));
        return &L->global->pseudotemp;
    }
    case LUA_GLOBALSINDEX:
    {
        sethvalue(L, &L->global->pseudotemp, L->gt);
        return &L->global->pseudotemp;
    }
    default:
    {
        Closure* func = curr_func(L);
        idx = LUA_GLOBALSINDEX - idx;
        return (idx <= func->nupvalues) ? &func->c.upvals[idx - 1] : cast_to(TValue*, luaO_nilobject);
    }
    }
}

static LUAU_FORCEINLINE TValue* index2addr(lua_State* L, int idx)
{
    if (idx > 0)
    {
        TValue* o = L->base + (idx - 1);
        api_check(L, idx <= L->ci->top - L->base);
        if (o >= L->top)
            return cast_to(TValue*, luaO_nilobject);
        else
            return o;
    }
    else if (idx > LUA_REGISTRYINDEX)
    {
        api_check(L, idx != 0 && -idx <= L->top - L->base);
        return L->top + idx;
    }
    else
    {
        return pseudo2addr(L, idx);
    }
}