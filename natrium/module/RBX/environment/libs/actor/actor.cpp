#include "actor.hpp"

#include <lstate.h>
#include <lualib.h>
#include <lgc.h>
#include <lapi.h>
#include <lobject.h>
#include <Windows.h>
#include <string>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <vector>

#include <RBX/environment/env.hpp>
#include <RBX/execution/execution.hpp>
#include <Utilitys/Globals.hpp>
#include <RBX/update.hpp>
#include <RBX/task_scheduler/task_scheduler.hpp>

#include <RBX/environment/libs/http/http.hpp>
#include <RBX/environment/libs/crypt/crypt.hpp>
#include <RBX/environment/libs/input/input.hpp>
#include <RBX/environment/libs/debug/debug.hpp>
#include <RBX/environment/libs/cache/cache.hpp>
#include <RBX/environment/libs/signals/signals.hpp>
#include <RBX/environment/libs/script/script.hpp>
#include <RBX/environment/libs/closures/closures.hpp>
#include <RBX/environment/libs/instance/instance.hpp>
#include <RBX/environment/libs/websocket/websocket.hpp>
#include <RBX/environment/libs/metatable/metatable.hpp>
#include <RBX/environment/libs/filesystem/filesystem.hpp>
#include <RBX/environment/libs/reflection/reflection.hpp>
#include <RBX/environment/libs/miscellaneous/miscellaneous.hpp>
#include <RBX/environment/libs/regex/regex.hpp>
#include <RBX/environment/libs/filedialog/filedialog.hpp>

// ── signal_safe_read ──────────────────────────────────────────
static inline bool signal_safe_read(const void* address, void* output, size_t size)
{
    if (!address || !output || !size) return false;
    MEMORY_BASIC_INFORMATION info{};
    if (!VirtualQuery(address, &info, sizeof(info)) || info.State != MEM_COMMIT ||
        (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
        return false;
    const uintptr_t start = reinterpret_cast<uintptr_t>(address);
    const uintptr_t end = reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
    if (start + size < start || start + size > end) return false;
    __try { memcpy(output, address, size); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

namespace Actor
{

    static std::string s_isparallelBytecode;
    static bool s_isparallelBytecodeReady = false;

    static std::string BuildIsparallelSource(bool PublishToGenv)
    {
        std::string src = R"LUA(
local ok, realtask = pcall(function()
    return task
end)
if not ok or typeof(realtask) ~= "table" then
    return
end

local threads = setmetatable({}, { __mode = "k" })
local copy = table.clone(realtask)

local okd, orig_desync = pcall(function()
    return rawget(copy, "desynchronize")
end)
local oks, orig_sync = pcall(function()
    return rawget(copy, "synchronize")
end)

if okd and typeof(orig_desync) == "function" then
    copy.desynchronize = function(...)
        orig_desync(...)
        threads[coroutine.running()] = true
    end
end

if oks and typeof(orig_sync) == "function" then
    copy.synchronize = function(...)
        orig_sync(...)
        threads[coroutine.running()] = nil
    end
end

local function current()
    return threads[coroutine.running()] == true
end
)LUA";

        if (PublishToGenv)
        {
            src += R"LUA(
local genv = getgenv and getgenv()
if genv then
    genv.task = copy
    genv.isparallel = current
end
)LUA";
        }
        else
        {
            src += R"LUA(
task = copy
isparallel = current
)LUA";
        }

        return src;
    }

    void QueueMainIsparallelBootstrap()
    {
        task_scheduler::RequestExecution(BuildIsparallelSource(true));
    }

    static void inject_isparallel_wrapper(lua_State* thread, lua_State* L)
    {

        if (!s_isparallelBytecodeReady)
        {
            s_isparallelBytecode = Execution::CompileScript(BuildIsparallelSource(false));
            s_isparallelBytecodeReady = !s_isparallelBytecode.empty();
        }
        if (!s_isparallelBytecodeReady) return;
        if (luau_load(thread, "=isparallel_init", s_isparallelBytecode.data(), s_isparallelBytecode.size(), NULL) != LUA_OK)
            return;
        task_scheduler::SetProtoCapabilities(clvalue(luaA_toobject(thread, -1))->l.p, &MaxCapabilities);
        lua_resume(thread, L, 0);
        lua_settop(thread, 0);
    }
    // ═══════════════════════════════════════════════════════════
    //  getactors
    // ═══════════════════════════════════════════════════════════
    int getactors(lua_State* L)
    {
        lua_newtable(L);
        int resultIdx = lua_gettop(L);
        int index = 0;

        lua_getglobal(L, "game");
        if (lua_isnil(L, -1)) { lua_pop(L, 1); return 1; }

        lua_getfield(L, -1, "GetDescendants");
        if (!lua_isfunction(L, -1)) { lua_pop(L, 2); return 1; }

        lua_pushvalue(L, -2);
        if (lua_pcall(L, 1, 1, 0) != LUA_OK) { lua_pop(L, 2); return 1; }
        if (!lua_istable(L, -1)) { lua_pop(L, 2); return 1; }

        int len = (int)lua_objlen(L, -1);
        for (int i = 1; i <= len; i++) {
            lua_rawgeti(L, -1, i);
            if (lua_isuserdata(L, -1)) {
                lua_getfield(L, -1, "ClassName");
                if (lua_isstring(L, -1) && strcmp(lua_tostring(L, -1), "Actor") == 0) {
                    lua_pop(L, 1);
                    lua_pushinteger(L, ++index);
                    lua_insert(L, -2);
                    lua_settable(L, resultIdx);
                }
                else { lua_pop(L, 2); }
            }
            else { lua_pop(L, 1); }
        }
        lua_pop(L, 2);
        return 1;
    }

    // ═══════════════════════════════════════════════════════════
    //  isparallel — C-level read of actor parallel flag
    // ═══════════════════════════════════════════════════════════

    bool CheckMemory(uintptr_t address)
    {
        if (address < 0x10000 || address > 0x7FFFFFFFFFFF)
            return false;

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) == 0)
            return false;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
            return false;
        return true;
    }

    // __try cannot share a function frame with C++ objects that require
    // unwinding (C2712), so the guarded read lives in its own function.
    bool ReadParallelFlag(uintptr_t actorPtr)
    {
        bool set = false;
        __try
        {
            set = *reinterpret_cast<const uint8_t*>(actorPtr + ParallelFlag) != 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            set = false;
        }
        return set;
    }



    int isparallel(lua_State* L)
    {
        if (!L) { lua_pushboolean(L, false); return 1; }

        const auto extra = reinterpret_cast<RobloxExtraSpace*>(
            reinterpret_cast<std::uintptr_t>(L->userdata));
        if (!extra) { lua_pushboolean(L, false); return 1; }

        auto actorPtr = extra->actor.lock();
        if (!actorPtr) { lua_pushboolean(L, false); return 1; }

        const auto actor = *actorPtr;
        if (!actor) { lua_pushboolean(L, false); return 1; }

        std::uintptr_t inner = 0;
        if (!signal_safe_read(reinterpret_cast<const void*>(actor + 0x18),
            &inner, sizeof(inner)) || !inner)
        {
            lua_pushboolean(L, false); return 1;
        }

        std::uintptr_t v8 = 0;
        if (!signal_safe_read(reinterpret_cast<const void*>(inner + 0x28),
            &v8, sizeof(v8)) || !v8)
        {
            lua_pushboolean(L, false); return 1;
        }

        std::uint8_t parallel = 0;
        if (!signal_safe_read(reinterpret_cast<const void*>(v8 + 0x100),
            &parallel, sizeof(parallel)))
        {
            lua_pushboolean(L, false); return 1;
        }

        lua_pushboolean(L, parallel != 0);
        return 1;
    }
    // ═══════════════════════════════════════════════════════════
    //  run_on_actor
    // ═══════════════════════════════════════════════════════════
    int run_on_actor(lua_State* L)
    {
        luaL_checktype(L, 1, LUA_TUSERDATA);
        luaL_checktype(L, 2, LUA_TSTRING);

        lua_getfield(L, 1, "ClassName");
        const auto class_name = std::string_view(lua_tolstring(L, -1, nullptr));
        lua_pop(L, 1);

        if (class_name != "Actor") {
            luaL_argerror(L, 1, "Actor expected");
            return 0;
        }

        auto actor = *reinterpret_cast<__int64*>(lua_touserdata(L, 1));
        auto Code = lua_tostring(L, 2);

        lua_remove(L, 2);
        lua_remove(L, 1);
        int Args = lua_gettop(L);

        lua_getglobal(L, "Instance");
        lua_getfield(L, -1, "new");
        lua_pushstring(L, "LocalScript");
        lua_call(L, 1, 1);
        auto LocalScript = *reinterpret_cast<uintptr_t*>(lua_touserdata(L, -1));
        *reinterpret_cast<std::uintptr_t*>(LocalScript + Offsets::Instance::Parent) = actor;

        const std::uintptr_t ScriptContext = reinterpret_cast<std::uintptr_t>(L->userdata->shared->scriptContext); /* S H A R E D SKID LESS*/
        uintptr_t unused = 0;
        lua_State* ActorState = reinterpret_cast<lua_State*>(
            task_scheduler::GetLuaState(ScriptContext, unused, LocalScript));

        auto NL = lua_newthread(ActorState);
        lua_pop(ActorState, 1);
        NL->userdata->actor = std::make_shared<uintptr_t>(static_cast<uintptr_t>(actor));
        task_scheduler::SetThreadCapabilities(NL, 8, MaxCapabilities);
        luaL_sandboxthread(NL);
        lua_settop(NL, 0);

        lua_newtable(NL); lua_setglobal(NL, "_G");
        lua_newtable(NL); lua_setglobal(NL, "shared");
        using namespace module::core::environment;

        http.register_lib(NL);
        Crypt::register_lib(NL);
        Input::register_lib(NL);
        Debug::register_lib(NL);
        Cache::register_lib(NL);
        Signals::register_lib(NL);
        Script::register_lib(NL);
        Closures::register_lib(NL);
        Instance::register_lib(NL);
        Websocket::register_lib(NL);
        Metatable::register_lib(NL);
        Filesystem::register_lib(NL);
        Reflection::register_lib(NL);
        Miscellaneous::register_lib(NL);
        Regex::register_lib(NL);
        FileDialog::register_lib(NL);

        // Register comm channel functions on actor thread
        Environment->make_global(NL, "get_comm_channel", Actor::get_comm_channel, 0);
        Environment->make_global(NL, "create_comm_channel", Actor::create_comm_channel, 0);

        // Inject isparallel Lua wrapper (overrides C-level with coroutine-aware version)
        inject_isparallel_wrapper(NL, L);

        // Deep copy helper
        std::function<void(lua_State*, lua_State*, int)> deepCopy =
            [&](lua_State* src, lua_State* dst, int idx)
            {
                int absIdx = lua_absindex(src, idx);
                switch (lua_type(src, absIdx))
                {
                case LUA_TTABLE: {
                    lua_newtable(dst);
                    lua_pushnil(src);
                    while (lua_next(src, absIdx)) {
                        deepCopy(src, dst, -2);
                        deepCopy(src, dst, -1);
                        lua_settable(dst, -3);
                        lua_pop(src, 1);
                    }
                    break;
                }
                case LUA_TUSERDATA: {
                    if (strcmp(luaL_typename(src, absIdx), "Instance") == 0)
                        Roblox::Void2(dst, lua_touserdata(src, absIdx));
                    else { lua_pushvalue(src, absIdx); lua_xmove(src, dst, 1); }
                    break;
                }
                case LUA_TSTRING: {
                    size_t len = 0;
                    const char* str = lua_tolstring(src, absIdx, &len);
                    lua_pushlstring(dst, str, len);
                    break;
                }
                case LUA_TNUMBER: lua_pushnumber(dst, lua_tonumber(src, absIdx)); break;
                case LUA_TBOOLEAN: lua_pushboolean(dst, lua_toboolean(src, absIdx)); break;
                case LUA_TNIL: lua_pushnil(dst); break;
                default: lua_pushvalue(src, absIdx); lua_xmove(src, dst, 1); break;
                }
            };

        std::string Bytecode = Execution::CompileScript(Code);
        int LoadResult = luau_load(NL, "Xploits", Bytecode.c_str(), Bytecode.size(), 0);
        if (LoadResult == LUA_OK) {
            if (Closure* Cl = clvalue(luaA_toobject(NL, -1)))
                if (Cl && Cl->l.p)
                    task_scheduler::SetProtoCapabilities(Cl->l.p, &MaxCapabilities);
            for (int i{ 1 }; i <= Args; i++)
                deepCopy(L, NL, i);
            Roblox::TaskDefer(NL);
        }
        else {
            const char* err = lua_tostring(NL, -1);
            lua_pop(NL, 1);
            luaL_error(L, "%s", err);
            return 0;
        }
        return 0;
    }

    int runonactor(lua_State* L) { return run_on_actor(L); }

    // ═══════════════════════════════════════════════════════════
    //  Comm channels — cross-thread safe via YieldQueue
    // ═══════════════════════════════════════════════════════════
    struct CommArg {
        enum Type { NIL, BOOLEAN, NUMBER, STRING, USERDATA };
        Type type = NIL;
        bool boolVal = false;
        double numVal = 0;
        std::string strVal;
        void* udPtr = nullptr;
    };

    struct CommChannelData {
        int channelRef;     // ref to channel table on main thread
        int signalRef;      // ref to .Event Signal on main thread
        lua_State* mainL;   // the thread that created it
    };

    static std::mutex commMutex;
    static std::unordered_map<int, CommChannelData> commIdToData;
    static int nextCommId = 1;

    // ── comm_fire dispatch: collects args, fires via YieldQueue ──
    static void DispatchFire(int commId, lua_State* callingL, int argStart, int nargs)
    {
        CommChannelData channelData;
        {
            std::lock_guard<std::mutex> lock(commMutex);
            auto it = commIdToData.find(commId);
            if (it == commIdToData.end()) return;
            channelData = it->second;
        }

        // Collect args from calling thread's stack
        auto args = std::make_shared<std::vector<CommArg>>();
        for (int i = 0; i < nargs; i++) {
            int idx = argStart + i;
            CommArg arg;
            switch (lua_type(callingL, idx)) {
            case LUA_TNIL:     arg.type = CommArg::NIL; break;
            case LUA_TBOOLEAN: arg.type = CommArg::BOOLEAN; arg.boolVal = lua_toboolean(callingL, idx) != 0; break;
            case LUA_TNUMBER:  arg.type = CommArg::NUMBER; arg.numVal = lua_tonumber(callingL, idx); break;
            case LUA_TSTRING: {
                size_t len = 0;
                const char* s = lua_tolstring(callingL, idx, &len);
                arg.type = CommArg::STRING;
                arg.strVal.assign(s, len);
                break;
            }
            case LUA_TUSERDATA: {
                arg.type = CommArg::USERDATA;
                arg.udPtr = lua_touserdata(callingL, idx);
                break;
            }
            default: arg.type = CommArg::NIL; break;
            }
            args->push_back(arg);
        }

        lua_State* mainL = channelData.mainL;
        int signalRef = channelData.signalRef;

        Shared::YieldQueue.emplace([mainL, signalRef, args]() {
            lua_getref(mainL, signalRef);
            if (!lua_istable(mainL, -1)) { lua_pop(mainL, 1); return; }

            lua_getfield(mainL, -1, "Fire");
            if (!lua_isfunction(mainL, -1)) { lua_pop(mainL, 2); return; }

            // Stack: [Signal, Fire]
            lua_insert(mainL, 1);
            // Stack: [Fire, Signal]

            for (auto& arg : *args) {
                switch (arg.type) {
                case CommArg::NIL:     lua_pushnil(mainL); break;
                case CommArg::BOOLEAN: lua_pushboolean(mainL, arg.boolVal); break;
                case CommArg::NUMBER:  lua_pushnumber(mainL, arg.numVal); break;
                case CommArg::STRING:  lua_pushlstring(mainL, arg.strVal.data(), (int)arg.strVal.size()); break;
                case CommArg::USERDATA: Roblox::Void2(mainL, arg.udPtr); break;
                }
            }
            // Stack: [Fire, Signal, a1, a2, ..., aN]
            lua_call(mainL, (int)args->size() + 1, 0);
            });
    }

    // ── comm_fire: called when channel:Fire(...) is invoked ────
    static int comm_fire(lua_State* L)
    {
        int commId = (int)lua_tointeger(L, lua_upvalueindex(1));
        int nargs = lua_gettop(L) - 1; // exclude self
        if (nargs < 0) nargs = 0;

        DispatchFire(commId, L, 2, nargs);
        return 0;
    }

    // ── create_comm_channel() ──────────────────────────────────
    int create_comm_channel(lua_State* L)
    {
        int commId;
        {
            std::lock_guard<std::mutex> lock(commMutex);
            commId = nextCommId++;
        }

        lua_newtable(L);
        int objIdx = lua_gettop(L);

        // Create Signal for .Event
        lua_getglobal(L, "Signal");
        if (lua_istable(L, -1)) {
            lua_getfield(L, -1, "new");
            if (lua_isfunction(L, -1)) {
                if (lua_pcall(L, 0, 1, 0) == LUA_OK) {
                    lua_setfield(L, objIdx, "Event");
                }
                else {
                    lua_pop(L, 1);
                    lua_newtable(L);
                    lua_setfield(L, objIdx, "Event");
                }
            }
            else {
                lua_pop(L, 1);
                lua_newtable(L);
                lua_setfield(L, objIdx, "Event");
            }
        }
        else {
            lua_pop(L, 1);
            lua_newtable(L);
            lua_setfield(L, objIdx, "Event");
        }

        // Ref the .Event Signal for cross-thread fire
        lua_getfield(L, objIdx, "Event");
        int signalRef = lua_ref(L, -1);
        lua_pop(L, 1);

        // Ref the channel object itself
        lua_pushvalue(L, objIdx);
        int channelRef = lua_ref(L, -1);
        lua_pop(L, 1);

        {
            std::lock_guard<std::mutex> lock(commMutex);
            commIdToData[commId] = { channelRef, signalRef, L };
        }

        // Fire function (works on main thread directly)
        lua_pushinteger(L, commId);
        lua_pushcclosure(L, comm_fire, "CommFire", 1);
        lua_setfield(L, objIdx, "Fire");

        lua_pushinteger(L, commId);
        lua_pushvalue(L, objIdx);
        return 2;
    }

    // ── get_comm_channel() ─────────────────────────────────────
    int get_comm_channel(lua_State* L)
    {
        if (lua_gettop(L) < 1 || lua_isnil(L, 1)) {
            lua_pushnil(L);
            return 1;
        }

        int commId = (int)lua_tointeger(L, 1);

        std::lock_guard<std::mutex> lock(commMutex);
        auto it = commIdToData.find(commId);
        if (it == commIdToData.end()) {
            lua_pushnil(L);
            return 1;
        }

        // Same thread as creator — return ref directly
        if (L == it->second.mainL) {
            lua_getref(L, it->second.channelRef);
            return 1;
        }

        // Different thread (actor thread) — return proxy table with Fire
        lua_newtable(L);

        // Fire closure that dispatches via YieldQueue
        lua_pushinteger(L, commId);
        lua_pushcclosure(L, comm_fire, "CommFire", 1);
        lua_setfield(L, -2, "Fire");

        return 1;
    }

    // ═══════════════════════════════════════════════════════════
    //  register_lib
    // ═══════════════════════════════════════════════════════════
    void register_lib(lua_State* L)
    {
        Environment->make_global(L, "getactors", Actor::getactors, funcnameinc++);
        Environment->make_global(L, "getactorthreads", Actor::getactors, funcnameinc++);
          Environment->make_global(L, "isparallel", Actor::isparallel, funcnameinc++);
          Environment->make_global(L, "checkparallel", Actor::isparallel, funcnameinc++);
        Environment->make_global(L, "run_on_actor", Actor::run_on_actor, funcnameinc++);
        Environment->make_global(L, "runonactor", Actor::runonactor, funcnameinc++);
        Environment->make_global(L, "runonthread", Actor::runonactor, funcnameinc++);
        Environment->make_global(L, "create_comm_channel", Actor::create_comm_channel, funcnameinc++);
        Environment->make_global(L, "get_comm_channel", Actor::get_comm_channel, funcnameinc++);
    }
}
