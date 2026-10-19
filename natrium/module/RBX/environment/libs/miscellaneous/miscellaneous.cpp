#include "Miscellaneous.hpp"

#include <lgc.h>
#include <lstate.h>
#include <lualib.h>

#include <Windows.h>
#include <shlobj.h>
#include <cstdio>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <RBX/execution/execution.hpp>
#include <RBX/environment/libs/script/script.hpp>
#include <RBX/environment/libs/http/http.hpp>
#include <map>
#include <string>
#include <sstream>
#include <lualib.h>
#include <optional>
#include <algorithm>
#include <Windows.h>

#include <chrono>
#include <cstdlib>
#include <cctype>
#include <mutex>


#include <Dependencies/nlohmann/json.hpp>
#include <RBX/environment/env.hpp>
#include <RBX/environment/yielding/yielding.hpp>

#include <Utilitys/Utils.hpp>
#include <Utilitys/Globals.hpp>
#include <RBX/execution/execution.hpp>
#include <RBX/environment/yielding/yielding.hpp>
#include <RBX/environment/env.hpp>
#include <RBX/task_scheduler/task_scheduler.hpp>
#include <RBX/fflags.hpp>


namespace Miscellaneous {

    // ??????????????????????????????????????????????????????????????
    //  Tovek local decompiler client
    // ??????????????????????????????????????????????????????????????

    namespace Tovek {

        static std::mutex LaunchMutex;
        static bool Launched = false;

        // Directory this module lives in - decompiler.exe is dropped beside it.
        static std::wstring ModuleDirectory()
        {
            HMODULE module = nullptr;
            if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(&ModuleDirectory), &module))
                return {};

            wchar_t path[MAX_PATH] = {};
            const DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
            if (length == 0 || length >= MAX_PATH)
                return {};

            std::wstring full(path, length);
            const size_t slash = full.find_last_of(L"\\/");
            if (slash == std::wstring::npos)
                return {};
            return full.substr(0, slash);
        }

        std::wstring DecompilerPath()
        {
            static const std::wstring cached = []() -> std::wstring {
                const std::wstring directory = ModuleDirectory();
                if (!directory.empty())
                {
                    const std::wstring candidate = directory + L"\\" + kExeName;
                    if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
                        return candidate;
                }

                wchar_t executable[MAX_PATH] = {};
                const DWORD length = GetModuleFileNameW(nullptr, executable, MAX_PATH);
                if (length > 0 && length < MAX_PATH)
                {
                    std::wstring full(executable, length);
                    const size_t slash = full.find_last_of(L"\\/");
                    if (slash != std::wstring::npos)
                    {
                        const std::wstring candidate = full.substr(0, slash) + L"\\" + kExeName;
                        if (GetFileAttributesW(candidate.c_str()) != INVALID_FILE_ATTRIBUTES)
                            return candidate;
                    }
                }
                return {};
            }();
            return cached;
        }

        bool LaunchServer(std::wstring& error)
        {
            const std::lock_guard<std::mutex> lock(LaunchMutex);

            const std::wstring path = DecompilerPath();
            if (path.empty())
            {
                error = L"decompiler.exe not found next to sodium.dll";
                return false;
            }

            if (Launched)
                return true;

            std::wstring command = L"\"" + path + L"\"";

            STARTUPINFOW startup{};
            startup.cb = sizeof(startup);
            startup.dwFlags = STARTF_USESHOWWINDOW;
            startup.wShowWindow = SW_HIDE;

            PROCESS_INFORMATION process{};
            const BOOL ok = CreateProcessW(
                path.c_str(), command.data(), nullptr, nullptr, FALSE,
                CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                nullptr, nullptr, &startup, &process);

            if (!ok)
            {
                error = L"CreateProcessW failed (" + std::to_wstring(GetLastError()) + L")";
                return false;
            }

            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            Launched = true;
            return true;
        }

        static int RetryAfterSeconds(const std::string& value, int fallback)
        {
            if (value.empty())
                return fallback;

            char* end = nullptr;
            const long seconds = std::strtol(value.c_str(), &end, 10);
            if (end == value.c_str() || seconds <= 0)
                return fallback;
            return static_cast<int>(seconds > 30 ? 30 : seconds);
        }

        // One round-trip: spawn/wait for the server if it is down, honour 503
        // backpressure, then report the server's answer.
        // status: HTTP status, 0 = never reached, -1 = decompiler.exe unusable.
        static std::string Send(const std::string& payload, const std::string& scriptName,
            unsigned encodeKey, int& status)
        {
            status = 0;

            httplib::Headers headers;
            headers.emplace("X-Encode-Key", std::to_string(encodeKey));
            if (!scriptName.empty())
                headers.emplace("X-Script-Name", scriptName);

            const std::wstring path = DecompilerPath();
            if (path.empty())
            {
                status = -1;
                return "decompiler.exe not found next to sodium.dll";
            }

            httplib::Client client(std::string("http://") + kHost + ":" + std::to_string(kPort));
            client.set_connection_timeout(5, 0);
            client.set_read_timeout(kRequestTimeoutMs / 1000, (kRequestTimeoutMs % 1000) * 1000);
            client.set_write_timeout(kRequestTimeoutMs / 1000, (kRequestTimeoutMs % 1000) * 1000);

            const auto deadline = std::chrono::steady_clock::now()
                + std::chrono::seconds(kDeadlineSeconds);

            while (true)
            {
                httplib::Result response = client.Post(kRawPath, headers, payload,
                    ("application/octet-stream"));

                // No answer at all: the server isn't up yet.
                if (!response || response->status == 0)
                {
                    std::wstring error;
                    if (!LaunchServer(error))
                    {
                        status = -1;
                        return "-- decompiler.exe failed to start";
                    }
                    if (std::chrono::steady_clock::now() >= deadline)
                    {
                        status = 0;
                        return "-- local decompiler (127.0.0.1:3000) did not answer in time";
                    }
                    Sleep(250);
                    continue;
                }

                // Queue full / slot wait - the server tells us how long to back off.
                if (response->status == 503)
                {
                    if (std::chrono::steady_clock::now() >= deadline)
                    {
                        status = 503;
                        return response->body;
                    }
                    Sleep(static_cast<DWORD>(RetryAfterSeconds(
                        response->get_header_value("Retry-After"), 1)) * 1000);
                    continue;
                }

                status = response->status;
                return response->body;
            }
        }

        std::string Request(const std::string& bytecode, const std::string& scriptName, int& status)
        {
            status = 0;

            if (bytecode.empty())
            {
                status = -1;
                return "empty bytecode";
            }

            std::string result;
            int finalStatus = 0;
            bool done = false;
            // First "this isn't parseable Luau bytecode" answer. Kept so a
            // completely hopeless upload still reports why it was rejected.
            std::string shapeError;
            int shapeErrorStatus = 0;

            auto tryVariant = [&](const std::string& payload, unsigned encodeKey)
            {
                if (done)
                    return;

                int attemptStatus = 0;
                std::string body = Send(payload, scriptName, encodeKey, attemptStatus);

                if (attemptStatus == 200)
                {
                    done = true;
                    finalStatus = 200;
                    result = std::move(body);
                    return;
                }

                // Wrong header/key shape: the bytes themselves are still worth
                // re-sending as other plausible readings of the same script.
                if (attemptStatus == 400 && body.find("deserialize") != std::string::npos)
                {
                    if (shapeError.empty())
                    {
                        shapeError = std::move(body);
                        shapeErrorStatus = attemptStatus;
                    }
                    return;
                }

                // Anything else (transport failure, 500, unsupported version
                // message, ...) is the real answer - stop guessing.
                done = true;
                finalStatus = attemptStatus;
                result = std::move(body);
            };

            // 1. as stored by Roblox (opcode-encoded, key 203), then plain.
            tryVariant(bytecode, kEncodeKey);
            tryVariant(bytecode, 1);

            // 2. Byte 0 of a fetched script gets rewritten to the executor's
            //    compiler version before it ever reaches us, which desyncs a
            //    v10-v14 chunk. Restoring it is a one-byte fix, so sweep every
            //    version the server understands until one parses.
            if (!done && !shapeError.empty())
            {
                const unsigned char original = static_cast<unsigned char>(bytecode[0]);

                for (const unsigned encodeKey : { kEncodeKey, 1u })
                {
                    for (unsigned char version = kMinVersion; version <= kMaxVersion; ++version)
                    {
                        if (version == original)
                            continue;

                        std::string fixed = bytecode;
                        fixed[0] = static_cast<char>(version);
                        tryVariant(fixed, encodeKey);

                        if (done)
                            break;
                    }
                    if (done)
                        break;
                }
            }

            if (!done)
            {
                finalStatus = shapeErrorStatus;
                result = shapeError;
            }

            status = finalStatus;
            return result;
        }
    }

    // ??????????????????????????????????????????????????????????????
    //  Existing functions
    // ??????????????????????????????????????????????????????????????

    int SetIdentity(lua_State* L) {
        lua_normalisestack(L, 1);

        if (lua_type(L, 1) != LUA_TNUMBER)
            luaL_typeerrorL(L, 1, lua_typename(L, LUA_TNUMBER));

        int identity = (int)lua_tointeger(L, 1);
        task_scheduler::SetThreadCapabilities(L, identity, identity == 8 ? MaxCapabilities : identity);
        return 0;
    }

    int setthreadidentity(lua_State* L)
    {
        
        luaL_checktype(L, 1, LUA_TNUMBER);
        int identity = (int)lua_tointeger(L, 1);

        if (!L->userdata)
            return 0;

        uint64_t caps = 0xFFFFFFFFFFFFFF00 | Roblox::GetCapabilities(&identity);

        if (identity == 8)
        {
            caps = MaxCapabilities;
        }

        L->userdata->identity.identity = identity;
        L->userdata->capabilities = caps;

        const uintptr_t identity_ptr = Roblox::GetIdentityStruct(*reinterpret_cast<uintptr_t*>(Offsets::RobloxThread::IdentityPtr));

        if (identity_ptr) {
            *reinterpret_cast<uint64_t*>(identity_ptr) = identity;
            *reinterpret_cast<uint64_t*>(identity_ptr + Offsets::Capabilities::Capabilities) = caps;
        }

        return 0;
    }

    int getthreadidentity(lua_State* L)
    {
        
        if (!L->userdata)
        {
            lua_pushinteger(L, 0);
            return 1;
        }
        lua_pushinteger(L, L->userdata->identity.identity);
        return 1;
    }

    int getgenv(lua_State* L)
    {
        lua_rawcheckstack(L, 1);
        luaC_threadbarrier(L);
        luaC_threadbarrier(Shared::ExploitThread);
        lua_pushvalue(Shared::ExploitThread, LUA_GLOBALSINDEX);
        lua_xmove(Shared::ExploitThread, L, 1);

        return 1;
    }

    int identifyexecutor(lua_State* L)
    {
        lua_pushstring(L, ("Sodium"));
        lua_pushstring(L, ("1.6.0"));

        return 2;
    }

    int getexecutorname(lua_State* L)
    {
        lua_pushstring(L, ("Sodium"));

        return 1;
    }

    int GetObjects(lua_State* L)
    {
        luaL_checktype(L, 1, LUA_TUSERDATA);
        luaL_checktype(L, 2, LUA_TSTRING);

        lua_getglobal(L, ("game"));
        lua_getfield(L, -1, ("GetService"));
        if (!lua_isfunction(L, -1))
        {
            lua_pop(L, 2);
            luaL_error(L, ("game:GetService is unavailable"));
            return 0;
        }
        lua_pushvalue(L, -2);
        lua_pushstring(L, ("InsertService"));
        if (lua_pcall(L, 2, 1, 0) != LUA_OK)
        {
            const char* err = lua_tostring(L, -1);
            char message[512];
            strncpy_s(message, err ? err : ("failed to get InsertService"), _TRUNCATE);
            luaL_error(L, ("%s"), message);
            return 0;
        }
        lua_remove(L, -2);

        lua_getfield(L, -1, ("LoadLocalAsset"));
        if (!lua_isfunction(L, -1))
        {
            lua_pop(L, 2);
            luaL_error(L, ("InsertService:LoadLocalAsset is unavailable"));
            return 0;
        }

        lua_pushvalue(L, -2);
        lua_pushvalue(L, 2);
        if (lua_pcall(L, 2, 1, NULL) != LUA_OK)
        {
            const char* err = lua_tostring(L, -1);
            char message[512];
            strncpy_s(message, err ? err : ("LoadLocalAsset failed"), _TRUNCATE);
            luaL_error(L, ("%s"), message);
            return 0;
        }

        if (lua_type(L, -1) == LUA_TSTRING)
            luaL_error(L, lua_tostring(L, -1));

        lua_createtable(L, 1, NULL);
        lua_pushvalue(L, -2);
        lua_rawseti(L, -2, 1);

        lua_remove(L, -3);
        lua_remove(L, -2);

        return 1;
    }

    static double s_fpscap = 0.0;
    static bool s_fpscap_set = false;

    int setfpscap(lua_State* L) {
        luaL_checktype(L, 1, LUA_TNUMBER);
        double fps = lua_tonumber(L, 1);
        if (fps < 0.0)
            fps = 0.0;

        s_fpscap = fps;
        s_fpscap_set = true;

        uintptr_t ptr = *reinterpret_cast<uintptr_t*>(Offsets::Scheduler::TaskScheduler);
        if (ptr)
        {
            double delay = (fps > 0.0) ? (1.0 / fps) : 0.0;
            *reinterpret_cast<double*>(ptr + Offsets::Scheduler::Fps) = delay;
        }

        __try {
            *reinterpret_cast<double*>(Offsets::Flags::TaskSchedulerTargetFps) = fps;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }

        return 0;
    }

    int getfpscap(lua_State* L)
    {
        if (s_fpscap_set)
        {
            lua_pushnumber(L, s_fpscap);
            return 1;
        }

        uintptr_t ptr = *reinterpret_cast<uintptr_t*>(Offsets::Scheduler::TaskScheduler);
        if (ptr)
        {
            __try {
                double delay = *reinterpret_cast<double*>(ptr + Offsets::Scheduler::Fps);
                if (delay > 0.0)
                {
                    lua_pushnumber(L, 1.0 / delay);
                    return 1;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
            }
        }

        lua_pushnumber(L, 0);
        return 1;
    }

    static std::unordered_map<std::string, std::string> s_fflags;

    static std::string fflag_default(const char* name)
    {
        std::string n = name ? name : "";
        if (n.rfind("FFlag", 0) == 0 || n.rfind("DFFlag", 0) == 0 || n.rfind("SFFlag", 0) == 0)
            return "false";
        if (n.rfind("FInt", 0) == 0 || n.rfind("DFInt", 0) == 0)
            return "0";
        if (n.rfind("FString", 0) == 0 || n.rfind("DFString", 0) == 0)
            return "";
        return "false";
    }

    int getfflag(lua_State* L)
    {
        const char* name = luaL_checkstring(L, 1);
        auto it = s_fflags.find(name);
        if (it != s_fflags.end())
        {
            lua_pushstring(L, it->second.c_str());
            return 1;
        }
        lua_pushstring(L, fflag_default(name).c_str());
        return 1;
    }

    int setfflag(lua_State* L)
    {
        const char* name = luaL_checkstring(L, 1);
        std::string value;
        if (lua_type(L, 2) == LUA_TBOOLEAN)
            value = lua_toboolean(L, 2) ? "true" : "false";
        else if (lua_type(L, 2) == LUA_TNUMBER)
            value = std::to_string(lua_tonumber(L, 2));
        else
            value = luaL_optstring(L, 2, "");
        s_fflags[name] = value;
        return 0;
    }

    int queueonteleport(lua_State* L)
    {
        size_t length = 0;
        const char* code = luaL_checklstring(L, 1, &length);
        std::lock_guard<std::mutex> lock(Shared::TeleportQueueMutex);
        Shared::TeleportQueue.emplace_back(code, length);
        return 0;
    }

    int clearteleportqueue(lua_State*)
    {
        std::lock_guard<std::mutex> lock(Shared::TeleportQueueMutex);
        Shared::TeleportQueue.clear();
        return 0;
    }

    int gethui(lua_State* L)
    {
        lua_getglobal(L, ("game"));
        if (!lua_isuserdata(L, -1)) { lua_pop(L, 1); lua_pushnil(L); return 1; }

        lua_getfield(L, -1, ("GetService"));
        if (!lua_isfunction(L, -1)) { lua_pop(L, 2); lua_pushnil(L); return 1; }

        lua_pushvalue(L, -2);
        lua_pushstring(L, ("CoreGui"));
        if (lua_pcall(L, 2, 1, 0) != LUA_OK) {
            lua_pop(L, 1);
            lua_pushnil(L);
            return 1;
        }

        if (!lua_isuserdata(L, -1)) { lua_pop(L, 1); lua_pushnil(L); return 1; }
        int coreGuiIdx = lua_gettop(L);

        lua_getfield(L, -1, ("FindFirstChildOfClass"));
        if (!lua_isfunction(L, -1)) { lua_pop(L, 1); lua_pushnil(L); return 1; }

        lua_pushvalue(L, coreGuiIdx);
        lua_pushstring(L, ("ScreenGui"));
        if (lua_pcall(L, 2, 1, 0) == LUA_OK && lua_isuserdata(L, -1)) {
            return 1;
        }

        lua_getglobal(L, ("Instance"));
        lua_getfield(L, -1, ("new"));
        lua_pushstring(L, ("ScreenGui"));
        lua_call(L, 1, 1);
        lua_remove(L, -2);

        if (lua_isuserdata(L, -1)) {
            lua_pushvalue(L, -1);
            lua_setfield(L, coreGuiIdx, ("Name"));
            lua_pushvalue(L, -1);
            lua_setfield(L, coreGuiIdx, ("Parent"));
            return 1;
        }

        lua_pop(L, 1);
        lua_pushnil(L);
        return 1;
    }

    // Full in-game path of an Instance, used as X-Script-Name so the chunk is
    // named after the script instead of an anonymous buffer.
    static bool GetInstancePath(lua_State* L, int index, std::string& out)
    {
        index = lua_absindex(L, index);

        lua_getfield(L, index, ("GetFullName"));
        if (!lua_isfunction(L, -1))
        {
            lua_pop(L, 1);
            return false;
        }

        lua_pushvalue(L, index);
        if (lua_pcall(L, 1, 1, 0) != LUA_OK || !lua_isstring(L, -1))
        {
            lua_pop(L, 1);
            return false;
        }

        const char* value = lua_tostring(L, -1);
        out = value ? value : "";
        lua_pop(L, 1);
        return !out.empty();
    }

    // Reads the bytecode straight off the Instance, exactly as Roblox stores
    // it. getscriptbytecode() is deliberately not used: it rewrites byte 0 to
    // the executor's compiler version before handing the script over, which
    // desynchronises a v10-v14 game chunk and leaves nothing parseable.
    static bool BytecodeFromInstance(lua_State* L, int index, std::string& out, std::string& error)
    {
        std::string className;
        if (!Script::GetInstanceClassName(L, index, className) || !Script::IsScriptClass(className))
        {
            error = "LocalScript, ModuleScript or Script expected";
            return false;
        }

        void** userdata = static_cast<void**>(lua_touserdata(L, index));
        if (!userdata || !*userdata)
        {
            error = "invalid instance";
            return false;
        }

        const std::uintptr_t script = reinterpret_cast<std::uintptr_t>(*userdata);

        bool read = false;
        try
        {
            read = Script::FetchBytecode(script, className == "ModuleScript", out);
        }
        catch (...)
        {
            read = false;
        }

        if (!read || out.empty())
        {
            out.clear();
            error = "could not read script bytecode";
            return false;
        }

        return true;
    }

    namespace LuaExpert
    {
        static std::string Base64Encode(const std::string& input)
        {
            static const char* kTable =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

            std::string output;
            output.reserve(((input.size() + 2) / 3) * 4);

            size_t index = 0;
            while (index + 3 <= input.size())
            {
                const unsigned value =
                    (static_cast<unsigned char>(input[index]) << 16) |
                    (static_cast<unsigned char>(input[index + 1]) << 8) |
                    static_cast<unsigned char>(input[index + 2]);

                output += kTable[(value >> 18) & 0x3F];
                output += kTable[(value >> 12) & 0x3F];
                output += kTable[(value >> 6) & 0x3F];
                output += kTable[value & 0x3F];

                index += 3;
            }

            const size_t remaining = input.size() - index;
            if (remaining == 1)
            {
                const unsigned value = static_cast<unsigned char>(input[index]) << 16;
                output += kTable[(value >> 18) & 0x3F];
                output += kTable[(value >> 12) & 0x3F];
                output += "==";
            }
            else if (remaining == 2)
            {
                const unsigned value =
                    (static_cast<unsigned char>(input[index]) << 16) |
                    (static_cast<unsigned char>(input[index + 1]) << 8);
                output += kTable[(value >> 18) & 0x3F];
                output += kTable[(value >> 12) & 0x3F];
                output += kTable[(value >> 6) & 0x3F];
                output += '=';
            }

            return output;
        }

        std::string Request(const std::string& bytecode, int& status)
        {
            status = 0;

            if (bytecode.empty())
            {
                status = -1;
                return "empty bytecode";
            }

            const std::string payload =
                "{\"script\":\"" + Base64Encode(bytecode) + "\"}";

            httplib::Headers headers;
            headers.insert({ ("Accept"), ("text/plain") });
            headers.insert({ ("User-Agent"), kUserAgent });

            const auto result = module::core::environment::c_http::do_request(
                module::core::environment::H_POST, kUrl, headers, payload, kContentType);

            if (!result.success)
            {
                status = 0;
                return result.error.empty()
                    ? std::string("no response from api.lua.expert")
                    : result.error;
            }

            status = result.status_code;
            return result.body;
        }
    }

    int decompile(lua_State* L) {
        if (!lua_isuserdata(L, 1) && lua_type(L, 1) != LUA_TSTRING)
            luaL_typeerrorL(L, 1, ("Instance or bytecode string"));

        auto start = std::chrono::steady_clock::now();

        std::string bytecode;
        std::string scriptName;
        std::string readError;

        if (lua_isuserdata(L, 1))
        {
            if (!BytecodeFromInstance(L, 1, bytecode, readError))
            {
                lua_pushlstring(L, readError.c_str(), readError.size());
                return 1;
            }

            if (lua_type(L, 2) == LUA_TSTRING)
                scriptName = lua_tostring(L, 2);
            else
                GetInstancePath(L, 1, scriptName);
        }
        else
        {
            size_t length = 0;
            const char* data = luaL_checklstring(L, 1, &length);
            bytecode.assign(data, length);

            if (lua_type(L, 2) == LUA_TSTRING)
                scriptName = lua_tostring(L, 2);
        }

        return Yielding::YieldExecution(L, [bytecode, scriptName, start]() -> std::function<int(lua_State*)>
            {
                int status = 0;
                std::string source = LuaExpert::Request(bytecode, status);

                if (status != 200 || source.empty())
                {
                    const int remoteStatus = status;
                    const std::string remoteSource = source;

                    int localStatus = 0;
                    std::string localSource = Tovek::Request(bytecode, scriptName, localStatus);

                    if (localStatus == 200 && !localSource.empty())
                    {
                        status = localStatus;
                        source = std::move(localSource);
                    }
                    else if (!remoteSource.empty())
                    {
                        status = remoteStatus;
                        source = remoteSource;
                    }
                    else
                    {
                        status = localStatus;
                        source = localSource;
                    }
                }

                return [source, status, start](lua_State* L) -> int
                    {
                        const double elapsed = std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - start).count();

                        if (status == 200)
                        {
                            char header[96];
                            std::snprintf(header, sizeof(header), "-- Sodium: Decompiled in %.1fs\n\n", elapsed);

                            const std::string result = std::string(header) + source;
                            lua_pushlstring(L, result.c_str(), result.size());
                            return 1;
                        }

                        std::string message = "-- decompile failed";
                        if (status > 0)
                            message += " (HTTP " + std::to_string(status) + ")";
                        message += ": " + source;

                        lua_pushlstring(L, message.c_str(), message.size());
                        return 1;
                    };
            });
    }

    static std::string escape_string(const char* s) {
        if (!s) return "";
        std::string result;
        for (const char* p = s; *p; ++p) {
            switch (*p) {
            case '\\': result += "\\\\"; break;
            case '"': result += "\\\""; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += *p; break;
            }
        }
        return result;
    }

    static void serialize_instance(lua_State* L, int instanceIdx, int depth, std::string& out) {
        if (!lua_isuserdata(L, instanceIdx)) return;

        lua_getglobal(L, "typeof");
        lua_pushvalue(L, instanceIdx);
        lua_call(L, 1, 1);
        const char* tp = lua_tostring(L, -1);
        lua_pop(L, 1);
        if (!tp || strcmp(tp, "Instance") != 0) return;

        lua_getfield(L, instanceIdx, "ClassName");
        const char* className = lua_isstring(L, -1) ? lua_tostring(L, -1) : "Instance";
        lua_pop(L, 1);

        lua_getfield(L, instanceIdx, "Name");
        const char* instName = lua_isstring(L, -1) ? lua_tostring(L, -1) : "";
        lua_pop(L, 1);

        std::string indent(depth * 4, ' ');
        std::string varName = "inst_" + std::to_string(reinterpret_cast<uintptr_t>(lua_touserdata(L, instanceIdx)));

        out += indent + "local " + varName + " = Instance.new(\"" + className + "\")\n";
        out += indent + varName + ".Name = \"" + escape_string(instName) + "\"\n";

        lua_getfield(L, instanceIdx, "ClassName");
        const char* cn = lua_isstring(L, -1) ? lua_tostring(L, -1) : "";
        lua_pop(L, 1);

        if (strcmp(cn, "Part") == 0 || strcmp(cn, "MeshPart") == 0 || strcmp(cn, "UnionOperation") == 0 ||
            strcmp(cn, "SpawnLocation") == 0 || strcmp(cn, "WedgePart") == 0 || strcmp(cn, "CornerWedgePart") == 0) {
            lua_getfield(L, instanceIdx, "Position");
            if (lua_istable(L, -1)) {
                lua_getfield(L, -1, "X"); double px = lua_tonumber(L, -1); lua_pop(L, 1);
                lua_getfield(L, -1, "Y"); double py = lua_tonumber(L, -1); lua_pop(L, 1);
                lua_getfield(L, -1, "Z"); double pz = lua_tonumber(L, -1); lua_pop(L, 1);
                lua_pop(L, 1);
                char buf[256];
                snprintf(buf, sizeof(buf), "%s%s.Position = Vector3.new(%g, %g, %g)\n", indent.c_str(), varName.c_str(), px, py, pz);
                out += buf;
            }
            else { lua_pop(L, 1); }

            lua_getfield(L, instanceIdx, "Size");
            if (lua_istable(L, -1)) {
                lua_getfield(L, -1, "X"); double sx = lua_tonumber(L, -1); lua_pop(L, 1);
                lua_getfield(L, -1, "Y"); double sy = lua_tonumber(L, -1); lua_pop(L, 1);
                lua_getfield(L, -1, "Z"); double sz = lua_tonumber(L, -1); lua_pop(L, 1);
                lua_pop(L, 1);
                char buf[256];
                snprintf(buf, sizeof(buf), "%s%s.Size = Vector3.new(%g, %g, %g)\n", indent.c_str(), varName.c_str(), sx, sy, sz);
                out += buf;
            }
            else { lua_pop(L, 1); }

            lua_getfield(L, instanceIdx, "BrickColor");
            if (!lua_isnil(L, -1) && !lua_isnone(L, -1)) {
                lua_getfield(L, -1, "Name");
                const char* bc = lua_isstring(L, -1) ? lua_tostring(L, -1) : nullptr;
                lua_pop(L, 1);
                lua_pop(L, 1);
                if (bc) {
                    out += indent + varName + ".BrickColor = BrickColor.new(\"" + bc + "\")\n";
                }
            }
            else { lua_pop(L, 1); }

            lua_getfield(L, instanceIdx, "Anchored");
            if (!lua_isnil(L, -1)) {
                out += indent + varName + ".Anchored = " + (lua_toboolean(L, -1) ? "true" : "false") + "\n";
            }
            lua_pop(L, 1);
        }

        lua_getfield(L, instanceIdx, "Parent");
        lua_pop(L, 1);

        out += "\n";
    }

    static void serialize_children(lua_State* L, int instanceIdx, int depth, std::string& out) {
        lua_getfield(L, instanceIdx, "GetChildren");
        if (!lua_isfunction(L, -1)) { lua_pop(L, 1); return; }
        lua_pushvalue(L, instanceIdx);
        if (lua_pcall(L, 1, 1, 0) != LUA_OK) { lua_pop(L, 1); return; }
        if (!lua_istable(L, -1)) { lua_pop(L, 1); return; }

        int tableIdx = lua_gettop(L);
        int len = (int)lua_objlen(L, tableIdx);
        for (int i = 1; i <= len; ++i) {
            lua_rawgeti(L, tableIdx, i);
            if (lua_isuserdata(L, -1)) {
                serialize_instance(L, -1, depth, out);
                serialize_children(L, lua_gettop(L), depth + 1, out);
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    }

    int saveinstance(lua_State* L) {
        
        const char* savePath = nullptr;
        int top = lua_gettop(L);

        if (top >= 2 && lua_istable(L, 2)) {
            lua_getfield(L, 2, "FileName");
            if (lua_isstring(L, -1)) {
                savePath = lua_tostring(L, -1);
            }
            lua_pop(L, 1);
        }
        else if (top >= 1 && lua_isstring(L, 1)) {
            savePath = lua_tostring(L, 1);
        }

        lua_getglobal(L, "game");
        if (!lua_isuserdata(L, -1)) {
            lua_pop(L, 1);
            luaL_error(L, ("game not found"));
            return 0;
        }
        int gameIdx = lua_gettop(L);

        std::string output;
        output += "-- Generated by executor saveinstance\n";
        output += "local game = game\n";

        lua_getfield(L, gameIdx, "PlaceId");
        char buf[256];
        snprintf(buf, sizeof(buf), "local PlaceId = %g\n", lua_tonumber(L, -1));
        output += buf;
        lua_pop(L, 1);

        lua_getfield(L, gameIdx, "JobId");
        lua_pop(L, 1);

        output += "\n";

        serialize_instance(L, gameIdx, 0, output);
        serialize_children(L, gameIdx, 1, output);

        lua_pop(L, 1);

        wchar_t pathBuf[MAX_PATH] = {};
        if (savePath && savePath[0]) {
            if (!Shared::workspace_folder.empty()) {
                std::wstring wsFolder = Shared::workspace_folder.wstring();
                wcscpy_s(pathBuf, MAX_PATH, wsFolder.c_str());
                wchar_t fileName[MAX_PATH] = {};
                MultiByteToWideChar(CP_UTF8, 0, savePath, -1, fileName, MAX_PATH);
                wcscat_s(pathBuf, MAX_PATH, L"\\");
                wcscat_s(pathBuf, MAX_PATH, fileName);
            }
            else {
                MultiByteToWideChar(CP_UTF8, 0, savePath, -1, pathBuf, MAX_PATH);
            }
        }
        else {
            if (!Shared::workspace_folder.empty()) {
                std::wstring wsFolder = Shared::workspace_folder.wstring();
                wcscpy_s(pathBuf, MAX_PATH, wsFolder.c_str());
                wcscat_s(pathBuf, MAX_PATH, L"\\savefile.lua");
            }
            else {
                wchar_t desktop[MAX_PATH] = {};
                SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, desktop);
                wcscpy_s(pathBuf, MAX_PATH, desktop);
                wcscat_s(pathBuf, MAX_PATH, L"\\savefile.lua");
            }
        }

        std::ofstream file(pathBuf);
        if (file.is_open()) {
            file << output;
            file.close();
            lua_pushboolean(L, true);
        }
        else {
            lua_pushboolean(L, false);
        }
        return 1;
    }

    // ??????????????????????????????????????????????????????????????
    //  Registration
    // ??????????????????????????????????????????????????????????????

    void register_lib(lua_State* L)
    {
        // getgenv stays registered as a normal executor closure: sUNC wants
        // isexecutorclosure(getgenv) to be true (executor globals are executor
        // closures) and it wants getfenv(getgenv) to answer with the calling
        // script's environment, which must never be the table getgenv() returns.
        // Un-tracking it here made getfenv fall back to cl->env - the exploit
        // thread globals - i.e. exactly getgenv()'s own result.
        Environment->make_global(L, ("getgenv"), getgenv, Miscellaneous::funcnameinc++);

        Environment->make_global(L, ("decompile"), decompile, Miscellaneous::funcnameinc++);
        Environment->make_global(L, ("saveinstance"), saveinstance, Miscellaneous::funcnameinc++);
        Environment->make_global(L, ("identifyexecutor"), identifyexecutor, Miscellaneous::funcnameinc++);
        Environment->make_global(L, ("getexecutorname"), getexecutorname, Miscellaneous::funcnameinc++);
        Environment->make_aliases(L, setthreadidentity, Miscellaneous::funcnameinc, { ("setthreadidentity"), ("setidentity"), ("setthreadcontext") });
       Environment->make_aliases(L, getthreadidentity, Miscellaneous::funcnameinc, { ("getthreadidentity"), ("getidentity"), ("getthreadcontext") });
       Environment->make_global(L, ("setfpscap"), setfpscap, Miscellaneous::funcnameinc++);
       Environment->make_global(L, ("getfpscap"), getfpscap, Miscellaneous::funcnameinc++);
       Environment->make_global(L, ("setfflag"), setfflag, Miscellaneous::funcnameinc++);
       Environment->make_global(L, ("getfflag"), getfflag, Miscellaneous::funcnameinc++);
       Environment->make_global(L, ("GetObjects"), GetObjects, Miscellaneous::funcnameinc++);
      Environment->make_aliases(L, queueonteleport, Miscellaneous::funcnameinc, { ("queueonteleport"), ("queue_on_teleport") });
     Environment->make_aliases(L, clearteleportqueue, Miscellaneous::funcnameinc, { ("clearteleportqueue"), ("clear_teleport_queue"), ("clearqueueonteleport") });
       Environment->make_aliases(L, gethui, Miscellaneous::funcnameinc, { ("gethui"), ("get_hidden_ui"), ("get_hidden_gui") });
    }
}
