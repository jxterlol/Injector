#pragma once

#include <lstate.h>
#include <lualib.h>

#include <string>

namespace Miscellaneous {

    static int funcnameinc = 0;

    // HTTP user agent (kept in sync with the C# SodiumAPI)
    inline constexpr const char* kUserAgent = "Sodium/1.6.0";

    // ══════════════════════════════════════════════════════════════
    //  Tovek local decompiler server
    //
    //  decompiler.exe sits next to Module.dll and listens on
    //  127.0.0.1:3000. The client below spawns it on demand and
    //  ships raw Roblox bytecode (encode key 203) to POST
    //  /decompile/raw, getting Luau source back as text/plain.
    // ══════════════════════════════════════════════════════════════
    namespace Tovek {
        inline constexpr const char* kHost = "127.0.0.1";
        inline constexpr int kPort = 3000;
        inline constexpr const char* kRawUrl = "http://127.0.0.1:3000/decompile/raw";
        inline constexpr const char* kRawPath = "/decompile/raw";
        inline constexpr const wchar_t* kExeName = L"decompiler.exe";
        // Roblox client bytecode: opcodes are stored multiplied by the inverse
        // of this key, and the server decodes with it unless told otherwise.
        inline constexpr unsigned kEncodeKey = 203;
        // Bytecode versions the server parses (4..=14).
        inline constexpr unsigned char kMinVersion = 4;
        inline constexpr unsigned char kMaxVersion = 14;
        // How long we keep (re)trying while the server is unreachable or
        // shedding load with 503 before giving up on this call.
        inline constexpr int kDeadlineSeconds = 45;
        // Per-request ceiling on the decompile itself (server side has no
        // CPU deadline; huge modules can legitimately take a while).
        inline constexpr int kRequestTimeoutMs = 180000;

        // Full path of decompiler.exe beside this module ("" if not present).
        std::wstring DecompilerPath();
        // Spawn the server hidden, at most once per process.
        bool LaunchServer(std::wstring& error);

        // POST bytecode to the local server. Retries while the server is down
        // (launching it on the first failure) and while it answers 503; if the
        // server rejects the upload as unparseable, re-sends it under the other
        // encode keys / header versions until one reads as Luau bytecode.
        // status: 200 = source in the return value, >0 = HTTP status from the
        // server, 0 = never reached it, -1 = decompiler.exe missing/failed.
        std::string Request(const std::string& bytecode, const std::string& scriptName, int& status);
    }

    namespace LuaExpert
    {
        inline constexpr const char* kUrl = "https://api.lua.expert/decompile";
        inline constexpr const char* kContentType = "application/json";
        inline constexpr const char* kUserAgent = "Sodium/1.6.0";

        std::string Request(const std::string& bytecode, int& status);
    }

    int SetIdentity(lua_State* L);
    int setthreadidentity(lua_State* L);
    int getthreadidentity(lua_State* L);
    int getgenv(lua_State* L);
    int identifyexecutor(lua_State* L);
    int getexecutorname(lua_State* L);
    int GetObjects(lua_State* L);
    int setfpscap(lua_State* L);
    int getfpscap(lua_State* L);
    int setfflag(lua_State* L);
    int getfflag(lua_State* L);
    int queueonteleport(lua_State* L);
    int clearteleportqueue(lua_State* L);
    int gethui(lua_State* L);
    int decompile(lua_State* L);
    int saveinstance(lua_State* L);
    void register_lib(lua_State* L);
}
