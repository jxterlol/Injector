#include <RBX/environment/libs/script/script.hpp>
#include <RBX/environment/env.hpp>

#include <lstate.h>
#include <lgc.h>
#include <lualib.h>
#include <ltable.h>
#include <wininet.h>
#include <urlmon.h>

#include <luacode.h>
#include <Luau/Bytecode.h>
#include <Luau/Compiler.h>
#include <winhttp.h>
#include <zstd/xxhash.h>
#include <zstd/zstd.h>
#include <Utilitys/Log.hpp>
#pragma comment(lib, "zstd_static.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "winhttp.lib")

#include <Utilitys/Utils.hpp>
#include <Utilitys/Globals.hpp>
#include <RBX/environment/yielding/yielding.hpp>
#include <RBX/update.hpp>
#include <RBX/task_scheduler/task_scheduler.hpp>
#include <Dependencies/Luau2/VM/src/lmem.h>
#include <RBX/environment/libs/closures/closures.hpp>
#include <RBX/environment/libs/crypt/crypt.hpp>


static LuaTable* RenvCache = nullptr;
static lua_State* RenvCacheState = nullptr;

typedef void(__fastcall* PushInstanceWeakPtrT)(lua_State* L, std::weak_ptr<uintptr_t>);

namespace HelperFuncs
{
    __forceinline bool CheckMemory(uintptr_t address) {
        if (address < 0x10000 || address > 0x7FFFFFFFFFFF) {
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) == 0) {
            return false;
        }

        if (mbi.Protect & PAGE_NOACCESS || mbi.State != MEM_COMMIT) {
            return false;
        }

        return true;
    }
}

namespace Script
{
    std::map<void*, std::string> ScriptHashes;
    std::vector<ScriptableCacheEntry> s_ScriptableCache;
    std::unordered_map<std::string, bool> s_DefaultPropStates;

    void add_defualtprop_state(const char* prop_name, bool was_scriptable) {
        std::string key(prop_name);
        if (s_DefaultPropStates.find(key) == s_DefaultPropStates.end()) {
            s_DefaultPropStates[key] = was_scriptable;
        }
    }

    bool find_upd_scriptablecache(uintptr_t instance, const char* prop_name, bool new_state) {
        for (auto& entry : s_ScriptableCache) {
            if (entry.instance == instance && entry.property_name == prop_name) {
                entry.is_scriptable = new_state;
                return true;
            }
        }
        return false;
    }

    int get_cachedscriptable_prop(uintptr_t instance, const char* prop_name) {
        for (const auto& entry : s_ScriptableCache) {
            if (entry.instance == instance && entry.property_name == prop_name) {
                return entry.is_scriptable ? 1 : 0;
            }
        }
        return -1;
    }

    int getcacheddefscriptableprop(const char* prop_name) {
        auto it = s_DefaultPropStates.find(prop_name);
        if (it != s_DefaultPropStates.end()) {
            return it->second ? 1 : 0;
        }
        return -1;
    }

    bool IsValidScriptClass(const char* className)
    {
        if (!className) return false;
        return strcmp(className, ("LocalScript")) == 0 ||
            strcmp(className, ("ModuleScript")) == 0 ||
            strcmp(className, ("Script")) == 0;
    }

    std::string Blake2Hash(const char* data, size_t len)
    {
        if (!data || len == 0) return std::string(96, '0');

        uint64_t h[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };

        for (size_t i = 0; i < len; i++) {
            uint64_t val = static_cast<unsigned char>(data[i]);
            h[i % 8] ^= val;
            h[i % 8] = (h[i % 8] << 7) | (h[i % 8] >> 57);
            h[(i + 1) % 8] += val;
        }

        for (int round = 0; round < 12; round++) {
            for (int i = 0; i < 8; i++) {
                h[i] ^= h[(i + 1) % 8];
                h[i] = (h[i] << 13) | (h[i] >> 51);
            }
        }

        char output[97];
        for (int i = 0; i < 6; i++) {
            sprintf_s(output + (i * 16), 17, ("%016llx"), h[i]);
        }
        output[96] = '\0';

        return std::string(output);
    }

    bool IsScriptClass(const std::string& className)
    {
        return className == ("LocalScript") || className == ("ModuleScript") || className == ("Script");
    }

    namespace Util
    {
        inline bool CheckMemory(uintptr_t address) {
            if (address < 0x10000 || address > 0x7FFFFFFFFFFF) {
                return false;
            }

            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) == 0) {
                return false;
            }

            if (mbi.Protect & PAGE_NOACCESS || mbi.State != MEM_COMMIT) {
                return false;
            }

            return true;
        }
    }

    namespace
    {
        constexpr std::size_t BytecodeSizeLimit = 64u * 1024u * 1024u;
        constexpr std::size_t ContainerHeaderSize = 8u;
        constexpr std::uintptr_t ScanBegin = 0x80;
        constexpr std::uintptr_t ScanEnd = 0x400;
        constexpr char ContainerSignature[4] = { 'R', 'S', 'B', '1' };
        constexpr std::uint64_t ContainerPlainMarker = 0xE009325B4A107A52ull;
        constexpr std::uint32_t ContainerFrameMagic = 0xFD2FB528u;
        constexpr std::uint32_t ContainerHashSeed = 42u;
        constexpr std::uint8_t ContainerHashStep = 41u;
        constexpr std::uint8_t BytecodeVersionCeiling = 31u;

        bool ReadRaw(std::uintptr_t address, void* buffer, std::size_t size)
        {
            if (size == 0 || !Util::CheckMemory(address) || !Util::CheckMemory(address + size - 1))
                return false;

            __try
            {
                std::memcpy(buffer, reinterpret_cast<const void*>(address), size);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        struct NativeString
        {
            union
            {
                char buffer[16];
                char* data;
            };

            std::size_t size;
            std::size_t capacity;
        };

        bool ReadStdString(std::uintptr_t address, std::string& out)
        {
            out.clear();

            NativeString value{};
            if (!ReadRaw(address, &value, sizeof(value)))
                return false;

            if (value.size <= ContainerHeaderSize || value.size > value.capacity
                || value.capacity > BytecodeSizeLimit)
                return false;

            if (value.capacity < sizeof(value.buffer))
            {
                out.assign(value.buffer, value.size);
                return true;
            }

            out.resize(value.size);

            if (!ReadRaw(reinterpret_cast<std::uintptr_t>(value.data), out.data(), value.size))
            {
                out.clear();
                return false;
            }

            return true;
        }

        bool DecodeBytecode(const std::string& source, std::string& out)
        {
            out.clear();

            if (source.size() <= ContainerHeaderSize)
                return false;

            std::vector<std::uint8_t> data(source.begin(), source.end());

            std::uint64_t marker = 0;
            std::memcpy(&marker, data.data(), sizeof(marker));

            if (marker == ContainerPlainMarker)
            {
                std::memcpy(data.data(), ContainerSignature, sizeof(ContainerSignature));
                std::memset(data.data() + sizeof(ContainerSignature), 0, sizeof(std::uint32_t));
            }
            else
            {
                std::uint8_t key[4]{};
                for (std::size_t i = 0; i < sizeof(key); ++i)
                {
                    const std::uint8_t masked = static_cast<std::uint8_t>(data[i] ^ ContainerSignature[i]);
                    key[i] = static_cast<std::uint8_t>(masked - static_cast<std::uint8_t>(i * ContainerHashStep));
                }

                for (std::size_t i = 0; i < data.size(); ++i)
                    data[i] ^= static_cast<std::uint8_t>(key[i % sizeof(key)] + static_cast<std::uint8_t>(i * ContainerHashStep));

                std::uint32_t expectedHash = 0;
                std::memcpy(&expectedHash, key, sizeof(expectedHash));

                if (XXH32(data.data(), data.size(), ContainerHashSeed) != expectedHash)
                    return false;
            }

            std::uint32_t decodedSize = 0;
            std::memcpy(&decodedSize, data.data() + sizeof(ContainerSignature), sizeof(decodedSize));

            if (decodedSize == 0)
            {
                out.assign(reinterpret_cast<const char*>(data.data()) + ContainerHeaderSize,
                    data.size() - ContainerHeaderSize);

                return !out.empty();
            }

            if (decodedSize > BytecodeSizeLimit || data.size() - ContainerHeaderSize <= sizeof(std::uint32_t))
                return false;

            std::uint32_t frameMagic = 0;
            std::memcpy(&frameMagic, data.data() + ContainerHeaderSize, sizeof(frameMagic));

            if (frameMagic != ContainerFrameMagic)
                return false;

            out.resize(decodedSize);

            const std::size_t written = ZSTD_decompress(
                out.data(),
                out.size(),
                data.data() + ContainerHeaderSize,
                data.size() - ContainerHeaderSize);

            if (ZSTD_isError(written) || written != decodedSize)
            {
                out.clear();
                return false;
            }

            return true;
        }

        bool LooksLikeBytecode(const std::string& bytecode)
        {
            if (bytecode.empty())
                return false;

            const std::uint8_t version = static_cast<std::uint8_t>(bytecode.front());
            return version != 0 && version <= BytecodeVersionCeiling;
        }

        bool ReadContainer(std::uintptr_t address, std::string& out)
        {
            std::string encoded;

            if (ReadStdString(address + Offsets::DataModel::ClassDescriptor, encoded)
                && DecodeBytecode(encoded, out) && LooksLikeBytecode(out))
                return true;

            if (ReadStdString(address, encoded) && DecodeBytecode(encoded, out) && LooksLikeBytecode(out))
                return true;

            out.clear();
            return false;
        }

        bool ReadBytecodeAt(std::uintptr_t field, std::string& out)
        {
            std::uintptr_t container = 0;

            if (ReadRaw(field, &container, sizeof(container)) && Util::CheckMemory(container)
                && ReadContainer(container, out))
                return true;

            return ReadContainer(field, out);
        }

        std::uintptr_t& LearnedOffset(bool moduleScript)
        {
            static std::uintptr_t localScriptOffset = 0;
            static std::uintptr_t moduleScriptOffset = 0;

            return moduleScript ? moduleScriptOffset : localScriptOffset;
        }
    }

    bool FetchBytecode(std::uintptr_t script, bool moduleScript, std::string& out)
    {
        static std::mutex guard;
        const std::lock_guard<std::mutex> lock(guard);

        const std::uintptr_t primary = moduleScript
            ? Offsets::Scripts::ModuleScriptByteCode
            : Offsets::Scripts::LocalScriptByteCode;

        std::uintptr_t& learned = LearnedOffset(moduleScript);

        if (primary != 0 && ReadBytecodeAt(script + primary, out))
            return true;

        if (learned != 0 && learned != primary && ReadBytecodeAt(script + learned, out))
            return true;

        for (std::uintptr_t offset = ScanBegin; offset <= ScanEnd; offset += sizeof(std::uintptr_t))
        {
            if (offset == primary || offset == learned)
                continue;

            if (ReadBytecodeAt(script + offset, out))
            {
                learned = offset;
                return true;
            }
        }

        return false;
    }

    int ScriptError(lua_State* L, const char* message)
    {
        const char* error = message ? message : ("script error");
        int top = lua_gettop(L);
        lua_getglobal(L, ("error"));
        if (lua_isfunction(L, -1))
        {
            lua_pushstring(L, error);
            lua_call(L, 1, 0);
            return 0;
        }

        lua_settop(L, top);
        lua_pushnil(L);
        lua_pushstring(L, error);
        return 2;
    }

    static std::uint8_t GetTargetBytecodeVersion()
    {
        static std::uint8_t cached = 0;
        if (cached != 0)
            return cached;
        std::string dummy = Luau::compile("return 0", {}, {});
        if (!dummy.empty())
            cached = static_cast<std::uint8_t>(dummy[0]);

        if (cached == 0)
            cached = static_cast<std::uint8_t>(LBC_VERSION_TARGET);

        return cached;
    }

    int getscriptbytecode(lua_State* L)
    {
        
        luaL_checktype(L, 1, LUA_TUSERDATA);

        const char* typeName = luaL_typename(L, 1);
        if (!typeName || std::strcmp(typeName, ("Instance")) != 0)
            luaL_typeerrorL(L, 1, ("Instance"));

        void** userdata = static_cast<void**>(lua_touserdata(L, 1));
        if (!userdata || !*userdata || !Util::CheckMemory(reinterpret_cast<std::uintptr_t>(*userdata)))
            luaL_argerrorL(L, 1, ("invalid instance"));

        const std::uintptr_t script = reinterpret_cast<std::uintptr_t>(*userdata);

        const int top = lua_gettop(L);
        lua_getfield(L, 1, ("ClassName"));

        std::string className;
        if (lua_isstring(L, -1))
            className = lua_tostring(L, -1);

        lua_settop(L, top);

        if (!IsScriptClass(className))
            luaL_typeerrorL(L, 1, ("LocalScript, ModuleScript or Script"));

        std::string bytecode;
        bool decoded = false;

        try
        {
            decoded = FetchBytecode(script, className == ("ModuleScript"), bytecode);
        }
        catch (...)
        {
            decoded = false;
        }

        if (!decoded || bytecode.empty())
        {
            lua_pushnil(L);
            return 1;
        }

        const std::uint8_t targetVersion = GetTargetBytecodeVersion();
        const std::uint8_t scriptVersion = static_cast<std::uint8_t>(bytecode[0]);

        if (scriptVersion != targetVersion && scriptVersion != 0)
        {
        
            bytecode[0] = static_cast<char>(targetVersion);
        }

        lua_pushlstring(L, bytecode.data(), bytecode.size());
        return 1;
    }





    bool IsModuleScriptValue(lua_State* L, int index)
    {
        if (!lua_isuserdata(L, index))
            return false;

        index = lua_absindex(L, index);
        const int top = lua_gettop(L);

        lua_getfield(L, index, ("ClassName"));
        const bool isModule = lua_isstring(L, -1) &&
            strcmp(lua_tostring(L, -1), ("ModuleScript")) == 0;

        lua_settop(L, top);
        return isModule;
    }

    int getloadedmodules(lua_State* L) {
        
        lua_normalisestack(L, 0);
        lua_newtable(L);

        struct GCOContext {
            lua_State* pLua;
            int                                 itemsFound;
            std::unordered_map<uintptr_t, bool> map;
        } gcCtx{ L, 0 };

        const auto oldThreshold = L->global->GCthreshold;
        L->global->GCthreshold = SIZE_MAX;

        luaM_visitgco(L, &gcCtx, [](void* ctx, lua_Page*, GCObject* pGcObj) -> bool {
            auto* c = static_cast<GCOContext*>(ctx);
            auto* cL = c->pLua;

            if (isdead(cL->global, pGcObj)) return false;
            if (pGcObj->gch.tt != LUA_TFUNCTION) return false;

            cL->top->value.gc = pGcObj;
            cL->top->tt = LUA_TFUNCTION;
            ++cL->top;

            lua_getfenv(cL, -1);
            if (!lua_isnil(cL, -1)) {
                lua_getfield(cL, -1, ("script"));
                if (!lua_isnil(cL, -1)) {
                    uintptr_t script_addr = *reinterpret_cast<uintptr_t*>(lua_touserdata(cL, -1));

                    const std::string& class_name_ref = **reinterpret_cast<std::string**>(
                        *reinterpret_cast<uintptr_t*>(script_addr + 0x18) + 0x8);

                    if (class_name_ref == ("ModuleScript") &&
                        c->map.emplace(script_addr, true).second) {
                        lua_rawseti(cL, -4, ++c->itemsFound);
                    }
                    else {
                        lua_pop(cL, 1);
                    }
                }
                else lua_pop(cL, 1);
            }
            lua_pop(cL, 2);
            return false;
            });

        L->global->GCthreshold = oldThreshold;
        return 1;
    }

    __forceinline int getscripts(lua_State* L) {
        
        struct instancecontext {
            lua_State* L;
            int n;
        } Context = { L, 0 };
        lua_createtable(L, 0, 0);
        const auto ullOldThreshold = L->global->GCthreshold;
        L->global->GCthreshold = SIZE_MAX;
        luaM_visitgco(L, &Context, [](void* ctx, lua_Page* page, GCObject* gco) -> bool {
            auto gCtx = static_cast<instancecontext*>(ctx);
            if (isdead(gCtx->L->global, gco)) return false;
            if (gco->gch.tt == LUA_TUSERDATA) {
                TValue* top = gCtx->L->top;
                top->value.p = reinterpret_cast<void*>(gco);
                top->tt = LUA_TUSERDATA;
                gCtx->L->top++;
                if (!strcmp(luaL_typename(gCtx->L, -1), ("Instance"))) {
                    lua_getfield(gCtx->L, -1, ("ClassName"));
                    const char* cls = lua_isstring(gCtx->L, -1) ? lua_tolstring(gCtx->L, -1, 0) : nullptr;
                    if (cls && (!strcmp(cls, ("LocalScript")) || !strcmp(cls, ("ModuleScript")) || !strcmp(cls, ("CoreScript")))) {
                        lua_pop(gCtx->L, 1);
                        gCtx->n++;
                        lua_rawseti(gCtx->L, -2, gCtx->n);
                    }
                    else if (cls && !strcmp(cls, ("Script"))) {
                        lua_pop(gCtx->L, 1);
                        lua_getfield(gCtx->L, -1, ("RunContext"));
                        if (lua_isuserdata(gCtx->L, -1) || lua_isstring(gCtx->L, -1)) {
                            lua_getfield(gCtx->L, -1, ("Name"));
                            const char* runContext = lua_isstring(gCtx->L, -1) ? lua_tostring(gCtx->L, -1) : nullptr;
                            lua_pop(gCtx->L, 1);
                            if (runContext && !strcmp(runContext, ("Client"))) {
                                lua_pop(gCtx->L, 1);
                                gCtx->n++;
                                lua_rawseti(gCtx->L, -2, gCtx->n);
                            }
                            else {
                                lua_pop(gCtx->L, 2);
                            }
                        }
                        else {
                            lua_pop(gCtx->L, 2);
                        }
                    }
                    else {
                        lua_pop(gCtx->L, 2);
                    }
                }
                else {
                    lua_pop(gCtx->L, 1);
                }
            }
            return true;
            });
        L->global->GCthreshold = ullOldThreshold;
        return 1;
    }

    void PushGCObjects(lua_State* L, bool includeTables)
    {
        lua_newtable(L);
        lua_newtable(L);

        lua_pushstring(L, ("kvs"));
        lua_setfield(L, -2, ("__mode"));
        lua_setmetatable(L, -2);

        typedef struct {
            lua_State* luaThread;
            bool includeTables;
            int itemsFound;
        } GCOContext;

        auto GCContext = GCOContext{ L, includeTables, 0 };

        const auto oldGCThreshold = L->global->GCthreshold;
        L->global->GCthreshold = SIZE_MAX;

        luaM_visitgco(L, &GCContext, [](void* ctx, lua_Page* page, GCObject* gcObj) -> bool {
            const auto context = static_cast<GCOContext*>(ctx);
            const auto luaThread = context->luaThread;

            if (isdead(luaThread->global, gcObj))
                return false;

            const auto gcObjectType = gcObj->gch.tt;
            if (gcObjectType == LUA_TFUNCTION || gcObjectType == LUA_TTHREAD || gcObjectType == LUA_TUSERDATA ||
                gcObjectType == LUA_TLIGHTUSERDATA || gcObjectType == LUA_TBUFFER ||
                (gcObjectType == LUA_TTABLE && context->includeTables)) {
                luaThread->top->value.gc = gcObj;
                luaThread->top->tt = gcObjectType;
                incr_top(luaThread);

                const auto newTableIndex = ++context->itemsFound;
                lua_rawseti(luaThread, -2, newTableIndex);
            }

            return false;
            });

        L->global->GCthreshold = oldGCThreshold;
    }

    int getgc(lua_State* L) {
        
        PushGCObjects(L, luaL_optboolean(L, 1, false));
        return 1;
    };

    int getrenv(lua_State* L)
    {
        
        lua_check(L, 0);
        lua_State* RobloxState = L->global->mainthread;

        if (RenvCacheState != RobloxState)
        {
            RenvCache = nullptr;
            RenvCacheState = RobloxState;
        }

        if (!RenvCache)
        {
            LuaTable* clone = luaH_clone(L, RobloxState->gt);

            lua_rawcheckstack(L, 2);
            luaC_threadbarrier(L);
            luaC_threadbarrier(RobloxState);
            L->top->value.p = clone;
            L->top->tt = LUA_TTABLE;
            L->top++;

            lua_pushvalue(L, -1);
            lua_ref(L, -1);
            lua_pop(L, 1);

            lua_rawgeti(L, LUA_REGISTRYINDEX, 2);
            lua_setfield(L, -2, ("_G"));
            lua_rawgeti(L, LUA_REGISTRYINDEX, 4);
            lua_setfield(L, -2, ("shared"));

            RenvCache = clone;
            lua_pop(L, 1);
        }

        lua_rawcheckstack(L, 1);
        luaC_threadbarrier(L);
        L->top->value.p = RenvCache;
        L->top->tt = LUA_TTABLE;
        L->top++;

        return 1;
    }

    int getcallingscript(lua_State* L)
    {
        CallInfo* ci = L->ci;

        while (ci > L->base_ci)
        {
            if (ci->func && ttisfunction(ci->func))
            {
                Closure* cl = clvalue(ci->func);

                bool is_executor = false;
                for (auto* exec_cl : Environment->function_array)
                {
                    if (exec_cl == cl)
                    {
                        is_executor = true;
                        break;
                    }
                }

                if (!is_executor && !cl->isC)
                {
                    lua_State* thread = L;
                    if (ci->func <= thread->stack)
                        thread = thread->global->mainthread;

                    auto* data = static_cast<RobloxExtraSpace*>(thread->userdata);

                    if (data && !data->script.expired())
                    {
                        Roblox::InstanceBridge::Weak(L, data->script);
                        return (1);
                    }
                }
            }
            ci--;
        }

        lua_pushnil(L);
        return (1);
    }

    int getsenv(lua_State* L) {
        
        luaL_checktype(L, 1, LUA_TUSERDATA);

        auto script = *reinterpret_cast<std::uintptr_t*>(lua_touserdata(L, 1));
        if (!script) {
            lua_pushnil(L);
            return 1;
        }

        lua_getfield(L, 1, ("ClassName"));
        std::string className = lua_tostring(L, -1);
        lua_pop(L, 1);

        if (className != ("LocalScript") && className != ("Script")) {
            lua_pushnil(L);
            return 1;
        }

        for (lua_Page* cur = L->global->allgcopages; cur;) {
            lua_Page* next = luaM_getnextpage(cur);

            char* start;
            char* end;
            int busy;
            int block;
            luaM_getpagewalkinfo(cur, &start, &end, &busy, &block);

            for (char* pos = start; pos != end; pos += block) {
                auto gco = reinterpret_cast<GCObject*>(pos);

                if (!gco || isdead(L->global, gco) || gco->gch.tt != LUA_TTHREAD)
                    continue;

                auto thread = reinterpret_cast<lua_State*>(pos);

                if (!thread->userdata || thread->userdata->script.expired())
                    continue;

                if ((uintptr_t)thread->userdata->script.lock().get() != script)
                    continue;

                if (thread->global->mainthread != L->global->mainthread) {
                    lua_pushnil(L);
                    return 1;
                }

                luaC_threadbarrier(L);
                luaC_threadbarrier(thread);

                lua_pushvalue(thread, LUA_GLOBALSINDEX);
                lua_xmove(thread, L, 1);
                return 1;
            }

            cur = next;
        }

        lua_pushnil(L);
        return 1;
    }

    int getscriptthread(lua_State* L)
    {
        
        luaL_checktype(L, 1, LUA_TUSERDATA);

        auto script = *reinterpret_cast<std::uintptr_t*>(lua_touserdata(L, 1));
        if (!script) {
            lua_pushnil(L);
            return 1;
        }

        lua_getfield(L, 1, ("ClassName"));
        std::string className;
        if (lua_isstring(L, -1))
            className = lua_tostring(L, -1);
        lua_pop(L, 1);

        if (className != ("LocalScript") && className != ("ModuleScript") &&
            className != ("Script") && className != ("CoreScript")) {
            lua_pushnil(L);
            return 1;
        }

        for (lua_Page* cur = L->global->allgcopages; cur;) {
            lua_Page* next = luaM_getnextpage(cur);

            char* start;
            char* end;
            int busy;
            int block;
            luaM_getpagewalkinfo(cur, &start, &end, &busy, &block);

            for (char* pos = start; pos != end; pos += block) {
                auto gco = reinterpret_cast<GCObject*>(pos);

                if (!gco || isdead(L->global, gco) || gco->gch.tt != LUA_TTHREAD)
                    continue;

                auto thread = reinterpret_cast<lua_State*>(pos);

                if (!thread->userdata || thread->userdata->script.expired())
                    continue;

                if ((uintptr_t)thread->userdata->script.lock().get() != script)
                    continue;

                if (thread->global->mainthread != L->global->mainthread) {
                    lua_pushnil(L);
                    return 1;
                }

                lua_pushthread(thread);
                lua_xmove(thread, L, 1);
                return 1;
            }

            cur = next;
        }

        lua_pushnil(L);
        return 1;
    }
    int checkcaller(lua_State* L) {
        
        if (Shared::ExploitThread && L == Shared::ExploitThread) {
            lua_pushboolean(L, true);
            return 1;
        }
        if (L && L->userdata &&
            (L->userdata->script.expired() ||
                L->userdata->capabilities == MaxCapabilities)) {
            lua_pushboolean(L, true);
            return 1;
        }
        lua_Debug ar;
        for (int level = 1; level <= 10; level++) {
            if (!lua_getinfo(L, level, ("f"), &ar))
                break;
            if (lua_isfunction(L, -1)) {
                Closure* cl = clvalue(index2addr(L, -1));
                if (cl->isC) {
                    for (auto func : Environment->function_array)
                        if (func == cl || func->c.f == cl->c.f) {
                            lua_pop(L, 1);
                            lua_pushboolean(L, true);
                            return 1;
                        }
                }
                else if (cl->l.p && cl->l.p->source) {
                    const char* src = getstr(cl->l.p->source);
                    if (src && (strcmp(src, ("=loadstring")) == 0 ||
                        strcmp(src, ("@Nam")) == 0 || strcmp(src, ("@Arona")) == 0)) {
                        lua_pop(L, 1);
                        lua_pushboolean(L, true);
                        return 1;
                    }
                }
                if (Closures::WrappedClosures.count(cl)) {
                    lua_pop(L, 1);
                    lua_pushboolean(L, true);
                    return 1;
                }
            }
            lua_pop(L, 1);
        }
        lua_pushboolean(L, false);
        return 1;
    }
    bool ReadProtectedString(uintptr_t address, std::string& out)
    {
        out.clear();

        static const size_t dataOffsets[] = { 0x10, 0x18 };
        static const size_t sizeOffsets[] = { 0x28, 0x20 };

        for (size_t dataOff : dataOffsets)
        {
            for (size_t sizeOff : sizeOffsets)
            {
                if (!HelperFuncs::CheckMemory(address + dataOff + sizeof(uintptr_t)))
                    continue;
                if (!HelperFuncs::CheckMemory(address + sizeOff + sizeof(size_t)))
                    continue;

                uintptr_t data = *reinterpret_cast<uintptr_t*>(address + dataOff);
                size_t len = *reinterpret_cast<size_t*>(address + sizeOff);

                if (len == 0 || len > 64 * 1024 * 1024)
                    continue;

                if (!HelperFuncs::CheckMemory(data) || !HelperFuncs::CheckMemory(data + len - 1))
                    continue;

                out.assign(reinterpret_cast<const char*>(data), len);
                return true;
            }
        }
        return false;
    }

    bool GetInstanceClassName(lua_State* L, int index, std::string& className)
    {
        int top = lua_gettop(L);
        lua_getfield(L, index, ("ClassName"));
        if (!lua_isstring(L, -1))
        {
            lua_settop(L, top);
            return false;
        }

        const char* value = lua_tostring(L, -1);
        className = value ? value : ("");
        lua_settop(L, top);
        return true;
    }

    int getscriptclosure(lua_State* L)
    {
        
        luaL_checktype(L, 1, LUA_TUSERDATA);

        std::string className;
        if (!GetInstanceClassName(L, 1, className))
            return ScriptError(L, ("Invalid Instance"));

        if (className != ("ModuleScript") && className != ("LocalScript") &&
            className != ("Script") && className != ("CoreScript"))
            return ScriptError(L, ("Script expected"));

        void* userdata = lua_touserdata(L, 1);
        if (!userdata)
            return ScriptError(L, ("Invalid Instance"));

        const std::uintptr_t script = *reinterpret_cast<const uintptr_t*>(userdata);

        if (!script)
            return ScriptError(L, ("Invalid Instance"));

        const bool UsesHolder = className != ("ModuleScript");

        const uintptr_t HolderR = UsesHolder ? Offsets::Scripts::LocalScriptByteCode : Offsets::Scripts::ModuleScriptByteCode;

        const uintptr_t HolderAddress = script + HolderR;

        if (!HelperFuncs::CheckMemory(HolderAddress))
            return ScriptError(L, ("Invalid bytecode holder address"));

        const std::uintptr_t holder = *reinterpret_cast<const std::uintptr_t*>(HolderAddress);

        if (!holder)
            return ScriptError(L, ("Null bytecode holder"));

        std::string encrypted;

        static const uintptr_t baseOffsets[] = { 0x18, 0x00, 0x10, 0x08 };
        bool found = false;
        for (uintptr_t baseOff : baseOffsets)
        {
            if (ReadProtectedString(holder + baseOff, encrypted) && !encrypted.empty())
            {
                found = true;
                break;
            }
        }

        if (!found || encrypted.empty())
            return ScriptError(L, ("string read failed"));

        if (encrypted.empty())
        {
            lua_pushnil(L);
            return 1;
        }

        lua_State* thread = lua_newthread(L);
        if (!thread)
            return ScriptError(L, ("Failed to create thread"));

        const int thread_ref = lua_ref(L, -1);
        lua_pop(L, 1);

        luaL_sandboxthread(thread);
        task_scheduler::SetIdentity(thread, 8, false);

        lua_pushvalue(L, 1);
        lua_xmove(L, thread, 1);
        lua_setglobal(thread, ("script"));

        const int loadResult = Roblox::LuaVMLoad(thread, &encrypted, ("getscriptclosure"), 0);

        if (loadResult != LUA_OK)
        {
            const char* error = lua_tostring(thread, -1);

            lua_settop(thread, 0);
            lua_unref(L, thread_ref);
            lua_pushnil(L);
            return 1;
        }

        if (!lua_isLfunction(thread, -1))
        {

            lua_settop(thread, 0);
            lua_unref(L, thread_ref);
            lua_pushnil(L);
            return 1;
        }

        Closure* closure = clvalue(luaA_toobject(thread, -1));

        if (!closure || closure->isC || !closure->l.p)
        {
            lua_settop(thread, 0);
            lua_unref(L, thread_ref);
            lua_pushnil(L);
            return 1;
        }

        task_scheduler::SetProtoCapabilities(closure->l.p, &MaxCapabilities);

        lua_xmove(thread, L, 1);
        lua_settop(thread, 0);
        lua_unref(L, thread_ref);

        return 1;
    }

    typedef void(__fastcall* PushInstanceWeakPtrT)(lua_State* L, std::weak_ptr<uintptr_t>);
    static PushInstanceWeakPtrT PushInstanceWeakPtr = (PushInstanceWeakPtrT)Roblox::PushInstance;

    int getscriptfromthread(lua_State* L)
    {
        

        luaL_checktype(L, 1, LUA_TTHREAD);

        lua_State* thread = lua_tothread(L, 1);

        if (!thread || !thread->userdata || thread->userdata->script.expired()) {
            lua_pushnil(L);
            return 1;
        }

        auto script = thread->userdata->script.lock();
        Roblox::InstanceBridge::Weak(L, script);

        return 1;
    }

    int getrunningscriptsv2(lua_State* L)
    {
        
        lua_newtable(L);
        int tableIndex = lua_gettop(L);
        int i = 0;
        std::unordered_map<std::shared_ptr<std::uintptr_t*>, bool> running_scripts = { };
        lua_rawcheckstack(L, 5);
        luaC_threadbarrier(L);
        lua_pushvalue(L, LUA_REGISTRYINDEX);
        lua_pushnil(L);
        while (lua_next(L, -2)) {
            if (lua_isthread(L, -1)) {
                lua_State* thread = lua_tothread(L, -1);
                if (thread && thread->userdata != nullptr && !thread->userdata->script.expired()) {
                    if (thread->global->mainthread == L->global->mainthread) {
                        const auto script = *reinterpret_cast<std::shared_ptr<std::uintptr_t*>*>(&thread->userdata->script);
                        if (!running_scripts.contains(script)) {
                            Roblox::InstanceBridge::SharedInstance(L, script);
                            lua_getfield(L, -1, ("ClassName"));
                            const char* className = lua_tostring(L, -1);
                            lua_pop(L, 1);

                            bool isValidScript = false;

                            if (className) {
                                if (strcmp(className, ("LocalScript")) == 0 || strcmp(className, ("ModuleScript")) == 0) {
                                    isValidScript = true;
                                }
                                else if (strcmp(className, ("Script")) == 0) {
                                    lua_getfield(L, -1, ("RunContext"));
                                    if (lua_type(L, -1) != LUA_TNIL) {
                                        if (lua_isnumber(L, -1)) {
                                            int runContext = lua_tointeger(L, -1);
                                            isValidScript = (runContext == 2);
                                        }
                                        else {
                                            lua_getfield(L, -1, ("Value"));
                                            if (lua_isnumber(L, -1)) {
                                                int runContext = lua_tointeger(L, -1);
                                                isValidScript = (runContext == 2);
                                            }
                                            lua_pop(L, 1);
                                        }
                                    }
                                    lua_pop(L, 1);
                                }
                            }

                            if (isValidScript) {
                                running_scripts[script] = true;
                                lua_rawseti(L, tableIndex, ++i);
                            }
                            else {
                                lua_pop(L, 1);
                            }
                        }
                    }
                }
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
        return 1;
    }

    int getallthreads(lua_State* L)
    {
        
        lua_newtable(L);
        int resultIdx = lua_gettop(L);
        int index = 0;

        global_State* g = L->global;
        if (!g) return 1;

        // Walk all GC pages and collect reachable threads
        const auto oldGCThreshold = g->GCthreshold;
        g->GCthreshold = SIZE_MAX;

        for (lua_Page* page = g->allgcopages; page; page = luaM_getnextpage(page))
        {
            char* start;
            char* end;
            int busy;
            int block;
            luaM_getpagewalkinfo(page, &start, &end, &busy, &block);

            for (char* pos = start; pos != end; pos += block)
            {
                GCObject* gco = reinterpret_cast<GCObject*>(pos);

                if (isdead(g, gco))
                    continue;

                if (gco->gch.tt != LUA_TTHREAD)
                    continue;

                lua_State* thread = reinterpret_cast<lua_State*>(pos);
                if (!thread)
                    continue;

                luaC_threadbarrier(L);
                lua_pushthread(thread);
                lua_xmove(thread, L, 1);

                index++;
                lua_rawseti(L, resultIdx, index);
            }
        }

        g->GCthreshold = oldGCThreshold;

        return 1;
    }

    namespace shaiscute {
        static const uint64_t K384[80] = {
            0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
            0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
            0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
            0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
            0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
            0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
            0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
            0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
            0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
            0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
            0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
            0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
            0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
            0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
            0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
            0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL,
        };
        inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
        inline uint64_t ch(uint64_t e, uint64_t f, uint64_t g) { return (e & f) ^ (~e & g); }
        inline uint64_t maj(uint64_t a, uint64_t b, uint64_t c) { return (a & b) ^ (a & c) ^ (b & c); }
        inline uint64_t s0(uint64_t a) { return rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39); }
        inline uint64_t s1(uint64_t e) { return rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41); }
        inline uint64_t o0(uint64_t w) { return rotr64(w, 1) ^ rotr64(w, 8) ^ (w >> 7); }
        inline uint64_t o1(uint64_t w) { return rotr64(w, 19) ^ rotr64(w, 61) ^ (w >> 6); }
    }

    inline std::string shatobyfron(const std::string& msg) {
        using namespace shaiscute;
        uint64_t h[8] = {
            0xcbbb9d5dc1059ed8ULL,0x629a292a367cd507ULL,0x9159015a3070dd17ULL,0x152fecd8f70e5939ULL,
            0x67332667ffc00b31ULL,0x8eb44a8768581511ULL,0xdb0c2e0d64f98fa7ULL,0x47b5481dbefa4fa4ULL,
        };

        uint64_t bitlen = (uint64_t)msg.size() * 8;
        std::vector<uint8_t> data(msg.begin(), msg.end());
        data.push_back(0x80);
        while (data.size() % 128 != 112) data.push_back(0x00);
        for (int i = 7; i >= 0; --i) data.push_back(0);
        for (int i = 7; i >= 0; --i) data.push_back((uint8_t)(bitlen >> (i * 8)));

        for (size_t chunk = 0; chunk < data.size(); chunk += 128) {
            uint64_t w[80] = {};
            for (int i = 0; i < 16; ++i) {
                w[i] = 0;
                for (int j = 0; j < 8; ++j)
                    w[i] = (w[i] << 8) | data[chunk + i * 8 + j];
            }
            for (int i = 16; i < 80; ++i)
                w[i] = o1(w[i - 2]) + w[i - 7] + o0(w[i - 15]) + w[i - 16];

            uint64_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
            for (int i = 0; i < 80; ++i) {
                uint64_t t1 = hh + s1(e) + ch(e, f, g) + K384[i] + w[i];
                uint64_t t2 = s0(a) + maj(a, b, c);
                hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
            }
            h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        }

        char buf[97];
        snprintf(buf, sizeof(buf),
            ("%016llx%016llx%016llx%016llx%016llx%016llx"),
            (unsigned long long)h[0], (unsigned long long)h[1], (unsigned long long)h[2],
            (unsigned long long)h[3], (unsigned long long)h[4], (unsigned long long)h[5]);
        return std::string(buf);
    }


    int getscripthash(lua_State* L)
    {
        
        luaL_checktype(L, 1, LUA_TUSERDATA);
        const char* typeName = luaL_typename(L, 1);
        if (!typeName || std::strcmp(typeName, "Instance") != 0)
            luaL_typeerrorL(L, 1, "Instance");

        void** userdata = static_cast<void**>(lua_touserdata(L, 1));
        if (!userdata || !*userdata || !Util::CheckMemory(reinterpret_cast<std::uintptr_t>(*userdata)))
            luaL_argerrorL(L, 1, "invalid instance");

        const std::uintptr_t script = reinterpret_cast<std::uintptr_t>(*userdata);

        const int top = lua_gettop(L);
        lua_getfield(L, 1, "ClassName");
        std::string className;
        if (lua_isstring(L, -1))
            className = lua_tostring(L, -1);
        lua_settop(L, top);

        if (!IsScriptClass(className))
            luaL_typeerrorL(L, 1, "LocalScript, ModuleScript or Script");

        std::string rawData;

        // Check if script has bytecode in engine
        std::string bytecode;
        bool hasBytecode = false;
        try {
            hasBytecode = FetchBytecode(script, className == "ModuleScript", bytecode) && !bytecode.empty();
        }
        catch (...) {
            hasBytecode = false;
        }

        if (hasBytecode) {
            rawData = std::move(bytecode);
        }
        else {
            // Check if Source property is set and non-empty (for cloned/in-memory scripts)
            lua_getfield(L, 1, "Source");
            if (lua_isstring(L, -1)) {
                size_t len = 0;
                const char* src = lua_tolstring(L, -1, &len);
                if (src && len > 0) {
                    rawData.assign(src, len);
                }
            }
            lua_pop(L, 1);
        }

        // If no bytecode and no source, return nil (per UNC standard)
        if (rawData.empty()) {
            lua_pushnil(L);
            return 1;
        }

        std::string hash = shatobyfron(rawData);
        lua_pushlstring(L, hash.data(), hash.size());
        return 1;
    }



    // find the coroutine belonging to `script` and push its globals table -
    // that table is the environment the module actually runs with
    static bool PushThreadEnvForScript(lua_State* L, std::uintptr_t script)
    {
        if (!script)
            return false;

        for (lua_Page* cur = L->global->allgcopages; cur;) {
            lua_Page* next = luaM_getnextpage(cur);

            char* start;
            char* end;
            int busy;
            int block;
            luaM_getpagewalkinfo(cur, &start, &end, &busy, &block);

            for (char* pos = start; pos != end; pos += block) {
                auto gco = reinterpret_cast<GCObject*>(pos);

                if (!gco || isdead(L->global, gco) || gco->gch.tt != LUA_TTHREAD)
                    continue;

                auto thread = reinterpret_cast<lua_State*>(pos);

                if (!thread->userdata || thread->userdata->script.expired())
                    continue;

                if ((uintptr_t)thread->userdata->script.lock().get() != script)
                    continue;

                if (thread->global->mainthread != L->global->mainthread)
                    continue;

                luaC_threadbarrier(L);
                luaC_threadbarrier(thread);

                lua_pushvalue(thread, LUA_GLOBALSINDEX);
                lua_xmove(thread, L, 1);
                return true;
            }

            cur = next;
        }

        return false;
    }

    // every closure the module body creates carries the module's env - pull a
    // Lua closure out of require()'s return value (function or export table)
    // and getfenv it. C closures are skipped: theirs point at foreign envs.
    static bool PushEnvFromExport(lua_State* L, int idx, int depth)
    {
        if (idx < 0)
            idx = lua_gettop(L) + idx + 1;

        if (lua_isfunction(L, idx))
        {
            if (!lua_isLfunction(L, idx))
                return false;

            lua_getfenv(L, idx);
            if (lua_istable(L, -1))
                return true;

            lua_pop(L, 1);
            return false;
        }

        if (!lua_istable(L, idx) || depth <= 0)
            return false;

        lua_pushnil(L);
        while (lua_next(L, idx))
        {
            if (lua_isLfunction(L, -1))
            {
                lua_getfenv(L, -1);
                if (lua_istable(L, -1))
                {
                    lua_remove(L, -2); // drop the closure
                    lua_remove(L, -2); // drop the key
                    return true;
                }
                lua_pop(L, 1);
            }
            else if (lua_istable(L, -1))
            {
                if (PushEnvFromExport(L, -1, depth - 1))
                {
                    lua_remove(L, -2); // drop the nested table
                    lua_remove(L, -2); // drop the key
                    return true;
                }
            }

            lua_pop(L, 1);
        }

        return false;
    }

    int getmenv(lua_State* L) {
        
        if (!lua_isuserdata(L, 1)) {
            lua_pushnil(L);
            return 1;
        }

        lua_getfield(L, 1, "ClassName");
        const char* cn = lua_isstring(L, -1) ? lua_tostring(L, -1) : nullptr;
        lua_pop(L, 1);

        if (!cn || strcmp(cn, "ModuleScript") != 0) {
            lua_pushnil(L);
            return 1;
        }

        void* userdata = lua_touserdata(L, 1);
        if (!userdata) {
            lua_pushnil(L);
            return 1;
        }

        const std::uintptr_t script = *reinterpret_cast<std::uintptr_t*>(userdata);

        // 1) the module already ran - its coroutine still owns the real env
        if (PushThreadEnvForScript(L, script))
            return 1;

        // 2) load it (require caches, so this only runs the body once)
        lua_getglobal(L, "require");
        if (lua_isfunction(L, -1))
        {
            lua_pushvalue(L, 1);
            if (lua_pcall(L, 1, 1, 0) == 0)
            {
                // it just executed - its coroutine env is alive right now
                if (PushThreadEnvForScript(L, script))
                {
                    lua_remove(L, -2);
                    return 1;
                }

                // otherwise recover the env from a closure it returned
                if (PushEnvFromExport(L, -1, 4))
                {
                    lua_remove(L, -2);
                    return 1;
                }

                lua_pop(L, 1);
            }
            else
            {
                lua_pop(L, 1);
            }
        }
        else
        {
            lua_pop(L, 1);
        }

        // 3) last resort: env of the freshly loaded main chunk - a sandbox
        //    table that still proxies reads to the real globals, has `script`
        lua_pushcclosure(L, getscriptclosure, nullptr, 0);
        lua_pushvalue(L, 1);
        if (lua_pcall(L, 1, 1, 0) == 0)
        {
            if (lua_isfunction(L, -1))
            {
                lua_getfenv(L, -1);
                if (lua_istable(L, -1))
                {
                    lua_remove(L, -2);
                    return 1;
                }
                lua_pop(L, 1);
            }
            lua_pop(L, 1);
        }
        else
        {
            lua_pop(L, 1);
        }

        lua_pushnil(L);
        return 1;
    }

    namespace FilterGCUtils
    {
        inline bool lua_equal_tuff(lua_State* L, int a, int b)
        {
            const int ta = lua_type(L, a);
            const int tb = lua_type(L, b);

            if (ta != tb)
                return false;

            if (ta == LUA_TNUMBER)
            {
                const lua_Number na = lua_tonumber(L, a);
                const lua_Number nb = lua_tonumber(L, b);

                if (std::isnan(na) && std::isnan(nb))
                    return true;

                return na == nb;
            }

            return lua_equal(L, a, b);
        }

        inline bool tableHasKeys(lua_State* L, int tableIndex, int keysIndex)
        {
            if (!lua_istable(L, keysIndex))
                return true;

            tableIndex = lua_absindex(L, tableIndex);
            keysIndex = lua_absindex(L, keysIndex);

            lua_pushnil(L);
            while (lua_next(L, keysIndex) != 0)
            {
                lua_pushvalue(L, -1);
                lua_rawget(L, tableIndex);
                const bool hasKey = !lua_isnil(L, -1);
                lua_pop(L, 2);

                if (!hasKey)
                {
                    lua_pop(L, 1);
                    return false;
                }
            }

            return true;
        }

        inline bool tableHasValues(lua_State* L, int tableIndex, int valuesIndex)
        {
            if (!lua_istable(L, valuesIndex))
                return true;

            tableIndex = lua_absindex(L, tableIndex);
            valuesIndex = lua_absindex(L, valuesIndex);

            lua_newtable(L);
            const int tempTableIndex = lua_gettop(L);
            int valueCount = 0;

            lua_pushnil(L);
            while (lua_next(L, tableIndex) != 0)
            {
                lua_rawseti(L, tempTableIndex, ++valueCount);
            }

            lua_pushnil(L);
            while (lua_next(L, valuesIndex) != 0)
            {
                bool found = false;

                for (int i = 1; i <= valueCount; ++i)
                {
                    lua_rawgeti(L, tempTableIndex, i);
                    const bool equal = lua_equal_tuff(L, -1, -2);
                    lua_pop(L, 1);

                    if (equal)
                    {
                        found = true;
                        break;
                    }
                }

                lua_pop(L, 1);
                if (!found)
                {
                    lua_pop(L, 2);
                    return false;
                }
            }

            lua_pop(L, 1);
            return true;
        }

        inline bool tableHasKeyValuePairs(lua_State* L, int tableIndex, int pairsIndex)
        {
            if (!lua_istable(L, pairsIndex))
                return true;

            tableIndex = lua_absindex(L, tableIndex);
            pairsIndex = lua_absindex(L, pairsIndex);

            lua_pushnil(L);
            while (lua_next(L, pairsIndex) != 0)
            {
                lua_pushvalue(L, -2);
                lua_rawget(L, tableIndex);
                const bool equal = lua_equal_tuff(L, -1, -2);
                lua_pop(L, 2);

                if (!equal)
                {
                    lua_pop(L, 1);
                    return false;
                }
            }

            return true;
        }

        inline bool tableHasMetatable(lua_State* L, int tableIndex, int expectedMT)
        {
            if (lua_isnil(L, expectedMT))
                return true;

            tableIndex = lua_absindex(L, tableIndex);
            expectedMT = lua_absindex(L, expectedMT);

            if (!lua_getmetatable(L, tableIndex))
                return false;

            const bool equal = lua_equal_tuff(L, -1, expectedMT);
            lua_pop(L, 1);
            return equal;
        }

        inline std::string getFunctionName(lua_State* L, int funcIndex)
        {
            funcIndex = lua_absindex(L, funcIndex);

            lua_Debug ar{};
            lua_pushvalue(L, funcIndex);
            if (lua_getinfo(L, -1, "n", &ar) && ar.name)
            {
                std::string result(ar.name);
                lua_pop(L, 1);
                return result;
            }
            lua_pop(L, 1);

            lua_pushvalue(L, funcIndex);
            const char* str = lua_tostring(L, -1);
            std::string result = str ? std::string(str) : "";
            lua_pop(L, 1);
            return result;
        }

        inline bool functionHasConstants(lua_State* L, int funcIndex, int constantsIndex)
        {
            if (!lua_istable(L, constantsIndex))
                return true;

            if (lua_iscfunction(L, funcIndex))
                return false;

            funcIndex = lua_absindex(L, funcIndex);
            constantsIndex = lua_absindex(L, constantsIndex);

            lua_getglobal(L, "debug");
            if (lua_isnil(L, -1))
            {
                lua_pop(L, 1);
                return false;
            }

            lua_getfield(L, -1, "getconstants");
            if (lua_isnil(L, -1))
            {
                lua_pop(L, 2);
                return false;
            }

            lua_pushvalue(L, funcIndex);
            if (lua_pcall(L, 1, 1, 0) != 0)
            {
                lua_pop(L, 2);
                return false;
            }

            const int actualConstants = lua_gettop(L);

            lua_pushnil(L);
            while (lua_next(L, constantsIndex) != 0)
            {
                bool found = false;

                lua_pushnil(L);
                while (lua_next(L, actualConstants) != 0)
                {
                    if (lua_equal_tuff(L, -1, -3))
                    {
                        found = true;
                        lua_pop(L, 2);
                        break;
                    }

                    lua_pop(L, 1);
                }

                lua_pop(L, 1);
                if (!found)
                {
                    lua_pop(L, 3);
                    return false;
                }
            }

            lua_pop(L, 2);
            return true;
        }

        inline bool functionHasUpvalues(lua_State* L, int funcIndex, int upvaluesIndex)
        {
            if (!lua_istable(L, upvaluesIndex))
                return true;

            funcIndex = lua_absindex(L, funcIndex);
            upvaluesIndex = lua_absindex(L, upvaluesIndex);

            lua_getglobal(L, "debug");
            if (lua_isnil(L, -1))
            {
                lua_pop(L, 1);
                return false;
            }

            lua_getfield(L, -1, "getupvalues");
            if (lua_isnil(L, -1))
            {
                lua_pop(L, 2);
                return false;
            }

            lua_pushvalue(L, funcIndex);
            if (lua_pcall(L, 1, 1, 0) != 0)
            {
                lua_pop(L, 2);
                return false;
            }

            const int actualUpvalues = lua_gettop(L);

            lua_pushnil(L);
            while (lua_next(L, upvaluesIndex) != 0)
            {
                bool found = false;

                lua_pushnil(L);
                while (lua_next(L, actualUpvalues) != 0)
                {
                    if (lua_equal_tuff(L, -1, -3))
                    {
                        found = true;
                        lua_pop(L, 2);
                        break;
                    }

                    lua_pop(L, 1);
                }

                lua_pop(L, 1);
                if (!found)
                {
                    lua_pop(L, 3);
                    return false;
                }
            }

            lua_pop(L, 2);
            return true;
        }
    }

    inline int filtergc(lua_State* L)
    {
        luaL_checkany(L, 1);

        constexpr int filterOptions = 2;
        const bool returnOne = lua_toboolean(L, 3);

        if (lua_isfunction(L, 1))
        {
            lua_newtable(L);
            const int matchesIndex = lua_gettop(L);
            int matchCount = 0;

            PushGCObjects(L, true);
            const int gcTable = lua_gettop(L);

            lua_pushnil(L);
            while (lua_next(L, gcTable) != 0)
            {
                lua_pushvalue(L, 1);
                lua_pushvalue(L, -2);

                if (lua_pcall(L, 1, 1, 0) == 0)
                {
                    if (lua_toboolean(L, -1))
                    {
                        lua_pop(L, 1);
                        lua_pushvalue(L, -1);
                        lua_rawseti(L, matchesIndex, ++matchCount);
                    }
                    else
                    {
                        lua_pop(L, 1);
                    }
                }
                else
                {
                    lua_pop(L, 1);
                }

                lua_pop(L, 1);
            }

            lua_pop(L, 1);
            return 1;
        }

        const char* filterType = luaL_checkstring(L, 1);

        lua_newtable(L);
        const int matchesIndex = lua_gettop(L);
        int matchCount = 0;

        if (strcmp(filterType, "table") == 0)
        {
            PushGCObjects(L, true);
            const int gcTable = lua_gettop(L);

            lua_pushnil(L);
            while (lua_next(L, gcTable) != 0)
            {
                if (lua_istable(L, -1))
                {
                    bool passed = true;
                    const int currentTable = lua_gettop(L);

                    if (passed && lua_istable(L, filterOptions))
                    {
                        lua_getfield(L, filterOptions, "Keys");
                        if (!lua_isnil(L, -1))
                            passed = FilterGCUtils::tableHasKeys(L, currentTable, lua_gettop(L));
                        lua_pop(L, 1);
                    }

                    if (passed && lua_istable(L, filterOptions))
                    {
                        lua_getfield(L, filterOptions, "Values");
                        if (!lua_isnil(L, -1))
                            passed = FilterGCUtils::tableHasValues(L, currentTable, lua_gettop(L));
                        lua_pop(L, 1);
                    }

                    if (passed && lua_istable(L, filterOptions))
                    {
                        lua_getfield(L, filterOptions, "KeyValuePairs");
                        if (!lua_isnil(L, -1))
                            passed = FilterGCUtils::tableHasKeyValuePairs(L, currentTable, lua_gettop(L));
                        lua_pop(L, 1);
                    }

                    if (passed && lua_istable(L, filterOptions))
                    {
                        lua_getfield(L, filterOptions, "Metatable");
                        if (!lua_isnil(L, -1))
                            passed = FilterGCUtils::tableHasMetatable(L, currentTable, lua_gettop(L));
                        lua_pop(L, 1);
                    }

                    if (passed)
                    {
                        if (returnOne)
                            return 1;

                        lua_pushvalue(L, currentTable);
                        lua_rawseti(L, matchesIndex, ++matchCount);
                    }
                }

                lua_pop(L, 1);
            }

            lua_pop(L, 1);
        }
        else if (strcmp(filterType, "function") == 0)
        {
            bool ignoreExecutor = true;
            if (lua_istable(L, filterOptions))
            {
                lua_getfield(L, filterOptions, "IgnoreExecutor");
                if (!lua_isnil(L, -1))
                    ignoreExecutor = lua_toboolean(L, -1);
                lua_pop(L, 1);
            }

            PushGCObjects(L, false);
            const int gcTable = lua_gettop(L);

            lua_pushnil(L);
            while (lua_next(L, gcTable) != 0)
            {
                if (lua_isfunction(L, -1))
                {
                    bool passed = true;
                    const int currentFunc = lua_gettop(L);
                    const bool isCClosure = lua_iscfunction(L, currentFunc);

                    if (passed && lua_istable(L, filterOptions))
                    {
                        lua_getfield(L, filterOptions, "Name");
                        if (!lua_isnil(L, -1))
                        {
                            const char* requiredName = lua_tostring(L, -1);
                            const std::string funcName = FilterGCUtils::getFunctionName(L, currentFunc);
                            passed = requiredName && funcName.find(requiredName) != std::string::npos;
                        }
                        lua_pop(L, 1);
                    }

                    if (passed && ignoreExecutor)
                    {
                        Closure* closure = clvalue(luaA_toobject(L, currentFunc));
                        if (Closures::IsExecutorClosure(closure))
                            passed = false;
                    }

                    if (isCClosure && lua_istable(L, filterOptions))
                    {
                        lua_getfield(L, filterOptions, "Hash");
                        const bool hasHash = !lua_isnil(L, -1);
                        lua_pop(L, 1);

                        lua_getfield(L, filterOptions, "Constants");
                        const bool hasConstants = !lua_isnil(L, -1);
                        lua_pop(L, 1);

                        lua_getfield(L, filterOptions, "Upvalues");
                        const bool hasUpvalues = !lua_isnil(L, -1);
                        lua_pop(L, 1);

                        if (hasHash || hasConstants || hasUpvalues)
                            passed = false;
                    }

                    if (passed && !isCClosure && lua_istable(L, filterOptions))
                    {
                        lua_getfield(L, filterOptions, "Hash");
                        if (!lua_isnil(L, -1))
                        {
                            const char* requiredHash = lua_tostring(L, -1);
                            Closure* closure = clvalue(luaA_toobject(L, currentFunc));

                            if (closure->isC)
                            {
                                passed = false;
                            }
                            else
                            {
                                Proto* proto = closure->l.p;
                                const std::vector<unsigned char> protoBytes = Crypt::getProtoBytes(proto);
                                const std::string hash = shatobyfron(std::string(
                                    reinterpret_cast<const char*>(protoBytes.data()),
                                    protoBytes.size()));

                                passed = requiredHash && hash == requiredHash;
                            }
                        }
                        lua_pop(L, 1);
                    }

                    if (passed && !isCClosure && lua_istable(L, filterOptions))
                    {
                        lua_getfield(L, filterOptions, "Constants");
                        if (!lua_isnil(L, -1))
                            passed = FilterGCUtils::functionHasConstants(L, currentFunc, lua_gettop(L));
                        lua_pop(L, 1);
                    }

                    if (passed && !isCClosure && lua_istable(L, filterOptions))
                    {
                        lua_getfield(L, filterOptions, "Upvalues");
                        if (!lua_isnil(L, -1))
                            passed = FilterGCUtils::functionHasUpvalues(L, currentFunc, lua_gettop(L));
                        lua_pop(L, 1);
                    }

                    if (passed)
                    {
                        if (returnOne)
                            return 1;

                        lua_pushvalue(L, currentFunc);
                        lua_rawseti(L, matchesIndex, ++matchCount);
                    }
                }

                lua_pop(L, 1);
            }

            lua_pop(L, 1);
        }
        else
        {
            luaL_error(L, ("Expected type 'function' or 'table', got '%s'"), filterType);
        }

        if (returnOne)
        {
            lua_pushnil(L);
            return 1;
        }

        return 1;
    }
    void register_lib(lua_State* L)
    {
        if (!L) return;

        Environment->make_global(L, ("getloadedmodules"), getloadedmodules, Script::funcnameinc++);
        Environment->make_global(L, ("getrunningscripts"), getrunningscriptsv2, Script::funcnameinc++);
        Environment->make_global(L, ("checkcaller"), checkcaller, Script::funcnameinc++);
        Environment->make_global(L, ("getscriptfromthread"), getscriptfromthread, Script::funcnameinc++);
        Environment->make_global(L, ("getscripts"), getscripts, Script::funcnameinc++);
        Environment->make_global(L, ("getrenv"), getrenv, Script::funcnameinc++);
        Environment->make_global(L, ("getscripthash"), getscripthash, Script::funcnameinc++);
        Environment->make_global(L, ("filtergc"), filtergc, Script::funcnameinc++);
        Environment->make_global(L, ("getcallingscript"), getcallingscript, Script::funcnameinc++);
        Environment->make_global(L, ("getgc"), getgc, Script::funcnameinc++);
        Environment->make_global(L, ("getsenv"), getsenv, Script::funcnameinc++);
        Environment->make_global(L, ("getmenv"), getmenv, Script::funcnameinc++);
        Environment->make_global(L, ("getscriptclosure"), getscriptclosure, Script::funcnameinc++);
        Environment->make_global(L, ("getscriptfunction"), getscriptclosure, Script::funcnameinc++);
        Environment->make_global(L, ("getscriptthread"), getscriptthread, Script::funcnameinc++);
       Environment->make_global(L, ("getscriptbytecode"), getscriptbytecode, Script::funcnameinc++);
        Environment->make_global(L, ("dumpstring"), getscriptbytecode, Script::funcnameinc++);
        Environment->make_global(L, ("getallthreads"), getallthreads, Script::funcnameinc++);
    }
}
