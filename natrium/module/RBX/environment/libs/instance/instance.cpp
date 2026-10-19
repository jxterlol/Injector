#include "Instance.hpp"

#include <Windows.h>
#include <lgc.h>
#include <lualib.h>
#include <string>

#include <RBX/environment/env.hpp>
#include <Utilitys/Log.hpp>
#include <RBX/environment/libs/closures/closures.hpp>
static bool can_read(uintptr_t address, size_t size = 1) noexcept
{
    if (address < 0x10000)
        return false;

    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) == 0)
        return false;

    if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
        return false;

    uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return address + size >= address && address + size <= regionEnd;
}

static bool IsRobloxInstance(lua_State* L, int idx)
{
   
    if (!lua_isuserdata(L, idx)) return false;
    lua_getglobal(L, ("typeof"));
    lua_pushvalue(L, idx);
    if (lua_pcall(L, 1, 1, 0) != LUA_OK) { lua_pop(L, 1); return false; }
    bool ok = lua_isstring(L, -1) && strcmp(lua_tostring(L, -1), ("Instance")) == 0;
    lua_pop(L, 1);
    return ok;
}

int Instance::getinstances(lua_State* L)
{
    
    luaL_trimstack(L, 0);

    lua_newtable(L);
    int resultIdx = lua_gettop(L);
    int index = 0;

    lua_pushvalue(L, LUA_REGISTRYINDEX);
    lua_pushlightuserdata(L, reinterpret_cast<void*>(Roblox::InstanceBridge::UintPtr));
    lua_rawget(L, -2);

    if (lua_istable(L, -1))
    {
        lua_pushnil(L);
        while (lua_next(L, -2) != 0)
        {
            if (!lua_isnil(L, -1))
            {
                lua_getglobal(L, ("typeof"));
                lua_pushvalue(L, -2);
                lua_pcall(L, 1, 1, 0);
                bool isInst = lua_isstring(L, -1) &&
                    strcmp(lua_tostring(L, -1), ("Instance")) == 0;
                lua_pop(L, 1);

                if (isInst)
                {
                    lua_pushinteger(L, ++index);
                    lua_pushvalue(L, -2);
                    lua_settable(L, resultIdx);
                }
            }
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 2);

    lua_getglobal(L, ("game"));
    if (!lua_isnil(L, -1))
    {
        bool found = false;
        for (int i = 1; i <= index; ++i)
        {
            lua_rawgeti(L, resultIdx, i);
            if (lua_rawequal(L, -1, -2)) { found = true; lua_pop(L, 1); break; }
            lua_pop(L, 1);
        }
        if (!found)
        {
            lua_pushinteger(L, ++index);
            lua_pushvalue(L, -2);
            lua_settable(L, resultIdx);
        }
    }
    lua_pop(L, 1);

    lua_pushvalue(L, resultIdx);
    return 1;
}

int Instance::getnilinstances(lua_State* L)
{
    
    luaL_trimstack(L, 0);

    lua_pushvalue(L, LUA_REGISTRYINDEX);
    lua_pushlightuserdata(L, reinterpret_cast<void*>(Roblox::InstanceBridge::UintPtr));
    lua_rawget(L, -2);

    if (!lua_istable(L, -1)) { lua_pop(L, 1); lua_pushnil(L); return 1; };

    lua_newtable(L);

    int index = 0;

    lua_pushnil(L);
    while (lua_next(L, -3) != 0) {

        if (!lua_isnil(L, -1)) {
            lua_getglobal(L, ("typeof"));
            lua_pushvalue(L, -2);
            lua_pcall(L, 1, 1, 0);

            std::string type = lua_tostring(L, -1);
            lua_pop(L, 1);

            if (type == ("Instance")) {
                lua_getfield(L, -1, ("Parent"));
                int parentType = lua_type(L, -1);
                lua_pop(L, 1);

                if (parentType == LUA_TNIL) {
                    lua_pushinteger(L, ++index);

                    lua_pushvalue(L, -2);
                    lua_settable(L, -5);
                }
            }
        }

        lua_pop(L, 1);
    }

    lua_remove(L, -2);

    return 1;
}

int Instance::isnetworkowner(lua_State* L)
{
    
    if (!L || !lua_isuserdata(L, 1)) {
        lua_pushboolean(L, 0);
        return 1;
    }

    lua_getfield(L, 1, ("Name"));
    if (lua_isstring(L, -1)) {
        const char* name = lua_tostring(L, -1);
        if (name && strcmp(name, ("HumanoidRootPart")) == 0) {
            lua_pop(L, 1);
            lua_pushboolean(L, 1);
            return 1;
        }
    }
    lua_pop(L, 1);

    lua_getfield(L, 1, ("ClassName"));
    if (!lua_isstring(L, -1)) {
        lua_pop(L, 1);
        lua_pushboolean(L, 0);
        return 1;
    }

    const char* cn = lua_tostring(L, -1);
    if (!cn) {
        lua_pop(L, 1);
        lua_pushboolean(L, 0);
        return 1;
    }
    lua_pop(L, 1);

    if (strcmp(cn, ("BasePart")) != 0 && strcmp(cn, ("Part")) != 0 &&
        strcmp(cn, ("MeshPart")) != 0 && strcmp(cn, ("UnionOperation")) != 0) {
        lua_pushboolean(L, 0);
        return 1;
    }

    lua_getfield(L, 1, ("GetNetworkOwner"));
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 1);
        lua_pushboolean(L, 0);
        return 1;
    }

    lua_pushvalue(L, 1);
    if (lua_pcall(L, 1, 1, 0) != 0) {
        lua_pop(L, 1);
        lua_pushboolean(L, 0);
        return 1;
    }

    lua_getglobal(L, ("game"));
    lua_getfield(L, -1, ("GetService"));
    lua_pushvalue(L, -2);
    lua_pushstring(L, ("Players"));

    if (lua_pcall(L, 2, 1, 0) != 0) {
        lua_pop(L, 3);
        lua_pushboolean(L, 0);
        return 1;
    }

    lua_getfield(L, -1, ("LocalPlayer"));
    bool is_owner = lua_rawequal(L, -1, -4);

    lua_pop(L, 4);
    lua_pushboolean(L, is_owner ? 1 : 0);
    return 1;
}

int Instance::getspecialinfo(lua_State* L)
{
    
    if (!lua_isuserdata(L, 1))
    {
        lua_pushnil(L);
        return 1;
    }

    lua_newtable(L);
    int T = lua_gettop(L);

    lua_getfield(L, 1, ("Name"));
    lua_setfield(L, T, ("Name"));

    lua_getfield(L, 1, ("ClassName"));
    lua_setfield(L, T, ("ClassName"));

    lua_getfield(L, 1, ("GetFullName"));
    if (lua_isfunction(L, -1))
    {
        lua_pushvalue(L, 1);
        if (lua_pcall(L, 1, 1, 0) == LUA_OK)
            lua_setfield(L, T, ("FullName"));
        else
            lua_pop(L, 1);
    }
    else { lua_pop(L, 1); }

    void* ud = lua_touserdata(L, 1);
    uintptr_t instance = 0;
    if (ud)
    {
        instance = *reinterpret_cast<uintptr_t*>(ud);
        char buf[32];
        snprintf(buf, sizeof(buf), ("0x%llX"), (unsigned long long)instance);
        lua_pushstring(L, buf);
        lua_setfield(L, T, ("Handle"));
    }

    lua_getfield(L, 1, ("Parent"));
    lua_pushboolean(L, lua_isnil(L, -1) ? 1 : 0);
    lua_setfield(L, T, ("IsNil"));
    lua_pop(L, 1);

    lua_getfield(L, 1, ("Parent"));
    if (lua_isuserdata(L, -1))
    {
        lua_getfield(L, -1, ("ClassName"));
        bool isService = lua_isstring(L, -1) &&
            strcmp(lua_tostring(L, -1), ("DataModel")) == 0;
        lua_pop(L, 1);
        lua_pushboolean(L, isService ? 1 : 0);
        lua_setfield(L, T, ("IsService"));
    }
    else
    {
        lua_pushboolean(L, 0);
        lua_setfield(L, T, ("IsService"));
    }
    lua_pop(L, 1);

    if (instance && !IsBadReadPtr(reinterpret_cast<void*>(instance + 0x30), 16))
    {
        uint64_t lo = *reinterpret_cast<uint64_t*>(instance + 0x30);
        uint64_t hi = *reinterpret_cast<uint64_t*>(instance + 0x38);
        char uid[48];
        snprintf(uid, sizeof(uid), ("%016llX%016llX"),
            (unsigned long long)hi, (unsigned long long)lo);
        lua_pushstring(L, uid);
        lua_setfield(L, T, ("UniqueId"));
    }

    lua_getfield(L, 1, ("Archivable"));
    lua_setfield(L, T, ("Archivable"));

    lua_getfield(L, 1, ("GetChildren"));
    if (lua_isfunction(L, -1))
    {
        lua_pushvalue(L, 1);
        if (lua_pcall(L, 1, 1, 0) == LUA_OK && lua_istable(L, -1))
        {
            lua_pushinteger(L, (int)lua_objlen(L, -1));
            lua_setfield(L, T, ("ChildCount"));
            lua_pop(L, 1);
        }
        else lua_pop(L, 1);
    }
    else lua_pop(L, 1);

    lua_getfield(L, 1, ("GetTags"));
    if (lua_isfunction(L, -1))
    {
        lua_pushvalue(L, 1);
        if (lua_pcall(L, 1, 1, 0) == LUA_OK)
            lua_setfield(L, T, ("Tags"));
        else
            lua_pop(L, 1);
    }
    else lua_pop(L, 1);

    lua_pushvalue(L, T);
    return 1;
}

int Instance::getthreads(lua_State* L)
{
    
    lua_newtable(L);
    int T = lua_gettop(L);
    int index = 0;

    global_State* g = L->global;
    if (!g) return 1;

    lua_State* main_thread = g->mainthread;
    if (!main_thread) return 1;

    lua_pushvalue(L, LUA_REGISTRYINDEX);
    int reg = lua_gettop(L);

    lua_pushnil(L);
    while (lua_next(L, reg) != 0)
    {
        if (lua_type(L, -1) == LUA_TTHREAD)
        {
            lua_State* thread = lua_tothread(L, -1);
            if (thread && thread != L)
            {
                lua_pushvalue(L, -1);
                lua_rawseti(L, T, ++index);
            }
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1);

    if (main_thread != L)
    {
        lua_pushthread(main_thread);
        lua_xmove(main_thread, L, 1);
        lua_rawseti(L, T, ++index);
    }

    lua_pushvalue(L, T);
    return 1;
}



int Instance::getsimulationradius(lua_State* L)
{
    
    if (!L) {
        lua_pushnumber(L, 0);
        lua_pushnumber(L, 0);
        return 2;
    }

    lua_getglobal(L, ("game"));
    if (!lua_isuserdata(L, -1)) {
        lua_pop(L, 1);
        lua_pushnumber(L, 0);
        lua_pushnumber(L, 0);
        return 2;
    }

    lua_getfield(L, -1, ("GetService"));
    if (!lua_isfunction(L, -1)) {
        lua_pop(L, 2);
        lua_pushnumber(L, 0);
        lua_pushnumber(L, 0);
        return 2;
    }

    lua_pushvalue(L, -2);
    lua_pushstring(L, ("Players"));

    if (lua_pcall(L, 2, 1, 0) != 0) {
        lua_pop(L, 2);
        lua_pushnumber(L, 0);
        lua_pushnumber(L, 0);
        return 2;
    }

    lua_getfield(L, -1, ("LocalPlayer"));
    if (lua_isuserdata(L, -1)) {
        lua_pushnumber(L, 1000.0);
        lua_pushnumber(L, 1000.0);
        lua_remove(L, -3);
        lua_remove(L, -3);
        return 2;
    }

    lua_pop(L, 2);
    lua_pushnumber(L, 0);
    lua_pushnumber(L, 0);
    return 2;
}

int Instance::setsimulationradius(lua_State* L)
{
    
    double radius = luaL_checknumber(L, 1);
    double maxRadius = luaL_optnumber(L, 2, radius);

    lua_getglobal(L, ("game"));
    lua_getfield(L, -1, ("GetService"));
    lua_pushvalue(L, -2);
    lua_pushstring(L, ("Players"));

    if (lua_pcall(L, 2, 1, 0) == 0) {
        lua_getfield(L, -1, ("LocalPlayer"));
        if (lua_isuserdata(L, -1)) {
            lua_pushnumber(L, radius);
            lua_setfield(L, -2, ("SimulationRadius"));

            lua_pushnumber(L, maxRadius);
            lua_setfield(L, -2, ("MaximumSimulationRadius"));
        }
    }

    return 0;
}

int Instance::getinstancecache(lua_State* L)
{
    
    lua_newtable(L);
    int resultIdx = lua_gettop(L);

    lua_pushvalue(L, LUA_REGISTRYINDEX);
    lua_pushlightuserdata(L, reinterpret_cast<void*>(Roblox::InstanceBridge::UintPtr));
    lua_rawget(L, -2);

    if (!lua_istable(L, -1)) { lua_pop(L, 2); return 1; }

    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
        if (!lua_isnil(L, -1) && lua_isuserdata(L, -2))
        {
            // Key is light userdata, value is instance
            lua_pushvalue(L, -2); // push key (light userdata)
            lua_pushvalue(L, -2); // push value (instance)
            lua_rawset(L, resultIdx);
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 2);

    return 1;
}
int Instance::cloneref(lua_State* L)
{
    LOG();

    lua_normalisestack(L, 1);
    luaL_checktype(L, 1, LUA_TUSERDATA);

    std::string ud_t = luaL_typename(L, 1);
    if (ud_t != ("Instance"))
        luaL_typeerrorL(L, 1, ("Instance"));

    const auto instance = *static_cast<void**>(lua_touserdata(L, 1));

    lua_pushlightuserdata(L, Roblox::InstanceBridge::SharedInstance);

    lua_rawget(L, LUA_REGISTRYINDEX);

    lua_pushlightuserdata(L, instance);
    lua_rawget(L, -2);

    lua_pushlightuserdata(L, instance);
    lua_pushnil(L);
    lua_rawset(L, -4);

    Roblox::InstanceBridge::UintPtr(L, reinterpret_cast<uintptr_t>(lua_touserdata(L, 1)));
    lua_pushlightuserdata(L, instance);
    lua_pushvalue(L, -3);
    lua_rawset(L, -5);

    if (lua_getmetatable(L, 1))
        lua_setmetatable(L, -2);

    lua_replace(L, -3);
    lua_pop(L, 1);

    return 1;
}
void Instance::register_lib(lua_State* L)
{
    if (!L) return;

    Environment->make_global(L, ("getnilinstances"), Instance::getnilinstances, Instance::funcnameinc++);
    Environment->make_global(L, ("cloneref"), Instance::cloneref, Instance::funcnameinc++);
    Environment->make_global(L, ("clonereference"), Instance::cloneref, Instance::funcnameinc++);
    Environment->make_global(L, ("getinstances"), Instance::getinstances, Instance::funcnameinc++);
    Environment->make_global(L, ("isnetworkowner"), Instance::isnetworkowner, Instance::funcnameinc++);
    Environment->make_global(L, ("getspecialinfo"), Instance::getspecialinfo, Instance::funcnameinc++);
    Environment->make_global(L, ("getthreads"), Instance::getthreads, Instance::funcnameinc++);
    Environment->make_global(L, ("getsimulationradius"), Instance::getsimulationradius, Instance::funcnameinc++);
    Environment->make_global(L, ("setsimulationradius"), Instance::setsimulationradius, Instance::funcnameinc++);
    Environment->make_global(L, ("getinstancecache"), Instance::getinstancecache, Instance::funcnameinc++);
}
