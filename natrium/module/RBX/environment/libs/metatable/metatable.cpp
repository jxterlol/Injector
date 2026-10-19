#include "Metatable.hpp"

#include <Windows.h>
#include <lstate.h>
#include <lobject.h>
#include <lfunc.h>
#include <lstring.h>
#include <ltable.h>
#include <lapi.h>
#include <ldo.h>
#include <lgc.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <string>
#include <lualib.h>

#include <Utilitys/Utils.hpp>
#include <Utilitys/Globals.hpp>

#include <RBX/environment/libs/closures/closures.hpp>
#include <RBX/environment/env.hpp>


namespace Metatable {

    int getrawmetatable(lua_State* LS) {
        
        if (LS->userdata == nullptr)
            return 0;

        luaL_checkany(LS, 1);

        if (!lua_getmetatable(LS, 1))
            lua_pushnil(LS);

        return 1;
    }

    int setreadonly(lua_State* L) {
        
        luaL_checktype(L, 1, LUA_TTABLE);
        luaL_checktype(L, 2, LUA_TBOOLEAN);
        hvalue(luaA_toobject(L, 1))->readonly = lua_toboolean(L, 2);
        return 0;
    }

    int isreadonly(lua_State* L) {
        
        luaL_checktype(L, 1, LUA_TTABLE);
        lua_pushboolean(L, hvalue(luaA_toobject(L, 1))->readonly);
        return 1;
    }

    int setrawmetatable(lua_State* L)
    {
        
        luaL_checkany(L, 1);
        luaL_checktype(L, 2, LUA_TTABLE);

        if (lua_isuserdata(L, 1) && !lua_getreadonly(L, 2) && lua_getmetatable(L, 1))
        {
            static const char* const preserved[] = { "__namecall", "__newindex" };

            for (const char* field : preserved)
            {
                lua_rawgetfield(L, 2, field);
                const bool defined = !lua_isnil(L, -1);
                lua_pop(L, 1);

                if (defined)
                    continue;

                lua_rawgetfield(L, -1, field);

                if (lua_isnil(L, -1))
                {
                    lua_pop(L, 1);
                    continue;
                }

                lua_rawsetfield(L, 2, field);
            }

            lua_pop(L, 1);
        }

        lua_settop(L, 2);
        lua_setmetatable(L, 1);
        lua_pushvalue(L, 1);
        return 1;
    }

    int makereadonly(lua_State* L) {
        
        luaL_checktype(L, 1, LUA_TTABLE);

        LuaTable* table = hvalue(luaA_toobject(L, 1));

        table->readonly = true;

        return 0;
    }


    int makewriteable(lua_State* L) {
        
        luaL_checktype(L, 1, LUA_TTABLE);

        LuaTable* table = hvalue(luaA_toobject(L, 1));

        table->readonly = false;

        return 0;
    }

    int getnamecallmethod(lua_State* L)
    {
        
        const char* namecall = lua_namecallatom(L, nullptr);

        if (!namecall)
        {
            lua_pushnil(L);
            return 1;
        }

        lua_pushstring(L, namecall);
        return 1;
    }



    int hookmetamethod(lua_State* L)
    {
        luaL_checkany(L, 1);
        luaL_checktype(L, 2, LUA_TSTRING);
        luaL_checktype(L, 3, LUA_TFUNCTION);

        const char* metamethod = lua_tostring(L, 2);

        if (!lua_getmetatable(L, 1)) {
            luaL_argerror(L, 1, ("object has no metatable"));
        }
        int mt_idx = lua_gettop(L);
        bool wasReadonly = lua_getreadonly(L, mt_idx);
        if (wasReadonly) {
            lua_setreadonly(L, mt_idx, false);
        }
        lua_getfield(L, mt_idx, metamethod);
        if (lua_isnil(L, -1)) {
            lua_pop(L, 1);
            if (wasReadonly) lua_setreadonly(L, mt_idx, true);
            luaL_argerror(L, 2, ("metamethod does not exist"));
        }
        int old_method = lua_gettop(L);
        if (lua_type(L, 1) == LUA_TTABLE && lua_isfunction(L, old_method))
        {
            lua_pushcfunction(L, Closures::hookfunction, "hookfunction");
            lua_pushvalue(L, old_method);
            lua_pushvalue(L, 3);
            if (lua_pcall(L, 2, 1, 0) != LUA_OK)
            {
                std::string Error = lua_isstring(L, -1) ? lua_tostring(L, -1) : "hookfunction failed";
                lua_pop(L, 1);
                lua_pop(L, 1);
                if (wasReadonly) lua_setreadonly(L, mt_idx, true);
                lua_pop(L, 1);
                luaL_error(L, "%s", Error.c_str());
                return 0;
            }
            if (wasReadonly) lua_setreadonly(L, mt_idx, true);
            lua_remove(L, old_method);
            return 1;
        }
        lua_pushvalue(L, 3);
        lua_setfield(L, mt_idx, metamethod);

        if (wasReadonly) {
            lua_setreadonly(L, mt_idx, true);
        }
        return 1;
    }
    void register_lib(lua_State* L)
    {
        Environment->make_global(L, ("hookmetamethod"), hookmetamethod, Metatable::funcnameinc++);
        Environment->make_global(L, ("getnamecallmethod"), getnamecallmethod, Metatable::funcnameinc++);
        Environment->make_global(L, ("setreadonly"), setreadonly, Metatable::funcnameinc++);
        Environment->make_global(L, ("isreadonly"), isreadonly, Metatable::funcnameinc++);
        Environment->make_global(L, ("getrawmetatable"), getrawmetatable, Metatable::funcnameinc++);
        Environment->make_global(L, ("setrawmetatable"), setrawmetatable, Metatable::funcnameinc++);
        Environment->make_global(L, ("makereadonly"), makereadonly, Metatable::funcnameinc++);
        Environment->make_global(L, ("makewriteable"), makewriteable, Metatable::funcnameinc++);
    }
}
