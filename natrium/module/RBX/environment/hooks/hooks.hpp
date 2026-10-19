#pragma once

#include <lua.h>
#include <lualib.h>

extern lua_CFunction original_index;
extern lua_CFunction original_namecall;

void initialize_hooks(lua_State* L);