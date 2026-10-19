#pragma once

#include <lua.h>
#include <lualib.h>

namespace Websocket
{
    void register_lib(lua_State* L);
    void teardown();
}

namespace module::core::environment
{
    struct c_websocket
    {
        void initialize(lua_State* L);
        static void clear_all_no_state();
    };

    inline c_websocket websocket{};
}