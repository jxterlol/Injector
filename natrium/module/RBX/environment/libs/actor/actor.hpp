#pragma once

#include <lstate.h>
#include <cstdint>

namespace Actor
{
    // Actor instance field offsets
    constexpr uintptr_t ParallelFlag = 0x545;
    constexpr uintptr_t Parent = 0x68;

    static int funcnameinc = 0;

    // run source inside the target Actor's VM state (ActorVMState),
    // not the shared ScriptContext / exploit state
    int run_on_actor(lua_State* L);
    int isparallel(lua_State* L);
    int getactors(lua_State* L);
    int create_comm_channel(lua_State* L);
    int get_comm_channel(lua_State* L);


    void register_lib(lua_State* L);
}
