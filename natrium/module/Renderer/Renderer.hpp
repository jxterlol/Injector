#pragma once

// Headless log shim used by the natrium core.
// There is no in-game overlay: Sodium's desktop window is the only UI.
// Routes output to OutputDebugStringA + the in-memory log store.

#include <cstdio>
#include <managers/logging/logging.h>


namespace Renderer
{
    inline void AddConsoleLog(const char* level, const char* source, const char* message)
    {
        char buf[1024];
        snprintf(buf, sizeof(buf), ("[%s] %s: %s"), level, source, message);
        OutputDebugStringA(buf);
        OutputDebugStringA(("\n"));
        log_mgr.add_log(buf);
    }

    inline void Initialize() {}
}
