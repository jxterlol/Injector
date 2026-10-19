#pragma once

#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <windows.h>

#define LOG_ENABLED 0

namespace LogFile
{
    struct State
    {
        CRITICAL_SECTION lock;
        HANDLE handle;
        char path[MAX_PATH];
    };

    inline State MakeState()
    {
        State state{};

        InitializeCriticalSection(&state.lock);
        state.handle = INVALID_HANDLE_VALUE;
        state.path[0] = '\0';

        return state;
    }

    inline State& Get()
    {
        static State state = MakeState();
        return state;
    }

    inline void Init()
    {
        Get();
    }

    inline const char* Path()
    {
        return Get().path;
    }

    inline void Write(const char* text, int length)
    {
    }

    inline void Call(const char* name)
    {
    }

    inline void Message(const char* source, const char* text)
    {
    }
}

inline void Log_Internal(const char* source, const char* fmt, ...)
{
}

#define LOG()
#define LOGF(source, ...)