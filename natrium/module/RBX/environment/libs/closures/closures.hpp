#pragma once
#include <string>
#include <cstdint>
#include <cstring>

#include <lstate.h>
#include <ldo.h>
#include <lfunc.h>
#include <lgc.h>
#include <lstring.h>
#include <lualib.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <Utilitys/Utils.hpp>
#include <Utilitys/Globals.hpp>
#include <RBX/Execution/Execution.hpp>
#include <RBX/task_scheduler/task_scheduler.hpp>
#include <RBX/environment/env.hpp>
#include <RBX/environment/libs/signals/signals.hpp>
#include <Utilitys/Log.hpp>
#include <RBX/update.hpp>

namespace Closures
{
#define lua_check(L, i) if (lua_gettop(L) > i) { lua_settop(L, i); }

    inline int funcnameinc = 0;

    struct HookRecord
    {
        int OriginalRef = LUA_NOREF;
        int HookRef = LUA_NOREF;
    };

    struct NewCClosureRecord
    {
        int FunctionRef = LUA_NOREF;
        bool Reusable = false;
    };

    static constexpr const char* LuaHookDispatcherName = "__lunarium_hookfunction_dispatch";

    // shared across every translation unit that includes this header so that
    // hookmetamethod / debug / invoke interception all see the same records
    inline std::unordered_map<Closure*, HookRecord> HookRecords;
    inline std::unordered_map<Closure*, NewCClosureRecord> NewCClosureRefs;
    inline std::unordered_set<Closure*> WrappedClosures;
    inline int LuaHookDispatcherRef = LUA_NOREF;

    // hooksignal / restoresignal bookkeeping (keyed by the signal userdata)
    struct SignalRecord
    {
        int SignalRef = LUA_NOREF;      // the RBXScriptSignal itself
        int ConnectionsRef = LUA_NOREF; // array of live RBXScriptConnections snapshot
        int FunctionsRef = LUA_NOREF;   // array of pre-hook handler functions, fire order
        int HookRef = LUA_NOREF;        // dispatcher connection (RBXScriptConnection)
        int CallbackRef = LUA_NOREF;    // the user callback passed to hooksignal
    };
    inline std::unordered_map<void*, SignalRecord> SignalRecords;

    // debug.info interception (preserves hooked function names)
    inline int DebugInfoOriginalRef = LUA_NOREF;

    // BindableFunction.Invoke interception (META_SECURITY spoof)
    inline int InvokeOriginalRef = LUA_NOREF;
    inline bool InvokeHookInstalled = false;

    inline void ensure_debug_info_hook(lua_State* L);
    inline void ensure_debug_traceback_hook(lua_State* L);
    inline void ensure_fenv_globals(lua_State* L);
    inline void EnsureInvokeSecurityHook(lua_State* L);
    inline bool IsExecutorClosure(Closure* closure);

    inline void ResetLibraryState()
    {
        HookRecords.clear();
        NewCClosureRefs.clear();
        WrappedClosures.clear();
        LuaHookDispatcherRef = LUA_NOREF;
        SignalRecords.clear();
        InvokeOriginalRef = LUA_NOREF;
        InvokeHookInstalled = false;
        // DebugInfoOriginalRef intentionally NOT cleared: it records that a
        // wrapper is installed on this state. The wrapper itself resolves the
        // real debug.info through its own upvalue, so the ref is never
        // dereferenced from another state's registry.
        // HiddenClosures / HiddenClosureRefs / HiddenLevels intentionally NOT
        // cleared here: process-lifetime state that must survive
        // re-registration. Every hidden closure is registry-anchored through
        // HiddenClosureRefs and released by UnhideClosure.
    }
    extern std::unordered_set<Closure*> HiddenClosures;
    struct HiddenLevel { lua_State* L; int level; Closure* cl; };
    extern std::vector<HiddenLevel> HiddenLevels;

    // HiddenClosures holds raw Closure*. Without an anchor a hidden function
    // can be collected and its address reused by an unrelated closure, which
    // silently hides the wrong frame on the next trace. The registry ref pins
    // the exact closure for as long as it stays marked hidden; UnhideClosure
    // releases it.
    inline std::unordered_map<Closure*, int> HiddenClosureRefs;

    // Saved original environment for closures that had their env replaced
    // by HideClosure. UnhideClosure restores it.
    inline std::unordered_map<Closure*, void*> HiddenClosureOrigEnvs;

    inline void HideClosure(lua_State* L, Closure* cl)
    {
        if (!cl) return;
        if (!HiddenClosures.insert(cl).second)
            return; // already hidden, anchor already held

        luaC_threadbarrier(L);
        setclvalue(L, L->top, cl);
        incr_top(L);
        HiddenClosureRefs[cl] = lua_ref(L, -1);
        lua_pop(L, 1);

        // Save the original env and replace it with a bare empty table so
        // getfenv(cl) can no longer echo the script environment back.
        //
        // Executor closures are excluded. Their env is the one they run on -
        // a hidden Lua closure with a stripped env resolves every global to
        // nil the moment it is called, and getfenv of it hands back an empty
        // table instead of the real one (getgenv, loadstring, every library
        // function we ship). Game closures are the ones a probe reads the
        // script environment out of, so those still get stripped. Our own
        // trampolines do not depend on this: PushOldTrampoline sets a bare
        // env on them explicitly before hiding.
        if (!IsExecutorClosure(cl) && cl->env && HiddenClosureOrigEnvs.find(cl) == HiddenClosureOrigEnvs.end())
        {
            HiddenClosureOrigEnvs[cl] = cl->env;
            // push the closure, set a bare env, pop
            luaC_threadbarrier(L);
            setclvalue(L, L->top, cl);
            incr_top(L);
            lua_newtable(L);
            lua_setfenv(L, -2);
            lua_pop(L, 1);
        }
    }

    inline void HideClosure(lua_State* L, Closure* hidden, Closure*)
    {
        HideClosure(L, hidden);
    }

    inline void UnhideClosure(lua_State* L, Closure* cl)
    {
        if (!cl) return;
        if (HiddenClosures.erase(cl) == 0)
            return;

        auto ref = HiddenClosureRefs.find(cl);
        if (ref != HiddenClosureRefs.end())
        {
            if (L)
                lua_unref(L, ref->second);
            HiddenClosureRefs.erase(ref);
        }

        // Restore the original environment that HideClosure saved
        auto envIt = HiddenClosureOrigEnvs.find(cl);
        if (envIt != HiddenClosureOrigEnvs.end())
        {
            cl->env = static_cast<decltype(cl->env)>(envIt->second);
            if (L && cl->env)
                luaC_objbarrier(L, cl, cl->env);
            HiddenClosureOrigEnvs.erase(envIt);
        }
    }

    // lua_FrameHiddenFn implementation installed into the VM.
    // Returns 1 when the activation record at 'level' should be omitted.
    // Consulted by lua_debugtrace and luaL_traceback; debug.info answers
    // through debug_info_wrapper instead, which walks the same set.
    inline int FrameHiddenFilter(lua_State* L, int level)
    {
        if (!L || level < 0)
            return 0;

        // same bound lua_getinfo uses: level 0 .. ci - base_ci - 1
        if (unsigned(level) >= unsigned(L->ci - L->base_ci))
            return 0;

        TValue* func = (L->ci - level)->func;
        if (!ttisfunction(func))
            return 0;

        return HiddenClosures.contains(clvalue(func)) ? 1 : 0;
    }

    static inline bool cl_isC(Closure* c) {
        return c->isC;
    }

    static inline uint8_t cl_nups(Closure* c) {
        return c->nupvalues;
    }

    static inline void gc_barrier(lua_State* L, global_State* g) {
        L->marked &= ~4u;
        L->gclist = g->gray;
        g->gray = obj2gco(L);
    }

    static inline Closure* to_closure(lua_State* L, int index)
    {
        luaL_checktype(L, index, LUA_TFUNCTION);
        return clvalue(index2addr(L, index));
    }

    static inline void push_closure(lua_State* L, Closure* closure)
    {
        luaC_threadbarrier(L);
        setclvalue(L, L->top, closure);
        incr_top(L);
    }

    // Closure::c.debugname is a GC object (TString*), not a char*. Every
    // collection cycle traverseclosure() runs stringmark() over it and
    // lgcdebug validates it as a real object reference, so it MUST be an
    // interned string owned by this state. A reinterpret_cast'd C literal
    // makes the VM read a fake GC header at a .rdata address: the mark bit
    // lands on unrelated memory, the string table gets walked through a
    // bogus pointer, and closure metadata comes out corrupted.
    //
    // luaS_new interns the bytes into a proper TString; the barrier keeps
    // that string alive when the target closure is already black.
    static inline void set_closure_debugname(lua_State* L, Closure* cl, const char* name)
    {
        if (!cl || !cl->isC || !name)
            return;

        cl->c.debugname = luaS_new(L, name);
        luaC_objbarrier(L, cl, cl->c.debugname);
    }

    static inline int finish_yieldable_call(lua_State* L)
    {
        if (L->status == SCHEDULED_REENTRY || L->status == LUA_YIELD || L->status == LUA_BREAK)
            return C_CALL_YIELD;

        return lua_gettop(L);
    }

    static int DispatchContinuation(lua_State* L, int status)
    {
        return lua_gettop(L);
    }

    static inline int call_referenced_function(lua_State* L, int ref)
    {
        lua_getref(L, ref);
        if (!lua_isfunction(L, -1))
        {
            luaL_error(L, ("hookfunction: referenced value is not a function"));
        }


        lua_insert(L, 1);
        luaD_callint(L, L->base, LUA_MULTRET, lua_isyieldable(L) != 0);
        int result = finish_yieldable_call(L);
        return result;
    }

    static Closure* clone_closure(lua_State* L, Closure* source)
    {
        Closure* clone = nullptr;

        if (source->isC)
        {
            clone = luaF_newCclosure(L, source->nupvalues, source->env);
            clone->stacksize = source->stacksize;
            clone->preload = source->preload;
            clone->c.f = source->c.f;
            clone->c.cont = static_cast<lua_Continuation>(source->c.cont);
            clone->c.debugname = source->c.debugname;

            for (int i = 0; i < source->nupvalues; ++i)
                setobj2n(L, &clone->c.upvals[i], &source->c.upvals[i]);

            auto wrapped = NewCClosureRefs.find(source);
            if (wrapped != NewCClosureRefs.end())
            {
                NewCClosureRefs[clone] = { wrapped->second.FunctionRef, false };
            }
        }
        else
        {
            clone = luaF_newLclosure(L, source->nupvalues, source->env, source->l.p);
            clone->stacksize = source->stacksize;
            clone->preload = source->preload;

            for (int i = 0; i < source->nupvalues; ++i)
                setobj2n(L, &clone->l.uprefs[i], &source->l.uprefs[i]);
        }

        return clone;
    }

    static inline void push_clone(lua_State* L, Closure* source)
    {
        push_closure(L, clone_closure(L, source));
    }

    static void copy_closure_body(lua_State* L, Closure* target, Closure* source)
    {
        target->stacksize = source->stacksize;
        target->preload = source->preload;
        target->nupvalues = source->nupvalues;
        target->env = source->env;
        if (source->env)
            luaC_objbarrier(L, target, source->env);

        if (source->isC)
        {
            target->c.f = source->c.f;
            target->c.cont = static_cast<lua_Continuation>(source->c.cont);
            target->c.debugname = source->c.debugname;
            if (target->c.debugname)
                luaC_objbarrier(L, target, target->c.debugname);

            for (int i = 0; i < source->nupvalues; ++i)
            {
                setobj2n(L, &target->c.upvals[i], &source->c.upvals[i]);
                luaC_barrier(L, target, &target->c.upvals[i]);
            }
        }
        else
        {
            target->l.p = source->l.p;
            if (source->l.p)
                luaC_objbarrier(L, target, source->l.p);

            for (int i = 0; i < source->nupvalues; ++i)
            {
                setobj2n(L, &target->l.uprefs[i], &source->l.uprefs[i]);
                luaC_barrier(L, target, &target->l.uprefs[i]);
            }
        }
    }

    inline int NewCClosureDispatcher(lua_State* L)
    {
        Closure* current = curr_func(L);
        auto it = NewCClosureRefs.find(current);
        if (it == NewCClosureRefs.end() || it->second.FunctionRef == LUA_NOREF)
        {
            luaL_error(L, ("newcclosure: missing wrapped function"));
        }

        return call_referenced_function(L, it->second.FunctionRef);
    }

    inline int HookCDispatcher(lua_State* L)
    {
        Closure* current = curr_func(L);
        auto it = HookRecords.find(current);
        if (it == HookRecords.end() || it->second.HookRef == LUA_NOREF)
        {
            luaL_error(L, ("hookfunction: missing hook"));
        }

        return call_referenced_function(L, it->second.HookRef);
    }

    inline int HookLuaDispatcher(lua_State* L)
    {
        Closure* target = to_closure(L, 1);
        lua_remove(L, 1);

        auto it = HookRecords.find(target);
        if (it == HookRecords.end() || it->second.HookRef == LUA_NOREF)
        {
            luaL_error(L, ("hookfunction: missing Lua hook"));
        }

        return call_referenced_function(L, it->second.HookRef);
    }

    // Builds a fresh dispatcher proto for one hooked Lua target. Every target
    // gets its own Proto so the debugname can mirror the original function:
    // debug.info(f, "n") resolves through getfuncname -> proto->debugname, and
    // a shared dispatcher proto would report the dispatcher's name instead of
    // the hooked function's name (Function Type Conversion detection).
    //
    // The luau_load closure is left on the stack: the caller must install
    // target->l.p before popping it so the proto stays reachable.
    static Proto* ensure_lua_hook_dispatcher_proto(lua_State* L)
    {
        if (LuaHookDispatcherRef != LUA_NOREF)
        {
            lua_getref(L, LuaHookDispatcherRef);
            Closure* closure = clvalue(index2addr(L, -1));
            Proto* proto = closure->l.p;
            lua_pop(L, 1);
            return proto;
        }

        std::string bytecode = Execution::CompileScript(("local f = debug.info(1, \"f\"); return __lunarium_hookfunction_dispatch(f, ...)"));
        if (luau_load(L, ("=hookfunction"), bytecode.data(), bytecode.size(), NULL) != LUA_OK)
        {
            lua_error(L);
        }

        Closure* closure = clvalue(index2addr(L, -1));
        task_scheduler::SetProtoCapabilities(closure->l.p, &MaxCapabilities);
        LuaHookDispatcherRef = lua_ref(L, -1);
        Proto* proto = closure->l.p;
        lua_pop(L, 1);
        return proto;
    }

    // Fresh dispatcher proto for one hooked Lua closure. Compiling the chunk
    // again gives it its own GC-owned Proto, and the original proto's
    // debugname is attached so debug.info(f, "n") reports the pre-hook name
    // natively (Function Type Conversion detection) with no debug.info
    // interception and no per-call overhead.
    static Proto* make_hook_dispatcher_proto(lua_State* L, Proto* nameSource)
    {
        std::string bytecode = Execution::CompileScript(("local f = debug.info(1, \"f\"); return __lunarium_hookfunction_dispatch(f, ...)"));
        if (luau_load(L, ("=hookfunction"), bytecode.data(), bytecode.size(), NULL) != LUA_OK)
        {
            lua_error(L);
        }

        Closure* loader = clvalue(index2addr(L, -1));
        Proto* proto = loader->l.p;
        task_scheduler::SetProtoCapabilities(proto, &MaxCapabilities);

        if (nameSource && nameSource->debugname)
        {
            proto->debugname = static_cast<TString*>(nameSource->debugname);
            luaC_objbarrier(L, proto, proto->debugname);
        }

        // loader closure stays on the stack so 'proto' is reachable;
        // caller assigns it to the target and pops afterwards
        return proto;
    }


    // ------------------------------------------------------------------
    // hookmetamethod trampoline
    //
    // Function Environment[3] Metamethods - DIRECT does
    //     debug.info(2, "f")     inside the xpcall message handler
    // then getfenv of the frame that raised the error. For a function value
    // getfenv is cl->env, so the erroring frame must carry a bare keyless
    // table with NO metatable: no script keys in it, and no __index chain
    // that could forward the probe's lookup into the script environment.
    // ------------------------------------------------------------------

    inline std::unordered_set<Closure*> HardenedErrorFrames;

    // fresh keyless table, no metatable - indexing it can only ever miss
    static void set_bare_env(lua_State* L, int absIdx)
    {
        lua_newtable(L);
        lua_setfenv(L, absIdx);
    }

    // The frames that can sit directly under the message handler when
    // debug.info(2, "f") runs (the VM walks back to the protected call
    // before invoking the handler, so the pcall/xpcall frame or error/assert
    // itself can be what the probe resolves to). None of them read globals
    // through their own env, so pinning them to an empty table costs nothing
    // and stops those frames echoing the script environment back.
    inline void HardenErrorFrameLibs(lua_State* L)
    {
        static const char* const names[] = { "xpcall", "pcall", "error", "assert" };

        const int top = lua_gettop(L);

        for (const char* name : names)
        {
            lua_getglobal(L, name);

            if (lua_isfunction(L, -1))
            {
                Closure* cl = clvalue(index2addr(L, -1));
                if (cl && HardenedErrorFrames.insert(cl).second)
                    set_bare_env(L, lua_gettop(L));
            }

            lua_settop(L, top);
        }

        lua_settop(L, top);
    }

    // Lua original metamethod: runs the real closure (its globals resolve
    // through its own env, untouched) protected, then rethrows the original
    // error object unchanged. The rethrow lands on THIS closure - a C frame
    // whose env is the empty table we installed - so getfenv of the erroring
    // frame in the handler comes back empty.
    static int ProtectedMetamethodTrampoline(lua_State* L)
    {
        int nargs = lua_gettop(L); // for a C closure this counts args only

        lua_pushvalue(L, lua_upvalueindex(1)); // original, real env intact
        lua_insert(L, 1);                      // [orig, a1..aN]

        if (lua_pcall(L, nargs, LUA_MULTRET, 0) != LUA_OK)
        {
            lua_error(L); // error object sits on top; this CI is now deepest
        }

        return lua_gettop(L);
    }

    // hands the hook a stand-in for the original metamethod instead of the
    // original itself.
    static int PushOldTrampoline(lua_State* L, int oldIdx)
    {
        Closure* original = clvalue(index2addr(L, oldIdx));

        // a hookfunction'd C target runs HookCDispatcher, which resolves its
        // hook through HookRecords keyed by the exact closure pointer — a
        // clone would miss that lookup and error with "missing hook". those
        // go through the protected trampoline below, which calls the
        // original value as-is.
        if (original->isC && !HookRecords.contains(original))
        {
            // C metamethod (Roblox __namecall, class __index, ...): resolves
            // globals through the thread, never its own env - so a clone with
            // an empty env behaves exactly like the original while reading
            // back as a provably clean environment. The clone, never the
            // shared original, becomes the frame that raises the error.
            Closure* clone = clone_closure(L, original);
            push_closure(L, clone);
            set_bare_env(L, lua_gettop(L));
            return 1;
        }

        // Lua original: keep it as-is (a bare env would break its own
        // GETIMPORT/GETGLOBAL) and hide the error behind our C frame instead.
        lua_pushvalue(L, oldIdx); // upvalue 1 = original
        lua_pushcclosurek(L, ProtectedMetamethodTrampoline, ("hookmetamethod"), 1, DispatchContinuation);

        int trampIdx = lua_gettop(L);
        set_bare_env(L, trampIdx);

        Closure* tramp = clvalue(index2addr(L, trampIdx));
        HideClosure(L, tramp);
        Shared::ExecutorClosures.insert(tramp);
        if (Environment)
            Environment->function_array.push_back(tramp);

        return 1;
    }

    static int clonefunction(lua_State* L)
    {
        Closure* source = to_closure(L, 1);
        push_clone(L, source);
        return 1;
    }

    // target/hook are passed as explicit stack indices so callers outside
    // the plain hookfunction(a, b) shape (hookmetamethod hands us the
    // metamethod it pulled out of the middle of the stack) can drive the
    // exact same hook logic. nothing is skipped or dropped.

    static int hookfunction(lua_State* L, int targetIndex, int hookIndex)
    {
        

        Closure* target = to_closure(L, targetIndex);
        Closure* hook = to_closure(L, hookIndex);

        HookRecord& record = HookRecords[target];
        if (record.OriginalRef == LUA_NOREF)
        {
            auto wrappedTarget = NewCClosureRefs.find(target);
            if (target->isC && wrappedTarget != NewCClosureRefs.end() && wrappedTarget->second.FunctionRef != LUA_NOREF)
            {
                lua_getref(L, wrappedTarget->second.FunctionRef);
            }
            else
            {
                push_clone(L, target);
            }

            record.OriginalRef = lua_ref(L, -1);
            lua_pop(L, 1);
        }
        else
        {
            lua_getref(L, record.OriginalRef);
            Closure* original = to_closure(L, -1);

            if (hook == original)
            {
                if (target->isC != original->isC)
                {
                    auto targetWrapped = NewCClosureRefs.find(target);
                    if (target->isC && !original->isC && targetWrapped != NewCClosureRefs.end())
                    {
                        target->stacksize = LUA_MINSTACK;
                        target->preload = 0;
                        target->nupvalues = 0;
                        target->env = original->env;
                        target->c.f = NewCClosureDispatcher;
                        target->c.cont = DispatchContinuation;
                        set_closure_debugname(L, target, ("newcclosure"));
                        if (original->env)
                            luaC_objbarrier(L, target, original->env);
                    }
                    else
                    {
                        lua_pop(L, 1);
                        luaL_error(L, ("hookfunction: incompatible closure layout"));
                    }
                }
                else
                {
                    copy_closure_body(L, target, original);

                    if (target->isC)
                    {
                        auto originalWrapped = NewCClosureRefs.find(original);
                        auto targetWrapped = NewCClosureRefs.find(target);

                        if (originalWrapped != NewCClosureRefs.end())
                        {
                            NewCClosureRefs[target] = { originalWrapped->second.FunctionRef, true };
                            WrappedClosures.insert(target);
                        }
                        else if (targetWrapped != NewCClosureRefs.end() && targetWrapped->second.Reusable)
                        {
                            NewCClosureRefs.erase(targetWrapped);
                            WrappedClosures.erase(target);
                        }
                    }
                }

                if (record.HookRef != LUA_NOREF)
                    lua_unref(L, record.HookRef);

                lua_unref(L, record.OriginalRef);
                HookRecords.erase(target);
                Shared::ExecutorClosures.erase(target);

                return 1;
            }

            lua_pop(L, 1);

            if (record.HookRef != LUA_NOREF)
            {
                lua_unref(L, record.HookRef);
                record.HookRef = LUA_NOREF;
            }
        }

        lua_pushvalue(L, hookIndex);
        record.HookRef = lua_ref(L, -1);
        lua_pop(L, 1);

        if (target->isC)
        {
            target->c.f = HookCDispatcher;
            target->c.cont = DispatchContinuation;
            set_closure_debugname(L, target, ("hookfunction"));
        }
        else
        {
            // own dispatcher proto per target, carrying the original proto's
    // debugname so debug.info(f, "n") matches the pre-hook name
    // natively (Function Type Conversion) with zero interception
            lua_getref(L, record.OriginalRef);
            Closure* original = to_closure(L, -1);
            Proto* nameSource = original->isC ? nullptr : original->l.p;
            lua_pop(L, 1);

            Proto* dispatcher = make_hook_dispatcher_proto(L, nameSource);

            target->stacksize = dispatcher->maxstacksize;
            target->preload = 0;
            target->nupvalues = 0;
            target->env = L->gt;
            target->l.p = dispatcher;
            luaC_objbarrier(L, target, L->gt);
            luaC_objbarrier(L, target, dispatcher);

            lua_pop(L, 1); // loader closure

        }

        Shared::ExecutorClosures.insert(target);
        lua_getref(L, record.OriginalRef);
        return 1;
    }

    // plain lua_CFunction entry point for the hookfunction/hookfunc/
    // replaceclosure globals — target at 1, hook at 2.
    static int hookfunction(lua_State* L)
    {
        
        return hookfunction(L, 1, 2);
    }
    static int restorefunction(lua_State* L)
    {
        
        Closure* target = to_closure(L, 1);
        auto it = HookRecords.find(target);
        if (it == HookRecords.end() || it->second.OriginalRef == LUA_NOREF)
        {
            lua_pushboolean(L, false);
            return 1;
        }

        lua_getref(L, it->second.OriginalRef);
        Closure* original = to_closure(L, -1);

        if (target->isC != original->isC)
        {
            // Case 1: target is C, original is Lua (hooked Lua with C function via newcclosure)
            auto targetWrapped = NewCClosureRefs.find(target);
            if (target->isC && !original->isC && targetWrapped != NewCClosureRefs.end())
            {
                target->stacksize = LUA_MINSTACK;
                target->preload = 0;
                target->nupvalues = 0;
                target->env = original->env;
                target->c.f = NewCClosureDispatcher;
                target->c.cont = DispatchContinuation;
                set_closure_debugname(L, target, ("newcclosure"));
                if (original->env)
                    luaC_objbarrier(L, target, original->env);

                lua_pop(L, 1);

                if (it->second.HookRef != LUA_NOREF)
                    lua_unref(L, it->second.HookRef);

                lua_unref(L, it->second.OriginalRef);
                HookRecords.erase(it);

                lua_pushboolean(L, true);
                return 1;
            }

            // Case 2: target is Lua, original is C (hooked C function with Lua function)
            // Need to convert target back to a C closure
            auto originalWrapped = NewCClosureRefs.find(original);
            if (!target->isC && original->isC)
            {
                // Restore as a C closure pointing to the original C function
                target->isC = true;
                target->stacksize = original->stacksize;
                target->preload = original->preload;
                target->nupvalues = original->nupvalues;
                target->env = original->env;
                target->c.f = original->c.f;
                target->c.cont = original->c.cont;
                if (original->env)
                    luaC_objbarrier(L, target, original->env);
                // Copy debug name from original C closure
                if (original->isC && original->c.debugname)
                {
                    const char* debugName = getstr(original->c.debugname);
                    set_closure_debugname(L, target, debugName);
                }

                // Transfer NewCClosureRefs if needed
                if (originalWrapped != NewCClosureRefs.end())
                {
                    NewCClosureRefs[target] = { originalWrapped->second.FunctionRef, true };
                    WrappedClosures.insert(target);
                }

                lua_pop(L, 1);

                if (it->second.HookRef != LUA_NOREF)
                    lua_unref(L, it->second.HookRef);

                lua_unref(L, it->second.OriginalRef);
                HookRecords.erase(it);

                lua_pushboolean(L, true);
                return 1;
            }

            lua_pop(L, 1);
            luaL_error(L, ("restorefunction: incompatible closure layout"));
        }

        copy_closure_body(L, target, original);
        if (target->isC)
        {
            auto originalWrapped = NewCClosureRefs.find(original);
            auto targetWrapped = NewCClosureRefs.find(target);

            if (originalWrapped != NewCClosureRefs.end())
            {
                NewCClosureRefs[target] = { originalWrapped->second.FunctionRef, true };
                WrappedClosures.insert(target);
            }
            else if (targetWrapped != NewCClosureRefs.end() && targetWrapped->second.Reusable)
            {
                NewCClosureRefs.erase(targetWrapped);
                WrappedClosures.erase(target);
            }
        }
        lua_pop(L, 1);

        if (it->second.HookRef != LUA_NOREF)
            lua_unref(L, it->second.HookRef);

        lua_unref(L, it->second.OriginalRef);
        HookRecords.erase(it);

        lua_pushboolean(L, true);
        return 1;
    }

    inline int newcclosure(lua_State* L)
    {
        
        luaL_checktype(L, 1, LUA_TFUNCTION);

        Closure* closure = clvalue(index2addr(L, 1));
      
        if (closure->isC) {
           
            lua_pushvalue(L, 1);
            return 1;
        }
  
        for (auto& pair : NewCClosureRefs) {
            if (!pair.second.Reusable)
                continue;

            lua_getref(L, pair.second.FunctionRef);
            bool same = lua_isfunction(L, -1) && clvalue(index2addr(L, -1)) == closure;
            lua_pop(L, 1);

            if (same) {
              
                push_closure(L, pair.first);
                return 1;
            }
        }
    
        const char* debugname = lua_isstring(L, 2) ? lua_tostring(L, 2) : ("newcclosure");
     
        lua_pushvalue(L, 1);

        lua_pushcclosurek(L, NewCClosureDispatcher, debugname, 1, DispatchContinuation);
      
        Closure* wrapper = clvalue(index2addr(L, -1));
 
        lua_pushvalue(L, 1);
  
        NewCClosureRefs[wrapper] = { lua_ref(L, -1), true };

        lua_pop(L, 1);

     
        WrappedClosures.insert(wrapper);
     
        wrapper->env = closure->env;
  
        Shared::ExecutorClosures.insert(wrapper);
        Environment->function_array.push_back(wrapper);
        return 1;
    }


    inline int isnewcclosure(lua_State* L)
    {
        
        luaL_checktype(L, 1, LUA_TFUNCTION);
        Closure* closure = clvalue(index2addr(L, 1));
        lua_pushboolean(L, WrappedClosures.count(closure) > 0);
        return 1;
    }
    static int isfunctionhooked(lua_State* L)
    {
        luaL_checktype(L, 1, LUA_TFUNCTION);
        Closure* closure = clvalue(index2addr(L, 1));
        lua_pushboolean(L, HookRecords.count(closure) > 0 && HookRecords[closure].OriginalRef != LUA_NOREF);
        return 1;
    }
    inline bool IsExecutorIdentity(lua_State* L)
    {
        if (!L)
            return false;

        if (L == Shared::ExploitThread)
            return true;

        if (!L->userdata)
            return false;

        auto* data = static_cast<RobloxExtraSpace*>(L->userdata);

        // identity 8 is the executor's context. ExecuteScript, the actor spawn path
        // and setthreadidentity(8) all land here, and every identity an escalation
        // vector can move a thread to (7 and below) lands outside it. deliberately
        // not a capability check: GetCapabilities() can saturate to all-ones for
        // high Roblox identities, which would hand the gate back to the caller.
        return data->identity.identity == 8;
    }
    inline int loadstring(lua_State* L)
    {
        
        luaL_checktype(L, 1, LUA_TSTRING);
        if (!IsExecutorIdentity(L))
        {
            lua_pushnil(L);
            lua_pushstring(L, ("loadstring is unavailable outside the executor context"));
            return 2;
        }
        const char* ChunkName = luaL_optstring(L, 2, ("natrium"));

        std::string Bytecode = Execution::CompileScript(lua_tostring(L, 1));

        if (luau_load(L, ChunkName, Bytecode.data(), Bytecode.size(), NULL) != LUA_OK)
        {
            // compiler errors used to be invisible: the caller only got nil
            // back and calling it produced "attempt to call a nil value"
            const char* CompileError = lua_tostring(L, -1);
            if (CompileError)
                Roblox::Print(3, ("[loadstring] %s"), CompileError);
            lua_pushnil(L);
            lua_insert(L, -2);
            return 2;
        }

        Closure* cls = clvalue(luaA_toobject(L, -1));
        task_scheduler::SetProtoCapabilities(cls->l.p, &MaxCapabilities);

        lua_setsafeenv(L, LUA_ENVIRONINDEX, false);

        return 1;
    }

    // ------------------------------------------------------------------
    // detection fix: Function Type Conversion
    //
    // hookfunction swaps the proto of a Lua target, which changes what
    // debug.info(f, "n") reports. The wrapper resolves name lookups for
    // hooked functions against the saved original closure instead.
    //
    // setstackhidden rides the same wrapper: db_info walks levels straight
    // off the CallInfo chain, so the VM-side filter never sees it. The
    // wrapper rewrites the level to skip frames that were marked hidden,
    // which makes a hidden frame indistinguishable from one that does not
    // exist to anything querying through debug.info.
    // ------------------------------------------------------------------

    static inline int frame_is_hidden_ci(CallInfo* ci)
    {
        if (!ci || !ttisfunction(ci->func))
            return 0;
        return HiddenClosures.contains(clvalue(ci->func)) ? 1 : 0;
    }

    // Maps the caller's stack level onto the level the real db_info must be
    // handed so it lands on the same visible frame the caller asked for.
    // Returns -1 when no visible frame is left at that depth.
    //
    // db_info resolves level 0 as its own C frame, level 1 as the function
    // that called debug.info - the dispatcher proto relies on that by using
    // debug.info(1, "f") to fetch itself.
    static inline int remap_debug_info_level(lua_State* L, lua_State* L1, int level)
    {
        if (level < 0)
            return -1;

        // level 0 is the debug.info frame itself: no caller-visible state,
        // never hidden, and it does not shift when this wrapper appears.
        if (level == 0)
            return 0;

        const int maxLevel = int(L1->ci - L1->base_ci);
        if (maxLevel <= 0)
            return -1;

        if (L1 == L)
        {
            // This wrapper sits between db_info and the caller, so while it
            // runs, frame j below it is what the caller sees as level j, and
            // once db_info is pushed that same frame becomes level j + 1.
            // Frame 1 is the caller itself - it is the one asking, so it is
            // never skipped (the hook dispatcher queries its own frame).
            for (int j = 1; j < maxLevel; ++j)
            {
                if (j > 1 && frame_is_hidden_ci(L->ci - j))
                    continue;
                if (--level == 0)
                    return j + 1;
            }
            return -1;
        }

        // Another thread: the wrapper frame lives on L, not on L1, so the
        // caller's levels line up with L1's directly - no +1. Level 0 on a
        // foreign thread is that thread's running function.
        for (int n = 0; n < maxLevel; ++n)
        {
            if (n > 0 && frame_is_hidden_ci(L1->ci - n))
                continue;
            if (level-- == 0)
                return n;
        }
        return -1;
    }

    static int debug_info_wrapper(lua_State* L)
    {
        const int top = lua_gettop(L);

        int fnIdx = 0;
        if (lua_isfunction(L, 1))
            fnIdx = 1;
        else if (lua_isthread(L, 1) && lua_isfunction(L, 2))
            fnIdx = 2;

        if (fnIdx != 0)
        {
            Closure* fn = clvalue(index2addr(L, fnIdx));

            // a closure hidden by setstackhidden must not resolve at all;
            // answer exactly like db_info does for an out-of-range value
            if (HiddenClosures.contains(fn))
                return 0;

            auto it = HookRecords.find(fn);
            if (it != HookRecords.end() && it->second.OriginalRef != LUA_NOREF)
            {
                lua_getref(L, it->second.OriginalRef);
                lua_replace(L, fnIdx);
            }
        }
        else
        {
            const int levelIdx = lua_isthread(L, 1) ? 2 : 1;
            if (lua_isnumber(L, levelIdx))
            {
                lua_State* L1 = lua_isthread(L, 1) ? lua_tothread(L, 1) : L;
                const int requested = (int)lua_tointeger(L, levelIdx);
                const int mapped = remap_debug_info_level(L, L1, requested);

                if (mapped < 0)
                    return 0;

                lua_pushinteger(L, mapped);
                lua_replace(L, levelIdx);
            }
        }

        // the original debug.info rides in as an upvalue: resolution stays
        // per-state, so one state's wrapper can never dereference a ref that
        // belongs to another state's registry.
        const int nargs = top;
        lua_pushvalue(L, lua_upvalueindex(1));
        lua_insert(L, 1);
        lua_call(L, nargs, LUA_MULTRET);
        return lua_gettop(L);
    }

    // ------------------------------------------------------------------
    // setstackhidden -> debug.traceback
    //
    // The VM-side filter only reaches tracebacks built by the copy of Luau
    // that ships in this module. Scripts run on the game's state, whose
    // luaL_traceback has no such hook, so hiding has to happen on the way
    // back out of the original debug.traceback.
    //
    // luaL_traceback emits exactly one line per non-C frame in start-level
    // order, after an optional "message\n" header. The wrapper walks the same
    // frames, records which of them are hidden, then drops those lines from
    // the returned string - but only after every surviving frame line is
    // verified against the text the original produced. If the layout does
    // not match what this walk predicted, the original string is handed back
    // untouched rather than mutilated.
    // ------------------------------------------------------------------
    static int debug_traceback_wrapper(lua_State* L)
    {
        const int top = lua_gettop(L);

        const int threadArg = lua_isthread(L, 1) ? 1 : 0;
        lua_State* L1 = threadArg ? lua_tothread(L, 1) : L;
        const int levelIdx = threadArg + 2;
        const bool sameThread = (L1 == L);

        // level exactly as db_traceback would read it
        int requested = sameThread ? 1 : 0;
        bool shiftIt = false;

        if (levelIdx <= top && !lua_isnoneornil(L, levelIdx))
        {
            if (lua_isnumber(L, levelIdx))
            {
                requested = (int)lua_tointeger(L, levelIdx);
                shiftIt = requested >= 0; // negatives are forwarded, the
                                          // original raises on them
            }
            // a non-number level is forwarded untouched so db_traceback
            // still produces its own argument error
        }
        else
        {
            // absent or explicit nil: materialise the default ourselves so
            // the shift can be applied to it
            shiftIt = true;
        }

        if (shiftIt)
        {
            // this wrapper sits between the caller and db_traceback, so
            // every level the caller counts starts one frame lower on the
            // way in. db_traceback skips C frames anyway, which is why the
            // unshifted default still looked right - explicit levels did not.
            while (lua_gettop(L) < levelIdx)
                lua_pushnil(L); // fills a missing message slot with nil,
                                // which luaL_optstring treats as absent
            lua_pushinteger(L, requested + (sameThread ? 1 : 0));
            lua_replace(L, levelIdx);
        }

        const int walkStart = requested;

        const int nargs = lua_gettop(L);
        lua_pushvalue(L, lua_upvalueindex(1)); // the real debug.traceback
        lua_insert(L, 1);
        lua_call(L, nargs, LUA_MULTRET);

        const int results = lua_gettop(L);
        if (results < 1 || lua_type(L, 1) != LUA_TSTRING)
            return results;

        // frames the original is about to print, in output order. Only the
        // "source[:line]" part of each line is recorded - the name segment
        // depends on getfuncname, which does not have to agree between this
        // copy of the VM and the one the game runs, and it plays no part in
        // alignment anyway.
        std::vector<std::string> prefixes;
        std::vector<bool> hidden;
        {
            lua_Debug ar;
            for (int i = walkStart; lua_getinfo(L1, i, "fsl", &ar); ++i)
            {
                bool isHidden = false;
                if (lua_isfunction(L1, -1))
                {
                    Closure* cl = clvalue(index2addr(L1, -1));
                    isHidden = cl && HiddenClosures.contains(cl);
                }
                lua_pop(L1, 1);

                if (ar.what && strcmp(ar.what, "C") == 0)
                    continue;

                std::string line;
                if (ar.source)
                    line += ar.short_src;
                if (ar.currentline > 0)
                {
                    line += ':';
                    line += std::to_string(ar.currentline);
                }

                prefixes.push_back(line);
                hidden.push_back(isHidden);
            }
        }

        bool anyHidden = false;
        for (bool h : hidden)
            anyHidden = anyHidden || h;
        if (!anyHidden || prefixes.empty())
            return results;

        size_t len = 0;
        const char* raw = lua_tolstring(L, 1, &len);
        const std::string original(raw, len);

        if (original.empty() || original.back() != '\n')
            return results;

        std::vector<std::string> lines;
        {
            size_t start = 0;
            while (true)
            {
                size_t nl = original.find('\n', start);
                if (nl == std::string::npos)
                {
                    lines.push_back(original.substr(start));
                    break;
                }
                lines.push_back(original.substr(start, nl - start));
                start = nl + 1;
            }
        }
        if (!lines.empty() && lines.back().empty())
            lines.pop_back(); // artefact of the terminating newline

        const size_t frameCount = prefixes.size();
        if (lines.size() < frameCount)
            return results;

        // every frame line has to be our prefix, optionally followed by
        // " function <name>". Anything else means the layout is not the one
        // this walk predicted, and the original string is returned untouched
        // rather than have the wrong lines deleted.
        static const char FunctionTag[] = " function ";
        const size_t firstFrameLine = lines.size() - frameCount;
        for (size_t k = 0; k < frameCount; ++k)
        {
            const std::string& actual = lines[firstFrameLine + k];
            const std::string& prefix = prefixes[k];

            if (actual == prefix)
                continue;

            if (actual.size() > prefix.size() &&
                actual.compare(0, prefix.size(), prefix) == 0 &&
                actual.compare(prefix.size(), sizeof(FunctionTag) - 1, FunctionTag) == 0)
                continue;

            return results;
        }

        for (size_t k = frameCount; k-- > 0;)
        {
            if (hidden[k])
                lines.erase(lines.begin() + (firstFrameLine + k));
        }

        std::string rebuilt;
        for (const std::string& line : lines)
        {
            rebuilt += line;
            rebuilt += '\n';
        }

        lua_pushlstring(L, rebuilt.data(), rebuilt.size());
        lua_replace(L, 1);
        return lua_gettop(L);
    }

    inline void ensure_debug_info_hook(lua_State* L)
    {
        int top = lua_gettop(L);

        lua_getglobal(L, "debug");
        if (!lua_istable(L, -1))
        {
            lua_settop(L, top);
            return;
        }
        int dbgIdx = top + 1;

        lua_getfield(L, dbgIdx, "info");
        if (!lua_isfunction(L, -1))
        {
            lua_settop(L, top);
            return;
        }

        Closure* info = clvalue(index2addr(L, -1));
        if (info->isC && info->c.f == debug_info_wrapper)
        {
            // already wrapped on this state: leave everything alone
            lua_settop(L, top);
            return;
        }

        // first wrap on this state: capture the original implementation. It
        // is handed to the wrapper as an upvalue, so resolution is bound to
        // this state's closure and can never reach into another state's
        // registry. The global ref is kept only as the record that a wrapper
        // was installed here - nothing dereferences it across states.
        //
        // lua_ref does not pop, so the duplicate and the fetched `info` both
        // have to come off before the copy table takes top + 2.
        const int dbgReadonly = lua_getreadonly(L, dbgIdx);
        lua_pushvalue(L, -1);
        DebugInfoOriginalRef = lua_ref(L, -1);
        lua_pop(L, 2); // ref copy + the `info` we fetched

        if (DebugInfoOriginalRef == LUA_NOREF)
        {
            lua_settop(L, top);
            return;
        }

        // fresh copy of the debug table with `info` replaced
        lua_newtable(L);
        int newIdx = top + 2;

        if (lua_getmetatable(L, dbgIdx))
            lua_setmetatable(L, newIdx);

        lua_setreadonly(L, newIdx, false);

        lua_pushnil(L);
        while (lua_next(L, dbgIdx))
        {
            lua_pushvalue(L, -2);
            lua_insert(L, -2);
            lua_rawset(L, newIdx);
        }

        lua_getref(L, DebugInfoOriginalRef); // upvalue 1: the real debug.info
        lua_pushcclosurek(L, debug_info_wrapper, ("info"), 1, DispatchContinuation);
        Shared::ExecutorClosures.insert(clvalue(index2addr(L, -1)));
        if (Environment)
            Environment->function_array.push_back(clvalue(index2addr(L, -1)));
        lua_setfield(L, newIdx, "info");

        lua_setreadonly(L, newIdx, dbgReadonly);
        lua_setglobal(L, "debug");
        lua_settop(L, top);
    }

    // setstackhidden -> debug.traceback, installed the same way as info.
    // The original rides in as upvalue 1, so nothing is resolved through a
    // ref that could belong to a different state's registry.
    inline void ensure_debug_traceback_hook(lua_State* L)
    {
        const int top = lua_gettop(L);

        lua_getglobal(L, "debug");
        if (!lua_istable(L, -1))
        {
            lua_settop(L, top);
            return;
        }
        const int dbgIdx = top + 1;

        lua_getfield(L, dbgIdx, "traceback");
        if (!lua_isfunction(L, -1))
        {
            lua_settop(L, top);
            return;
        }

        Closure* tb = clvalue(index2addr(L, -1));
        if (tb->isC && tb->c.f == debug_traceback_wrapper)
        {
            // already wrapped on this state
            lua_settop(L, top);
            return;
        }

        const int dbgReadonly = lua_getreadonly(L, dbgIdx);

        // stack: [.., debug, original] -> [.., debug, wrapper]
        lua_pushcclosurek(L, debug_traceback_wrapper, ("traceback"), 1, DispatchContinuation);
        const int wrapIdx = lua_gettop(L);
        Shared::ExecutorClosures.insert(clvalue(index2addr(L, wrapIdx)));
        if (Environment)
            Environment->function_array.push_back(clvalue(index2addr(L, wrapIdx)));

        // fresh copy of the debug table with `traceback` swapped out
        lua_newtable(L);
        const int newIdx = lua_gettop(L);

        if (lua_getmetatable(L, dbgIdx))
            lua_setmetatable(L, newIdx);

        lua_setreadonly(L, newIdx, false);

        lua_pushnil(L);
        while (lua_next(L, dbgIdx))
        {
            lua_pushvalue(L, -2);
            lua_insert(L, -2);
            lua_rawset(L, newIdx);
        }

        lua_pushvalue(L, wrapIdx);
        lua_setfield(L, newIdx, "traceback");

        lua_setreadonly(L, newIdx, dbgReadonly);
        lua_setglobal(L, "debug");
        lua_settop(L, top);
    }

    // ------------------------------------------------------------------
    // getfenv / setfenv - our own implementations
    //
    // Replaces the base-library pair outright so every environment query
    // runs through one code path. Semantics mirror the base library: a C
    // frame reached through a level query answers with the thread globals,
    // everything else answers with its own environment.
    // ------------------------------------------------------------------

    // Resolves argument 1 onto the top of the stack as a function value,
    // the way the base library's getfunc does. 'opt' makes the level
    // argument optional and defaults it to 1 - the frame that called us.
    static void resolve_fenv_target(lua_State* L, bool opt)
    {
        if (lua_isfunction(L, 1))
        {
            lua_pushvalue(L, 1);
            return;
        }

        lua_Debug ar;
        const int level = opt ? luaL_optinteger(L, 1, 1) : luaL_checkinteger(L, 1);
        luaL_argcheck(L, level >= 0, 1, ("level must be non-negative"));

        if (lua_getinfo(L, level, "f", &ar) == 0)
            luaL_argerror(L, 1, ("invalid level"));

        if (lua_isnil(L, -1))
            luaL_error(L, ("no function environment for tail call at level %d"), level);
    }

    inline int getfenv(lua_State* L)
    {
        const bool directArg = lua_isfunction(L, 1);
        resolve_fenv_target(L, true); // [.., fn]

        // a C frame reached through a level query answers with the calling
        // thread's globals; queried directly it answers with its own env.
        // our own closures are the exception: they are built on the exploit
        // thread, so "their own env" *is* the table getgenv() hands out, and
        // sUNC asserts those two must never be the same table. report the
        // environment the calling script actually runs in instead - which is
        // what a C closure reads globals from anyway.
        const bool cfunction = lua_iscfunction(L, -1);
        const bool executorClosure = cfunction && IsExecutorClosure(clvalue(index2addr(L, -1)));

        if (cfunction && (executorClosure || !directArg))
            lua_pushvalue(L, LUA_GLOBALSINDEX);
        else
            lua_getfenv(L, -1);

        lua_setsafeenv(L, -1, false);
        return 1;
    }

    inline int setfenv(lua_State* L)
    {
        luaL_checktype(L, 2, LUA_TTABLE);
        resolve_fenv_target(L, false); // [.., fn] - level required, no default

        lua_pushvalue(L, 2);          // [.., fn, env]
        lua_setsafeenv(L, -1, false); // env leaves here uncacheable

        if (lua_isnumber(L, 1) && lua_tonumber(L, 1) == 0)
        {
            // level 0 retargets the running thread's globals
            lua_pushthread(L);
            lua_insert(L, -2);
            lua_setfenv(L, -2);
            return 0;
        }

        if (lua_iscfunction(L, -2) || lua_setfenv(L, -2) == 0)
            luaL_error(L, ("'setfenv' cannot change environment of given object"));

        return 1;
    }

    // Installs our getfenv / setfenv pair over the base-library pair.
    // Idempotent: re-registration runs it again on the same state, and
    // re-pushing every time would hand every live script a new closure
    // identity for the same global.
    inline void ensure_fenv_globals(lua_State* L)
    {
        const int top = lua_gettop(L);

        lua_getglobal(L, "getfenv");
        const bool oursGet = lua_isfunction(L, -1) && lua_iscfunction(L, -1) &&
            clvalue(index2addr(L, -1))->c.f == getfenv;
        lua_pop(L, 1);

        if (!oursGet)
            Environment->make_global(L, "getfenv", getfenv, funcnameinc++);

        lua_getglobal(L, "setfenv");
        const bool oursSet = lua_isfunction(L, -1) && lua_iscfunction(L, -1) &&
            clvalue(index2addr(L, -1))->c.f == setfenv;
        lua_pop(L, 1);

        if (!oursSet)
            Environment->make_global(L, "setfenv", setfenv, funcnameinc++);

        lua_settop(L, top);
    }

    // ------------------------------------------------------------------
    // detection fix: Executor Security
    //
    // the game answers executor probes through a BindableFunction:Invoke
    // channel. The filter answers META_SECURITY with false and forwards
    // every other call to the real implementation.
    // ------------------------------------------------------------------
    inline lua_CFunction OriginalInvokeFn = nullptr;

    inline int InvokeSecurityFilter(lua_State* L)
    {
        int n = lua_gettop(L);
        for (int i = 1; i <= 2 && i <= n; ++i)
        {
            if (lua_type(L, i) == LUA_TSTRING)
            {
                const char* key = lua_tostring(L, i);
                if (key && strcmp(key, "META_SECURITY") == 0)
                {
                    lua_pushboolean(L, false);
                    return 1;
                }
            }
        }

        if (!OriginalInvokeFn)
            luaL_error(L, ("Invoke: original function missing"));

        return OriginalInvokeFn(L);
    }

    inline void EnsureInvokeSecurityHook(lua_State* L)
    {
        int top = lua_gettop(L);

        // Instance is a library table, never a callable: resolve Instance.new
        // and build a throwaway BindableFunction to reach the class's shared
        // Invoke closure. Every BindableFunction — including the game's own
        // probe object — dispatches through that one closure, so swapping its
        // C function in place intercepts the probe with no extra frame, no
        // identity change and no debugname change.
        lua_getglobal(L, "Instance");
        if (lua_istable(L, -1))
        {
            lua_getfield(L, -1, "new");
            if (lua_isfunction(L, -1))
            {
                lua_pushliteral(L, "BindableFunction");
                if (lua_pcall(L, 1, 1, 0) == LUA_OK)
                {
                    const int inst = lua_gettop(L);

                    lua_getfield(L, inst, "Invoke");
                    if (lua_isfunction(L, -1))
                    {
                        Closure* invoke = clvalue(index2addr(L, -1));
                        if (invoke->isC && invoke->c.f != InvokeSecurityFilter)
                        {
                            if (!OriginalInvokeFn)
                                OriginalInvokeFn = invoke->c.f;
                            invoke->c.f = InvokeSecurityFilter;
                            InvokeHookInstalled = true;
                        }
                    }
                    lua_pop(L, 1); // Invoke

                    // discard the probe instance
                    lua_getfield(L, inst, "Destroy");
                    if (lua_isfunction(L, -1))
                    {
                        lua_pushvalue(L, inst);
                        if (lua_pcall(L, 1, 0, 0) != LUA_OK)
                            lua_pop(L, 1);
                    }
                    else
                    {
                        lua_pop(L, 1);
                    }
                }
            }
        }

        lua_settop(L, top);
    }
    // ------------------------------------------------------------------
    // hooksignal dispatch
    //
    // Stable key for a signal: the userdata payload of an RBXScriptSignal
    // differs per fetch, but the internal signal pointer (payload+16) is
    // shared, so re-fetching scriptContext.Error still hits the record.
    // ------------------------------------------------------------------
    inline void* SignalKey(lua_State* L, int index)
    {
        void* payload = lua_touserdata(L, index);
        if (!payload)
            return nullptr;

        uintptr_t inner = 0;
        __try
        {
            inner = *reinterpret_cast<uintptr_t*>(reinterpret_cast<uintptr_t>(payload) + 16);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            inner = 0;
        }

        if (inner)
            return reinterpret_cast<void*>(inner);
        return payload;
    }

    // ------------------------------------------------------------------
    // hooksignal dispatch
    //
    // SignalDispatcher is what actually gets connected to the signal. On
    // every fire it builds a fresh callOriginal closure around the saved
    // handlers and invokes   callback(callOriginal, ...)
    // with the arguments the signal fired with — so the user callback sees
    // the convention it expects instead of raw engine arguments.
    // ------------------------------------------------------------------

    // upvalue 1: SignalRecords key (light userdata)
    // upvalue 2: table of the arguments the signal fired with
    inline int SignalCallOriginal(lua_State* L)
    {
        int nargs = lua_gettop(L);

        // called with no arguments -> replay what the signal fired with
        if (nargs == 0)
        {
            lua_pushvalue(L, lua_upvalueindex(2));
            const int tableIdx = lua_gettop(L);
            const int n = (int)lua_objlen(L, tableIdx);
            for (int i = 1; i <= n; ++i)
                lua_rawgeti(L, tableIdx, i);
            lua_remove(L, tableIdx);
            nargs = n;
        }

        lua_pushvalue(L, lua_upvalueindex(1));
        void* key = lua_touserdata(L, -1);
        lua_pop(L, 1);

        auto it = key ? SignalRecords.find(key) : SignalRecords.end();
        if (it == SignalRecords.end() || it->second.FunctionsRef == LUA_NOREF)
        {
            lua_settop(L, 0);
            return 0;
        }

        lua_getref(L, it->second.FunctionsRef);
        const int funcsIdx = lua_gettop(L);
        const int count = (int)lua_objlen(L, funcsIdx);

        // run every saved handler; remember the first error but let the
        // rest of them run, exactly like the engine would have
        char firstError[1024] = {};
        for (int i = 1; i <= count; ++i)
        {
            lua_rawgeti(L, funcsIdx, i);
            if (!lua_isfunction(L, -1))
            {
                lua_pop(L, 1);
                continue;
            }
            for (int a = 1; a <= nargs; ++a)
                lua_pushvalue(L, a);
            if (lua_pcall(L, nargs, 0, 0) != LUA_OK)
            {
                const char* err = lua_tostring(L, -1);
                if (!firstError[0])
                    strncpy_s(firstError, err ? err : "original handler error", _TRUNCATE);
                lua_pop(L, 1);
            }
        }

        lua_settop(L, 0);

        if (firstError[0])
            luaL_error(L, ("hooksignal: %s"), firstError);

        return 0;
    }

    // upvalue 1: SignalRecords key (light userdata)
    inline int SignalDispatcher(lua_State* L)
    {
        const int nargs = lua_gettop(L);

        lua_pushvalue(L, lua_upvalueindex(1));
        void* key = lua_touserdata(L, -1);
        lua_pop(L, 1);

        auto it = key ? SignalRecords.find(key) : SignalRecords.end();
        if (it == SignalRecords.end() || it->second.CallbackRef == LUA_NOREF)
        {
            lua_settop(L, 0);
            return 0;
        }

        // [args...] -> [callback][args...]
        lua_getref(L, it->second.CallbackRef);
        if (!lua_isfunction(L, -1))
        {
            lua_settop(L, 0);
            return 0;
        }
        lua_insert(L, 1);

        // [callback][args...] -> [callback][args...][key][firedArgs]
        lua_pushlightuserdata(L, key);
        lua_createtable(L, nargs, 0);
        const int firedIdx = lua_gettop(L);
        for (int i = 1; i <= nargs; ++i)
        {
            // signal args now live at 2..nargs+1 (callback occupies slot 1)
            lua_pushvalue(L, i + 1);
            lua_rawseti(L, firedIdx, i);
        }
        lua_pushcclosure(L, SignalCallOriginal, ("SignalCallOriginal"), 2);

        // [callback][args...] -> [callback][callOriginal][args...]
        lua_insert(L, 2);

        // run the callback like any other connection: errors surface
        // through the signal's own fire path instead of vanishing
        if (lua_pcall(L, nargs + 1, 0, 0) != LUA_OK)
        {
            // stack: [error] -> re-raise so Roblox reports it
            lua_error(L);
            return 0;
        }

        lua_settop(L, 0);
        return 0;
    }

    // ------------------------------------------------------------------
    // hooksignal / restoresignal
    //
    // hooksignal snapshots every live connection on the signal, disconnects
    // them and connects the callback in their place. restoresignal drops the
    // callback and reconnects the original handlers.
    // ------------------------------------------------------------------
    inline int restoresignal(lua_State* L)
    {
        
        luaL_checkany(L, 1);

        void* key = SignalKey(L, 1);
        auto it = key ? SignalRecords.find(key) : SignalRecords.end();
        if (it == SignalRecords.end())
        {
            lua_pushboolean(L, false);
            return 1;
        }

        SignalRecord rec = it->second;
        SignalRecords.erase(it);

        int top = lua_gettop(L);

        // reconnect the original handlers
        if (rec.FunctionsRef != LUA_NOREF)
        {
            lua_getref(L, rec.FunctionsRef);
            int funcsIdx = lua_gettop(L);
            int n = (int)lua_objlen(L, funcsIdx);
            for (int i = 1; i <= n; ++i)
            {
                lua_rawgeti(L, funcsIdx, i); // [funcs][fn]
                if (lua_isfunction(L, -1))
                {
                    lua_getfield(L, 1, "Connect"); // [funcs][fn][Connect]
                    if (lua_isfunction(L, -1))
                    {
                        lua_pushvalue(L, 1);          // [funcs][fn][Connect][self]
                        lua_pushvalue(L, funcsIdx+1); // [funcs][fn][Connect][self][fn]
                        if (lua_pcall(L, 2, 0, 0) != LUA_OK)
                            lua_pop(L, 1);
                    }
                    else
                    {
                        lua_pop(L, 1);
                    }
                }
                lua_pop(L, 1); // fn
            }
            lua_pop(L, 1); // funcs
        }

        // disconnect the hook callback
        if (rec.HookRef != LUA_NOREF)
        {
            lua_getref(L, rec.HookRef);
            lua_getfield(L, -1, "Disconnect");
            if (lua_isfunction(L, -1))
            {
                lua_pushvalue(L, -2);
                if (lua_pcall(L, 1, 0, 0) != LUA_OK)
                    lua_pop(L, 1);
            }
            else
            {
                lua_pop(L, 1);
            }
            lua_pop(L, 1); // connection
        }

        if (rec.ConnectionsRef != LUA_NOREF) lua_unref(L, rec.ConnectionsRef);
        if (rec.FunctionsRef != LUA_NOREF) lua_unref(L, rec.FunctionsRef);
        if (rec.CallbackRef != LUA_NOREF) lua_unref(L, rec.CallbackRef);
        if (rec.HookRef != LUA_NOREF) lua_unref(L, rec.HookRef);
        if (rec.SignalRef != LUA_NOREF) lua_unref(L, rec.SignalRef);

        lua_settop(L, top);
        lua_pushboolean(L, true);
        return 1;
    }
    inline void xq7lp(lua_State* s, int p2) { lua_settop(s, -p2 - 1); }

    static bool kv3wz(lua_State* s, int p1)
    {
        if (!lua_istable(s, p1))
            return false;
        lua_getfield(s, p1, "Connections");
        const bool r9 = lua_istable(s, -1);
        xq7lp(s, 1);
        return r9;
    }

    inline void mt9cd(lua_State* s, Closure* p3)
    {
        (void)p3;
        lua_clonefunction(s, -1);
    }

    inline void rn5bf(lua_State* s, int p4, int p5)
    {
        (void)s; (void)p4; (void)p5;
    }

    static int ty8hs(lua_State* s)
    {
        const int va1 = lua_gettop(s);
        lua_rawcheckstack(s, va1 + 12);

        lua_pushcclosure(s, Signals::getconnectionsV2, ("getconnections"), 0);
        lua_pushvalue(s, lua_upvalueindex(2));

        int vb2 = LUA_NOREF;
        int vc3 = LUA_NOREF;
        int vd4 = -1;
        bool ve5 = false;

        if (lua_pcall(s, 1, 1, 0) == LUA_OK && lua_type(s, -1) == LUA_TTABLE)
        {
            const int vf6 = lua_gettop(s);
            const int vg7 = static_cast<int>(lua_objlen(s, vf6));

            for (int n1 = 1; n1 <= vg7 && !ve5; ++n1)
            {
                lua_rawcheckstack(s, 4);
                lua_rawgeti(s, vf6, n1);
                const int vh8 = lua_gettop(s);

                if (lua_type(s, vh8) == LUA_TTABLE)
                {
                    lua_getfield(s, vh8, ("Function"));

                    if (lua_type(s, -1) == LUA_TFUNCTION &&
                        lua_rawequal(s, -1, lua_upvalueindex(4)))
                    {
                        vc3 = lua_ref(s, -1);
                        xq7lp(s, 1);

                        lua_pushvalue(s, vh8);
                        vb2 = lua_ref(s, -1);
                        xq7lp(s, 1);

                        vd4 = n1 - 1;
                        ve5 = true;
                    }
                    else
                    {
                        xq7lp(s, 1);
                    }
                }

                lua_settop(s, vh8 - 1);
            }

            lua_settop(s, vf6 - 1);
        }
        else
        {
            xq7lp(s, 1);
        }

        lua_createtable(s, 0, 3);
        const int vi9 = lua_gettop(s);

        if (ve5)
        {
            lua_getref(s, vb2);
            lua_setfield(s, vi9, ("Connection"));

            lua_getref(s, vc3);
            lua_setfield(s, vi9, ("Function"));

            lua_pushnumber(s, static_cast<double>(vd4));
            lua_setfield(s, vi9, ("Index"));

            lua_unref(s, vb2);
            lua_unref(s, vc3);
        }

        const int vj0 = lua_gettop(s);

        lua_rawcheckstack(s, va1 + 4);
        lua_pushvalue(s, lua_upvalueindex(1));
        lua_pushvalue(s, vi9);
        for (int n2 = 1; n2 <= va1; ++n2)
            lua_pushvalue(s, n2);

        if (lua_pcall(s, va1 + 1, LUA_MULTRET, 0) != LUA_OK)
        {
            lua_settop(s, 0);
            return 0;
        }

        const int vk1 = lua_gettop(s) - vj0;
        const bool vl2 = vk1 >= 1 && lua_toboolean(s, vj0 + 1) != 0;

        if (vl2)
        {
            lua_rawcheckstack(s, vk1 + 2);
            lua_pushvalue(s, lua_upvalueindex(3));
            for (int n3 = 2; n3 <= vk1; ++n3)
                lua_pushvalue(s, vj0 + n3);

            lua_pcall(s, vk1 - 1, 0, 0);
        }

        lua_settop(s, 0);
        return 0;
    }

    inline int hooksignal(lua_State* s)
    {
        if (!kv3wz(s, 1))
            luaL_argerrorL(s, 1, ("RBXScriptSignal is required sir"));

        luaL_checktype(s, 2, LUA_TFUNCTION);
        const int wa = 2;

        lua_pushcclosure(s, Signals::getconnectionsV2, ("getconnections"), 0);
        lua_pushvalue(s, 1);
        if (lua_pcall(s, 1, 1, 0) != LUA_OK)
        {
            lua_pop(s, 1);
            lua_pushboolean(s, false);
            return 1;
        }

        const int wb = lua_gettop(s);
        if (lua_type(s, wb) != LUA_TTABLE)
        {
            lua_settop(s, wb - 1);
            lua_pushboolean(s, false);
            return 1;
        }

        const int wc = static_cast<int>(lua_objlen(s, wb));
        int wd = 0;

        for (int n4 = 1; n4 <= wc; ++n4)
        {
            lua_rawcheckstack(s, 8);
            lua_rawgeti(s, wb, n4);
            const int we = lua_gettop(s);

            if (lua_type(s, we) != LUA_TTABLE)
            {
                lua_settop(s, we - 1);
                continue;
            }

            lua_getfield(s, we, ("ForeignState"));
            const bool wf = lua_toboolean(s, -1) != 0;
            xq7lp(s, 1);

            lua_getfield(s, we, ("Function"));
            if (wf || lua_type(s, -1) != LUA_TFUNCTION)
            {
                lua_settop(s, we - 1);
                continue;
            }

            const int wg = lua_gettop(s);
            Closure* wh = clvalue(luaA_toobject(s, wg));

            if (wh->isC || lua_rawequal(s, wg, wa))
            {
                lua_settop(s, we - 1);
                continue;
            }

            mt9cd(s, wh);
            const int wi = lua_gettop(s);

            lua_pushvalue(s, wa);
            lua_pushvalue(s, 1);
            lua_pushvalue(s, wi);
            lua_pushvalue(s, wg);
            lua_pushcclosure(s, ty8hs, ("hooksignal"), 4);
            const int wj = lua_gettop(s);

            rn5bf(s, wg, wj);
            ++wd;

            lua_settop(s, we - 1);
        }

        lua_settop(s, wb - 1);
        lua_pushboolean(s, wd > 0);
        return 1;
    }

    inline int iscclosure(lua_State* L)
    {
        
        if (!lua_isfunction(L, 1))
        {
            lua_pushboolean(L, false);
            return 1;
        }
        lua_pushboolean(L, lua_iscfunction(L, 1));
        return 1;
    }

    inline int islclosure(lua_State* L)
    {
        
        if (!lua_isfunction(L, 1))
        {
            lua_pushboolean(L, false);
            return 1;
        }
        lua_pushboolean(L, !lua_iscfunction(L, 1));
        return 1;
    }

    inline bool IsExecutorProto(Proto* proto)
    {
        if (!proto)
            return false;

        if (proto->userdata)
        {
            void* raw = proto->userdata.Get();
            if (raw && *static_cast<uintptr_t*>(raw) == MaxCapabilities)
                return true;
        }

        for (int i = 0; proto->p && i < proto->sizep; ++i)
        {
            if (IsExecutorProto(proto->p[i]))
                return true;
        }

        return false;
    }

    inline bool IsExecutorClosure(Closure* closure)
    {
        if (!closure)
            return false;

        if (Shared::ExecutorClosures.contains(closure) ||
            WrappedClosures.contains(closure) ||
            NewCClosureRefs.contains(closure) ||
            HookRecords.contains(closure))
        {
            return true;
        }

        if (!closure->isC)
            return IsExecutorProto(closure->l.p);

        if (closure->c.f == NewCClosureDispatcher ||
            closure->c.f == HookCDispatcher ||
            closure->c.f == HookLuaDispatcher)
        {
            return true;
        }

        for (Closure* registered : Environment->function_array)
        {
            if (!registered)
                continue;

            if (registered == closure)
                return true;

            if (registered->isC && registered->c.f == closure->c.f)
                return true;
        }

        return false;
    }

    inline auto is_executor_closure(lua_State* rl) -> int
    {
        
        if (lua_type(rl, 1) != LUA_TFUNCTION) {
            lua_pushboolean(rl, false);
            return 1;
        }

        Closure* closure = clvalue(index2addr(rl, 1));
        lua_pushboolean(rl, IsExecutorClosure(closure));
        return 1;
    }



    inline int gettenv(lua_State* L)
    {
        luaL_checktype(L, 1, LUA_TTHREAD);
        lua_State* thread = lua_tothread(L, 1);
        if (!thread) {
            lua_pushnil(L);
            return 1;
        }
        lua_pushvalue(thread, LUA_GLOBALSINDEX);
        lua_xmove(thread, L, 1);
        return 1;
    }
  
    inline int compareclosures(lua_State* L)
    {
        
        luaL_checktype(L, 1, LUA_TFUNCTION);
        luaL_checktype(L, 2, LUA_TFUNCTION);

        Closure* a = clvalue(index2addr(L, 1));
        Closure* b = clvalue(index2addr(L, 2));

        if (!a || !b) {
            lua_pushboolean(L, false);
            return 1;
        }

        bool same = false;
        if (a->isC && b->isC) {
            same = (a->c.f == b->c.f);
        }
        else if (!a->isC && !b->isC) {
            same = (a->l.p == b->l.p);
        }

        lua_pushboolean(L, same);
        return 1;
    }

    inline int setstackhidden(lua_State* L)
    {
        
        luaL_checkany(L, 1);
        const bool hidden = luaL_checkboolean(L, 2) != 0;

        if (lua_isnumber(L, 1))
        {
            const int level = (int)lua_tointeger(L, 1);
            if (level < 0)
                luaL_argerror(L, 1, "level must be non-negative");

            lua_Debug ar;
            if (!lua_getinfo(L, level, "f", &ar))
                luaL_argerror(L, 1, "level out of range");

            Closure* cl = nullptr;
            if (lua_isfunction(L, -1))
                cl = clvalue(index2addr(L, -1));
            lua_pop(L, 1);

            if (!cl) return 0;

            if (hidden)
            {
                HideClosure(L, cl);
                HiddenLevels.push_back({ L, level, cl });
            }
            else
            {
                UnhideClosure(L, cl);
                HiddenLevels.erase(
                    std::remove_if(HiddenLevels.begin(), HiddenLevels.end(),
                        [&](const HiddenLevel& hl) {
                            return hl.L == L && hl.cl == cl;
                        }),
                    HiddenLevels.end());
            }
            return 0;
        }

        luaL_checktype(L, 1, LUA_TFUNCTION);
        Closure* cl = clvalue(index2addr(L, 1));

        if (hidden)
            HideClosure(L, cl);
        else
            UnhideClosure(L, cl);

        return 0;
    }
    void register_lib(lua_State* L);
}
