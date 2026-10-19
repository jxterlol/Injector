#include <RBX/environment/env.hpp>
#include <RBX/environment/hooks/hooks.hpp>
#include <Utilitys/Communication/Communication.hpp>

#include <Utilitys/Utils.hpp>
#include <Utilitys/TPHandler.hpp>
#include <Utilitys/Globals.hpp>
#include <RBX/update.hpp>

#include <RBX/environment/libs/drawingimmediate/drawingimmediate.hpp>

#include <cstring>

// â”€â”€ Global EnvironmentAPI instance â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
EnvironmentAPI _g_Environment;
EnvironmentAPI* Environment = &_g_Environment;



// â”€â”€ Closure Tracking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
void EnvironmentAPI::TrackClosure(Closure* c)
{
	if (!c) return;
	Shared::ExecutorClosures.insert(c);

	for (Closure* existing : function_array)
	{
		if (existing == c)
			return;
	}
	function_array.push_back(c);
}

// â”€â”€ make_global â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
void EnvironmentAPI::make_global(lua_State* L, const char* name, lua_CFunction func, int id)
{

	lua_pushcclosure(L, func, nullptr, 0);
	TrackClosure(clvalue(index2addr(L, -1)));
	lua_setglobal(L, name);
}

// â”€â”€ make_table_function â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
void EnvironmentAPI::make_table_function(lua_State* L, const char* name, lua_CFunction func, int id)
{
	lua_pushcclosure(L, func, nullptr, 0);
	TrackClosure(clvalue(index2addr(L, -1)));
	lua_setfield(L, -2, name);
}

// â”€â”€ make_aliases â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
void EnvironmentAPI::make_aliases(lua_State* L, lua_CFunction func, int id, std::initializer_list<const char*> aliases)
{
	for (const char* alias : aliases)
	{
		lua_pushcclosure(L, func, nullptr, 0);
		TrackClosure(clvalue(index2addr(L, -1)));
		lua_setglobal(L, alias);
	}
}

// â”€â”€ Reset State â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
void EnvironmentAPI::ResetState()
{
	Shared::ExecutorClosures.clear();
	function_array.clear();
	{
		std::lock_guard<std::mutex> lock(Shared::YieldQueueMutex);
		std::queue<std::function<void()>> empty;
		Shared::YieldQueue.swap(empty);
	}
	{
		std::lock_guard<std::mutex> lock(Shared::ExecutionRequestsMutex);
		Shared::ExecutionRequests.clear();
	}
	DrawingImmediate::ClearAll();
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
//  Library includes â€” each library's .hpp declares register_lib
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#include <RBX/environment/libs/http/http.hpp>
#include <RBX/environment/libs/cache/cache.hpp>
#include <RBX/environment/libs/crypt/crypt.hpp>
#include <RBX/environment/libs/input/input.hpp>
#include <RBX/environment/libs/debug/debug.hpp>
#include <RBX/environment/libs/script/script.hpp>
#include <RBX/environment/libs/closures/closures.hpp>
#include <RBX/environment/libs/instance/instance.hpp>
#include <RBX/environment/libs/metatable/metatable.hpp>
#include <RBX/environment/libs/filesystem/filesystem.hpp>
#include <RBX/environment/libs/miscellaneous/miscellaneous.hpp>
#include <RBX/environment/libs/signals/signals.hpp>
#include <RBX/environment/libs/regex/regex.hpp>
#include <RBX/environment/libs/filedialog/filedialog.hpp>
#include <RBX/environment/libs/bit/bit.hpp>
#include <RBX/environment/libs/drawing/drawing.hpp>
#include <RBX/environment/libs/reflection/reflection.hpp>
#include <RBX/environment/libs/oth/oth.hpp>
#include <RBX/environment/libs/raknet/raknet.hpp>
#include <RBX/environment/libs/drawingimmediate/drawingimmediate.hpp>
#include <RBX/environment/libs/luastateproxy/luastateproxy.hpp>
#include <RBX/environment/libs/actor/actor.hpp>
#include <RBX/environment/libs/websocket/websocket.hpp>
#include <RBX/environment/libs/rconsole/rconsole.hpp>


#define LuaState L


namespace module::core::environment
{
  
    namespace Bit              = ::Bit;
    namespace Cache            = ::Cache;
    namespace Closures         = ::Closures;
    namespace Crypt            = ::Crypt;
    namespace Debug            = ::Debug;
    namespace Drawing          = ::Drawing;
    namespace DrawingImmediate = ::DrawingImmediate;
    namespace FileDialog       = ::FileDialog;
    namespace Filesystem       = ::Filesystem;
    namespace Input            = ::Input;
    namespace Instance         = ::Instance;
    namespace LuaStateProxy    = ::LuaStateProxy;
    namespace Metatable        = ::Metatable;
    namespace Miscellaneous    = ::Miscellaneous;
    namespace Oth              = ::Oth;
    namespace Raknet           = ::Raknet;
    namespace RConsole         = ::RConsole;
    namespace Reflection       = ::Reflection;
    namespace Regex            = ::Regex;
    namespace Script           = ::Script;
    namespace Signals          = ::Signals;
    namespace Websocket        = ::Websocket;
    namespace Actor            = ::Actor;
}


LUAU_FASTFLAG(LuauCIProto)
void ApplyLuauFlags()
{
    FFlag::LuauCIProto.value = true;
}

static void SafeClearUdata(lua_State* L)
{
    __try
    {
        std::memset(L->global->udatadirect, 0, sizeof(L->global->udatadirect));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        OutputDebugStringA(("[ENV] udatadirect memset failed, skipping\n"));
    }
}


static lua_CFunction g_OrigPrint = nullptr;
static lua_CFunction g_OrigWarn = nullptr;
static lua_CFunction g_OrigError = nullptr;

static std::string JoinConsoleArgs(lua_State* L, int Start, int MaxCount)
{
    std::string Out;
    const int Top = lua_gettop(L);
    int End = Top;
    if (MaxCount > 0 && Start + MaxCount - 1 < End)
        End = Start + MaxCount - 1;

    for (int i = Start; i <= End; ++i)
    {
        if (i > Start)
            Out.push_back('\t');

        if (lua_type(L, i) == LUA_TBOOLEAN)
        {
            Out.append(lua_toboolean(L, i) ? ("true") : ("false"));
            continue;
        }

        size_t Len = 0;
        const char* Str = lua_tolstring(L, i, &Len);
        if (Str)
            Out.append(Str, Len);
        else
            Out.append(luaL_typename(L, i));
    }
    return Out;
}

static int ConsolePrintHook(lua_State* L)
{
    {
        std::string Msg = JoinConsoleArgs(L, 1, 0);
        if (!Msg.empty())
            ConsoleChannel::Enqueue('p', Msg.data(), Msg.size());
    }
    lua_CFunction Orig = g_OrigPrint;
    return Orig ? Orig(L) : 0;
}

static int ConsoleWarnHook(lua_State* L)
{
    {
        std::string Msg = JoinConsoleArgs(L, 1, 0);
        if (!Msg.empty())
            ConsoleChannel::Enqueue('w', Msg.data(), Msg.size());
    }
    lua_CFunction Orig = g_OrigWarn;
    return Orig ? Orig(L) : 0;
}

static int ConsoleErrorHook(lua_State* L)
{
    {
        std::string Msg = JoinConsoleArgs(L, 1, 1);
        if (!Msg.empty())
            ConsoleChannel::Enqueue('e', Msg.data(), Msg.size());
    }
    lua_CFunction Orig = g_OrigError;
    return Orig ? Orig(L) : 0;
}

static bool PatchConsoleFunction(lua_State* L, const char* Name, lua_CFunction Hook, lua_CFunction* OutOrig)
{
    lua_getglobal(L, Name);
    if (!lua_iscfunction(L, -1))
    {
        lua_pop(L, 1);
        return false;
    }

    Closure* Cl = clvalue(L->top - 1);
    if (!Cl || !Cl->isC || !Cl->c.f || Cl->c.f == Hook)
    {
        lua_pop(L, 1);
        return false;
    }

    *OutOrig = Cl->c.f;
    Cl->c.f = Hook;
    lua_pop(L, 1);
    return true;
}

void EnvironmentAPI::initalizeEnvironment(lua_State* L)
{
    SafeClearUdata(L);

    Closures::ResetLibraryState();
    Signals::ResetLibraryState();

    Oth::ResetLibrary();
    Websocket::teardown();
    Shared::RobloxPcallRef = LUA_NOREF;

    lua_getglobal(L, "pcall");
    if (lua_isfunction(L, -1))
        Shared::RobloxPcallRef = lua_ref(L, -1);
    lua_pop(L, 1);
    ResetState();

    module::core::environment::c_http::register_lib(LuaState);
    module::core::environment::Crypt::register_lib(LuaState);
    module::core::environment::Input::register_lib(LuaState);
    module::core::environment::Debug::register_lib(LuaState);
    module::core::environment::Cache::register_lib(LuaState);
    module::core::environment::Signals::register_lib(LuaState);
    module::core::environment::Script::register_lib(LuaState);
    module::core::environment::Drawing::register_lib(LuaState);
    module::core::environment::Closures::register_lib(LuaState);
    module::core::environment::Instance::register_lib(LuaState);
    module::core::environment::Metatable::register_lib(LuaState);
    module::core::environment::Filesystem::register_lib(LuaState);
    module::core::environment::Miscellaneous::register_lib(LuaState);
    module::core::environment::Regex::register_lib(LuaState);
    module::core::environment::FileDialog::register_lib(LuaState);
    module::core::environment::Bit::register_lib(LuaState);
    module::core::environment::Reflection::register_lib(LuaState);
    module::core::environment::Oth::register_lib(LuaState);
    module::core::environment::Raknet::register_lib(LuaState);
    module::core::environment::DrawingImmediate::register_lib(LuaState);
    module::core::environment::LuaStateProxy::register_lib(LuaState);
    module::core::environment::Actor::register_lib(LuaState);

    module::core::environment::RConsole::register_lib(LuaState);
    module::core::environment::Websocket::register_lib(LuaState);
    initialize_hooks(LuaState);




    lua_pushvalue(L, LUA_GLOBALSINDEX);
    lua_setglobal(L, ("_G"));

    lua_newtable(L);
    lua_setglobal(L, ("shared"));

    // Signal library (Lua bootstrap)
    std::string signal = R"LUA(local Signal = {}
Signal.__index = Signal

function Signal.new()
    local self = setmetatable({}, Signal)
    self._connections = {}
    return self
end

function Signal:Connect(callback)
    local conn = {
        _callback = callback,
        _signal = self,
        _connected = true,
    }
    conn.Disconnect = function(c)
        c._connected = false
        for i, v in ipairs(self._connections) do
            if v == c then
                table.remove(self._connections, i)
                break
            end
        end
    end
    table.insert(self._connections, conn)
    return conn
end

function Signal:Once(callback)
    local conn
    conn = self:Connect(function(...)
        conn:Disconnect()
        callback(...)
    end)
    return conn
end

function Signal:Fire(...)
    for _, conn in ipairs(table.clone(self._connections)) do
        if conn._connected then
            task.spawn(conn._callback, ...)
        end
    end
end

function Signal:Wait()
    local thread = coroutine.running()
    local conn
    conn = self:Connect(function(...)
        conn:Disconnect()
        task.spawn(thread, ...)
    end)
    return coroutine.yield()
end

getgenv().Signal = Signal)LUA";
    


   

                    std::string websocketScript = R"LUA(
do
    local WebSocket = {}

    function WebSocket.connect(url)
        local id, err = __ws_open(url)
        if type(id) ~= "number" then
            error(type(err) == "string" and err or "the connection could not be opened", 2)
        end

        local function makeEvent()
            local ok, inst = pcall(function()
                return Instance.new("BindableEvent")
            end)
            if ok and inst and inst.Event then
                return {
                    Event = inst.Event,
                    Fire = function(self, ...)
                        inst:Fire(...)
                    end
                }
            end
            local sig = Signal.new()
            return {
                Event = sig,
                Fire = function(self, ...)
                    sig:Fire(...)
                end
            }
        end

        local messages = makeEvent()
        local closed = makeEvent()

        local socket = {}
        socket.OnMessage = messages.Event
        socket.OnClose = closed.Event

        function socket.Send(self, message)
            if self ~= socket then
                message = self
            end
            if type(message) == "string" then
                __ws_send(id, message)
            else
                __ws_send(id, tostring(message))
            end
        end

        function socket.Close(self)
            __ws_close(id)
        end

        socket.send = socket.Send
        socket.close = socket.Close

        task.spawn(function()
            while true do
                local inbox, done = __ws_poll(id)

                if inbox then
                    for index = 1, #inbox do
                        messages:Fire(inbox[index])
                    end
                end

                if done then
                    closed:Fire()
                    break
                end

                task.wait(0.03)
            end
        end)

        return socket
    end

    WebSocket.Connect = WebSocket.connect
    WebSocket.New = WebSocket.connect
    WebSocket.new = WebSocket.connect

    local genv = getgenv and getgenv() or _G
    genv.WebSocket = WebSocket
    genv.websocket = WebSocket

    if type(genv.syn) == "table" then
        genv.syn.websocket = WebSocket
    else
        genv.syn = { websocket = WebSocket }
    end

    _G.WebSocket = WebSocket
    _G.websocket = WebSocket
    shared.WebSocket = WebSocket
    shared.websocket = WebSocket
end
)LUA";


 
    task_scheduler::RequestExecution(signal);
    task_scheduler::RequestExecution(websocketScript);
    ApplyLuauFlags();

    PatchConsoleFunction(L, ("print"), ConsolePrintHook, &g_OrigPrint);
    PatchConsoleFunction(L, ("warn"), ConsoleWarnHook, &g_OrigWarn);
    PatchConsoleFunction(L, ("error"), ConsoleErrorHook, &g_OrigError);
}
