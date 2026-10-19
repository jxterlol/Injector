#include <Utilitys/Globals.hpp>
#include <RBX/execution/execution.hpp>
#include <RBX/task_scheduler/task_scheduler.hpp>
#include <RBX/environment/hooks/hooks.hpp>
#include <cstdio>

class BytecodeEncoder : public Luau::BytecodeEncoder
{
	inline void encode(uint32_t* data, size_t count) override
	{
		if (!data || count == 0)
			return;
		const auto LookupTable = reinterpret_cast<BYTE*>(Offsets::OpcodeLookupTable);
		if (!LookupTable)
			return;
		for (size_t i = 0; i < count;)
		{
			uint8_t Opcode = LUAU_INSN_OP(data[i]);
			uint8_t FinalOpcode = Opcode * 227;
			FinalOpcode = LookupTable[FinalOpcode];

			data[i] = (FinalOpcode) | (data[i] & ~0xFF);
			int Step = Luau::getOpLength(static_cast<LuauOpcode>(Opcode));
			if (Step <= 0)
				Step = 1;
			i += static_cast<size_t>(Step);
		}
	}
};

std::string Execution::CompileScript(std::string Source)
{
	auto BytecodeEncoding = BytecodeEncoder();
	static const char* CommonGlobals[] = { "Game", "Workspace", "game", "plugin", "script", "shared", "workspace", "_G", "_ENV", nullptr };

	Luau::CompileOptions Options;
	Options.debugLevel = 2;
	Options.optimizationLevel = 1;
	Options.mutableGlobals = CommonGlobals;
	Options.vectorLib = "Vector3";
	Options.vectorCtor = "new";
	Options.vectorType = "Vector3";

	return Luau::compile(Source, Options, {}, &BytecodeEncoding);
}

void Execution::ExecuteScript(lua_State* L, std::string Script)
{
	if (!L || Script.empty())
		return;

	// Large hub mains (Eclipse etc. are MBs) compile on the game thread inside
	// stepHook, so the game looks frozen while this runs. Log slow stages so
	// F9 / debugger shows whether it's just a slow CPU vs a real hang.
	const uint64_t T0 = GetTickCount64();

	int OriginalTop = lua_gettop(L);
	lua_State* ExecutionThread = lua_newthread(L);
	lua_pop(L, 1);

	// make the hooks recognise this thread (and (re)patch the game metatable
	// before every run so game:HttpGet & co always resolve for our scripts)
	Shared::ExecutorThreads.insert(ExecutionThread);
	initialize_hooks(L);

	luaL_sandboxthread(ExecutionThread);
	task_scheduler::SetThreadCapabilities(ExecutionThread, 8, MaxCapabilities);

	std::string Bytecode = Execution::CompileScript(Script);
	const uint64_t TCompile = GetTickCount64();
	if (luau_load(ExecutionThread, "", Bytecode.data(), Bytecode.size(), NULL) != LUA_OK)
	{
		lua_pop(ExecutionThread, 1);
		lua_settop(L, OriginalTop);
		return;
	}

	Closure* Closure = clvalue(luaA_toobject(ExecutionThread, -1));
	task_scheduler::SetProtoCapabilities(Closure->l.p, &MaxCapabilities);

	// defer through the task scheduler so yields/waits inside the script
	// keep working; fall back to a direct call when task.defer is missing
	lua_getglobal(ExecutionThread, "task");
	lua_getfield(ExecutionThread, -1, "defer");
	if (lua_isfunction(ExecutionThread, -1))
	{
		lua_remove(ExecutionThread, -2);
		lua_insert(ExecutionThread, -2);

		if (lua_pcall(ExecutionThread, 1, 0, 0) != LUA_OK)
			lua_pop(ExecutionThread, 1);
	}
	else
	{
		// no task library in this state — run the chunk inline so the
		// script still executes instead of silently doing nothing
		lua_pop(ExecutionThread, 2);
		if (lua_pcall(ExecutionThread, 0, 0, 0) != LUA_OK)
			lua_pop(ExecutionThread, 1);
	}

	lua_settop(L, OriginalTop);

	// Only report when slow: on low-spec CPUs a multi-MB hub main can take
	// seconds to compile, which looks like a freeze. This tells us if the
	// time went to compile vs load vs defer-queue.
	const uint64_t TEnd = GetTickCount64();
	if (TEnd - T0 > 2000)
	{
		char Msg[256];
		std::snprintf(Msg, sizeof(Msg),
			"[natrium] slow ExecuteScript: %llums total (compile %llums) script_bytes=%zu",
			(unsigned long long)(TEnd - T0),
			(unsigned long long)(TCompile - T0), Script.size());
		OutputDebugStringA(Msg);
		OutputDebugStringA("\n");
	}
}
