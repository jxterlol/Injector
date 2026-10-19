#include <Utilitys/Globals.hpp>
#include <RBX/environment/yielding/yielding.hpp>

static void SehInvoke(const std::function<void()>& fn)
{
	__try
	{
		fn();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
}

void Yielding::RunYield()
{
	// drain up to 64 queued resumes per tick (v6 drained only 1)
	for (int drained = 0; drained < 64; ++drained)
	{
		std::function<void()> YieldingRequest;
		{
			std::lock_guard<std::mutex> lock(Shared::YieldQueueMutex);
			if (Shared::YieldQueue.empty())
				return;
			
			YieldingRequest = std::move(Shared::YieldQueue.front());
			Shared::YieldQueue.pop();
		}
		
		SehInvoke(YieldingRequest);
	}
}

int Yielding::YieldExecution(lua_State* L, const std::function<Yielded()>& YieldingClosure)
{
	// the resume path dereferences L->userdata->shared->scriptContext; a thread
	// without ExtraSpace would take the process down there, so answer with an
	// error string instead (callers already handle a string result)
	if (!L || !L->userdata || !L->userdata->shared)
	{
		lua_pushstring(L, "yield unavailable: thread extra space missing");
		return 1;
	}

	const uint64_t Generation = Shared::StateGeneration.load();
	lua_pushthread(L);
	int YieldedThreadRef = lua_ref(L, -1);
	lua_pop(L, 1);

	std::thread([=]
	{
		Yielded ResumeFunction = YieldingClosure();
		if (Generation != Shared::StateGeneration.load())
			return;

		{
			std::lock_guard<std::mutex> lock(Shared::YieldQueueMutex);
			Shared::YieldQueue.emplace([=]() -> void
			{
				if (Generation != Shared::StateGeneration.load())
					return;
				YieldingLuaThread YieldingLuaThreadObject = { .L = L };
				YieldingLuaThread* YieldingLuaThread = &YieldingLuaThreadObject;

				YieldState YieldState = { 0 };
				auto ScriptContext = reinterpret_cast<uintptr_t>(L->userdata->shared->scriptContext);
				Roblox::ScriptContextResume(ScriptContext + Offsets::ExtraSpace::ScriptContextToResume, &YieldState, &YieldingLuaThread, ResumeFunction(L), NULL, NULL);

				lua_unref(L, YieldedThreadRef);
			});
		}
	}).detach();

	return lua_yield(L, NULL);
}
