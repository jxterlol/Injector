#pragma once

#include <lapi.h>
#include <string>
#include <lstate.h>
#include <Windows.h>

namespace task_scheduler
{
	void TeleportHandler();

	uintptr_t GetDataModel();
	uintptr_t GetScriptContext(uintptr_t DataModel);
	uintptr_t GetJobByTypeName(const std::string& TypeName);

	void RequestExecution(std::string Script);
	void SetProtoCapabilities(Proto* Proto, uintptr_t* Capabilities);
	void SetThreadCapabilities(lua_State* L, int Level, uintptr_t Capabilities);
	void SetIdentity(lua_State* Thread, int Identity, bool IsInstance);

	lua_State* GetLuaState(uintptr_t ScriptContext, uintptr_t Identity, uintptr_t Script);
}
