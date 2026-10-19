#include <Utilitys/Globals.hpp>
#include <Utilitys/Utils.hpp>
#include <RBX/execution/execution.hpp>
#include <RBX/environment/env.hpp>
#include <RBX/task_scheduler/task_scheduler.hpp>
#include <RBX/environment/yielding/yielding.hpp>
#include <RBX/environment/libs/raknet/raknet.hpp>
#include <Renderer/Renderer.hpp>
#include <RBX/environment/env.hpp>
#include <Utilitys/InjectNotice.hpp>
#include <Windows.h>

#include <chrono>
#include <string>

namespace
{
    std::string LastSchedulerError;

    void ReportSchedulerError(const char* Message)
    {
        if (LastSchedulerError == Message)
            return;

        LastSchedulerError = Message;
        OutputDebugStringA(Message);
        OutputDebugStringA(("\n"));
    }
}

void task_scheduler::SetProtoCapabilities(Proto* Root, uintptr_t* Capabilities)
{
    if (!Root)
        return;

    std::vector<Proto*> Pending{ Root };
    while (!Pending.empty())
    {
        Proto* Current = Pending.back();
        Pending.pop_back();
        if (!Current)
            continue;

        Current->userdata = Capabilities;
        if (Current->sizep < 0 || Current->sizep > 100000 || (!Current->p && Current->sizep != 0))
            continue;

        for (int Index = 0; Index < Current->sizep; ++Index)
            if (Current->p[Index])
                Pending.push_back(Current->p[Index]);
    }
}

void task_scheduler::SetThreadCapabilities(lua_State* L, int Level, uintptr_t Capabilities)
{
    if (!L || !L->userdata)
        return;

    L->userdata->identity.identity = Level;
    L->userdata->capabilities = Capabilities;
}

void task_scheduler::SetIdentity(lua_State* Thread, int Identity, bool IsInstance)
{
    if (!Thread) {
        return;
    }
    if (!Thread->userdata) {
        return;
    }

    RobloxExtraSpace* basedData = reinterpret_cast<RobloxExtraSpace*>(Thread->userdata);
    basedData->identity.identity = Identity;
    basedData->capabilities = Roblox::GetCapabilities(&Identity);

    if (IsInstance) {
        try {
            uintptr_t IdentityPointer = *reinterpret_cast<uintptr_t*>(Offsets::RobloxThread::IdentityPtr);
            if (!IdentityPointer || IdentityPointer > 0xFFFFFFFFFFFF) {
                return;
            }
            uintptr_t IdentityStructure = Roblox::GetIdentityStruct(IdentityPointer);
            if (!IdentityStructure) {
                return;
            }
            *reinterpret_cast<int32_t*>(IdentityStructure) = Identity;
            *reinterpret_cast<uintptr_t*>(IdentityStructure + Offsets::Capabilities::GetCapabilities) =
                Roblox::GetCapabilities(&Identity);
        }
        catch (...) {
        }
    }
}

uintptr_t task_scheduler::GetDataModel()
{
    __try
    {
        uintptr_t FakeDataModel = *reinterpret_cast<uintptr_t*>(Offsets::DataModel::FakeDataModelPointer);
        if (!FakeDataModel)
            return 0;
        return *reinterpret_cast<uintptr_t*>(FakeDataModel + Offsets::DataModel::FakeDataModelToDataModel);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

uintptr_t task_scheduler::GetScriptContext(uintptr_t DataModel)
{
    if (!DataModel)
        return 0;
    __try
    {
        uintptr_t Children = *reinterpret_cast<uintptr_t*>(DataModel + Offsets::DataModel::Children);
        if (!Children)
            return 0;
        uintptr_t FirstChild = *reinterpret_cast<uintptr_t*>(Children);
        if (!FirstChild)
            return 0;
        return *reinterpret_cast<uintptr_t*>(FirstChild + Offsets::DataModel::ScriptContext);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

inline bool CheckMemory(uintptr_t address)
{
    if (address < 0x10000 || address > 0x7FFFFFFFFFFF)
        return false;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) == 0)
        return false;

    if (mbi.Protect & PAGE_NOACCESS || mbi.State != MEM_COMMIT)
        return false;

    return true;
}

inline lua_State* GetLuaStateForInstance(uintptr_t sc)
{
    if (!sc)
        return nullptr;

    __try
    {
        *reinterpret_cast<BOOLEAN*>(sc + Offsets::ExtraSpace::RequireBypass) = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return nullptr;
    }

    auto vmval1 = [](uint32_t a, uint32_t b) -> uint32_t { return b - a; };
    auto vmval2 = [](uint32_t a, uint32_t b) -> uint32_t { return a + b; };
    auto vmval3 = [](uint32_t a, uint32_t b) -> uint32_t { return a ^ b; };
    auto vmval4 = [](uint32_t a, uint32_t b) -> uint32_t { return a - b; };

    auto enc_test = [&](uintptr_t address, uint32_t e0, uint32_t e1, auto&& op) -> uintptr_t
        {
            uint32_t low = op(static_cast<uint32_t>(address), e0);
            uint32_t high = op(static_cast<uint32_t>(address), e1);

            uintptr_t ptr =
                (static_cast<uint64_t>(high) << 32) | static_cast<uint64_t>(low);

            if (!ptr)
                return 0;

            if (!CheckMemory(ptr))
                return 0;

            __try
            {
                uintptr_t test = *reinterpret_cast<uintptr_t*>(ptr);
                if (!test)
                    return 0;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return 0;
            }

            return ptr;
        };

    for (uintptr_t offset = 0; offset <= 0x1000; offset += 0x8)
    {
        uintptr_t address = sc + offset;

        if (!CheckMemory(address))
            continue;

        __try
        {
            uint32_t* encrypted = reinterpret_cast<uint32_t*>(address);
            uint32_t e0 = encrypted[0];
            uint32_t e1 = encrypted[1];

            if (e0 == 0 && e1 == 0)
                continue;

            if (uintptr_t p = enc_test(address, e0, e1, vmval1)) return reinterpret_cast<lua_State*>(p);
            if (uintptr_t p = enc_test(address, e0, e1, vmval2)) return reinterpret_cast<lua_State*>(p);
            if (uintptr_t p = enc_test(address, e0, e1, vmval3)) return reinterpret_cast<lua_State*>(p);
            if (uintptr_t p = enc_test(address, e0, e1, vmval4)) return reinterpret_cast<lua_State*>(p);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            continue;
        }
    }

    return nullptr;
}

lua_State* task_scheduler::GetLuaState(uintptr_t ScriptContext, uintptr_t Identity, uintptr_t Script)
{
    return Roblox::GetLuaStateForInstance(ScriptContext, &Identity, &Script);
}

static uint32_t GetGameLoaded(uintptr_t Datamodel)
{
    if (!Datamodel)
        return 0;
    __try
    {
        return *reinterpret_cast<uint32_t*>(Datamodel + Offsets::DataModel::GameLoaded);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }
}

int ScriptsHandler(lua_State* L)
{
    lua_State* BoundExecutorThread = static_cast<lua_State*>(
        lua_touserdata(L, lua_upvalueindex(1)));
    if (!BoundExecutorThread || BoundExecutorThread != Shared::ExploitThread)
        return 0;

    // Same one-per-tick rule as ExecuteGameImpl: never compile several
    // hub-sized scripts inside a single job step.
    {
        std::string Script;
        {
            std::lock_guard<std::mutex> lock(Shared::ExecutionRequestsMutex);
            if (Shared::ExecutionRequests.empty())
                goto drain_done;
            Script = std::move(Shared::ExecutionRequests.front());
            Shared::ExecutionRequests.erase(Shared::ExecutionRequests.begin());
        }

        if (!Script.empty())
            Execution::ExecuteScript(BoundExecutorThread, std::move(Script));
    }
drain_done:

    Raknet::ProcessCallbacks(BoundExecutorThread);

    Yielding::RunYield();

    return 0;
}

void Reset()
{
    Shared::ExploitThread = nullptr;
    Shared::RobloxState = nullptr;
    Shared::ExecutorThreads.clear();
    Shared::StateGeneration.fetch_add(1);
    OutputDebugStringA("[sodium] Successfully injected!\n");
}

// Queued separately because InitializeGameImpl uses SEH __try, which
// forbids locals/temporaries with destructors (C2712) in the same body.
static void QueueInjectNotice()
{
    task_scheduler::RequestExecution(InjectNotice::BuildScript());
}

static bool InitializeGameImpl()
{
    if (Shared::IsInitializedOnGame)
        return true;

    uintptr_t ScriptContext =
        task_scheduler::GetScriptContext(Shared::LastDataModel);

    if (!ScriptContext)
        return false;
    lua_State* MainThread = nullptr;
    __try { MainThread = GetLuaStateForInstance(ScriptContext); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }

    if (!MainThread)
        return false;

    Shared::RobloxState = MainThread;

    Shared::RobloxState = reinterpret_cast<lua_State*>(MainThread);
    if (!Shared::RobloxState)
        return false;

    Shared::ExploitThread = lua_newthread(Shared::RobloxState);
    if (!Shared::ExploitThread)
        return false;

    Shared::ExecutorThreads.insert(Shared::ExploitThread);

    luaL_sandboxthread(Shared::ExploitThread);
    Environment->initalizeEnvironment(Shared::ExploitThread);

    Shared::IsInitializedOnGame = true;

    // Built-in "connected" toast, queued internally (never crosses the
    // wire, never touches disk). Runs once per successful game init,
    // including after teleports which re-initialize.
    QueueInjectNotice();

    return true;
}

static bool InitializeGame()
{
    __try
    {
        return InitializeGameImpl();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Shared::IsInitializedOnGame = false;
        Shared::RobloxState = nullptr;
        Shared::ExploitThread = nullptr;
        return false;
    }
}

static bool ExecuteGameImpl()
{
    // One script per scheduler tick. Draining the whole queue here blocks
    // WaitingHybridScriptsJob's step (the game thread) for the sum of all
    // compiles — on low-spec CPUs a single MB-sized hub main already takes
    // seconds, and a loader queuing several looks like a permanent freeze.
    // Leftovers run on following ticks; the game stays responsive in between.
    std::string Next;

    {
        std::lock_guard<std::mutex> lock(Shared::ExecutionRequestsMutex);

        if (Shared::ExploitThread && !Shared::ExecutionRequests.empty())
        {
            Next = std::move(Shared::ExecutionRequests.front());
            Shared::ExecutionRequests.erase(Shared::ExecutionRequests.begin());
        }
    }

    if (!Next.empty())
        Execution::ExecuteScript(Shared::ExploitThread, std::move(Next));

    Raknet::ProcessCallbacks(Shared::ExploitThread);
    Yielding::RunYield();
    return true;
}

static bool ExecuteGame()
{
    __try
    {
        return ExecuteGameImpl();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static uintptr_t stepHook(uintptr_t Job, uintptr_t Stats)
{
    if (!Shared::OriginalStepFunction)
        return 0;

    if (Shared::JobStepLocked)
        return Shared::OriginalStepFunction(Job, Stats);

    if (!Shared::IsInitializedOnGame)
    {
        if (!InitializeGame())
            return Shared::OriginalStepFunction(Job, Stats);
    }
    else if (!ExecuteGame())
    {
        return Shared::OriginalStepFunction(Job, Stats);
    }

    return Shared::OriginalStepFunction(Job, Stats);
}

void task_scheduler::TeleportHandler()
{
    Shared::IsInitializedOnGame = false;
    Reset();

    uintptr_t DataModel = task_scheduler::GetDataModel();

    if (GetGameLoaded(DataModel) == 15) {
        while (GetGameLoaded(task_scheduler::GetDataModel()) == 15) {
            Sleep(100);
        }
    }

    if (!Shared::LastDataModel || Shared::LastDataModel != task_scheduler::GetDataModel()) {
        Shared::LastDataModel = task_scheduler::GetDataModel();
    }

    uintptr_t GameWHSJ = 0;
    for (int Attempt = 0; Attempt < 400 && !GameWHSJ; ++Attempt)
    {
        uintptr_t CurrentDataModel = task_scheduler::GetDataModel();
        if (CurrentDataModel && CurrentDataModel != Shared::LastDataModel)
        {
            std::thread(&task_scheduler::TeleportHandler).detach();
            return;
        }

        GameWHSJ = task_scheduler::GetJobByTypeName(("WaitingHybridScriptsJob(Default;Ugc)"));
        if (!GameWHSJ || !CheckMemory(GameWHSJ))
        {
            GameWHSJ = 0;
            Sleep(50);
        }
    }

    if (!GameWHSJ)
        return;

    Shared::LastWaitingHybridScriptsJob = GameWHSJ;

    uintptr_t* JobVTable = *reinterpret_cast<uintptr_t**>(GameWHSJ);
    if (JobVTable != Shared::HybridJobVtable)
    {
        if (!Shared::HybridJobVtable)
            Shared::HybridJobVtable = new uintptr_t[9];

        memcpy(Shared::HybridJobVtable, JobVTable, sizeof(uintptr_t) * 9);

        Shared::OriginalStepFunction = reinterpret_cast<Shared::JobStep_t>(JobVTable[8]);
        Shared::HybridJobVtable[8] = reinterpret_cast<uintptr_t>(&stepHook);
    }

    Shared::JobStepLocked = false;

    *reinterpret_cast<uintptr_t**>(Shared::LastWaitingHybridScriptsJob) = static_cast<uintptr_t*>(Shared::HybridJobVtable);

    while (true)
    {
        uintptr_t currentDatamodel = task_scheduler::GetDataModel();

        if (currentDatamodel && currentDatamodel != Shared::LastDataModel &&
            GetGameLoaded(currentDatamodel) >= 15)
        {
            std::thread(&task_scheduler::TeleportHandler).detach();
            break;
        }

        Sleep(10);
    }
}

void task_scheduler::RequestExecution(std::string Script)
{
    std::lock_guard<std::mutex> lock(Shared::ExecutionRequestsMutex);
    Shared::ExecutionRequests.push_back(Script);
}

uintptr_t task_scheduler::GetJobByTypeName(const std::string& TypeName)
{
    uintptr_t task_scheduler =
        *reinterpret_cast<uintptr_t*>(
            Offsets::Scheduler::TaskScheduler
            );

    if (!task_scheduler)
        return 0;

    uintptr_t JobsStart =
        *reinterpret_cast<uintptr_t*>(
            task_scheduler + Offsets::Scheduler::JobStart
            );

    uintptr_t JobsEnd =
        *reinterpret_cast<uintptr_t*>(
            task_scheduler +
            Offsets::Scheduler::JobStart +
            sizeof(uintptr_t)
            );

    if (!JobsStart || !JobsEnd || JobsStart >= JobsEnd)
        return 0;

    const size_t nameLen = TypeName.size();
    if (nameLen == 0 || nameLen >= 0x100)
        return 0;

    static constexpr uintptr_t kNameOffsets[] = { 0x18, 0xF8, 0x118 };

    for (uintptr_t Current = JobsStart;
        Current < JobsEnd;
        Current += 0x10)
    {
        uintptr_t Job =
            *reinterpret_cast<uintptr_t*>(Current);

        if (!Job)
            continue;

        for (uintptr_t off : kNameOffsets)
        {
            if (!CheckMemory(Job + off))
                continue;

            const char* candidate = *reinterpret_cast<const char**>(Job + off);
            if (!candidate)
                continue;

            uintptr_t candAddr = (uintptr_t)candidate;
            if (candAddr < 0x10000 || candAddr > 0x7FFFFFFFFFFF)
                continue;

            if (!CheckMemory(candAddr))
                continue;

            if (memcmp(candidate, TypeName.c_str(), nameLen) == 0)
                return Job;
        }
    }

    return 0;
}