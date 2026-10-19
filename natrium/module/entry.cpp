#include <Utilitys/Utils.hpp>
#include <Utilitys/Globals.hpp>
#include <Utilitys/VMP.hpp>
#include <Utilitys/Communication/Communication.hpp>
#include <RBX/task_scheduler/task_scheduler.hpp>
#include <Utilitys/TPHandler.hpp>
#include <RBX/environment/libs/raknet/raknet.hpp>

#include <filesystem>
#include <thread>
#include <windows.h>
#include <shlobj.h>

void raknetwatcher()
{
    uintptr_t RakNet = task_scheduler::GetJobByTypeName("Net Peer Send");

    if (!RakNet)
    {
        while (true)
        {
            uintptr_t RakNet = task_scheduler::GetJobByTypeName("Net Peer Send");
            if (RakNet)
            {
                break;
            }
        }
    }
    Raknet::InitializeHook(RakNet);
    while (true)
    {
        uintptr_t RakNet = task_scheduler::GetJobByTypeName("Net Peer Send");
        if (!RakNet)
        {
            std::thread(&raknetwatcher).detach();
            break;
        }
    }
}

void MainThread(HMODULE hModule)
{
    SODIUM_VMP_MUTATION("MainThread");

    // Canonical store: %LOCALAPPDATA%\Sodium\{workspace,autoexec} (created by
    // Sodium.exe on launch, see Sodium/SodiumCpp/src/AppPaths.h). The DLL dir
    // is only a fallback so dev/load-from-anywhere builds still work.
    bool fromAppData = false;
    {
        PWSTR raw = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &raw)) && raw)
        {
            std::filesystem::path root(raw);
            CoTaskMemFree(raw);
            root /= L"Sodium";
            Shared::workspace_folder = root / L"workspace";
            Shared::autoexecute_folder = root / L"autoexec";
            fromAppData = true;
        }
    }
    if (!fromAppData)
    {
        char modulePath[MAX_PATH] = {};
        if (GetModuleFileNameA(hModule, modulePath, MAX_PATH) && modulePath[0] != '\0')
        {
            const auto moduleDir = std::filesystem::path(modulePath).parent_path();
            Shared::workspace_folder = moduleDir / ("workspace");
            Shared::autoexecute_folder = moduleDir / ("autoexec");
        }
        else
        {
            Shared::workspace_folder = std::filesystem::path(("workspace"));
            Shared::autoexecute_folder = std::filesystem::path(("autoexec"));
        }
    }

    {
        std::error_code ec;
        if (!std::filesystem::exists(Shared::workspace_folder, ec))
            std::filesystem::create_directories(Shared::workspace_folder, ec);
        if (!std::filesystem::exists(Shared::autoexecute_folder, ec))
            std::filesystem::create_directories(Shared::autoexecute_folder, ec);
    }

    Communication::Initialize();

    TpHandler::Initialize();

    std::thread(raknetwatcher).detach();

    SODIUM_VMP_END();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        std::thread(MainThread, hModule).detach();
    }

    return TRUE;
}