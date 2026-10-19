#pragma once
#include <Windows.h>
#include <thread>
#include <atomic>
#include <Utilitys/Utils.hpp>
#include <Utilitys/Globals.hpp>
#include <RBX/task_scheduler/task_scheduler.hpp>
#include <Renderer/Renderer.hpp>

namespace TpHandler
{
    inline void Initialize()
    {
        static std::atomic<bool> running{ false };
        if (running.exchange(true))
            return;

        std::thread([]() {
            OutputDebugStringA("[natrium] TeleportHandler: starting\n");
            Renderer::AddConsoleLog(("INFO"), ("natrium"), ("Injected successfully"));

            task_scheduler::TeleportHandler();

        }).detach();
    }
}
