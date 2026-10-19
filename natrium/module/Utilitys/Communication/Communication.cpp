#include <Utilitys/Communication/Communication.hpp>
#include <Utilitys/VMP.hpp>
#include <RBX/task_scheduler/task_scheduler.hpp>
#include <RBX/security/secure_channel.hpp>
#include <RBX/security/key_token.hpp>
#include <Utilitys/Globals.hpp>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <chrono>
#include <cstdint>

namespace Antitamper
{
    // Light debugger tripwire. Fail-closed: when a debugger is present we
    // silently refuse execution instead of crashing (never punish the game).
    inline bool DebuggerAttached()
    {
        if (IsDebuggerPresent())
            return true;
        BOOL remote = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote)
            return true;
        if (HMODULE ntdll = GetModuleHandleW(L"ntdll.dll"))
        {
            using NtQueryInfoProc_t = LONG(NTAPI*)(HANDLE, INT, PVOID, ULONG, PULONG);
            auto fn = reinterpret_cast<NtQueryInfoProc_t>(
                GetProcAddress(ntdll, "NtQueryInformationProcess"));
            if (fn)
            {
                HANDLE debugPort = nullptr;
                ULONG retLen = 0;
                if (fn(GetCurrentProcess(), 7 /*ProcessDebugPort*/,
                       &debugPort, sizeof(debugPort), &retLen) == 0 && debugPort)
                    return true;
            }
        }
        return false;
    }
}

bool ReadExactSocket(SOCKET Socket, void* Buffer, size_t Size)
{
    size_t Total = 0;
    char* Out = static_cast<char*>(Buffer);
    while (Total < Size)
    {
        int Received = recv(Socket, Out + Total, static_cast<int>(Size - Total), 0);
        if (Received <= 0)
            return false;

        Total += static_cast<size_t>(Received);
    }

    return true;
}

void TcpServer()
{
    SODIUM_VMP_MUTATION("TcpServer");

    WSADATA Wsa;
    if (WSAStartup(MAKEWORD(2, 2), &Wsa) != 0)
        return;

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    addrinfo Hints{};
    addrinfo* Result = nullptr;

    Hints.ai_family = AF_INET;
    Hints.ai_socktype = SOCK_STREAM;
    Hints.ai_protocol = IPPROTO_TCP;
    Hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(("127.0.0.1"), ("1212"), &Hints, &Result) != 0)
    {
        WSACleanup();
        return;
    }

    ListenSocket = socket(Result->ai_family, Result->ai_socktype, Result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET)
    {
        freeaddrinfo(Result);
        WSACleanup();
        return;
    }

    // Exclusive bind: no other local process can steal the port out from
    // under us (SO_REUSEADDR on Windows would permit exactly that).
    BOOL Exclusive = TRUE;
    setsockopt(ListenSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               reinterpret_cast<const char*>(&Exclusive), sizeof(Exclusive));
    if (bind(ListenSocket, Result->ai_addr, static_cast<int>(Result->ai_addrlen)) == SOCKET_ERROR)
    {
        closesocket(ListenSocket);
        freeaddrinfo(Result);
        WSACleanup();
        return;
    }

    freeaddrinfo(Result);
    if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        closesocket(ListenSocket);
        WSACleanup();
        return;
    }

    SODIUM_VMP_END();

    // Consecutive auth failures -> tarpit (slows brute-force / fuzzing).
    int consecutiveViolations = 0;

    while (true)
    {
        ClientSocket = accept(ListenSocket, nullptr, nullptr);
        if (ClientSocket == INVALID_SOCKET)
        {
            Sleep(100);
            continue;
        }

        // Defense in depth alongside the select-based timeouts below.
        DWORD ioTimeout = 5000;
        setsockopt(ClientSocket, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&ioTimeout), sizeof(ioTimeout));
        setsockopt(ClientSocket, SOL_SOCKET, SO_SNDTIMEO,
                   reinterpret_cast<const char*>(&ioTimeout), sizeof(ioTimeout));

        uint8_t sessionKey[SodiumChannel::kKeyLen];
        uint8_t clientNonce[SodiumChannel::kNonceLen];
        uint8_t serverNonce[SodiumChannel::kNonceLen];

        if (!SodiumChannel::ServerHandshake(ClientSocket, sessionKey,
                                            clientNonce, serverNonce, 5000))
        {
            SodiumChannel::SecureZero(sessionKey, sizeof(sessionKey));
            closesocket(ClientSocket);
            consecutiveViolations++;
            Sleep((consecutiveViolations * 400 > 6000) ? 6000 : consecutiveViolations * 400);
            continue;
        }

        std::string licensed;
        const int frame = SodiumChannel::ReadExecFrame(
            ClientSocket, sessionKey, clientNonce, serverNonce, licensed, 5000);
        SodiumChannel::SecureZero(sessionKey, sizeof(sessionKey));
        SodiumChannel::SecureZero(clientNonce, sizeof(clientNonce));
        SodiumChannel::SecureZero(serverNonce, sizeof(serverNonce));

        if (frame == 0)
        {
            // Clean probe (UI health check): handshake only, nothing to run.
            // Probes stay license-free so the UI can detect injection;
            // Execute frames always require a license (checked below).
            consecutiveViolations = 0;
            closesocket(ClientSocket);
            continue;
        }

        if (frame < 0)
        {
            closesocket(ClientSocket);
            consecutiveViolations++;
            Sleep((consecutiveViolations * 400 > 6000) ? 6000 : consecutiveViolations * 400);
            continue;
        }

        // Second gate: HWID-bound 24h JWT inside the encrypted frame.
        // Plaintext layout: u16BE(jwtLen) | jwt | lua. jwtLen==0 (old or
        // foreign UI) is rejected here, not just in Sodium.exe.
        std::string jwt, script;
        long long licenseExp = 0;
        if (!SodiumLicense::SplitLicensedPlaintext(licensed, jwt, script) ||
            !SodiumLicense::VerifyLocal(jwt, licenseExp))
        {
            SodiumChannel::SecureZero(licensed.data(), licensed.size());
            closesocket(ClientSocket);
            consecutiveViolations++;
            Sleep((consecutiveViolations * 400 > 6000) ? 6000 : consecutiveViolations * 400);
            continue;
        }
        SodiumChannel::SecureZero(licensed.data(), licensed.size());

        if (Antitamper::DebuggerAttached())
        {
            // Fail closed: swallow the script, reveal nothing.
            Sleep(750);
            closesocket(ClientSocket);
            continue;
        }

        consecutiveViolations = 0;
        task_scheduler::RequestExecution(script);

        closesocket(ClientSocket);
    }

    closesocket(ListenSocket);
    WSACleanup();
}

void Communication::Initialize()
{
    SODIUM_VMP_MUTATION("Communication::Initialize");
    std::thread(TcpServer).detach();
    SODIUM_VMP_END();
}

namespace ConsoleChannel
{
    static std::mutex g_Mutex;
    static std::condition_variable g_Cv;
    static std::deque<std::string> g_Queue;
    static bool g_Started = false;
    static SOCKET g_Sock = INVALID_SOCKET;

    static void CloseSock()
    {
        if (g_Sock != INVALID_SOCKET)
        {
            closesocket(g_Sock);
            g_Sock = INVALID_SOCKET;
        }
    }

    static bool EnsureConnected()
    {
        SODIUM_VMP_MUTATION("ConsoleChannel::EnsureConnected");

        if (g_Sock != INVALID_SOCKET)
            return true;

        SOCKET S = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (S == INVALID_SOCKET)
            return false;

        sockaddr_in Addr{};
        Addr.sin_family = AF_INET;
        Addr.sin_port = htons(1213);
        Addr.sin_addr.s_addr = inet_addr(("127.0.0.1"));

        if (connect(S, reinterpret_cast<sockaddr*>(&Addr), sizeof(Addr)) == SOCKET_ERROR)
        {
            closesocket(S);
            return false;
        }

        DWORD Timeout = 300;
        setsockopt(S, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&Timeout), sizeof(Timeout));
        BOOL NoDelay = TRUE;
        setsockopt(S, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&NoDelay), sizeof(NoDelay));

        g_Sock = S;
        SODIUM_VMP_END();
        return true;
    }

    static bool SendAll(SOCKET S, const char* Data, size_t Size)
    {
        size_t Total = 0;
        while (Total < Size)
        {
            int Sent = send(S, Data + Total, static_cast<int>(Size - Total), 0);
            if (Sent <= 0)
                return false;
            Total += static_cast<size_t>(Sent);
        }
        return true;
    }

    static void Worker()
    {
        WSADATA Wsa;
        WSAStartup(MAKEWORD(2, 2), &Wsa);

        std::vector<std::string> Batch;
        while (true)
        {
            {
                std::unique_lock<std::mutex> Lock(g_Mutex);
                g_Cv.wait_for(Lock, std::chrono::milliseconds(300),
                    [] { return !g_Queue.empty(); });
                if (g_Queue.empty())
                    continue;
                Batch.assign(std::make_move_iterator(g_Queue.begin()),
                    std::make_move_iterator(g_Queue.end()));
                g_Queue.clear();
            }

            bool Connected = true;
            for (const std::string& Frame : Batch)
            {
                if (!EnsureConnected())
                {
                    Connected = false;
                    break;
                }
                if (!SendAll(g_Sock, Frame.data(), Frame.size()))
                {
                    CloseSock();
                    if (EnsureConnected())
                    {
                        if (!SendAll(g_Sock, Frame.data(), Frame.size()))
                        {
                            CloseSock();
                            Connected = false;
                            break;
                        }
                    }
                    else
                    {
                        Connected = false;
                        break;
                    }
                }
            }
            Batch.clear();

            if (!Connected)
                Sleep(400);
        }
    }

    void Enqueue(char Level, const char* Data, size_t Size)
    {
        if (!Data || Size == 0)
            return;
        if (Size > (400 * 1024))
            Size = 400 * 1024;

        {
            std::lock_guard<std::mutex> Lock(g_Mutex);
            if (!g_Started)
            {
                g_Started = true;
                std::thread(Worker).detach();
            }
        }

        const uint32_t PayloadLen = static_cast<uint32_t>(Size) + 1;
        std::string Frame;
        Frame.reserve(4 + PayloadLen);
        Frame.push_back(static_cast<char>((PayloadLen >> 24) & 0xFF));
        Frame.push_back(static_cast<char>((PayloadLen >> 16) & 0xFF));
        Frame.push_back(static_cast<char>((PayloadLen >> 8) & 0xFF));
        Frame.push_back(static_cast<char>(PayloadLen & 0xFF));
        Frame.push_back(Level);
        Frame.append(Data, Size);

        {
            std::lock_guard<std::mutex> Lock(g_Mutex);
            if (g_Queue.size() >= 512)
                g_Queue.pop_front();
            g_Queue.push_back(std::move(Frame));
        }
        g_Cv.notify_one();
    }
}