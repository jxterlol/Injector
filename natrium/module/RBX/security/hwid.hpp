#pragma once

// natrium HWID mirror. MUST STAY IN SYNC WITH Sodium/SodiumCpp/src/Hwid.h
// Same inputs/separator/hash. Used to bind the license JWT to this PC:
// a key issued for HWID_A is rejected on HWID_B even if copied.

#include <windows.h>
#include <bcrypt.h>
#include <intrin.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>

namespace SodiumHwid
{
    inline std::string Narrow(const std::wstring& w)
    {
        if (w.empty()) return {};
        int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
        if (n <= 0) return {};
        std::string s((size_t)n, 0);
        WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), s.data(), n, nullptr, nullptr);
        return s;
    }

    inline std::string ReadMachineGuid()
    {
        HKEY h = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
            return {};
        wchar_t buf[128] = {};
        DWORD cb = sizeof(buf);
        DWORD ty = 0;
        std::string out;
        if (RegQueryValueExW(h, L"MachineGuid", nullptr, &ty, reinterpret_cast<BYTE*>(buf), &cb) == ERROR_SUCCESS)
            out = Narrow(buf);
        RegCloseKey(h);
        return out;
    }

    inline std::string VolumeSerial()
    {
        DWORD serial = 0;
        if (GetVolumeInformationW(L"C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0))
        {
            char b[16];
            snprintf(b, sizeof(b), "%08lX", (unsigned long)serial);
            return b;
        }
        return {};
    }

    inline std::string ComputerName()
    {
        wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD n = (DWORD)(sizeof(buf) / sizeof(buf[0]));
        if (GetComputerNameW(buf, &n)) return Narrow(buf);
        return {};
    }

    inline std::string CpuVendor()
    {
        int regs[4] = {};
        __cpuid(regs, 0);
        char v[13] = {};
        memcpy(v + 0, &regs[1], 4);
        memcpy(v + 4, &regs[3], 4);
        memcpy(v + 8, &regs[2], 4);
        v[12] = 0;
        return v;
    }

    inline bool Sha256(const void* data, size_t len, uint8_t out[32])
    {
        BCRYPT_ALG_HANDLE h = nullptr;
        BCRYPT_HASH_HANDLE hh = nullptr;
        bool ok = false;
        if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) != 0)
            return false;
        if (BCryptCreateHash(h, &hh, nullptr, 0, nullptr, 0, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(h, 0);
            return false;
        }
        if (len && BCryptHashData(hh, (PUCHAR)data, (ULONG)len, 0) != 0) goto done;
        ok = (BCryptFinishHash(hh, out, 32, 0) == 0);
    done:
        if (hh) BCryptDestroyHash(hh);
        if (h) BCryptCloseAlgorithmProvider(h, 0);
        return ok;
    }

    inline std::string Get()
    {
        std::string g = ReadMachineGuid();
        std::string v = VolumeSerial();
        std::string c = ComputerName();
        std::string u = CpuVendor();
        if (g.empty() && v.empty()) return {};
        std::string joined = g + "|" + v + "|" + c + "|" + u;
        uint8_t h[32] = {};
        if (!Sha256(joined.data(), joined.size(), h)) return {};
        static const char* hex = "0123456789abcdef";
        std::string out;
        out.reserve(64);
        for (int i = 0; i < 32; ++i)
        {
            out.push_back(hex[(h[i] >> 4) & 15]);
            out.push_back(hex[h[i] & 15]);
        }
        SecureZeroMemory(h, sizeof(h));
        return out;
    }
} // namespace SodiumHwid
