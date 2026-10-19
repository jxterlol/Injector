#pragma once

// natrium license enforcement (MODULE side).
// Mirrors Sodium/SodiumCpp/src/KeyToken.h: same P-256 pubkey, same JWT checks.
// Wire: UI encrypts [u16BE(jwtLen) | jwt | lua] with the existing session key
// (see SecureChannel). DLL decrypts, splits, verifies JWT (sig + HWID + exp)
// and only then queues the Lua. Anything else is dropped + tarpitted.
//
// PROTOCOL NOTE: jwtLen==0 (old UI / foreign UI) is REJECTED. This is the
// second gate: patching Sodium.exe alone is not enough, natrium must also
// be patched (VMP + integrity tripwires raise that cost).

#include <windows.h>
#include <bcrypt.h>

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include <RBX/security/hwid.hpp>

namespace SodiumLicense
{
    // REPLACE with `node KeyServer/jwk.mjs` output. Must match KeyToken.h.
    // All-zero FAILS CLOSED.
    inline constexpr uint8_t kPubQx[32] = {
        0x32, 0xa2, 0xb3, 0x7d, 0xaa, 0xfe, 0xf1, 0x23, 0xaf, 0xae, 0x88, 0xd3, 0x55, 0x20, 0xb5, 0x5b,
        0xea, 0x04, 0x0f, 0xaa, 0xe9, 0xed, 0xfd, 0x2a, 0xff, 0x1e, 0x70, 0x90, 0xdd, 0x12, 0xea, 0x93
    };
    inline constexpr uint8_t kPubQy[32] = {
        0xd9, 0x32, 0x00, 0x55, 0x96, 0x1d, 0x0e, 0x8c, 0x55, 0x93, 0xac, 0x6d, 0xdb, 0xeb, 0x7a, 0x7e,
        0xc0, 0xa8, 0x4e, 0x41, 0x30, 0x2f, 0xf8, 0xe3, 0x8e, 0xa7, 0xc9, 0x5e, 0x38, 0xb5, 0x51, 0x8a
    };

    inline bool IsConfigured()
    {
        for (int i = 0; i < 32; ++i)
            if (kPubQx[i] || kPubQy[i]) return true;
        return false;
    }

    inline int B64Val(char c)
    {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+' || c == '-') return 62;
        if (c == '/' || c == '_') return 63;
        return -1;
    }

    inline bool B64UrlDecode(const std::string& in, std::vector<uint8_t>& out)
    {
        out.clear();
        int acc = 0, bits = 0;
        for (char c : in)
        {
            if (c == '=') break;
            int v = B64Val(c);
            if (v < 0) return false;
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                out.push_back((uint8_t)((acc >> bits) & 0xFF));
            }
        }
        return true;
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

    inline bool ExtractJsonString(const std::string& json, const char* key, std::string& out)
    {
        std::string pat = std::string("\"") + key + "\"";
        size_t p = json.find(pat);
        if (p == std::string::npos) return false;
        p = json.find(':', p + pat.size());
        if (p == std::string::npos) return false;
        p = json.find('"', p + 1);
        if (p == std::string::npos) return false;
        size_t e = json.find('"', p + 1);
        if (e == std::string::npos) return false;
        out = json.substr(p + 1, e - p - 1);
        return true;
    }

    inline bool ExtractJsonInt(const std::string& json, const char* key, long long& out)
    {
        std::string pat = std::string("\"") + key + "\"";
        size_t p = json.find(pat);
        if (p == std::string::npos) return false;
        p = json.find(':', p + pat.size());
        if (p == std::string::npos) return false;
        size_t s = json.find_first_of("-0123456789", p + 1);
        if (s == std::string::npos) return false;
        size_t e = json.find_first_not_of("0123456789", s + (json[s] == '-' ? 1 : 0));
        try { out = std::stoll(json.substr(s, e == std::string::npos ? e : e - s)); }
        catch (...) { return false; }
        return true;
    }

    inline bool CtEqualLower(const std::string& a, const std::string& b)
    {
        if (a.size() != b.size()) return false;
        unsigned d = 0;
        for (size_t i = 0; i < a.size(); ++i)
            d |= (unsigned)(tolower((unsigned char)a[i]) ^ tolower((unsigned char)b[i]));
        return d == 0;
    }

#pragma pack(push, 1)
    struct EccPubBlob
    {
        BCRYPT_ECCKEY_BLOB hdr;
        uint8_t qx[32];
        uint8_t qy[32];
    };
#pragma pack(pop)

    // Full offline check: sig + HWID(this PC) + expiry. False = drop + tarpit.
    inline bool VerifyLocal(const std::string& jwt, long long& expOut)
    {
        expOut = 0;
        if (!IsConfigured() || jwt.empty()) return false;
        std::string hwid = SodiumHwid::Get();
        if (hwid.size() != 64) return false;
        size_t d1 = jwt.find('.');
        size_t d2 = d1 == std::string::npos ? std::string::npos : jwt.find('.', d1 + 1);
        if (d1 == std::string::npos || d2 == std::string::npos) return false;
        std::string hB64 = jwt.substr(0, d1);
        std::string pB64 = jwt.substr(d1 + 1, d2 - d1 - 1);
        std::string sB64 = jwt.substr(d2 + 1);
        std::vector<uint8_t> sig;
        if (!B64UrlDecode(sB64, sig) || sig.size() != 64) return false;
        std::vector<uint8_t> payload;
        if (!B64UrlDecode(pB64, payload)) return false;
        std::string signing = hB64 + "." + pB64;
        uint8_t digest[32] = {};
        if (!Sha256(signing.data(), signing.size(), digest)) return false;

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        bool ok = false;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0) != 0)
            return false;
        EccPubBlob blob{};
        blob.hdr.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        blob.hdr.cbKey = 32;
        memcpy(blob.qx, kPubQx, 32);
        memcpy(blob.qy, kPubQy, 32);
        if (BCryptImportKeyPair(hAlg, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                &hKey, (PUCHAR)&blob, sizeof(blob), 0) != 0)
            goto done;
        if (BCryptVerifySignature(hKey, nullptr, digest, sizeof(digest),
                sig.data(), (ULONG)sig.size(), 0) != 0)
            goto done;
        {
            std::string ps(payload.begin(), payload.end());
            std::string tokHwid;
            long long exp = 0;
            if (!ExtractJsonString(ps, "hwid", tokHwid)) goto done;
            if (!ExtractJsonInt(ps, "exp", exp)) goto done;
            if (!CtEqualLower(tokHwid, hwid)) goto done; // key belongs to another PC
            long long now = (long long)_time64(nullptr);
            if (exp <= now + 60) goto done;
            expOut = exp;
            ok = true;
        }
    done:
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        SecureZeroMemory(digest, sizeof(digest));
        return ok;
    }

    // Split decrypted exec plaintext: u16BE(jwtLen) | jwt | lua.
    // Returns false on any violation (caller tarpits). jwtLen==0 is rejected.
    inline bool SplitLicensedPlaintext(const std::string& plain, std::string& jwtOut, std::string& luaOut)
    {
        jwtOut.clear();
        luaOut.clear();
        if (plain.size() < 2) return false;
        uint16_t jl = (uint16_t)(((uint8_t)plain[0] << 8) | (uint8_t)plain[1]);
        if (jl == 0 || jl > 4096) return false;
        if (plain.size() < (size_t)2 + jl + 1) return false;
        jwtOut.assign(plain.data() + 2, jl);
        luaOut.assign(plain.data() + 2 + jl, plain.size() - 2 - jl);
        if (luaOut.empty() || luaOut.size() > 8 * 1024 * 1024) return false;
        return true;
    }
} // namespace SodiumLicense
