#pragma once

// Sodium secure UI <-> module channel (MODULE side).
//
// Server mirror of the handshake in SodiumCpp/src/SecureChannel.h:
//
//   1. Hello      UI -> DLL : magic(4) | ver u16 BE | clientNonce(16) | tag(32)
//   2. Challenge DLL -> UI  : serverNonce(16) | tag2(32)
//   3. Exec frame UI -> DLL : totalLen u32 BE | iv(12) | ciphertext | tag(16)
//      (AES-256-GCM, AAD binds magic|ver|both nonces; zero totalLen = probe)
//
// Anything that fails magic/version/HMAC/GCM checks is dropped silently
// (plus tarpit in TcpServer) so a foreign UI or a replayed capture can
// never queue scripts.
//
// PROTOCOL CONSTANTS MUST STAY IN SYNC WITH
//   Sodium/SodiumCpp/src/SecureChannel.h
// (same magic/version/labels/sizes/derivation, mirrored roles).

#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace SodiumChannel
{
    inline constexpr uint8_t kMagic[4] = { 'S', 'N', 'E', '2' };
    inline constexpr uint16_t kVersion = 0x0002;
    inline constexpr size_t kNonceLen = 16;
    inline constexpr size_t kTagLen = 32;
    inline constexpr size_t kGcmTagLen = 16;
    inline constexpr size_t kIvLen = 12;
    inline constexpr size_t kKeyLen = 32;
    inline constexpr size_t kHelloLen = 4 + 2 + 16 + 32;
    inline constexpr size_t kChallengeLen = 16 + 32;
    inline constexpr size_t kMaxScript = 8 * 1024 * 1024;

    inline constexpr const char kHelloLabel[] = "SODIUM-HELLO-v1";
    inline constexpr const char kChallengeLabel[] = "SODIUM-CHALLENGE-v1";
    inline constexpr const char kHkdfInfo[] = "sodium-exec-v2";

    // Same obfuscated master as the UI. stored[i] = rol3(secret[i]) ^ (0x5A + i*0x23).
    inline const uint8_t kObfMaster[kKeyLen] = {
        0x92, 0x1D, 0x46, 0x13, 0xE4, 0x09, 0x09, 0xDD,
        0x91, 0x57, 0x91, 0x76, 0xEA, 0x87, 0xB3, 0x08,
        0x9A, 0x27, 0x86, 0xD4, 0x7E, 0x7F, 0x65, 0x8B,
        0x8B, 0x2F, 0xC4, 0x81, 0x0A, 0x64, 0x87, 0x4D
    };

    inline void MasterSecret(uint8_t out[kKeyLen])
    {
        volatile uint8_t acc = 0;
        for (size_t i = 0; i < kKeyLen; ++i)
        {
            const uint8_t k = static_cast<uint8_t>((0x5A + i * 0x23) & 0xFF);
            const uint8_t v = static_cast<uint8_t>(kObfMaster[i] ^ k);
            const uint8_t s = static_cast<uint8_t>(((v >> 3) | (v << 5)) & 0xFF);
            out[i] = s;
            acc = static_cast<uint8_t>(acc + s);
        }
        (void)acc;
    }

    inline void SecureZero(void* p, size_t n)
    {
        SecureZeroMemory(p, n);
    }

    inline bool ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t n)
    {
        uint8_t d = 0;
        for (size_t i = 0; i < n; ++i)
            d |= static_cast<uint8_t>(a[i] ^ b[i]);
        return d == 0;
    }

    inline bool HmacSha256(const uint8_t* key, size_t keyLen,
                           const uint8_t* p1, size_t l1,
                           const uint8_t* p2, size_t l2,
                           uint8_t out[kTagLen])
    {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool ok = false;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                MS_PRIMITIVE_PROVIDER, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            return false;
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0,
                const_cast<PUCHAR>(key), static_cast<ULONG>(keyLen), 0) != 0)
        {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }
        if (l1 && BCryptHashData(hHash, const_cast<PUCHAR>(p1), static_cast<ULONG>(l1), 0) != 0)
            goto done;
        if (l2 && BCryptHashData(hHash, const_cast<PUCHAR>(p2), static_cast<ULONG>(l2), 0) != 0)
            goto done;
        ok = (BCryptFinishHash(hHash, out, kTagLen, 0) == 0);
    done:
        if (hHash) BCryptDestroyHash(hHash);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        return ok;
    }

    inline bool HkdfSha256(const uint8_t master[kKeyLen],
                           const uint8_t* salt, size_t saltLen,
                           const char* info, uint8_t out[kKeyLen])
    {
        uint8_t prk[kTagLen];
        const size_t infoLen = strlen(info);
        uint8_t expandIn[128];
        if (infoLen + 1 > sizeof(expandIn))
            return false;
        memcpy(expandIn, info, infoLen);
        expandIn[infoLen] = 0x01;
        bool ok = false;
        if (!HmacSha256(salt, saltLen, master, kKeyLen, nullptr, 0, prk))
            return false;
        ok = HmacSha256(prk, sizeof(prk), expandIn, infoLen + 1, nullptr, 0, out);
        SecureZero(prk, sizeof(prk));
        SecureZero(expandIn, sizeof(expandIn));
        return ok;
    }

    inline bool RandomBytes(uint8_t* out, size_t len)
    {
        return BCryptGenRandom(nullptr, out, static_cast<ULONG>(len),
                   BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
    }

    struct AesGcm
    {
        static bool Open(BCRYPT_ALG_HANDLE& hAlg)
        {
            if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM,
                    MS_PRIMITIVE_PROVIDER, 0) != 0)
                return false;
            if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                    (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0)
            {
                BCryptCloseAlgorithmProvider(hAlg, 0);
                hAlg = nullptr;
                return false;
            }
            return true;
        }

        static bool Decrypt(const uint8_t key[kKeyLen],
                            const uint8_t iv[kIvLen],
                            const uint8_t* aad, size_t aadLen,
                            const uint8_t* cipher, size_t cipherLen,
                            uint8_t* plain, const uint8_t gcmTag[kGcmTagLen])
        {
            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCRYPT_KEY_HANDLE hKey = nullptr;
            bool ok = false;
            DWORD cbKeyObj = 0, cbDone = 0;
            ULONG ulen = 0;
            if (!Open(hAlg))
                return false;
            if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                    (PUCHAR)&cbKeyObj, sizeof(cbKeyObj), &cbDone, 0) != 0)
                goto done;
            {
                std::vector<uint8_t> keyObj(cbKeyObj);
                if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), cbKeyObj,
                        const_cast<PUCHAR>(key), kKeyLen, 0) != 0)
                    goto done;
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
                BCRYPT_INIT_AUTH_MODE_INFO(info);
                info.pbNonce = const_cast<PUCHAR>(iv);
                info.cbNonce = static_cast<ULONG>(kIvLen);
                info.pbAuthData = const_cast<PUCHAR>(aad);
                info.cbAuthData = aad ? static_cast<ULONG>(aadLen) : 0;
                info.pbTag = const_cast<PUCHAR>(gcmTag);
                info.cbTag = static_cast<ULONG>(kGcmTagLen);
                ok = (BCryptDecrypt(hKey, const_cast<PUCHAR>(cipher),
                        static_cast<ULONG>(cipherLen), &info, nullptr, 0,
                        plain, static_cast<ULONG>(cipherLen), &ulen, 0) == 0
                      && ulen == cipherLen);
                SecureZero(keyObj.data(), keyObj.size());
            }
        done:
            if (hKey) BCryptDestroyKey(hKey);
            if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
            return ok;
        }
    };

    inline bool SendExact(SOCKET s, const uint8_t* data, size_t len, int timeoutMs)
    {
        size_t sent = 0;
        while (sent < len)
        {
            fd_set wf;
            FD_ZERO(&wf);
            FD_SET(s, &wf);
            timeval tv{ timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
            int r = select(0, nullptr, &wf, nullptr, &tv);
            if (r <= 0 || !FD_ISSET(s, &wf))
                return false;
            int n = send(s, reinterpret_cast<const char*>(data + sent),
                         static_cast<int>(len - sent), 0);
            if (n <= 0)
                return false;
            sent += static_cast<size_t>(n);
        }
        return true;
    }

    inline bool RecvExact(SOCKET s, uint8_t* data, size_t len, int timeoutMs)
    {
        size_t got = 0;
        while (got < len)
        {
            fd_set rf;
            FD_ZERO(&rf);
            FD_SET(s, &rf);
            timeval tv{ timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
            int r = select(0, &rf, nullptr, nullptr, &tv);
            if (r <= 0 || !FD_ISSET(s, &rf))
                return false;
            int n = recv(s, reinterpret_cast<char*>(data + got),
                         static_cast<int>(len - got), 0);
            if (n <= 0)
                return false;
            got += static_cast<size_t>(n);
        }
        return true;
    }

    // Server side of the handshake. Reads + verifies hello, replies with
    // the challenge, derives the session key. False = drop the client.
    inline bool ServerHandshake(SOCKET s, uint8_t sessionKey[kKeyLen],
                                uint8_t clientNonce[kNonceLen],
                                uint8_t serverNonce[kNonceLen],
                                int timeoutMs)
    {
        uint8_t master[kKeyLen];
        MasterSecret(master);

        uint8_t hello[kHelloLen];
        if (!RecvExact(s, hello, sizeof(hello), timeoutMs))
        {
            SecureZero(master, sizeof(master));
            return false;
        }
        if (memcmp(hello, kMagic, 4) != 0 ||
            hello[4] != static_cast<uint8_t>((kVersion >> 8) & 0xFF) ||
            hello[5] != static_cast<uint8_t>(kVersion & 0xFF))
        {
            SecureZero(master, sizeof(master));
            SecureZero(hello, sizeof(hello));
            return false;
        }
        memcpy(clientNonce, hello + 6, kNonceLen);

        uint8_t body[4 + 2 + kNonceLen];
        memcpy(body, kMagic, 4);
        body[4] = hello[4];
        body[5] = hello[5];
        memcpy(body + 6, clientNonce, kNonceLen);
        uint8_t expect[kTagLen];
        bool ok = HmacSha256(master, kKeyLen,
                             reinterpret_cast<const uint8_t*>(kHelloLabel),
                             sizeof(kHelloLabel) - 1, body, sizeof(body), expect);
        SecureZero(body, sizeof(body));
        if (!ok)
        {
            SecureZero(master, sizeof(master));
            SecureZero(hello, sizeof(hello));
            return false;
        }
        ok = ConstantTimeEqual(expect, hello + 6 + kNonceLen, kTagLen);
        SecureZero(expect, sizeof(expect));
        SecureZero(hello, sizeof(hello));
        if (!ok)
        {
            SecureZero(master, sizeof(master));
            return false;
        }

        if (!RandomBytes(serverNonce, kNonceLen))
        {
            SecureZero(master, sizeof(master));
            return false;
        }

        uint8_t challenge[kChallengeLen];
        memcpy(challenge, serverNonce, kNonceLen);
        {
            uint8_t chalBody[kNonceLen + kNonceLen];
            memcpy(chalBody, serverNonce, kNonceLen);
            memcpy(chalBody + kNonceLen, clientNonce, kNonceLen);
            if (!HmacSha256(master, kKeyLen,
                            reinterpret_cast<const uint8_t*>(kChallengeLabel),
                            sizeof(kChallengeLabel) - 1,
                            chalBody, sizeof(chalBody),
                            challenge + kNonceLen))
            {
                SecureZero(master, sizeof(master));
                SecureZero(chalBody, sizeof(chalBody));
                SecureZero(challenge, sizeof(challenge));
                return false;
            }
            SecureZero(chalBody, sizeof(chalBody));
        }
        if (!SendExact(s, challenge, sizeof(challenge), timeoutMs))
        {
            SecureZero(master, sizeof(master));
            SecureZero(challenge, sizeof(challenge));
            return false;
        }
        SecureZero(challenge, sizeof(challenge));

        uint8_t salt[kNonceLen + kNonceLen];
        memcpy(salt, clientNonce, kNonceLen);
        memcpy(salt + kNonceLen, serverNonce, kNonceLen);
        ok = HkdfSha256(master, salt, sizeof(salt), kHkdfInfo, sessionKey);
        SecureZero(salt, sizeof(salt));
        SecureZero(master, sizeof(master));
        return ok;
    }

    // Reads one post-handshake frame. Returns 1 + script on success,
    // 0 on clean probe (zero length), -1 on any violation.
    inline int ReadExecFrame(SOCKET s,
                             const uint8_t sessionKey[kKeyLen],
                             const uint8_t clientNonce[kNonceLen],
                             const uint8_t serverNonce[kNonceLen],
                             std::string& luaOut, int timeoutMs)
    {
        uint8_t lenBytes[4];
        if (!RecvExact(s, lenBytes, sizeof(lenBytes), timeoutMs))
            return -1;
        const uint32_t bodyLen =
            (static_cast<uint32_t>(lenBytes[0]) << 24) |
            (static_cast<uint32_t>(lenBytes[1]) << 16) |
            (static_cast<uint32_t>(lenBytes[2]) << 8) |
            static_cast<uint32_t>(lenBytes[3]);
        if (bodyLen == 0)
            return 0; // probe: handshake only
        if (bodyLen < kIvLen + kGcmTagLen + 1 ||
            bodyLen > kIvLen + kMaxScript + kGcmTagLen)
            return -1;

        std::vector<uint8_t> body(bodyLen);
        if (!RecvExact(s, body.data(), bodyLen, timeoutMs))
            return -1;

        const uint8_t* iv = body.data();
        const size_t cipherLen = static_cast<size_t>(bodyLen) - kIvLen - kGcmTagLen;
        const uint8_t* cipher = body.data() + kIvLen;
        const uint8_t* tag = body.data() + kIvLen + cipherLen;

        // IV must be the handshake-bound one (anti-replay across conns).
        uint8_t expectIv[kIvLen];
        memcpy(expectIv, clientNonce, 6);
        memcpy(expectIv + 6, serverNonce, 6);
        if (!ConstantTimeEqual(iv, expectIv, kIvLen))
            return -1;

        uint8_t aad[4 + 2 + kNonceLen + kNonceLen];
        memcpy(aad, kMagic, 4);
        aad[4] = static_cast<uint8_t>((kVersion >> 8) & 0xFF);
        aad[5] = static_cast<uint8_t>(kVersion & 0xFF);
        memcpy(aad + 6, clientNonce, kNonceLen);
        memcpy(aad + 6 + kNonceLen, serverNonce, kNonceLen);

        std::string plain;
        plain.resize(cipherLen);
        const bool ok = AesGcm::Decrypt(sessionKey, iv, aad, sizeof(aad),
                                        cipher, cipherLen,
                                        reinterpret_cast<uint8_t*>(&plain[0]), tag);
        SecureZero(aad, sizeof(aad));
        if (!ok)
            return -1;
        if (plain.empty() || plain.size() > kMaxScript)
            return -1;
        luaOut = std::move(plain);
        return 1;
    }
} // namespace SodiumChannel
