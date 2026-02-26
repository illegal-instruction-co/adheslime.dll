#pragma once
/**
 * bigbro SDK - Shared Internals
 *
 * XorStr, CRC32, SHA-256, retpoline, global state, InternalBan/Log helpers.
 * Included by all src/ modules. NOT a public header.
 */
#include <bigbro/Sdk.h>

#include <vector>
#include <string>
#include <array>
#include <chrono>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <fstream>
#include <filesystem>

#include <windows.h>
#include <bcrypt.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <intrin.h>

using namespace std;

struct duk_hthread;
typedef struct duk_hthread duk_context;

namespace fs = filesystem;

template<size_t N, uint8_t Key = 0x5A>
struct XorStr final {
    char data[N];
    constexpr XorStr(const char* s) : data{} {
        for (size_t i = 0; i < N; ++i)
            data[i] = s[i] ^ (uint8_t)(Key + i * 7);
    }
    string Decrypt() const {
        string s;
        for (size_t i = 0; i < N - 1; ++i)
            s += (char)(data[i] ^ (uint8_t)(Key + i * 7));
        return s;
    }
};
#define X(s) []{ constexpr XorStr<sizeof(s), (uint8_t)(__COUNTER__ * 131 + 47)> res(s); return res.Decrypt(); }()

__forceinline uint32_t CalculateCRC32(const unsigned char* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

using Sha256Digest = array<uint8_t, 32>;

__forceinline bool CalculateSHA256(const uint8_t* data, size_t length, Sha256Digest& out) {
    BCRYPT_ALG_HANDLE  hAlg  = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        return false;
    if (BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0) != 0)
        goto cleanup;
    if (BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(length), 0) != 0)
        goto cleanup;
    if (BCryptFinishHash(hHash, out.data(), 32, 0) != 0)
        goto cleanup;
    ok = true;

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

extern "C" void retpoline_call_rax();
extern "C" void retpoline_dispatch_fn(void* target);

typedef void (*DetectionFunc)();

__forceinline void RetpolineDispatch(DetectionFunc fn) {
    retpoline_dispatch_fn(reinterpret_cast<void*>(fn));
}

extern bigbro::Config g_config;
extern duk_context*      g_duk;
extern atomic<bool>      g_initialized;
extern atomic<bool>      g_banned;
extern shared_mutex      g_mutex;
extern vector<string>    g_ruleScripts;
extern Sha256Digest      g_textBaseline;
extern bool              g_textBaselineSet;
extern Sha256Digest      g_dispatchHash;
extern bool              g_dispatchHashSet;
extern DWORD             g_dispatchProtect;

extern atomic<bool>      g_bgStop;
extern thread            g_bgThread;

extern atomic<uint64_t>  g_heartbeatTick;
extern atomic<DWORD>     g_tickThreadId;
extern bool              g_heartbeatArmed;

extern Sha256Digest      g_iatBaseline;
extern bool              g_iatBaselineSet;

__forceinline void InternalBan(uint32_t code, const char* reason) {
    bigbro::SDK::Get().ReportBan(code, reason);
}
__forceinline void InternalLog(const char* msg) {
    bigbro::SDK::Get().ReportLog(msg);
}
