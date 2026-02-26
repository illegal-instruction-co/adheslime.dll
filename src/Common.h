#pragma once
/**
 * adheslime SDK — Shared Internals
 *
 * XorStr, CRC32, global state, InternalBan/Log helpers.
 * Included by all src/ modules. NOT a public header.
 */
#include <adheslime/Sdk.h>

#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <fstream>
#include <filesystem>

#include <windows.h>
#include <bcrypt.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <intrin.h>

using namespace std;

// Forward declaration — full definition in engine/duktape.h
struct duk_hthread;
typedef struct duk_hthread duk_context;

namespace fs = filesystem;

// ============================================================
// COMPILE-TIME STRING OBFUSCATION
// ============================================================
template<size_t N>
struct XorStr final {
    char data[N];
    constexpr XorStr(const char* s) : data{} {
        for (size_t i = 0; i < N; ++i) data[i] = s[i] ^ 0x5A;
    }
    string Decrypt() const {
        string s;
        for (size_t i = 0; i < N - 1; ++i) s += (data[i] ^ 0x5A);
        return s;
    }
};
#define X(s) []{ constexpr XorStr<(sizeof(s))> res(s); return res.Decrypt(); }()

// ============================================================
// CRC32
// ============================================================
inline uint32_t CalculateCRC32(const unsigned char* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

// ============================================================
// RETPOLINE (defined in retpoline.asm)
// ============================================================
extern "C" void retpoline_call_rax();

typedef void (*DetectionFunc)();
__declspec(noinline) inline void RetpolineDispatch(DetectionFunc fn) {
    fn();
}

// ============================================================
// GLOBAL STATE (shared across modules)
// ============================================================
extern adheslime::Config g_config;
extern duk_context*      g_duk;
extern atomic<bool>      g_initialized;
extern atomic<bool>      g_banned;
extern mutex             g_mutex;
extern vector<string>    g_ruleScripts;
extern uint32_t          g_textBaseline;
extern DWORD             g_dispatchProtect;

// ============================================================
// INTERNAL HELPERS
// ============================================================
inline void InternalBan(uint32_t code, const char* reason) {
    adheslime::SDK::Get().ReportBan(code, reason);
}
inline void InternalLog(const char* msg) {
    adheslime::SDK::Get().ReportLog(msg);
}
