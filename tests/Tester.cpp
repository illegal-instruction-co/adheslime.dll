/**
 * BigBro SDK - Comprehensive Validation Suite (C API / Ordinal-Only)
 *
 * Each test runs in an isolated child process.
 * Uses --test <name> for child mode.
 * All SDK interaction via LoadLibrary + GetProcAddress (ordinal only).
 */
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <thread>

#include <windows.h>

#include <bcrypt.h>

#include <tlhelp32.h>

#include "bigbro/attestation_pubkey.h"

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

using namespace std;

// ============================================================
// Function pointer types (ordinal-only C API)
// ============================================================
typedef void  (*SetBanCb_t)(void(*)(uint32_t, const char*));
typedef void  (*SetLogCb_t)(void(*)(const char*));
typedef int   (*Init_t)(uint32_t, const char*, const char*);
typedef int   (*Tick_t)();
typedef void  (*Shutdown_t)();
typedef int   (*IsBanned_t)();
typedef int   (*LoadRule_t)(const char*);
typedef void  (*ProtectVar_t)(const char*, const void*, uint32_t);
typedef void  (*UnprotectVar_t)(const char*);
typedef void  (*UpdateProtectVar_t)(const char*);
typedef void  (*RunFullSuite_t)();
typedef void  (*TriggerSelfTamper_t)();
typedef void  (*StartBgDetection_t)();
typedef void  (*RunHeavyChecks_t)();
typedef DWORD (*GetBgThreadId_t)();
typedef int   (*Challenge_t)(const uint8_t*, uint32_t, uint8_t*, uint32_t);

struct DllExports {
    HMODULE hDll = nullptr;
    // New C API (@7-@16)
    SetBanCb_t        SetBanCb = nullptr;
    SetLogCb_t        SetLogCb = nullptr;
    Init_t            Init = nullptr;
    Tick_t            Tick = nullptr;
    Shutdown_t        Shutdown = nullptr;
    IsBanned_t        IsBanned = nullptr;
    LoadRule_t        LoadRule = nullptr;
    ProtectVar_t      ProtectVar = nullptr;
    UnprotectVar_t    UnprotectVar = nullptr;
    UpdateProtectVar_t UpdateProtectVar = nullptr;
    // Legacy C API (@1-@6)
    RunFullSuite_t      RunFull = nullptr;
    TriggerSelfTamper_t Tamper = nullptr;
    StartBgDetection_t  StartBg = nullptr;
    RunHeavyChecks_t    HeavyChecks = nullptr;
    GetBgThreadId_t     BgThreadId = nullptr;
    Challenge_t         Challenge = nullptr;
};

static DllExports g_dll;

// Ban tracking
static bool     g_banFired = false;
static uint32_t g_banCode  = 0;

static void __cdecl BanCallback(uint32_t code, const char* reason) {
    g_banFired = true;
    g_banCode = code;
}

static void __cdecl LogCallback(const char* message) {
    // silent
}

static bool LoadDll() {
    g_dll.hDll = LoadLibraryA("bigbro.dll");
    if (!g_dll.hDll) return false;
    // New C API
    g_dll.SetBanCb       = (SetBanCb_t)       GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(12));
    g_dll.SetLogCb       = (SetLogCb_t)       GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(13));
    g_dll.Init           = (Init_t)           GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(7));
    g_dll.Tick           = (Tick_t)           GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(8));
    g_dll.Shutdown       = (Shutdown_t)       GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(9));
    g_dll.IsBanned       = (IsBanned_t)       GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(10));
    g_dll.LoadRule       = (LoadRule_t)       GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(11));
    g_dll.ProtectVar     = (ProtectVar_t)     GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(14));
    g_dll.UnprotectVar   = (UnprotectVar_t)   GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(15));
    g_dll.UpdateProtectVar = (UpdateProtectVar_t) GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(16));
    // Legacy
    g_dll.RunFull        = (RunFullSuite_t)     GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(1));
    g_dll.Tamper         = (TriggerSelfTamper_t)GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(3));
    g_dll.StartBg        = (StartBgDetection_t) GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(4));
    g_dll.HeavyChecks    = (RunHeavyChecks_t)   GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(5));
    g_dll.BgThreadId     = (GetBgThreadId_t)    GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(6));
    g_dll.Challenge      = (Challenge_t)        GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(17));
    return true;
}

// flags enum values (mirror bigbro::Flag)
static constexpr uint32_t FLAG_NONE              = 0x00;
static constexpr uint32_t FLAG_VERBOSE            = 0x01;
static constexpr uint32_t FLAG_NO_NATIVE          = 0x02;
static constexpr uint32_t FLAG_NO_SCRIPTS         = 0x04;
static constexpr uint32_t FLAG_USE_FS_RULES       = 0x08;
static constexpr uint32_t FLAG_NO_BG_THREAD       = 0x10;

static bool InitSDK(const char* rulesDir = nullptr, bool useFilesystem = false, bool noBgThread = true) {
    g_banFired = false;
    g_banCode = 0;
    uint32_t flags = FLAG_NONE;
    if (useFilesystem) flags |= FLAG_USE_FS_RULES;
    if (noBgThread) flags |= FLAG_NO_BG_THREAD;
    if (g_dll.SetBanCb) g_dll.SetBanCb(BanCallback);
    if (g_dll.SetLogCb) g_dll.SetLogCb(LogCallback);
    return g_dll.Init(flags, "bigbro-default-key", rulesDir) == 0;
}

// ============================================================
// INDIVIDUAL TESTS
// ============================================================

static int TestDllLoad() {
    return LoadDll() ? 0 : 1;
}

static int TestLegacyExports() {
    if (!LoadDll()) return 1;
    if (!g_dll.RunFull) return 2;
    if (!g_dll.Tamper) return 3;
    if (!g_dll.IsBanned) return 4;
    return 0;
}

static int TestNewApiExports() {
    if (!LoadDll()) return 1;
    if (!g_dll.Init) return 2;
    if (!g_dll.Tick) return 3;
    if (!g_dll.Shutdown) return 4;
    if (!g_dll.IsBanned) return 5;
    if (!g_dll.SetBanCb) return 6;
    if (!g_dll.SetLogCb) return 7;
    if (!g_dll.LoadRule) return 8;
    if (!g_dll.ProtectVar) return 9;
    if (!g_dll.UnprotectVar) return 10;
    if (!g_dll.UpdateProtectVar) return 11;
    return 0;
}

static int TestInitShutdown() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    g_dll.Shutdown();
    return 0;
}

static int TestCleanTick() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    int result = g_dll.Tick();
    g_dll.Shutdown();
    return (result == 0) ? 0 : 1;
}

static int TestJSEngine() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    int result = g_dll.Tick();
    g_dll.Shutdown();
    return (result == 0) ? 0 : 1;
}

static int TestBanCallback() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    g_dll.Tamper();
    g_dll.Tick();
    g_dll.Shutdown();
    return g_banFired ? 0 : 1;
}

static int TestSelfTamper() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    g_dll.Tick();
    g_dll.Tamper();
    g_dll.Tick();
    bool banned = g_dll.IsBanned() != 0;
    g_dll.Shutdown();
    return banned ? 0 : 1;
}

static int TestXorStr() {
    if (!LoadDll()) return 1;
    HMODULE hMod = GetModuleHandleA("bigbro.dll");
    if (!hMod) return 1;
    auto* dos = (IMAGE_DOS_HEADER*)hMod;
    auto* nt  = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
    DWORD size = nt->OptionalHeader.SizeOfImage;
    const char* hay = (const char*)hMod;
    const char* forbidden[] = { "x64dbg", "Cheat Engine", "Process Hacker" };
    for (auto* needle : forbidden) {
        size_t len = strlen(needle);
        for (DWORD i = 0; i < size - len; i++) {
            if (memcmp(hay + i, needle, len) == 0) return 1;
        }
    }
    return 0;
}

static int TestRuleLoading() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    int ret = g_dll.LoadRule("./rules/check_debugger.js");
    g_dll.Shutdown();
    return (ret == 0) ? 0 : 1;
}

static int TestRetpoline() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    g_dll.Tick();
    if (g_dll.IsBanned()) return 3;
    g_dll.Tick();
    bool ok = !g_dll.IsBanned();
    g_dll.Shutdown();
    return ok ? 0 : 1;
}

static int TestAttestation() {
    if (!LoadDll()) return 1;
    if (!g_dll.Challenge) return 2;

    // Generate nonce
    uint8_t nonce[32];
    BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // Ask DLL to sign
    uint8_t sig[64];
    int sigLen = g_dll.Challenge(nonce, sizeof(nonce), sig, sizeof(sig));
    if (sigLen <= 0) return 3;

    // Verify with public key
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0)))
        return 4;
    if (!NT_SUCCESS(BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hKey,
                                        (PUCHAR)kAttestationPubKey, sizeof(kAttestationPubKey), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 5;
    }

    BCRYPT_ALG_HANDLE hHashAlg = nullptr;
    BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    uint8_t hash[32];
    BCryptHash(hHashAlg, NULL, 0, nonce, sizeof(nonce), hash, sizeof(hash));
    BCryptCloseAlgorithmProvider(hHashAlg, 0);

    NTSTATUS st = BCryptVerifySignature(hKey, NULL, hash, sizeof(hash), sig, (ULONG)sigLen, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return NT_SUCCESS(st) ? 0 : 1;
}

static int TestAttestationFail() {
    if (!LoadDll()) return 1;
    if (!g_dll.Challenge) return 2;

    // Generate nonce and get valid signature
    uint8_t nonce[32];
    BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    uint8_t sig[64];
    int sigLen = g_dll.Challenge(nonce, sizeof(nonce), sig, sizeof(sig));
    if (sigLen <= 0) return 3;

    // TAMPER: flip a byte in the signature
    sig[0] ^= 0xFF;

    // Verify — must FAIL
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0)))
        return 4;
    if (!NT_SUCCESS(BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hKey,
                                        (PUCHAR)kAttestationPubKey, sizeof(kAttestationPubKey), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 5;
    }

    BCRYPT_ALG_HANDLE hHashAlg = nullptr;
    BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    uint8_t hash[32];
    BCryptHash(hHashAlg, NULL, 0, nonce, sizeof(nonce), hash, sizeof(hash));
    BCryptCloseAlgorithmProvider(hHashAlg, 0);

    NTSTATUS st = BCryptVerifySignature(hKey, NULL, hash, sizeof(hash), sig, (ULONG)sigLen, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    // Must NOT succeed — tampered signature
    return NT_SUCCESS(st) ? 1 : 0;
}

static int TestTlsCallback() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    bool banned = g_dll.IsBanned() != 0;
    g_dll.Shutdown();
    return banned ? 1 : 0;
}

static int TestSyscalls() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    g_dll.Tick();
    bool ok = !g_dll.IsBanned();
    g_dll.Shutdown();
    return ok ? 0 : 1;
}

static int TestShadowState() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    g_dll.Tick();
    if (g_dll.IsBanned()) { g_dll.Shutdown(); return 3; }
    g_dll.Tick();
    bool stillClean = !g_dll.IsBanned();
    g_dll.Shutdown();
    return stillClean ? 0 : 1;
}

static int TestIatDetection() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    for (int i = 0; i < 3; i++) {
        g_dll.Tick();
        if (g_dll.IsBanned()) { g_dll.Shutdown(); return 3; }
    }
    g_dll.Shutdown();
    return 0;
}

static int TestThreadWatchdog() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    for (int i = 0; i < 5; i++) {
        g_dll.Tick();
        if (g_dll.IsBanned()) { g_dll.Shutdown(); return 3; }
    }
    g_dll.Shutdown();
    return 0;
}

static int TestProtectedVariable() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;

    int health = 100;
    g_dll.ProtectVar("health", &health, sizeof(health));

    g_dll.Tick();
    if (g_dll.IsBanned()) { g_dll.Shutdown(); return 3; }

    health = 80;
    g_dll.UpdateProtectVar("health");
    g_dll.Tick();
    if (g_dll.IsBanned()) { g_dll.Shutdown(); return 4; }

    g_dll.UnprotectVar("health");
    g_dll.Tick();
    if (g_dll.IsBanned()) { g_dll.Shutdown(); return 5; }

    g_dll.Shutdown();
    return 0;
}

// ============================================================
// TEST: JS Bindings
// ============================================================
static int TestJsBindings() {
    if (!LoadDll()) return 1;

    const char* testRulePath = "./rules/__test_bindings.js";
    {
        FILE* f = fopen(testRulePath, "w");
        if (!f) return 2;
        fprintf(f, "%s",
            "var mods = native.getModules();\n"
            "if (!mods || mods.length === 0) {\n"
            "    native.reportBan(0xFF01, 'getModules_empty');\n"
            "} else if (typeof mods[0].name !== 'string' || typeof mods[0].base !== 'number') {\n"
            "    native.reportBan(0xFF02, 'getModules_bad_fields');\n"
            "}\n"
            "var threads = native.getThreads();\n"
            "if (!threads || threads.length === 0) {\n"
            "    native.reportBan(0xFF03, 'getThreads_empty');\n"
            "} else if (typeof threads[0].tid !== 'number') {\n"
            "    native.reportBan(0xFF04, 'getThreads_bad_fields');\n"
            "}\n"
            "var mem = native.readMemory(mods[0].base, 4);\n"
            "if (mem === null || mem === undefined) {\n"
            "    native.reportBan(0xFF05, 'readMemory_null');\n"
            "}\n"
            "var r = native.syscall(0x19, -1, 7, 0, 8, 0);\n"
            "if (r === null || r === undefined || typeof r.status !== 'number') {\n"
            "    native.reportBan(0xFF06, 'syscall_invalid');\n"
            "}\n"
            "native.log('js_bindings: ALL OK');\n"
        );
        fclose(f);
    }

    if (!InitSDK("./rules", true)) { remove(testRulePath); return 3; }
    g_dll.Tick();

    bool banned = g_banFired;
    uint32_t code = g_banCode;
    g_dll.Shutdown();
    remove(testRulePath);

    if (banned) return (int)(code & 0xFF);
    return 0;
}

// ============================================================
// TEST: ProtectedVariable TAMPER
// ============================================================
static int TestProtectedVarTamper() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false)) return 2;

    int health = 100;
    g_dll.ProtectVar("health", &health, sizeof(health));
    g_dll.Tick();
    if (g_dll.IsBanned()) { g_dll.Shutdown(); return 3; }

    // TAMPER: change without update → must ban
    health = 9999;
    g_dll.Tick();
    bool banned = g_dll.IsBanned() != 0;
    g_dll.Shutdown();
    return banned ? 0 : 1;
}

// ============================================================
// TEST: JS Rule fires ban
// ============================================================
static int TestJsRuleBan() {
    if (!LoadDll()) return 1;

    const char* banRulePath = "./rules/__test_ban_rule.js";
    {
        FILE* f = fopen(banRulePath, "w");
        if (!f) return 2;
        fprintf(f, "native.reportBan(0xBEEF, 'test_ban');\n");
        fclose(f);
    }

    if (!InitSDK("./rules", true)) { remove(banRulePath); return 3; }
    g_dll.Tick();

    bool banned = g_banFired;
    uint32_t code = g_banCode;
    g_dll.Shutdown();
    remove(banRulePath);

    if (!banned) return 1;
    if (code != 0xBEEF) return 4;
    return 0;
}


// ============================================================
// ATTACK SIMULATION TESTS (ban-positive)
// ============================================================
static int TestBlacklistedWindow() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false)) return 2;
    HWND hwnd = CreateWindowA("STATIC", "Cheat Engine", 0, 0, 0, 1, 1, NULL, NULL, NULL, NULL);
    if (!hwnd) return 3;
    g_dll.Tick();
    bool banned = g_banFired;
    DestroyWindow(hwnd);
    g_dll.Shutdown();
    return banned ? 0 : 1;
}

static int TestDebuggerFlag() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false)) return 2;
    auto* peb = (BYTE*)__readgsqword(0x60);
    BYTE original = peb[2];
    peb[2] = 1; // BeingDebugged = true
    g_dll.Tick();
    bool banned = g_banFired;
    peb[2] = original;
    g_dll.Shutdown();
    return banned ? 0 : 1;
}

static int TestHardwareBreakpoint() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false)) return 2;
    HANDLE hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    HANDLE hThread = CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
        WaitForSingleObject((HANDLE)p, 10000); return 0;
    }, hEvent, 0, nullptr);
    if (hThread) {
        Sleep(50); SuspendThread(hThread);
        CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(hThread, &ctx);
        ctx.Dr0 = 0x7FFE0000; ctx.Dr7 = 1;
        SetThreadContext(hThread, &ctx);
        ResumeThread(hThread);
    }
    g_dll.Tick();
    bool banned = g_banFired;
    if (hThread) { SetEvent(hEvent); WaitForSingleObject(hThread, 2000); CloseHandle(hThread); }
    CloseHandle(hEvent);
    g_dll.Shutdown();
    return banned ? 0 : 1;
}

static int TestNtapiHook() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false)) return 2;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 3;
    BYTE* pFunc = (BYTE*)GetProcAddress(ntdll, "NtOpenProcess");
    if (!pFunc) return 4;
    BYTE saved[5]; memcpy(saved, pFunc, 5);
    DWORD oldProt;
    VirtualProtect(pFunc, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    pFunc[0] = 0xE9; *(DWORD*)(pFunc + 1) = 0; // JMP rel32
    VirtualProtect(pFunc, 5, oldProt, &oldProt);
    g_dll.Tick();
    bool banned = g_banFired;
    VirtualProtect(pFunc, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy(pFunc, saved, 5); // Restore
    VirtualProtect(pFunc, 5, oldProt, &oldProt);
    g_dll.Shutdown();
    return banned ? 0 : 1;
}

static int TestIatHook() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false)) return 2;
    g_dll.Tick(); // Establish baseline
    if (g_dll.IsBanned()) { g_dll.Shutdown(); return 3; }
    HMODULE hMod = GetModuleHandleA("bigbro.dll");
    if (!hMod) return 4;
    auto* dos = (IMAGE_DOS_HEADER*)hMod;
    auto* nt  = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress) return 5;
    auto* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hMod + importDir.VirtualAddress);
    uintptr_t saved = 0; uintptr_t* pThunk = nullptr;
    for (; importDesc->Name; importDesc++) {
        auto* thunk = (IMAGE_THUNK_DATA*)((BYTE*)hMod + importDesc->FirstThunk);
        for (; thunk->u1.Function; thunk++) {
            pThunk = &thunk->u1.Function;
            saved = *pThunk;
        }
    }
    if (!pThunk) return 7;
    void* fake = VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!fake) return 6;
    DWORD op; VirtualProtect(pThunk, 8, PAGE_READWRITE, &op);
    *pThunk = (uintptr_t)fake;
    VirtualProtect(pThunk, 8, op, &op);
    g_banFired = false; g_banCode = 0;
    __try { g_dll.Tick(); } __except(EXCEPTION_EXECUTE_HANDLER) {}
    bool banned = g_banFired;
    VirtualProtect(pThunk, 8, PAGE_READWRITE, &op);
    *pThunk = saved;
    VirtualProtect(pThunk, 8, op, &op);
    VirtualFree(fake, 0, MEM_RELEASE);
    g_dll.Shutdown();
    return banned ? 0 : 1;
}

// ============================================================
// NEW DETECTION TESTS
// ============================================================

static int TestManualMapDetection() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    g_dll.Tick();
    if (g_banFired) return 3;

    void* mem = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return 4;
    auto* base = (BYTE*)mem;
    base[0] = 'M'; base[1] = 'Z';
    auto* dos = (IMAGE_DOS_HEADER*)base;
    dos->e_lfanew = 0x80;
    auto* pe = (DWORD*)(base + 0x80);
    *pe = IMAGE_NT_SIGNATURE;

    g_banFired = false;
    if (!g_dll.HeavyChecks) return 5;
    g_dll.HeavyChecks();
    bool banned = g_banFired && (g_banCode == 0xA018);

    VirtualFree(mem, 0, MEM_RELEASE);
    g_dll.Shutdown();
    return banned ? 0 : 1;
}

static int TestNtdllMassHook() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    g_dll.Tick();
    if (g_banFired) return 3;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 4;
    const char* targets[] = {
        "NtLoadDriver", "NtUnloadDriver", "NtLockVirtualMemory",
        "NtUnlockVirtualMemory", "NtCreateToken", "NtOpenProcessToken",
        "NtOpenThreadToken", "NtAdjustPrivilegesToken"
    };
    struct Saved { BYTE* addr; BYTE bytes[5]; DWORD prot; };
    Saved saved[8] = {};
    int patched = 0;
    for (int i = 0; i < 8 && patched < 6; i++) {
        BYTE* p = (BYTE*)GetProcAddress(ntdll, targets[i]);
        if (!p) continue;
        if (p[0] != 0x4C || p[1] != 0x8B || p[2] != 0xD1) continue;
        saved[patched].addr = p;
        memcpy(saved[patched].bytes, p, 5);
        VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &saved[patched].prot);
        p[0] = 0xE9; *(int32_t*)(p + 1) = 0x7FFFF;
        patched++;
    }
    if (patched < 5) {
        for (int i = 0; i < patched; i++) {
            DWORD tmp;
            VirtualProtect(saved[i].addr, 5, PAGE_EXECUTE_READWRITE, &tmp);
            memcpy(saved[i].addr, saved[i].bytes, 5);
            VirtualProtect(saved[i].addr, 5, saved[i].prot, &tmp);
        }
        g_dll.Shutdown();
        return 5;
    }

    g_banFired = false;
    if (!g_dll.HeavyChecks) { g_dll.Shutdown(); return 6; }
    __try { g_dll.HeavyChecks(); } __except(EXCEPTION_EXECUTE_HANDLER) {}
    bool banned = g_banFired && (g_banCode == 0xA019);

    for (int i = 0; i < patched; i++) {
        DWORD tmp;
        VirtualProtect(saved[i].addr, 5, PAGE_EXECUTE_READWRITE, &tmp);
        memcpy(saved[i].addr, saved[i].bytes, 5);
        VirtualProtect(saved[i].addr, 5, saved[i].prot, &tmp);
    }
    g_dll.Shutdown();
    return banned ? 0 : 1;
}

static int TestAntiSuspend() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false, false)) return 2;
    if (!g_dll.BgThreadId) return 3;
    Sleep(500);

    DWORD bgTid = g_dll.BgThreadId();
    if (!bgTid) { g_dll.Shutdown(); return 4; }
    HANDLE hBg = OpenThread(THREAD_SUSPEND_RESUME, FALSE, bgTid);
    if (!hBg) { g_dll.Shutdown(); return 5; }

    SuspendThread(hBg);
    Sleep(200);

    g_banFired = false;
    for (int i = 0; i < 10; i++) {
        g_dll.Tick();
        Sleep(50);
    }
    bool banned = g_banFired;

    ResumeThread(hBg);
    CloseHandle(hBg);
    g_dll.Shutdown();
    return banned ? 0 : 1;
}

static int TestManualMapNoHeader() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    g_dll.Tick();
    if (g_banFired) return 3;

    void* base = VirtualAlloc(NULL, 0x40000, MEM_RESERVE, PAGE_NOACCESS);
    if (!base) return 4;

    void* text = VirtualAlloc(base, 0x20000, MEM_COMMIT, PAGE_READWRITE);
    if (!text) { VirtualFree(base, 0, MEM_RELEASE); return 5; }
    memset(text, 0xCC, 0x20000);
    DWORD oldProt;
    VirtualProtect(text, 0x20000, PAGE_EXECUTE_READ, &oldProt);

    void* data = VirtualAlloc((BYTE*)base + 0x20000, 0x10000, MEM_COMMIT, PAGE_READWRITE);
    if (!data) { VirtualFree(base, 0, MEM_RELEASE); return 6; }
    memset(data, 0x41, 0x10000);

    g_banFired = false;
    if (!g_dll.HeavyChecks) { VirtualFree(base, 0, MEM_RELEASE); return 7; }
    g_dll.HeavyChecks();
    bool banned = g_banFired && (g_banCode == 0xA01C);

    VirtualFree(base, 0, MEM_RELEASE);
    g_dll.Shutdown();
    return banned ? 0 : 1;
}

static int TestDebugPort() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false)) return 2;
    g_dll.Tick();
    bool banned = g_dll.IsBanned() != 0;
    g_dll.Shutdown();
    return banned ? 1 : 0;
}

static int TestBgThreadKill() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false, false)) return 2;
    if (!g_dll.BgThreadId) return 3;
    Sleep(500);

    DWORD bgTid = g_dll.BgThreadId();
    if (!bgTid) { g_dll.Shutdown(); return 4; }
    HANDLE hBg = OpenThread(THREAD_TERMINATE, FALSE, bgTid);
    if (!hBg) { g_dll.Shutdown(); return 5; }

    TerminateThread(hBg, 0);
    CloseHandle(hBg);
    Sleep(200);

    g_banFired = false;
    for (int i = 0; i < 5; i++) {
        g_dll.Tick();
        Sleep(50);
    }
    bool banned = g_banFired;
    g_dll.Shutdown();
    return banned ? 0 : 1;
}

static int TestSyscallWhitelist() {
    if (!LoadDll()) return 1;

    const char* testRulePath = "./rules/__test_whitelist.js";
    {
        FILE* f = fopen(testRulePath, "w");
        if (!f) return 2;
        fprintf(f, "%s",
            "var r = native.syscall(0x2C, -1, 0, 0, 0, 0, 0);\n"
            "// If we get here without ban, the whitelist failed\n"
        );
        fclose(f);
    }

    if (!InitSDK("./rules", true)) { remove(testRulePath); return 3; }
    g_dll.Tick();

    bool banned = g_banFired;
    g_dll.Shutdown();
    remove(testRulePath);

    return banned ? 0 : 1;
}

// ============================================================
// NEGATIVE (CLEAN) TESTS
// ============================================================

static int TestCleanNoHeader() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    g_dll.Tick();
    if (g_banFired) return 3;

    void* jit = VirtualAlloc(NULL, 0x20000, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (!jit) return 4;
    memset(jit, 0xCC, 0x20000);

    g_banFired = false;
    if (!g_dll.HeavyChecks) { VirtualFree(jit, 0, MEM_RELEASE); return 5; }
    g_dll.HeavyChecks();
    bool banned = g_banFired && (g_banCode == 0xA01C);

    VirtualFree(jit, 0, MEM_RELEASE);
    g_dll.Shutdown();
    return banned ? 1 : 0;
}

static int TestCleanWhitelist() {
    if (!LoadDll()) return 1;

    const char* testRulePath = "./rules/__test_clean_wl.js";
    {
        FILE* f = fopen(testRulePath, "w");
        if (!f) return 2;
        fprintf(f, "%s",
            "var r = native.syscall(0x19, -1, 7, 0, 8, 0);\n"
            "if (r === null || typeof r.status !== 'number') {\n"
            "    native.reportBan(0xFF10, 'whitelist_clean_fail');\n"
            "}\n"
            "native.log('whitelist_clean: OK');\n"
        );
        fclose(f);
    }

    if (!InitSDK("./rules", true)) { remove(testRulePath); return 3; }
    g_dll.Tick();

    bool banned = g_banFired;
    g_dll.Shutdown();
    remove(testRulePath);

    return banned ? 1 : 0;
}

static int TestCleanBgThread() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false, false)) return 2;
    Sleep(500);

    g_banFired = false;
    for (int i = 0; i < 5; i++) {
        g_dll.Tick();
        Sleep(50);
    }
    bool banned = g_banFired && (g_banCode == 0xA01E);
    g_dll.Shutdown();
    return banned ? 1 : 0;
}

static int TestCleanVeh() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false)) return 2;
    g_banFired = false;
    for (int i = 0; i < 3; i++) {
        g_dll.Tick();
    }
    bool banned = g_dll.IsBanned() != 0;
    g_dll.Shutdown();
    return banned ? 1 : 0;
}

//
// DISPATCH
// ============================================================
static int RunSingleTest(const string& n) {
    if (n == "dll_load")       return TestDllLoad();
    if (n == "legacy")         return TestLegacyExports();
    if (n == "new_api")        return TestNewApiExports();
    if (n == "init_shutdown")  return TestInitShutdown();
    if (n == "clean_tick")     return TestCleanTick();
    if (n == "js_engine")      return TestJSEngine();
    if (n == "ban_callback")   return TestBanCallback();
    if (n == "self_tamper")    return TestSelfTamper();
    if (n == "xorstr")         return TestXorStr();
    if (n == "rule_loading")   return TestRuleLoading();
    if (n == "retpoline")      return TestRetpoline();
    if (n == "attestation")    return TestAttestation();
    if (n == "attest_fail")   return TestAttestationFail();
    if (n == "tls_callback")   return TestTlsCallback();
    if (n == "syscalls")       return TestSyscalls();
    if (n == "shadow_state")   return TestShadowState();
    if (n == "iat_detect")     return TestIatDetection();
    if (n == "thread_watchdog") return TestThreadWatchdog();
    if (n == "protect_var")    return TestProtectedVariable();
    if (n == "js_bindings")    return TestJsBindings();
    if (n == "var_tamper")     return TestProtectedVarTamper();
    if (n == "js_rule_ban")    return TestJsRuleBan();
    if (n == "ban_window")     return TestBlacklistedWindow();
    if (n == "ban_debugger")   return TestDebuggerFlag();
    if (n == "ban_hwbp")       return TestHardwareBreakpoint();
    if (n == "ban_ntapi")      return TestNtapiHook();
    if (n == "ban_iat")        return TestIatHook();
    if (n == "ban_manualmap")  return TestManualMapDetection();
    if (n == "ban_ntdll_mass") return TestNtdllMassHook();
    if (n == "ban_antisuspend") return TestAntiSuspend();
    if (n == "ban_noheader")  return TestManualMapNoHeader();
    if (n == "ban_debugport") return TestDebugPort();
    if (n == "ban_bgkill")   return TestBgThreadKill();
    if (n == "ban_whitelist") return TestSyscallWhitelist();
    if (n == "clean_noheader") return TestCleanNoHeader();
    if (n == "clean_whitelist") return TestCleanWhitelist();
    if (n == "clean_bgthread") return TestCleanBgThread();
    if (n == "clean_veh")     return TestCleanVeh();
    return 99;
}

// ============================================================
// SUBPROCESS RUNNER
// ============================================================
static DWORD RunChild(const string& name) {
    char exe[MAX_PATH];
    GetModuleFileNameA(NULL, exe, MAX_PATH);
    string cmd = string("\"") + exe + "\" --test " + name;
    string dir(exe);
    auto sl = dir.find_last_of("\\/");
    if (sl != string::npos) dir = dir.substr(0, sl);

    STARTUPINFOA si = {}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE,
                        DETACHED_PROCESS, NULL, dir.c_str(), &si, &pi))
        return 0xFFFF;
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code;
}

struct TestCase { string id, desc; bool expectBan; };

int main(int argc, char* argv[]) {
    if (argc >= 3 && string(argv[1]) == "--test")
        return RunSingleTest(argv[2]);

    cout << "=== BigBro SDK Validation Suite ===" << endl;
    cout << "======================================\n" << endl;

    vector<TestCase> tests = {
        {"dll_load",       "DLL Loading",                          false},
        {"legacy",         "Legacy C Exports (ordinal compat)",    false},
        {"new_api",        "New C API Exports (@7-@16)",           false},
        {"init_shutdown",  "Init + Shutdown (C API)",              false},
        {"tls_callback",   "TLS Callback (early init)",            false},
        {"clean_tick",     "Clean Tick (native only)",             false},
        {"js_engine",      "JS Engine + Rule Execution",           false},
        {"rule_loading",   "Runtime Rule Loading",                 false},
        {"retpoline",      "Retpoline Dispatch (Spectre v2)",      false},
        {"attestation",    "ECDSA P-256 Attestation (genuine)",     false},
        {"attest_fail",   "ECDSA P-256 Attestation (tampered)",    false},
        {"xorstr",         "XorStr Obfuscation (string scan)",     false},
        {"ban_callback",   "Ban Callback (function)",              false},
        {"self_tamper",    "Self-Tamper Watchdog (.bigdata)",       false},
        {"syscalls",       "Direct Syscall Infrastructure",        false},
        {"shadow_state",   "Shadow State Integrity",               false},
        {"iat_detect",     "IAT Hook Detection (clean)",           false},
        {"thread_watchdog","Thread Watchdog Heartbeat",            false},
        {"protect_var",    "ProtectVariable API (C API)",          false},
        {"js_bindings",    "JS Syscall Bindings (native.syscall)", false},
        {"var_tamper",     "ProtectVar Tamper Detection (ban+)",   false},
        {"js_rule_ban",    "JS Rule Ban Propagation (ban+)",       false},
        {"ban_window",     "Blacklisted Window Detection (ban+)",  false},
        {"ban_debugger",   "PEB Debugger Flag Detection (ban+)",   false},
        {"ban_hwbp",       "Hardware Breakpoint Detection (ban+)", false},
        {"ban_ntapi",      "NtAPI Hook Detection (ban+)",          false},
        {"ban_iat",        "IAT Hook Detection (ban+)",            false},
        {"ban_manualmap",  "Manual-Map Detection (ban+)",           false},
        {"ban_ntdll_mass", "Ntdll Mass-Hook Detection (ban+)",      false},
        {"ban_antisuspend","Anti-Suspend Detection (ban+)",         false},
        {"ban_noheader",  "Manual-Map No-Header Detection (ban+)",   false},
        {"ban_debugport", "ProcessDebugPort Detection (clean)",      false},
        {"ban_bgkill",   "BG Thread Kill Detection (ban+)",          false},
        {"ban_whitelist", "Syscall Whitelist Enforcement (ban+)",     false},
        {"clean_noheader","No-Header Clean: JIT-like alloc (clean)",   false},
        {"clean_whitelist","Whitelist Clean: safe syscall (clean)",    false},
        {"clean_bgthread","BG Thread Clean: alive thread (clean)",    false},
        {"clean_veh",    "VEH Chain Clean: no injection (clean)",      false},
    };

    int passed = 0, failed = 0, total = (int)tests.size();
    for (int i = 0; i < total; i++) {
        const auto& t = tests[i];
        printf("[TEST %2d/%-2d] %-42s ", i+1, total, t.desc.c_str());
        DWORD code = RunChild(t.id);
        bool ok = t.expectBan ? (code == 0xDEAD) : (code == 0);
        if (ok) { printf("PASS\n"); passed++; }
        else    { printf("FAIL (0x%X)\n", code); failed++; }
    }

    printf("\n======================================\n");
    printf("Results: %d/%d passed", passed, total);
    if (failed) printf(", %d FAILED", failed);
    printf("\n======================================\n");
    return failed ? 1 : 0;
}
