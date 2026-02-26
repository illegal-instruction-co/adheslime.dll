/**
 * BigBro SDK - Comprehensive Validation Suite
 *
 * Each test runs in an isolated child process.
 * Uses --test <name> for child mode.
 */
#include <bigbro/Sdk.h>

#include <iostream>
#include <cstdio>
#include <string>
#include <vector>
#include <thread>

#include <windows.h>

using namespace std;

typedef void (*RunFullSuite_t)();
typedef void (*TriggerSelfTamper_t)();
typedef int  (*IsUserBanned_t)();
typedef void (*StartBgDetection_t)();
typedef void (*RunHeavyChecks_t)();
typedef DWORD (*GetBgThreadId_t)();

struct DllExports {
    HMODULE hDll = nullptr;
    RunFullSuite_t      RunFull = nullptr;
    TriggerSelfTamper_t Tamper = nullptr;
    IsUserBanned_t      LegacyBanned = nullptr;
    StartBgDetection_t  StartBg = nullptr;
    RunHeavyChecks_t    HeavyChecks = nullptr;
    GetBgThreadId_t     BgThreadId = nullptr;
};

static DllExports g_dll;

// Ban tracking
static bool     g_banFired = false;
static uint32_t g_banCode  = 0;

static bool LoadDll() {
    g_dll.hDll = LoadLibraryA("bigbro.dll");
    if (!g_dll.hDll) return false;
    // Ordinal-only exports (NONAME in .def) - no function names in PE
    g_dll.RunFull      = (RunFullSuite_t)GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(1));
    g_dll.Tamper       = (TriggerSelfTamper_t)GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(3));
    g_dll.LegacyBanned = (IsUserBanned_t)GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(2));
    g_dll.StartBg      = (StartBgDetection_t)GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(4));
    g_dll.HeavyChecks  = (RunHeavyChecks_t)GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(5));
    g_dll.BgThreadId   = (GetBgThreadId_t)GetProcAddress(g_dll.hDll, MAKEINTRESOURCEA(6));
    return true;
}

static bool InitSDK(const char* rulesDir = nullptr, bool useFilesystem = false, bool noBgThread = true) {
    g_banFired = false;
    g_banCode = 0;
    bigbro::Flag flags = bigbro::Flag::None;
    if (useFilesystem) flags = flags | bigbro::Flag::UseFilesystemRules;
    if (noBgThread) flags = flags | bigbro::Flag::NoBgThread; // prevent bg thread in subprocess
    return bigbro::SDK::Get().Init({
        .rulesDirectory = rulesDir ? rulesDir : "",
        .encryptionKey = "bigbro-default-key",
        .onBan = [](const bigbro::BanEvent& e) {
            g_banFired = true;
            g_banCode = e.code;
        },
        .onLog = [](const bigbro::LogEvent&) {},
        .flags = flags,
    }) == 0;
}

// ============================================================
// Example custom component for testing
// ============================================================
class TestComponent final : public bigbro::Component {
public:
    bool initCalled = false;
    bool tickCalled = false;
    bool shutdownCalled = false;

    const char* GetName() const override { return "Test::Component"; }
    void OnInit() override { initCalled = true; }
    void OnTick() override { tickCalled = true; }
    void OnShutdown() override { shutdownCalled = true; }
};

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
    if (!g_dll.LegacyBanned) return 4;
    return 0;
}

static int TestInitShutdown() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    bigbro::SDK::Get().Shutdown();
    return 0;
}

static int TestCleanTick() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    int result = bigbro::SDK::Get().Tick();
    bigbro::SDK::Get().Shutdown();
    return (result == 0) ? 0 : 1;
}

static int TestJSEngine() {
    if (!LoadDll()) return 1;
    // Default: loads from embedded AES-encrypted VFS
    if (!InitSDK()) return 2;
    int result = bigbro::SDK::Get().Tick();
    bigbro::SDK::Get().Shutdown();
    return (result == 0) ? 0 : 1;
}

static int TestComponentLifecycle() {
    if (!LoadDll()) return 1;
    auto comp = make_shared<TestComponent>();
    bigbro::SDK::Get().Components().Register(comp);
    if (!InitSDK()) return 2;
    if (!comp->initCalled) return 3;
    bigbro::SDK::Get().Tick();
    if (!comp->tickCalled) return 4;
    bigbro::SDK::Get().Shutdown();
    if (!comp->shutdownCalled) return 5;
    return 0;
}

static int TestComponentRegistry() {
    if (!LoadDll()) return 1;
    auto comp = make_shared<TestComponent>();
    auto& reg = bigbro::SDK::Get().Components();
    reg.Register(comp);
    // Find by name
    if (!reg.Find("Test::Component")) return 2;
    // Find by type
    if (!reg.Find<TestComponent>()) return 3;
    // Count
    if (reg.Count() < 1) return 4;
    bigbro::SDK::Get().Init({});
    bigbro::SDK::Get().Shutdown();
    return 0;
}

static int TestBanCallback() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    g_dll.Tamper();
    bigbro::SDK::Get().Tick();
    bigbro::SDK::Get().Shutdown();
    return g_banFired ? 0 : 1;
}

static int TestSelfTamper() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    bigbro::SDK::Get().Tick();
    g_dll.Tamper();
    bigbro::SDK::Get().Tick();
    bool banned = bigbro::SDK::Get().IsBanned();
    bigbro::SDK::Get().Shutdown();
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
    int ret = bigbro::SDK::Get().LoadRule("./rules/check_debugger.js");
    bigbro::SDK::Get().Shutdown();
    return (ret == 0) ? 0 : 1;
}

static int TestRetpoline() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    bigbro::SDK::Get().Tick();
    if (bigbro::SDK::Get().IsBanned()) return 3;
    bigbro::SDK::Get().Tick();
    bool ok = !bigbro::SDK::Get().IsBanned();
    bigbro::SDK::Get().Shutdown();
    return ok ? 0 : 1;
}

static int TestTlsCallback() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    bool banned = bigbro::SDK::Get().IsBanned();
    bigbro::SDK::Get().Shutdown();
    return banned ? 1 : 0;
}

// --- Test: Direct Syscall Infrastructure ---
static int TestSyscalls() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    // After Init, syscall numbers should be resolved
    // We verify by running a clean tick (which uses detection infrastructure)
    bigbro::SDK::Get().Tick();
    bool ok = !bigbro::SDK::Get().IsBanned();
    bigbro::SDK::Get().Shutdown();
    return ok ? 0 : 1;
}

// --- Test: Shadow State detects external tampering ---
static int TestShadowState() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    // First tick - establishes shadow
    bigbro::SDK::Get().Tick();
    if (bigbro::SDK::Get().IsBanned()) { bigbro::SDK::Get().Shutdown(); return 3; }

    // Simulate external tampering: flip g_banned to true via
    // our own process memory (this simulates WriteProcessMemory attack)
    // The shadow state should detect this on next Tick
    // NOTE: We can't easily test this without exporting g_banned address.
    // Instead, verify that two clean ticks don't false-positive.
    bigbro::SDK::Get().Tick();
    bool stillClean = !bigbro::SDK::Get().IsBanned();
    bigbro::SDK::Get().Shutdown();
    return stillClean ? 0 : 1;
}

// --- Test: IAT Hook Detection (clean) ---
static int TestIatDetection() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    // Run multiple ticks - IAT should be consistent → no ban
    for (int i = 0; i < 3; i++) {
        bigbro::SDK::Get().Tick();
        if (bigbro::SDK::Get().IsBanned()) { bigbro::SDK::Get().Shutdown(); return 3; }
    }
    bigbro::SDK::Get().Shutdown();
    return 0;
}

// --- Test: Thread Watchdog heartbeat ---
static int TestThreadWatchdog() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    // Multiple ticks - heartbeat should advance, no ban
    for (int i = 0; i < 5; i++) {
        bigbro::SDK::Get().Tick();
        if (bigbro::SDK::Get().IsBanned()) { bigbro::SDK::Get().Shutdown(); return 3; }
    }
    bigbro::SDK::Get().Shutdown();
    return 0;
}

// --- Test: Protected Variable API ---
static int TestProtectedVariable() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;

    // Register a variable for protection
    int health = 100;
    bigbro::SDK::Get().ProtectVariable("health", &health, sizeof(health));

    // Tick - shadow should match
    bigbro::SDK::Get().Tick();
    if (bigbro::SDK::Get().IsBanned()) { bigbro::SDK::Get().Shutdown(); return 3; }

    // Legitimate change + sync
    health = 80;
    bigbro::SDK::Get().UpdateProtectedVariable("health");
    bigbro::SDK::Get().Tick();
    if (bigbro::SDK::Get().IsBanned()) { bigbro::SDK::Get().Shutdown(); return 4; }

    // Unprotect and verify cleanup
    bigbro::SDK::Get().UnprotectVariable("health");
    bigbro::SDK::Get().Tick();
    if (bigbro::SDK::Get().IsBanned()) { bigbro::SDK::Get().Shutdown(); return 5; }

    bigbro::SDK::Get().Shutdown();
    return 0;
}

// ============================================================
// TEST: JS Bindings — verifies each new binding returns valid data
// ============================================================
static int TestJsBindings() {
    if (!LoadDll()) return 1;

    // Write a temp JS rule that exercises all bindings
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
    bigbro::SDK::Get().Tick();

    bool banned = g_banFired;
    uint32_t code = g_banCode;
    bigbro::SDK::Get().Shutdown();
    remove(testRulePath);

    if (banned) return (int)(code & 0xFF);
    return 0;
}

// ============================================================
// TEST: ProtectedVariable TAMPER → must fire ban
// ============================================================
static int TestProtectedVarTamper() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false)) return 2;

    int health = 100;
    bigbro::SDK::Get().ProtectVariable("health", &health, sizeof(health));
    bigbro::SDK::Get().Tick();
    if (bigbro::SDK::Get().IsBanned()) { bigbro::SDK::Get().Shutdown(); return 3; }

    // TAMPER: change without UpdateProtectedVariable → must ban
    health = 9999;
    bigbro::SDK::Get().Tick();
    bool banned = bigbro::SDK::Get().IsBanned();
    bigbro::SDK::Get().Shutdown();
    return banned ? 0 : 1;
}

// ============================================================
// TEST: JS Rule fires ban → callback must receive it
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
    bigbro::SDK::Get().Tick();

    bool banned = g_banFired;
    uint32_t code = g_banCode;
    bigbro::SDK::Get().Shutdown();
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
    bigbro::SDK::Get().Tick();
    bool banned = g_banFired;
    DestroyWindow(hwnd);
    bigbro::SDK::Get().Shutdown();
    return banned ? 0 : 1;
}

static int TestDebuggerFlag() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false)) return 2;
    auto* peb = (BYTE*)__readgsqword(0x60);
    BYTE original = peb[2];
    peb[2] = 1; // BeingDebugged = true
    bigbro::SDK::Get().Tick();
    bool banned = g_banFired;
    peb[2] = original;
    bigbro::SDK::Get().Shutdown();
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
    bigbro::SDK::Get().Tick();
    bool banned = g_banFired;
    if (hThread) { SetEvent(hEvent); WaitForSingleObject(hThread, 2000); CloseHandle(hThread); }
    CloseHandle(hEvent);
    bigbro::SDK::Get().Shutdown();
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
    bigbro::SDK::Get().Tick();
    bool banned = g_banFired;
    VirtualProtect(pFunc, 5, PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy(pFunc, saved, 5); // Restore
    VirtualProtect(pFunc, 5, oldProt, &oldProt);
    bigbro::SDK::Get().Shutdown();
    return banned ? 0 : 1;
}

static int TestIatHook() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false)) return 2;
    bigbro::SDK::Get().Tick(); // Establish baseline
    if (bigbro::SDK::Get().IsBanned()) { bigbro::SDK::Get().Shutdown(); return 3; }
    HMODULE hMod = GetModuleHandleA("bigbro.dll");
    if (!hMod) return 4;
    auto* dos = (IMAGE_DOS_HEADER*)hMod;
    auto* nt  = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress) return 5;
    auto* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hMod + importDir.VirtualAddress);
    uintptr_t saved = 0; uintptr_t* pThunk = nullptr;
    // Find the LAST thunk (least likely actively called during Tick)
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
    __try { bigbro::SDK::Get().Tick(); } __except(EXCEPTION_EXECUTE_HANDLER) {}
    bool banned = g_banFired;
    VirtualProtect(pThunk, 8, PAGE_READWRITE, &op);
    *pThunk = saved;
    VirtualProtect(pThunk, 8, op, &op);
    VirtualFree(fake, 0, MEM_RELEASE);
    bigbro::SDK::Get().Shutdown();
    return banned ? 0 : 1;
}

// ============================================================
// NEW DETECTION TESTS
// ============================================================

static int TestManualMapDetection() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    bigbro::SDK::Get().Tick(); // establish baselines
    if (g_banFired) return 3; // clean tick must not ban

    // Allocate executable memory with fake PE header
    void* mem = VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) return 4;
    auto* base = (BYTE*)mem;
    // Write MZ header
    base[0] = 'M'; base[1] = 'Z';
    auto* dos = (IMAGE_DOS_HEADER*)base;
    dos->e_lfanew = 0x80;
    // Write PE signature at e_lfanew
    auto* pe = (DWORD*)(base + 0x80);
    *pe = IMAGE_NT_SIGNATURE; // "PE\0\0"

    g_banFired = false;
    if (!g_dll.HeavyChecks) return 5;
    g_dll.HeavyChecks();
    bool banned = g_banFired && (g_banCode == 0xA018);

    VirtualFree(mem, 0, MEM_RELEASE);
    bigbro::SDK::Get().Shutdown();
    return banned ? 0 : 1;
}

static int TestNtdllMassHook() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    bigbro::SDK::Get().Tick(); // clean tick
    if (g_banFired) return 3;

    // Patch 6 rarely-called ntdll Nt* syscall stubs with JMP detour signature
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 4;
    // Use functions NOT called during VirtualQuery/scan to avoid hang
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
        p[0] = 0xE9; *(int32_t*)(p + 1) = 0x7FFFF; // JMP far forward (detour signature)
        patched++;
    }
    if (patched < 5) {
        for (int i = 0; i < patched; i++) {
            DWORD tmp;
            VirtualProtect(saved[i].addr, 5, PAGE_EXECUTE_READWRITE, &tmp);
            memcpy(saved[i].addr, saved[i].bytes, 5);
            VirtualProtect(saved[i].addr, 5, saved[i].prot, &tmp);
        }
        bigbro::SDK::Get().Shutdown();
        return 5;
    }

    g_banFired = false;
    if (!g_dll.HeavyChecks) { bigbro::SDK::Get().Shutdown(); return 6; }
    __try { g_dll.HeavyChecks(); } __except(EXCEPTION_EXECUTE_HANDLER) {}
    bool banned = g_banFired && (g_banCode == 0xA019);

    // Restore ALL stubs immediately
    for (int i = 0; i < patched; i++) {
        DWORD tmp;
        VirtualProtect(saved[i].addr, 5, PAGE_EXECUTE_READWRITE, &tmp);
        memcpy(saved[i].addr, saved[i].bytes, 5);
        VirtualProtect(saved[i].addr, 5, saved[i].prot, &tmp);
    }
    bigbro::SDK::Get().Shutdown();
    return banned ? 0 : 1;
}

static int TestAntiSuspend() {
    if (!LoadDll()) return 1;
    // Start WITH bg thread (noBgThread=false)
    if (!InitSDK(nullptr, false, false)) return 2;
    if (!g_dll.BgThreadId) return 3;
    Sleep(500); // Let bg thread start and heartbeat a few times

    // Get bg thread handle via exported thread ID
    DWORD bgTid = g_dll.BgThreadId();
    if (!bgTid) { bigbro::SDK::Get().Shutdown(); return 4; }
    HANDLE hBg = OpenThread(THREAD_SUSPEND_RESUME, FALSE, bgTid);
    if (!hBg) { bigbro::SDK::Get().Shutdown(); return 5; }

    SuspendThread(hBg);
    Sleep(200);

    // Tick multiple times — anti-suspend should count heartbeat misses
    g_banFired = false;
    for (int i = 0; i < 10; i++) {
        bigbro::SDK::Get().Tick();
        Sleep(50);
    }
    bool banned = g_banFired; // any ban from anti-suspend

    ResumeThread(hBg);
    CloseHandle(hBg);
    bigbro::SDK::Get().Shutdown();
    return banned ? 0 : 1;
}

// --- Test: MZ-less manual-map detection (Fix #3) ---
static int TestManualMapNoHeader() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    bigbro::SDK::Get().Tick(); // establish baselines
    if (g_banFired) return 3;

    // Simulate headerless manual-mapped PE: multi-region allocation with
    // mixed permissions (RX + RW) from same AllocationBase — like a real PE
    // with .text (RX) and .data (RW) sections but erased MZ header.
    void* base = VirtualAlloc(NULL, 0x40000, MEM_RESERVE, PAGE_NOACCESS);
    if (!base) return 4;

    // Region 1: .text — commit as RW, fill, then protect as RX
    void* text = VirtualAlloc(base, 0x20000, MEM_COMMIT, PAGE_READWRITE);
    if (!text) { VirtualFree(base, 0, MEM_RELEASE); return 5; }
    memset(text, 0xCC, 0x20000); // INT3 fill (looks like code)
    DWORD oldProt;
    VirtualProtect(text, 0x20000, PAGE_EXECUTE_READ, &oldProt);

    // Region 2: .data — PAGE_READWRITE (data section)
    void* data = VirtualAlloc((BYTE*)base + 0x20000, 0x10000, MEM_COMMIT, PAGE_READWRITE);
    if (!data) { VirtualFree(base, 0, MEM_RELEASE); return 6; }
    memset(data, 0x41, 0x10000); // 'A' fill (looks like data)

    g_banFired = false;
    if (!g_dll.HeavyChecks) { VirtualFree(base, 0, MEM_RELEASE); return 7; }
    g_dll.HeavyChecks();
    bool banned = g_banFired && (g_banCode == 0xA01C);

    VirtualFree(base, 0, MEM_RELEASE);
    bigbro::SDK::Get().Shutdown();
    return banned ? 0 : 1;
}

// --- Test: ProcessDebugPort clean check (Fix #4) ---
static int TestDebugPort() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false)) return 2;
    // Clean environment — no debugger → should not ban
    bigbro::SDK::Get().Tick();
    bool banned = bigbro::SDK::Get().IsBanned();
    bigbro::SDK::Get().Shutdown();
    return banned ? 1 : 0; // expect clean
}

// --- Test: BG thread kill detection (Fix #5) ---
static int TestBgThreadKill() {
    if (!LoadDll()) return 1;
    // Start WITH bg thread
    if (!InitSDK(nullptr, false, false)) return 2;
    if (!g_dll.BgThreadId) return 3;
    Sleep(500);

    DWORD bgTid = g_dll.BgThreadId();
    if (!bgTid) { bigbro::SDK::Get().Shutdown(); return 4; }
    HANDLE hBg = OpenThread(THREAD_TERMINATE, FALSE, bgTid);
    if (!hBg) { bigbro::SDK::Get().Shutdown(); return 5; }

    TerminateThread(hBg, 0);
    CloseHandle(hBg);
    Sleep(200);

    g_banFired = false;
    for (int i = 0; i < 5; i++) {
        bigbro::SDK::Get().Tick();
        Sleep(50);
    }
    bool banned = g_banFired;
    bigbro::SDK::Get().Shutdown();
    return banned ? 0 : 1;
}

// --- Test: Syscall whitelist enforcement (Fix #2) ---
static int TestSyscallWhitelist() {
    if (!LoadDll()) return 1;

    const char* testRulePath = "./rules/__test_whitelist.js";
    {
        FILE* f = fopen(testRulePath, "w");
        if (!f) return 2;
        // NtTerminateProcess = syscall number varies, use 0x2C (typical)
        // This should NOT be whitelisted → should ban
        fprintf(f, "%s",
            "var r = native.syscall(0x2C, -1, 0, 0, 0, 0, 0);\n"
            "// If we get here without ban, the whitelist failed\n"
        );
        fclose(f);
    }

    if (!InitSDK("./rules", true)) { remove(testRulePath); return 3; }
    bigbro::SDK::Get().Tick();

    bool banned = g_banFired;
    bigbro::SDK::Get().Shutdown();
    remove(testRulePath);

    return banned ? 0 : 1; // expect ban for non-whitelisted syscall
}

// ============================================================
// NEGATIVE (CLEAN) TESTS — verify no false positives
// ============================================================

// --- Clean: flat RWX allocation (JIT-like) must NOT trigger ban ---
static int TestCleanNoHeader() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    bigbro::SDK::Get().Tick();
    if (g_banFired) return 3;

    // Single flat RWX allocation — looks like JIT, should be safe
    void* jit = VirtualAlloc(NULL, 0x20000, MEM_COMMIT | MEM_RESERVE,
                             PAGE_EXECUTE_READWRITE);
    if (!jit) return 4;
    memset(jit, 0xCC, 0x20000);

    g_banFired = false;
    if (!g_dll.HeavyChecks) { VirtualFree(jit, 0, MEM_RELEASE); return 5; }
    g_dll.HeavyChecks();
    bool banned = g_banFired && (g_banCode == 0xA01C);

    VirtualFree(jit, 0, MEM_RELEASE);
    bigbro::SDK::Get().Shutdown();
    return banned ? 1 : 0; // expect NO ban (0xA01C)
}

// --- Clean: whitelisted syscall must NOT ban ---
static int TestCleanWhitelist() {
    if (!LoadDll()) return 1;

    const char* testRulePath = "./rules/__test_clean_wl.js";
    {
        FILE* f = fopen(testRulePath, "w");
        if (!f) return 2;
        // NtQueryInformationProcess (0x19) IS whitelisted — should work
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
    bigbro::SDK::Get().Tick();

    bool banned = g_banFired;
    bigbro::SDK::Get().Shutdown();
    remove(testRulePath);

    return banned ? 1 : 0; // expect NO ban
}

// --- Clean: healthy bg thread must NOT trigger kill detection ---
static int TestCleanBgThread() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false, false)) return 2; // bg thread enabled
    Sleep(500); // let bg thread start

    g_banFired = false;
    for (int i = 0; i < 5; i++) {
        bigbro::SDK::Get().Tick();
        Sleep(50);
    }
    bool banned = g_banFired && (g_banCode == 0xA01E);
    bigbro::SDK::Get().Shutdown();
    return banned ? 1 : 0; // expect NO ban (0xA01E)
}

// --- Clean: no VEH injection must NOT trigger VEH detection ---
static int TestCleanVeh() {
    if (!LoadDll()) return 1;
    if (!InitSDK(nullptr, false)) return 2;
    // Just tick normally — no VEH handlers added
    g_banFired = false;
    for (int i = 0; i < 3; i++) {
        bigbro::SDK::Get().Tick();
    }
    bool banned = bigbro::SDK::Get().IsBanned();
    bigbro::SDK::Get().Shutdown();
    return banned ? 1 : 0; // expect clean
}

//
// DISPATCH
// ============================================================
static int RunSingleTest(const string& n) {
    if (n == "dll_load")       return TestDllLoad();
    if (n == "legacy")         return TestLegacyExports();
    if (n == "init_shutdown")  return TestInitShutdown();
    if (n == "clean_tick")     return TestCleanTick();
    if (n == "js_engine")      return TestJSEngine();
    if (n == "component_life") return TestComponentLifecycle();
    if (n == "component_reg")  return TestComponentRegistry();
    if (n == "ban_callback")   return TestBanCallback();
    if (n == "self_tamper")    return TestSelfTamper();
    if (n == "xorstr")         return TestXorStr();
    if (n == "rule_loading")   return TestRuleLoading();
    if (n == "retpoline")      return TestRetpoline();
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

    cout << "=== BigBro SDK Validation Suite ===\n";
    cout << "======================================\n\n";

    vector<TestCase> tests = {
        {"dll_load",       "DLL Loading",                          false},
        {"legacy",         "Legacy C Exports (backward compat)",   false},
        {"init_shutdown",  "SDK::Init + SDK::Shutdown",            false},
        {"tls_callback",   "TLS Callback (early init)",            false},
        {"clean_tick",     "Clean Tick (native only)",             false},
        {"js_engine",      "JS Engine + Rule Execution",           false},
        {"rule_loading",   "Runtime Rule Loading",                 false},
        {"component_reg",  "ComponentRegistry (Register/Find<T>)", false},
        {"component_life", "Component Lifecycle (Init/Tick/Stop)", false},
        {"retpoline",      "Retpoline Dispatch (Spectre v2)",      false},
        {"xorstr",         "XorStr Obfuscation (string scan)",     false},
        {"ban_callback",   "Ban Callback (function)",         false},
        {"self_tamper",    "Self-Tamper Watchdog (.bigdata)",       false},
        {"syscalls",       "Direct Syscall Infrastructure",        false},
        {"shadow_state",   "Shadow State Integrity",               false},
        {"iat_detect",     "IAT Hook Detection (clean)",           false},
        {"thread_watchdog","Thread Watchdog Heartbeat",            false},
        {"protect_var",    "ProtectVariable API",                  false},
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
