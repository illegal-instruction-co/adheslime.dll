/**
 * Adheslime SDK — Comprehensive Validation Suite
 *
 * Each test runs in an isolated child process.
 * Uses --test <name> for child mode.
 */
#include <adheslime/Sdk.h>

#include <iostream>
#include <cstdio>
#include <string>
#include <vector>

#include <windows.h>

using namespace std;

// --- Export Types (GetProcAddress for DLL boundary) ---
typedef void (*RunFullSuite_t)();
typedef void (*TriggerSelfTamper_t)();
typedef int  (*IsUserBanned_t)();

struct DllExports {
    HMODULE hDll = nullptr;
    RunFullSuite_t    RunFull = nullptr;
    TriggerSelfTamper_t Tamper = nullptr;
    IsUserBanned_t    LegacyBanned = nullptr;
};

static DllExports g_dll;

// Ban tracking
static bool     g_banFired = false;
static uint32_t g_banCode  = 0;

static bool LoadDll() {
    g_dll.hDll = LoadLibraryA("adheslime.dll");
    if (!g_dll.hDll) return false;
    g_dll.RunFull      = (RunFullSuite_t)GetProcAddress(g_dll.hDll, "RunFullSuite");
    g_dll.Tamper       = (TriggerSelfTamper_t)GetProcAddress(g_dll.hDll, "TriggerSelfTamper");
    g_dll.LegacyBanned = (IsUserBanned_t)GetProcAddress(g_dll.hDll, "IsUserBanned");
    return true;
}

static bool InitSDK(const char* rulesDir = nullptr, bool useFilesystem = false) {
    g_banFired = false;
    g_banCode = 0;
    adheslime::Flag flags = adheslime::Flag::None;
    if (useFilesystem) flags = flags | adheslime::Flag::UseFilesystemRules;
    return adheslime::SDK::Get().Init({
        .rulesDirectory = rulesDir ? rulesDir : "",
        .encryptionKey = "adheslime-default-key",
        .onBan = [](const adheslime::BanEvent& e) {
            g_banFired = true;
            g_banCode = e.code;
        },
        .onLog = [](const adheslime::LogEvent&) {},
        .flags = flags,
    }) == 0;
}

// ============================================================
// Example custom component for testing
// ============================================================
class TestComponent final : public adheslime::Component {
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
    adheslime::SDK::Get().Shutdown();
    return 0;
}

static int TestCleanTick() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    int result = adheslime::SDK::Get().Tick();
    adheslime::SDK::Get().Shutdown();
    return (result == 0) ? 0 : 1;
}

static int TestJSEngine() {
    if (!LoadDll()) return 1;
    // Default: loads from embedded AES-encrypted VFS
    if (!InitSDK()) return 2;
    int result = adheslime::SDK::Get().Tick();
    adheslime::SDK::Get().Shutdown();
    return (result == 0) ? 0 : 1;
}

static int TestComponentLifecycle() {
    if (!LoadDll()) return 1;
    auto comp = make_shared<TestComponent>();
    adheslime::SDK::Get().Components().Register(comp);
    if (!InitSDK()) return 2;
    if (!comp->initCalled) return 3;
    adheslime::SDK::Get().Tick();
    if (!comp->tickCalled) return 4;
    adheslime::SDK::Get().Shutdown();
    if (!comp->shutdownCalled) return 5;
    return 0;
}

static int TestComponentRegistry() {
    if (!LoadDll()) return 1;
    auto comp = make_shared<TestComponent>();
    auto& reg = adheslime::SDK::Get().Components();
    reg.Register(comp);
    // Find by name
    if (!reg.Find("Test::Component")) return 2;
    // Find by type
    if (!reg.Find<TestComponent>()) return 3;
    // Count
    if (reg.Count() < 1) return 4;
    adheslime::SDK::Get().Init({});
    adheslime::SDK::Get().Shutdown();
    return 0;
}

static int TestBanCallback() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    g_dll.Tamper();
    adheslime::SDK::Get().Tick();
    adheslime::SDK::Get().Shutdown();
    return g_banFired ? 0 : 1;
}

static int TestSelfTamper() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    adheslime::SDK::Get().Tick();
    g_dll.Tamper();
    adheslime::SDK::Get().Tick();
    bool banned = adheslime::SDK::Get().IsBanned();
    adheslime::SDK::Get().Shutdown();
    return banned ? 0 : 1;
}

static int TestXorStr() {
    if (!LoadDll()) return 1;
    HMODULE hMod = GetModuleHandleA("adheslime.dll");
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
    int ret = adheslime::SDK::Get().LoadRule("./rules/check_debugger.js");
    adheslime::SDK::Get().Shutdown();
    return (ret == 0) ? 0 : 1;
}

static int TestRetpoline() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    adheslime::SDK::Get().Tick();
    if (adheslime::SDK::Get().IsBanned()) return 3;
    adheslime::SDK::Get().Tick();
    bool ok = !adheslime::SDK::Get().IsBanned();
    adheslime::SDK::Get().Shutdown();
    return ok ? 0 : 1;
}

static int TestTlsCallback() {
    if (!LoadDll()) return 1;
    if (!InitSDK()) return 2;
    bool banned = adheslime::SDK::Get().IsBanned();
    adheslime::SDK::Get().Shutdown();
    return banned ? 1 : 0;
}

// ============================================================
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

    cout << "=== Adheslime SDK Validation Suite ===\n";
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
        {"self_tamper",    "Self-Tamper Watchdog (.adhdata)",       false},
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
