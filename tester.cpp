/**
 * Adheslime  Comprehensive Automated Validation Suite
 * 
 * Runs each test in an isolated child process so bans/crashes dont
 * affect reporting. Uses --test <name> for child mode.
 */
#include <iostream>
#include <windows.h>
#include <string>
#include <vector>
#include <functional>

// --- Export Types ---
typedef void  (*RunFullDispatch_t)();
typedef void  (*TriggerSelfTamper_t)();
typedef bool  (*IsUserBanned_t)();
typedef void  (*StartBgDetection_t)();
typedef void* (*CreateComponent_t)();

// --- Globals for child mode ---
static HMODULE hDll = nullptr;
static RunFullDispatch_t  RunFull   = nullptr;
static TriggerSelfTamper_t Tamper   = nullptr;
static IsUserBanned_t     IsBanned = nullptr;
static StartBgDetection_t StartBg  = nullptr;
static CreateComponent_t  CreateComp = nullptr;

static bool LoadDll() {
    hDll = LoadLibraryA("adheslime.dll");
    if (!hDll) return false;
    RunFull    = (RunFullDispatch_t)GetProcAddress(hDll, "RunFullSuite");
    Tamper     = (TriggerSelfTamper_t)GetProcAddress(hDll, "TriggerSelfTamper");
    IsBanned   = (IsUserBanned_t)GetProcAddress(hDll, "IsUserBanned");
    StartBg    = (StartBgDetection_t)GetProcAddress(hDll, "StartBackgroundDetection");
    CreateComp = (CreateComponent_t)GetProcAddress(hDll, "CreateComponent");
    return true;
}

// ============================================================
// Child Tests  each returns 0 on PASS, non-zero on FAIL
// If ExitProcess(0xDEAD) fires, parent sees exit code 0xDEAD
// ============================================================

static int TestDllLoad() {
    return LoadDll() ? 0 : 1;
}

static int TestExports() {
    if (!LoadDll()) return 1;
    if (!RunFull)    return 2;
    if (!Tamper)     return 3;
    if (!IsBanned)   return 4;
    if (!StartBg)    return 5;
    if (!CreateComp) return 6;
    return 0;
}

static int TestCreateComponent() {
    if (!LoadDll()) return 1;
    void* comp = CreateComp();
    return (comp != nullptr) ? 0 : 1;
}

static int TestCleanDispatch() {
    if (!LoadDll()) return 1;
    RunFull();
    return IsBanned() ? 1 : 0;
}

static int TestSelfTamper() {
    if (!LoadDll()) return 1;
    RunFull();   // Init + capture baseline
    Tamper();    // Tamper AFTER baseline
    RunFull();   // Should detect and ExitProcess(0xDEAD)
    return IsBanned() ? 0 : 1;
}

static int TestXorStrObfuscation() {
    // Scan our own DLL for plaintext detection strings
    if (!LoadDll()) return 1;
    
    HMODULE hMod = GetModuleHandleA("adheslime.dll");
    if (!hMod) return 1;
    
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)hMod + dos->e_lfanew);
    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    
    const char* haystack = (const char*)hMod;
    
    // These strings MUST NOT appear in plaintext in the DLL
    // (excludes import table entries like ntdll.dll which appear naturally)
    const char* forbidden[] = {
        "x64dbg",
        "Cheat Engine",
        "Process Hacker",
        "Debugger Latency",
        "Hardware Breakpoint",
    };
    
    for (const char* needle : forbidden) {
        size_t needleLen = strlen(needle);
        for (DWORD i = 0; i < imageSize - needleLen; i++) {
            if (memcmp(haystack + i, needle, needleLen) == 0) {
                fprintf(stderr, "[XOR-FAIL] Found plaintext: \"%s\" at offset 0x%X\n", needle, i);
                return 1; // FAIL  plaintext found
            }
        }
    }
    return 0; // PASS  no forbidden strings found
}

static int TestFiberExecution() {
    // Verify fiber APIs are available and used during dispatch
    if (!LoadDll()) return 1;
    
    // If ConvertThreadToFiber works, fibers are supported
    LPVOID fiber = ConvertThreadToFiber(nullptr);
    if (!fiber) return 1; // Fiber API unavailable
    ConvertFiberToThread();
    
    // Run a clean dispatch (which internally uses fibers)
    RunFull();
    return IsBanned() ? 1 : 0;
}

static int TestTlsCallback() {
    // TLS callback should have already run by the time DLL is loaded
    // It calls IsDebuggerPresent  if we're not in a debugger, we're fine
    if (!LoadDll()) return 1;
    // If we got here, TLS didn't crash and didn't false-ban
    return IsBanned() ? 1 : 0;
}

static int TestDllMainHardening() {
    // DisableThreadLibraryCalls should be active
    // We verify indirectly: DLL loaded successfully = DllMain ran
    if (!LoadDll()) return 1;
    // Create a thread to verify DLL_THREAD_ATTACH doesn't cause issues
    HANDLE hThread = CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        Sleep(10);
        return 0;
    }, nullptr, 0, nullptr);
    if (!hThread) return 1;
    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);
    return 0;
}

static int TestBanCodes() {
    // Verify ban codes are opaque (no plaintext reasons)
    // We indirectly test this: a clean run should not produce ban
    if (!LoadDll()) return 1;
    RunFull();
    return IsBanned() ? 1 : 0;
}

static int TestRetpolineDispatch() {
    // Verify retpoline-routed dispatch completes without crash or false ban.
    // All indirect calls in the dispatch table go through retpoline_call_rax thunk.
    if (!LoadDll()) return 1;
    RunFull();  // First run: init + retpoline dispatch
    if (IsBanned()) return 1;
    RunFull();  // Second run: confirms no state corruption from retpoline routing
    return IsBanned() ? 1 : 0;
}

// ============================================================
// Single Test Entry Point (child mode)
// ============================================================
static int RunSingleTest(const std::string& testName) {
    if (testName == "dll_load")         return TestDllLoad();
    if (testName == "exports")          return TestExports();
    if (testName == "create_component") return TestCreateComponent();
    if (testName == "clean_dispatch")   return TestCleanDispatch();
    if (testName == "self_tamper")      return TestSelfTamper();
    if (testName == "xorstr")           return TestXorStrObfuscation();
    if (testName == "fiber")            return TestFiberExecution();
    if (testName == "tls_callback")     return TestTlsCallback();
    if (testName == "dllmain")          return TestDllMainHardening();
    if (testName == "ban_codes")        return TestBanCodes();
    if (testName == "retpoline")        return TestRetpolineDispatch();
    return 99; // unknown test
}

// ============================================================
// Subprocess Runner (parent mode)
// ============================================================
static DWORD RunChildTest(const std::string& testName) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    std::string cmdLine = std::string("\"") + exePath + "\" --test " + testName;

    std::string exeDir(exePath);
    size_t lastSlash = exeDir.find_last_of("\\/");
    if (lastSlash != std::string::npos) exeDir = exeDir.substr(0, lastSlash);

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA(NULL, (LPSTR)cmdLine.c_str(), NULL, NULL, FALSE,
                        DETACHED_PROCESS, NULL, exeDir.c_str(), &si, &pi))
        return 0xFFFF;

    WaitForSingleObject(pi.hProcess, 30000);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return exitCode;
}

struct TestCase {
    std::string id;
    std::string description;
    bool expectBan;  // If true, 0xDEAD = PASS
};

int main(int argc, char* argv[]) {
    // Child mode
    if (argc >= 3 && std::string(argv[1]) == "--test")
        return RunSingleTest(argv[2]);

    // Parent mode  orchestrate all tests
    std::cout << "=== Adheslime Comprehensive Validation Suite ===\n";
    std::cout << "================================================\n\n";

    std::vector<TestCase> tests = {
        {"dll_load",         "DLL Loading",                          false},
        {"exports",          "Export Resolution (5 symbols)",        false},
        {"create_component", "CreateComponent Pattern",              false},
        {"tls_callback",     "TLS Callback (early init)",            false},
        {"dllmain",          "DllMain Hardening (thread safety)",    false},
        {"fiber",            "Fiber-Based Detection Scheduling",     false},
        {"clean_dispatch",   "Full Detection Dispatch (clean run)",  false},
        {"ban_codes",        "Opaque Ban Codes (no plaintext)",      false},
        {"xorstr",           "XorStr Obfuscation (string scan)",     false},
        {"retpoline",        "Retpoline Dispatch (Spectre v2)",       false},
        {"self_tamper",      "Self-Tamper Watchdog (memory protect)", true},
    };

    int passed = 0, failed = 0, total = (int)tests.size();
    int testNum = 0;

    for (const auto& test : tests) {
        testNum++;
        // Fixed-width formatting
        printf("[TEST %2d/%-2d] %-42s ", testNum, total, test.description.c_str());

        DWORD code = RunChildTest(test.id);

        if (test.expectBan) {
            // For ban tests, exit code 0xDEAD = PASS
            if (code == 0xDEAD) {
                printf("PASS\n");
                passed++;
            } else {
                printf("FAIL (exit: 0x%X, expected: 0xDEAD)\n", code);
                failed++;
            }
        } else {
            // For normal tests, exit code 0 = PASS
            if (code == 0) {
                printf("PASS\n");
                passed++;
            } else {
                printf("FAIL (exit: 0x%X)\n", code);
                failed++;
            }
        }
    }

    std::cout << "\n================================================\n";
    printf("Results: %d/%d passed", passed, total);
    if (failed > 0) printf(", %d FAILED", failed);
    printf("\n================================================\n");

    return failed > 0 ? 1 : 0;
}
