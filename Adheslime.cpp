#include "VfsManager.hpp"
#include "HardwareProfiler.hpp"
#include "ComponentSystem.hpp"

#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <thread>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <atomic>

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

// --- No using namespace std in a DLL ---

// --- Globals ---
static std::atomic<bool> isBanned{false};
static std::string banReason;
static std::mutex banMutex;

// --- CRC32 ---
static uint32_t CalculateCRC32(const unsigned char* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

// --- Compile-time String Obfuscation ---
template<size_t N>
struct XorStr final {
    char data[N];
    constexpr XorStr(const char* s) : data{} {
        for (size_t i = 0; i < N; ++i) data[i] = s[i] ^ 0x5A;
    }
    std::string Decrypt() const {
        std::string s;
        for (size_t i = 0; i < N - 1; ++i) s += (data[i] ^ 0x5A);
        return s;
    }
};

#define X(s) []{ constexpr XorStr<(sizeof(s))> res(s); return res.Decrypt(); }()

// --- BANNED Screen (generic — no detection details) ---
static void ShowBannedScreen(uint32_t code) {
    // Check if we have a console (child processes may not)
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    bool hasConsole = (hOut != NULL && hOut != INVALID_HANDLE_VALUE);
    
    if (hasConsole) {
        system("cls");
        std::cout << "\n\n";
        std::cout << "  ################################################################\n";
        std::cout << "  #                                                              #\n";
        std::cout << "  #   BBBBBB      AA    NN      N  NN      N  EEEEEEE  DDDDD     #\n";
        std::cout << "  #   B     B    A  A   N N     N  N N     N  E        D    D    #\n";
        std::cout << "  #   B     B   A    A  N  N    N  N  N    N  E        D     D   #\n";
        std::cout << "  #   BBBBBB    AAAAAA  N   N   N  N   N   N  EEEEEE   D     D   #\n";
        std::cout << "  #   B     B   A    A  N    N  N  N    N  N  E        D     D   #\n";
        std::cout << "  #   B     B   A    A  N     N N  N     N N  E        D    D    #\n";
        std::cout << "  #   BBBBBB    A    A  N      NN  N      NN  EEEEEEE  DDDDD     #\n";
        std::cout << "  #                                                              #\n";
        std::cout << "  ################################################################\n";
        std::cout << "\n";
        std::cout << "  YOU HAVE BEEN PERMANENTLY BANNED.\n";
        std::cout << "  Code: 0x" << std::hex << std::uppercase << code << "\n";
        std::cout << "\n  Session terminated.";
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    ExitProcess(0xDEAD);
}

static void TriggerBan(uint32_t code) {
    std::lock_guard<std::mutex> lock(banMutex);
    if (isBanned) return;
    isBanned = true;
    ShowBannedScreen(code);
}

// Ban codes (opaque — don't reveal detection type)
enum BanCode : uint32_t {
    BC_DEBUGGER_LATENCY  = 0xA001,
    BC_TIMING_ANOMALY    = 0xA002,
    BC_HWBP_DETECTED     = 0xA003,
    BC_EXTERN_EXEC       = 0xA004,
    BC_TEXT_INTEGRITY     = 0xA005,
    BC_NTAPI_HOOK        = 0xA006,
    BC_BLACKLISTED_APP   = 0xA007,
    BC_MEM_PROTECT       = 0xA008,
    BC_HEARTBEAT_FAIL    = 0xA009,
    BC_DEBUGGER_PRESENT  = 0xA00A,
    BC_QPC_ANOMALY       = 0xA00B,
    BC_TICK_ANOMALY      = 0xA00C,
};

// --- Detection Components ---

__declspec(noinline) static void RaiseExceptionWrapper() {
    __try {
        RaiseException(0x40010006, 0, 0, NULL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}

class AntiDebug final {
public:
    static void CheckDebuggerState() {
        auto start = std::chrono::high_resolution_clock::now();
        RaiseExceptionWrapper();
        auto end = std::chrono::high_resolution_clock::now();
        auto delta = (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        if (delta > 500) TriggerBan(BC_DEBUGGER_LATENCY);
    }

    static void CheckTimingAnomaly() {
        static constexpr uintptr_t kUserSharedData = 0x7FFE0000;
        static constexpr uint32_t ksSystemTimeOffset = 0x14;
        volatile unsigned long long* pSystemTime = (unsigned long long*)(kUserSharedData + ksSystemTimeOffset);
        unsigned long long t1 = *pSystemTime;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        unsigned long long t2 = *pSystemTime;
        if (t2 - t1 == 0) TriggerBan(BC_TIMING_ANOMALY);
    }

    static void CheckIsDebuggerPresent() {
        if (IsDebuggerPresent()) TriggerBan(BC_DEBUGGER_PRESENT);
    }

    static void CheckQPCTiming() {
        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        QueryPerformanceCounter(&end);
        double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;
        // If sleep(5ms) took > 500ms, someone is single-stepping
        if (elapsed > 500.0) TriggerBan(BC_QPC_ANOMALY);
    }

    static void CheckTickCount() {
        DWORD t1 = GetTickCount();
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        DWORD t2 = GetTickCount();
        if (t2 - t1 > 500) TriggerBan(BC_TICK_ANOMALY);
    }
};

class ProcessMonitor final {
public:
    static void ScanProcessThreads() {
        std::vector<std::pair<DWORD64, DWORD64>> moduleBounds;
        HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
        if (hModSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me;
            me.dwSize = sizeof(me);
            if (Module32First(hModSnap, &me)) {
                do {
                    moduleBounds.push_back({(DWORD64)me.modBaseAddr, (DWORD64)me.modBaseAddr + me.modBaseSize});
                } while (Module32Next(hModSnap, &me));
            }
            CloseHandle(hModSnap);
        }

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap == INVALID_HANDLE_VALUE) return;
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        DWORD pid = GetCurrentProcessId();
        if (Thread32First(hSnap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid && te.th32ThreadID != GetCurrentThreadId()) ActiveThreadHijack(te.th32ThreadID, moduleBounds);
            } while (Thread32Next(hSnap, &te));
        }
        CloseHandle(hSnap);
    }

private:
    static void ActiveThreadHijack(DWORD tid, const std::vector<std::pair<DWORD64, DWORD64>>& moduleBounds) {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
        if (!hThread) return;
        SuspendThread(hThread);
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
        if (GetThreadContext(hThread, &ctx)) {
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) TriggerBan(BC_HWBP_DETECTED);
            bool inModule = false;
            for (const auto& bound : moduleBounds) if (ctx.Rip >= bound.first && ctx.Rip < bound.second) inModule = true;
            if (!inModule) TriggerBan(BC_EXTERN_EXEC);
        }
        ResumeThread(hThread);
        CloseHandle(hThread);
    }
};

class SectionIntegrity final {
public:
    static uint32_t GetTextSectionChecksum() {
        HMODULE hModule = GetModuleHandleA(X("adheslime.dll").c_str());
        if (!hModule) return 0;
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)section[i].Name, X(".text").c_str()) == 0) return CalculateCRC32((BYTE*)hModule + section[i].VirtualAddress, section[i].Misc.VirtualSize);
        }
        return 0;
    }

    static void ValidateModuleSections() {
        static uint32_t originalHash = 0;
        if (originalHash == 0) originalHash = GetTextSectionChecksum();
        uint32_t currentHash = GetTextSectionChecksum();
        if (currentHash != originalHash) TriggerBan(BC_TEXT_INTEGRITY);
    }

    static void CheckNtapiHooks() {
        auto hNtdll = GetModuleHandleA(X("ntdll.dll").c_str());
        auto pNtOpenProcess = (BYTE*)GetProcAddress(hNtdll, X("NtOpenProcess").c_str());
        if (pNtOpenProcess && *pNtOpenProcess == 0xE9) TriggerBan(BC_NTAPI_HOOK);
    }
};

class BlacklistMonitor final {
public:
    static void ScanBlacklistedWindows() {
        // All window names obfuscated
        if (FindWindowA(NULL, X("x64dbg").c_str())) TriggerBan(BC_BLACKLISTED_APP);
        if (FindWindowA(NULL, X("Cheat Engine").c_str())) TriggerBan(BC_BLACKLISTED_APP);
        if (FindWindowA(NULL, X("Process Hacker").c_str())) TriggerBan(BC_BLACKLISTED_APP);
    }
};

class SelfWatchdog final {
public:
    static void MonitorDispatchProtection(const void* arrayAddr) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(arrayAddr, &mbi, sizeof(mbi))) return;

        static DWORD initialProtect = 0;
        if (initialProtect == 0) {
            initialProtect = mbi.Protect;
            return;
        }

        if (mbi.Protect != initialProtect) TriggerBan(BC_MEM_PROTECT);
    }
};

class TelemetryService final {
public:
    static void SendHeartbeat(bool integrityOk) {
        if (!integrityOk) TriggerBan(BC_HEARTBEAT_FAIL);
        // Silent — no console output
    }
};

class V8ScriptEngine final : public fx::Component {
public:
    typedef void (*NativeHandler)(void* context);
    inline static std::vector<std::pair<uint64_t, NativeHandler>> nativeHandlers;

    const char* GetName() const override { return X("fx::ResourceScriptingComponent").c_str(); }

    static void RegisterNativeHandler(uint64_t hash, NativeHandler handler) {
        nativeHandlers.push_back({hash, handler});
    }

    static void BindHostFunctions() {
        RegisterNativeHandler(0x1, [](void*) { AntiDebug::CheckDebuggerState(); });
        RegisterNativeHandler(0x2, [](void*) { ProcessMonitor::ScanProcessThreads(); });
        RegisterNativeHandler(0x3, [](void*) { SectionIntegrity::ValidateModuleSections(); });
    }

    void ExecuteDetectionRules() {
        std::vector<char> scriptData;
        if (adheslime::vfs::Manager::Get().ReadFile("rules:/anti_aim.js", scriptData)) {
            for (auto& [id, handler] : nativeHandlers) if (handler) handler(nullptr);
        }
    }
};

// --- Dispatch Table ---
typedef void (*pDetectionFunc)();

// Dedicated read-only section — VirtualProtect changes are detectable by watchdog
#pragma section(".adhdata", read)
__declspec(allocate(".adhdata")) static pDetectionFunc detectionDispatch[] = {
    AntiDebug::CheckIsDebuggerPresent,
    AntiDebug::CheckDebuggerState,
    AntiDebug::CheckTimingAnomaly,
    AntiDebug::CheckQPCTiming,
    AntiDebug::CheckTickCount,
    ProcessMonitor::ScanProcessThreads,
    SectionIntegrity::ValidateModuleSections,
    SectionIntegrity::CheckNtapiHooks,
    BlacklistMonitor::ScanBlacklistedWindows,
    adheslime::HardwareProfiler::ProfileCPUID,
    []() { 
        if (auto v8 = (V8ScriptEngine*)fx::ComponentRegistry::GetInstance().GetComponent("fx::ResourceScriptingComponent")) v8->ExecuteDetectionRules();
    }
};

static constexpr size_t kDispatchCount = sizeof(detectionDispatch) / sizeof(detectionDispatch[0]);

// --- Fiber-Based Detection Scheduler ---
static LPVOID mainFiber = nullptr;
static LPVOID detectionFiber = nullptr;

static void CALLBACK DetectionFiberProc(LPVOID) {
    // Run watchdog + all detection functions inside fiber
    SelfWatchdog::MonitorDispatchProtection(detectionDispatch);
    for (auto func : detectionDispatch) if (func) func();
    TelemetryService::SendHeartbeat(true);
    // Switch back to main fiber
    if (mainFiber) SwitchToFiber(mainFiber);
}

// --- AdheslimeClient ---
class AdheslimeClient final {
private:
    bool _initialized = false;

public:
    void Initialize() {
        if (_initialized) return;
        _initialized = true;

        auto v8 = std::make_shared<V8ScriptEngine>();
        fx::ComponentRegistry::GetInstance().Register(v8);
        V8ScriptEngine::BindHostFunctions();

        auto packfile = std::make_unique<adheslime::vfs::PackfileDevice>();
        packfile->AddFile("anti_aim.js", "/* Rule Content */");
        adheslime::vfs::Manager::Get().Mount("rules:/", std::move(packfile));

        // Capture watchdog baseline EAGERLY during init
        SelfWatchdog::MonitorDispatchProtection(detectionDispatch);
    }

    void RunDispatchLoop() {
        SelfWatchdog::MonitorDispatchProtection(detectionDispatch);
        SectionIntegrity::ValidateModuleSections();

        // Use fibers for cooperative detection scheduling
        mainFiber = ConvertThreadToFiber(nullptr);
        if (mainFiber) {
            detectionFiber = CreateFiber(0, DetectionFiberProc, nullptr);
            if (detectionFiber) {
                SwitchToFiber(detectionFiber);
                DeleteFiber(detectionFiber);
                detectionFiber = nullptr;
            }
            ConvertFiberToThread();
            mainFiber = nullptr;
        } else {
            // Fallback: direct execution if fiber creation fails
            for (auto func : detectionDispatch) if (func) func();
            TelemetryService::SendHeartbeat(true);
        }
    }
};

// --- Single Global Client Instance ---
static AdheslimeClient* clientInstance = nullptr;

// --- Exports ---
extern "C" __declspec(dllexport) fx::Component* CreateComponent() {
    if (!clientInstance) {
        clientInstance = new AdheslimeClient();
        clientInstance->Initialize();
    }
    return (fx::Component*)fx::ComponentRegistry::GetInstance().GetComponent("fx::ResourceScriptingComponent");
}

// Internal functions called by host/tester via GetProcAddress
extern "C" __declspec(dllexport) void RunFullSuite() {
    if (!clientInstance) {
        clientInstance = new AdheslimeClient();
        clientInstance->Initialize();
    }
    clientInstance->RunDispatchLoop();
}

extern "C" __declspec(dllexport) bool IsUserBanned() {
    return isBanned.load();
}

extern "C" __declspec(dllexport) void StartBackgroundDetection() {
    std::thread([]() {
        if (!clientInstance) {
            clientInstance = new AdheslimeClient();
            clientInstance->Initialize();
        }
        while (!isBanned) {
            clientInstance->RunDispatchLoop();
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }).detach();
}

extern "C" __declspec(dllexport) void TriggerSelfTamper() {
    DWORD oldProtect;
    // Use PAGE_EXECUTE_READWRITE (0x40) — guaranteed to differ from any initial protection
    VirtualProtect((void*)detectionDispatch, sizeof(detectionDispatch), PAGE_EXECUTE_READWRITE, &oldProtect);
}

// --- TLS Callback for Early Initialization ---
#pragma section(".CRT$XLB", read)
static void NTAPI TlsCallback(PVOID hModule, DWORD reason, PVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Early anti-debug check — runs before DllMain
        if (IsDebuggerPresent()) TriggerBan(BC_DEBUGGER_PRESENT);
    }
}
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK pTlsCallback = TlsCallback;

// --- DllMain with hardening ---
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
    }
    return TRUE;
}
