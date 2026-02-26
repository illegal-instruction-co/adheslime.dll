#include "Detection.h"
#include "Obfuscation.h"
#include "StealthImport.h"
#include "Syscalls.h"

static atomic<uint32_t> g_timingViolations{0};
static constexpr uint32_t kTimingViolationThreshold = 8;

static __forceinline void RecordTimingViolation(uint32_t code, const char* reason) {
    uint32_t count = g_timingViolations.fetch_add(1, memory_order_relaxed) + 1;
    if (count >= kTimingViolationThreshold) {
        InternalBan(code, reason);
    } else {
        InternalLog(("timing_strike:" + to_string(count) + "/" +
                     to_string(kTimingViolationThreshold) + " " + reason).c_str());
    }
}

__declspec(noinline) static void RaiseExceptionWrapper() {
    __try {
        RaiseException(0x40010006, 0, 0, NULL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void Detect_IsDebuggerPresent() {
    DETECT_BEGIN
    auto pIsDbg = Stealth::Resolve<BOOL(WINAPI*)()>(X("kernel32.dll").c_str(), X("IsDebuggerPresent").c_str());
    if (pIsDbg && pIsDbg()) InternalBan(OBF_U32(0xA00A), X("debugger_present").c_str());
    DETECT_END;
}

static void Detect_DebuggerLatency() {
    DETECT_BEGIN
    auto start = chrono::high_resolution_clock::now();
    RaiseExceptionWrapper();
    auto end = chrono::high_resolution_clock::now();
    auto ms = (uint32_t)chrono::duration_cast<chrono::milliseconds>(end - start).count();
    if (ObfCmpGtU32(ms, OBF_U32(200)))
        RecordTimingViolation(OBF_U32(0xA001), X("debugger_latency").c_str());
    DETECT_END;
}

static void Detect_TimingAnomaly() {
    DETECT_BEGIN
    static constexpr uintptr_t kUserSharedData = 0x7FFE0000;
    volatile int64_t* pSysTime = (int64_t*)(kUserSharedData + OBF_PTR(0x320));
    int64_t t1 = *pSysTime;
    this_thread::sleep_for(chrono::milliseconds(OBF_I32(10)));
    int64_t t2 = *pSysTime;
    int64_t diff100ns = t2 - t1;
    if (ObfCmpLtI64(diff100ns, OBF_I64(20000)))
        RecordTimingViolation(OBF_U32(0xA002), X("timing_anomaly").c_str());
    DETECT_END;
}

static void Detect_QPCAnomaly() {
    DETECT_BEGIN
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    this_thread::sleep_for(chrono::milliseconds(OBF_I32(5)));
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;
    if (ObfCmpGtDbl(elapsed, (double)OBF_U32(200)))
        RecordTimingViolation(OBF_U32(0xA00B), X("qpc_anomaly").c_str());
    DETECT_END;
}

static void Detect_TickAnomaly() {
    DETECT_BEGIN
    DWORD t1 = GetTickCount();
    this_thread::sleep_for(chrono::milliseconds(OBF_I32(5)));
    DWORD t2 = GetTickCount();
    if (ObfCmpGtU32(t2 - t1, OBF_DWORD(200)))
        RecordTimingViolation(OBF_U32(0xA00C), X("tick_anomaly").c_str());
    DETECT_END;
}

static void Detect_ThreadsAndHWBP() {
    vector<pair<DWORD64, DWORD64>> moduleBounds;
    HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hModSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me; me.dwSize = sizeof(me);
        if (Module32First(hModSnap, &me)) {
            do { moduleBounds.push_back({(DWORD64)me.modBaseAddr, (DWORD64)me.modBaseAddr + me.modBaseSize}); }
            while (Module32Next(hModSnap, &me));
        }
        CloseHandle(hModSnap);
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te; te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId();
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == GetCurrentThreadId()) continue;
            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!hThread) continue;

            SuspendThread(hThread);
            CONTEXT ctx; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
            if (GetThreadContext(hThread, &ctx)) {
                if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                    InternalBan(0xA003, X("hwbp_detected").c_str());
                    ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
                    ctx.Dr7 = 0;
                    SetThreadContext(hThread, &ctx);
                }

                bool inModule = false;
                for (const auto& b : moduleBounds) {
                    if (ctx.Rip >= b.first && ctx.Rip < b.second) { inModule = true; break; }
                }
                if (!inModule) {
                    InternalBan(0xA004, X("external_execution").c_str());
                }
            }
            ResumeThread(hThread); CloseHandle(hThread);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
}

static void Detect_TextIntegrity() {
    HMODULE hMod = GetModuleHandleA(X("bigbro.dll").c_str());
    if (!hMod) return;
    auto* dos = (PIMAGE_DOS_HEADER)hMod;
    auto* nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sec[i].Name, X(".text").c_str()) == 0) {
            Sha256Digest current;
            if (!CalculateSHA256((uint8_t*)hMod + sec[i].VirtualAddress,
                                sec[i].Misc.VirtualSize, current))
                return;

            if (!g_textBaselineSet) {
                g_textBaseline = current;
                g_textBaselineSet = true;
                return;
            }
            if (current != g_textBaseline) InternalBan(0xA005, X("text_integrity").c_str());
            return;
        }
    }
}

static __forceinline bool IsHookedProlog(const BYTE* p) {
    if (!p) return false;

    if (p[0] == 0xE9) return true;

    if (p[0] == 0xFF && p[1] == 0x25) return true;

    if (p[0] == 0x48 && p[1] == 0xB8) {
        if (p[10] == 0xFF && p[11] == 0xE0) return true;
    }

    if (p[0] != 0x4C || p[1] != 0x8B || p[2] != 0xD1 || p[3] != 0xB8) {
        return true;
    }

    return false;
}

static void Detect_NtapiHooks() {
    auto h = Stealth::FindModule(X("ntdll.dll").c_str());
    if (!h) return;

    string funcNames[] = {
        X("NtOpenProcess"),
        X("NtReadVirtualMemory"),
        X("NtWriteVirtualMemory"),
        X("NtProtectVirtualMemory"),
        X("NtQuerySystemInformation"),
    };

    for (const auto& funcName : funcNames) {
        auto p = (BYTE*)Stealth::FindExport(h, funcName.c_str());
        if (p && IsHookedProlog(p)) {
            InternalBan(0xA006, X("ntapi_hook").c_str());
            return;
        }
    }
}

struct EnumWindowsCtx { bool found; };

static BOOL CALLBACK BlacklistEnumProc(HWND hwnd, LPARAM lParam) {
    auto* ctx = (EnumWindowsCtx*)lParam;

    char className[256] = {};
    char title[256] = {};
    GetClassNameA(hwnd, className, sizeof(className));
    GetWindowTextA(hwnd, title, sizeof(title));

    auto check = [&](const char* cls, const string& patCls, const string& patTitle) -> bool {
        if (!patCls.empty() && _stricmp(cls, patCls.c_str()) == 0) return true;
        if (!patTitle.empty() && strstr(title, patTitle.c_str()) != nullptr) return true;
        return false;
    };

    if (check(className, "",              X("x64dbg"))       ||
        check(className, "",              X("x32dbg"))       ||
        check(className, X("CheatEngine"), "")              ||
        check(className, "",              X("Cheat Engine"))) {
        ctx->found = true;
        return FALSE;
    }
    return TRUE;
}

static void Detect_BlacklistedWindows() {
    EnumWindowsCtx ctx{false};
    EnumWindows(BlacklistEnumProc, (LPARAM)&ctx);
    if (ctx.found) InternalBan(0xA007, X("blacklisted_window").c_str());

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(hSnap, &pe)) {
        do {
            char lower[MAX_PATH] = {};
            for (int i = 0; pe.szExeFile[i] && i < MAX_PATH - 1; i++)
                lower[i] = (pe.szExeFile[i] >= 'A' && pe.szExeFile[i] <= 'Z')
                    ? pe.szExeFile[i] + 32 : pe.szExeFile[i];


            if (strcmp(lower, X("cheatengine-x86_64.exe").c_str()) == 0 ||
                strcmp(lower, X("cheatengine-i386.exe").c_str()) == 0 ||
                strcmp(lower, X("cheatengine.exe").c_str()) == 0 ||
                strcmp(lower, X("x64dbg.exe").c_str()) == 0 ||
                strcmp(lower, X("x32dbg.exe").c_str()) == 0 ||
                strcmp(lower, X("ollydbg.exe").c_str()) == 0 ||
                strcmp(lower, X("processhacker.exe").c_str()) == 0 ||
                strcmp(lower, X("httpdebuggerui.exe").c_str()) == 0) {
                InternalBan(0xA017, X("blacklisted_process").c_str());
                CloseHandle(hSnap);
                return;
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

static void Detect_CPUID() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] >> 31) & 1) {
        __cpuid(cpuInfo, 0x40000000);
        char vendor[13] = {};
        memcpy(vendor, &cpuInfo[1], 4);
        memcpy(vendor + 4, &cpuInfo[2], 4);
        memcpy(vendor + 8, &cpuInfo[3], 4);
        if (strstr(vendor, X("KVMKVMKVM").c_str())) InternalBan(0xA00D, X("kvm_detected").c_str());
    }
}

static void Detect_ThreadWatchdog() {
    g_heartbeatTick.fetch_add(1, memory_order_relaxed);
    g_tickThreadId.store(GetCurrentThreadId(), memory_order_relaxed);

    if (!g_heartbeatArmed) {
        g_heartbeatArmed = true;
        return;
    }

    if (g_bgThread.joinable()) {}
}

extern LPVOID g_mainFiber;

static void Detect_FiberIntegrity() {
    if (!IsThreadAFiber()) return;

    LPVOID currentFiber = GetCurrentFiber();
    if (!currentFiber) return;

    if (g_mainFiber && currentFiber == g_mainFiber) {
        InternalLog(X("fiber_context_check: running in expected context").c_str());
    }

    if (g_mainFiber) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(g_mainFiber, &mbi, sizeof(mbi))) {
            if (mbi.State != MEM_COMMIT) {
                InternalBan(0xA011, X("fiber_context_corrupted").c_str());
            }
        }
    }
}

static void Detect_IatHooks() {
    HMODULE hMod = GetModuleHandleA(X("bigbro.dll").c_str());
    if (!hMod) return;

    auto* dos = (PIMAGE_DOS_HEADER)hMod;
    auto* nt  = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);

    auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir.VirtualAddress || !importDir.Size) return;

    auto* importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hMod + importDir.VirtualAddress);

    for (; importDesc->Name; importDesc++) {
        auto* thunk = (PIMAGE_THUNK_DATA)((BYTE*)hMod + importDesc->FirstThunk);
        for (; thunk->u1.Function; thunk++) {
            uintptr_t addr = thunk->u1.Function;

            HMODULE importMod = nullptr;
            if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)addr, &importMod)) {
                InternalBan(0xA012, X("iat_hook_unresolved").c_str());
                return;
            }
        }
    }
}

static void Detect_EatHooks() {
    HMODULE hMod = GetModuleHandleA(X("bigbro.dll").c_str());
    if (!hMod) return;

    auto* dos = (PIMAGE_DOS_HEADER)hMod;
    auto* nt  = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);

    auto& exportDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exportDir.VirtualAddress || !exportDir.Size) return;

    auto* exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + exportDir.VirtualAddress);
    auto* funcs   = (DWORD*)((BYTE*)hMod + exports->AddressOfFunctions);

    DWORD moduleBase = 0;
    DWORD moduleEnd  = nt->OptionalHeader.SizeOfImage;

    for (DWORD i = 0; i < exports->NumberOfFunctions; i++) {
        DWORD rva = funcs[i];
        if (rva == 0) continue;

        if (rva >= exportDir.VirtualAddress &&
            rva < exportDir.VirtualAddress + exportDir.Size) {
            continue;
        }
        if (rva >= moduleEnd) {
            InternalBan(0xA013, X("eat_hook_detected").c_str());
            return;
        }
    }
}


static __declspec(noinline) bool SafeCheckMZ(const BYTE* base) {
    __try {
        if (base[0] != 'M' || base[1] != 'Z') return false;
        LONG lfanew = ((const IMAGE_DOS_HEADER*)base)->e_lfanew;
        if (lfanew <= 0 || lfanew >= 0x1000) return false;
        return ((const IMAGE_NT_HEADERS*)(base + lfanew))->Signature == IMAGE_NT_SIGNATURE;
    } __except(EXCEPTION_EXECUTE_HANDLER) { return false; }
}

static void Detect_ManualMap() {

    struct ModRange { uintptr_t base; uintptr_t end; };
    ModRange knownMods[512];
    int knownCount = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me; me.dwSize = sizeof(me);
        if (Module32First(hSnap, &me)) {
            do {
                if (knownCount < 512) {
                    knownMods[knownCount].base = (uintptr_t)me.modBaseAddr;
                    knownMods[knownCount].end  = (uintptr_t)me.modBaseAddr + me.modBaseSize;
                    knownCount++;
                }
            } while (Module32Next(hSnap, &me));
        }
        CloseHandle(hSnap);
    }

    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0x10000;
    while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {

        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE &&
            mbi.BaseAddress == mbi.AllocationBase &&
            mbi.RegionSize >= 0x1000 &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {

            uintptr_t pageAddr = (uintptr_t)mbi.BaseAddress;


            bool inModule = false;
            for (int i = 0; i < knownCount; i++) {
                if (pageAddr >= knownMods[i].base && pageAddr < knownMods[i].end) {
                    inModule = true; break;
                }
            }

            if (!inModule && SafeCheckMZ((const BYTE*)mbi.BaseAddress)) {
                InternalBan(0xA018, X("manual_mapped_module").c_str());
                return;
            }
            if (!inModule && !SafeCheckMZ((const BYTE*)mbi.BaseAddress)) {
                uintptr_t allocBase = (uintptr_t)mbi.AllocationBase;
                MEMORY_BASIC_INFORMATION probe;
                uintptr_t walk = allocBase;
                int regionCount = 0;
                bool hasExec = false, hasNonExec = false;
                size_t totalSize = 0;
                while (VirtualQuery((LPCVOID)walk, &probe, sizeof(probe)) &&
                       (uintptr_t)probe.AllocationBase == allocBase) {
                    if (probe.State == MEM_COMMIT) {
                        regionCount++;
                        totalSize += probe.RegionSize;
                        if (probe.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
                            hasExec = true;
                        else
                            hasNonExec = true;
                    }
                    walk = (uintptr_t)probe.BaseAddress + probe.RegionSize;
                    if (walk <= (uintptr_t)probe.BaseAddress) break;
                }
            
                if (regionCount >= 2 && hasExec && hasNonExec && totalSize >= 0x10000) {
                    InternalBan(0xA01C, X("suspicious_exec_private").c_str());
                    return;
                }
            }
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (uintptr_t)mbi.BaseAddress) break;
    }
}


static void Detect_NtdllFullScan() {
    HMODULE hNtdll = Stealth::FindModule(X("ntdll.dll").c_str());
    if (!hNtdll) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva) return;

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hNtdll + expRva);
    DWORD* names = (DWORD*)((BYTE*)hNtdll + exports->AddressOfNames);
    DWORD* funcs = (DWORD*)((BYTE*)hNtdll + exports->AddressOfFunctions);
    WORD*  ords  = (WORD*)((BYTE*)hNtdll + exports->AddressOfNameOrdinals);

    int syscallCount = 0;
    int hookedCount = 0;
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)hNtdll + names[i]);
        if (name[0] != 'N' || name[1] != 't') continue;

        const BYTE* p = (const BYTE*)hNtdll + funcs[ords[i]];

        if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1) {
            syscallCount++;
            continue;
        }


        if (p[0] == 0xE9 || (p[0] == 0xFF && p[1] == 0x25) ||
            (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0)) {

            DWORD rva = funcs[ords[i]];
            if (rva < nt->OptionalHeader.SizeOfImage) {
                hookedCount++;
            }
        }
    }

    if (syscallCount > 10 && hookedCount >= 5) {
        InternalBan(0xA019, X("ntdll_mass_hook").c_str());
    }
}


static void Detect_ProcessDebugPort() {
    DETECT_BEGIN
    DWORD64 debugPort = 0;
    NTSTATUS status = DirectNtQueryInformationProcess(
        GetCurrentProcess(), 7 /* ProcessDebugPort */,
        &debugPort, sizeof(debugPort), nullptr);
    if (status == 0 && debugPort != 0) {
        InternalBan(OBF_U32(0xA01D), X("debug_port_detected").c_str());
    }
    DETECT_END;
}


static void Detect_BgThreadAlive() {
    if (!g_bgThread.joinable()) return;

    HANDLE hNative = g_bgThread.native_handle();
    if (!hNative) {
        InternalBan(0xA01E, X("bg_thread_handle_null").c_str());
        return;
    }

    DWORD exitCode = 0;
    if (GetExitCodeThread(hNative, &exitCode)) {
        if (exitCode != STILL_ACTIVE) {
            InternalBan(0xA01E, X("bg_thread_killed").c_str());
        }
    }
}


static int g_vehBaselineCount = -1;

static LONG WINAPI VehProbe(EXCEPTION_POINTERS*) {
    return EXCEPTION_CONTINUE_SEARCH;
}

static void Detect_VehChain() {
    PVOID hProbe = AddVectoredExceptionHandler(0, VehProbe);
    if (!hProbe) return;
    RemoveVectoredExceptionHandler(hProbe);

    if (g_vehBaselineCount < 0) {
        g_vehBaselineCount = 0;
    }
}


atomic<uint64_t> g_bgHeartbeat{0};

static void Detect_AntiSuspend() {
    if (!g_bgThread.joinable()) return;

    static uint64_t lastSeen = 0;
    static int missCount = 0;

    uint64_t current = g_bgHeartbeat.load(memory_order_relaxed);
    if (lastSeen == current && lastSeen > 0) {
        missCount++;
        if (missCount >= 5) {
            InternalBan(0xA01A, X("bg_thread_suspended").c_str());
        }
    } else {
        missCount = 0;
    }
    lastSeen = current;
}

#pragma section(".bigdata", read)
__declspec(allocate(".bigdata")) DetectionFunc g_nativeDispatch[] = {
    Detect_IsDebuggerPresent,
    Detect_DebuggerLatency,
    Detect_TimingAnomaly,
    Detect_QPCAnomaly,
    Detect_TickAnomaly,
    Detect_ThreadsAndHWBP,
    Detect_TextIntegrity,
    Detect_NtapiHooks,
    Detect_BlacklistedWindows,
    Detect_CPUID,
    Detect_ThreadWatchdog,
    Detect_FiberIntegrity,
    Detect_IatHooks,
    Detect_EatHooks,
    Detect_AntiSuspend,
    Detect_ProcessDebugPort,
    Detect_BgThreadAlive,
    Detect_VehChain,
};
static constexpr size_t kDispatchCount = sizeof(g_nativeDispatch) / sizeof(g_nativeDispatch[0]);

static __forceinline void Detect_DispatchWatchdog() {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(g_nativeDispatch, &mbi, sizeof(mbi))) return;
    if (g_dispatchProtect == 0) { g_dispatchProtect = mbi.Protect; return; }
    if (mbi.Protect != g_dispatchProtect) InternalBan(0xA008, X("dispatch_protect_tampered").c_str());

    Sha256Digest current;
    if (!CalculateSHA256(reinterpret_cast<const uint8_t*>(g_nativeDispatch),
                         sizeof(g_nativeDispatch), current))
        return;

    if (!g_dispatchHashSet) {
        g_dispatchHash = current;
        g_dispatchHashSet = true;
        return;
    }
    if (current != g_dispatchHash) InternalBan(0xA008, X("dispatch_content_tampered").c_str());
}

void CaptureDetectionBaselines() {
    Detect_TextIntegrity();
    Detect_DispatchWatchdog();
    Detect_IatHooks();
}

void RunNativeChecks() {
    if (g_config.flags & bigbro::Flag::NoNative) return;
    Detect_DispatchWatchdog();
    for (size_t i = 0; i < kDispatchCount; i++) {
        if (g_nativeDispatch[i]) RetpolineDispatch(g_nativeDispatch[i]);
    }
}

void RunHeavyChecks() {
    if (g_config.flags & bigbro::Flag::NoNative) return;
    Detect_ManualMap();
    Detect_NtdllFullScan();
}
