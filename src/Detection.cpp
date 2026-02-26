#include "Detection.h"

// ============================================================
// SEH WRAPPER (separate function — no C++ destructors)
// ============================================================
__declspec(noinline) static void RaiseExceptionWrapper() {
    __try {
        RaiseException(0x40010006, 0, 0, NULL);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

// ============================================================
// NATIVE DETECTION FUNCTIONS
// ============================================================
static void Detect_IsDebuggerPresent() {
    if (IsDebuggerPresent()) InternalBan(0xA00A, "debugger_present");
}

static void Detect_DebuggerLatency() {
    auto start = chrono::high_resolution_clock::now();
    RaiseExceptionWrapper();
    auto end = chrono::high_resolution_clock::now();
    auto ms = (uint32_t)chrono::duration_cast<chrono::milliseconds>(end - start).count();
    if (ms > 500) InternalBan(0xA001, "debugger_latency");
}

static void Detect_TimingAnomaly() {
    static constexpr uintptr_t kUserSharedData = 0x7FFE0000;
    volatile unsigned long long* pSysTime = (unsigned long long*)(kUserSharedData + 0x14);
    unsigned long long t1 = *pSysTime;
    this_thread::sleep_for(chrono::milliseconds(10));
    unsigned long long t2 = *pSysTime;
    if (t2 - t1 == 0) InternalBan(0xA002, "timing_anomaly");
}

static void Detect_QPCAnomaly() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    this_thread::sleep_for(chrono::milliseconds(5));
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;
    if (elapsed > 500.0) InternalBan(0xA00B, "qpc_anomaly");
}

static void Detect_TickAnomaly() {
    DWORD t1 = GetTickCount();
    this_thread::sleep_for(chrono::milliseconds(5));
    DWORD t2 = GetTickCount();
    if (t2 - t1 > 500) InternalBan(0xA00C, "tick_anomaly");
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
                bool mod = false;
                if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
                    ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0; ctx.Dr7 = 0;
                    mod = true; InternalBan(0xA003, "hwbp_detected");
                }
                bool inMod = false; DWORD64 nearest = 0;
                for (const auto& b : moduleBounds) {
                    if (ctx.Rip >= b.first && ctx.Rip < b.second) { inMod = true; break; }
                    if (!nearest) nearest = b.first;
                }
                if (!inMod && nearest) { ctx.Rip = nearest; mod = true; InternalBan(0xA004, "external_execution"); }
                if (mod) SetThreadContext(hThread, &ctx);
            }
            ResumeThread(hThread); CloseHandle(hThread);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
}

static void Detect_TextIntegrity() {
    HMODULE hMod = GetModuleHandleA(X("adheslime.dll").c_str());
    if (!hMod) return;
    auto* dos = (PIMAGE_DOS_HEADER)hMod;
    auto* nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sec[i].Name, X(".text").c_str()) == 0) {
            uint32_t crc = CalculateCRC32((BYTE*)hMod + sec[i].VirtualAddress, sec[i].Misc.VirtualSize);
            if (g_textBaseline == 0) { g_textBaseline = crc; return; }
            if (crc != g_textBaseline) InternalBan(0xA005, "text_integrity");
            return;
        }
    }
}

static void Detect_NtapiHooks() {
    auto h = GetModuleHandleA(X("ntdll.dll").c_str());
    auto p = (BYTE*)GetProcAddress(h, X("NtOpenProcess").c_str());
    if (p && *p == 0xE9) InternalBan(0xA006, "ntapi_hook");
}

static void Detect_BlacklistedWindows() {
    if (FindWindowA(NULL, X("x64dbg").c_str())) InternalBan(0xA007, "blacklisted_window");
    if (FindWindowA(NULL, X("Cheat Engine").c_str())) InternalBan(0xA007, "blacklisted_window");
    if (FindWindowA(NULL, X("Process Hacker").c_str())) InternalBan(0xA007, "blacklisted_window");
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
        if (strstr(vendor, "KVMKVMKVM")) InternalBan(0xA00D, "kvm_detected");
    }
}

// ============================================================
// DISPATCH TABLE — .adhdata section
// ============================================================
#pragma section(".adhdata", read)
__declspec(allocate(".adhdata")) DetectionFunc g_nativeDispatch[] = {
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
};
static constexpr size_t kDispatchCount = sizeof(g_nativeDispatch) / sizeof(g_nativeDispatch[0]);

static void Detect_DispatchWatchdog() {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(g_nativeDispatch, &mbi, sizeof(mbi))) return;
    if (g_dispatchProtect == 0) { g_dispatchProtect = mbi.Protect; return; }
    if (mbi.Protect != g_dispatchProtect) InternalBan(0xA008, "dispatch_tampered");
}

// ============================================================
// PUBLIC INTERFACE
// ============================================================
void CaptureDetectionBaselines() {
    Detect_TextIntegrity();
    Detect_DispatchWatchdog();
}

void RunNativeChecks() {
    if (g_config.flags & adheslime::Flag::NoNative) return;
    Detect_DispatchWatchdog();
    for (size_t i = 0; i < kDispatchCount; i++) {
        if (g_nativeDispatch[i]) RetpolineDispatch(g_nativeDispatch[i]);
    }
}
