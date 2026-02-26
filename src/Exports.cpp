#include "Detection.h"
#include "StealthImport.h"

extern "C" {

void RunFullSuite() {
    if (!g_initialized) {
        bigbro::SDK::Get().Init({});
    }
    bigbro::SDK::Get().Tick();
}

int IsUserBanned() {
    return bigbro::SDK::Get().IsBanned() ? 1 : 0;
}

void TriggerSelfTamper() {
    DWORD old;
    VirtualProtect((void*)g_nativeDispatch, sizeof(DetectionFunc) * 18, PAGE_EXECUTE_READWRITE, &old);
}

void StartBackgroundDetection() {
    g_bgStop = false;

    if (g_bgThread.joinable()) return; 

    g_bgThread = thread([]() {
        if (!g_initialized) bigbro::SDK::Get().Init({});
        while (!g_bgStop && !g_banned) {
            bigbro::SDK::Get().Tick();
            for (int i = 0; i < 20 && !g_bgStop; ++i)
                this_thread::sleep_for(chrono::milliseconds(100));
        }
    });
}

void RunHeavyChecksExport() {
    RunHeavyChecks();
}

DWORD GetBgThreadId() {
    if (!g_bgThread.joinable()) return 0;
    return GetThreadId(g_bgThread.native_handle());
}

} 

#pragma section(".CRT$XLB", read)
static void NTAPI TlsCallback(PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        auto pIsDbg = Stealth::Resolve<BOOL(WINAPI*)()>(X("kernel32.dll").c_str(), X("IsDebuggerPresent").c_str());
        if (pIsDbg && pIsDbg()) {
            InternalBan(0xA00A, X("debugger_tls").c_str());
        }
    }
}
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK pTlsCallback = TlsCallback;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(hModule);
    return TRUE;
}
