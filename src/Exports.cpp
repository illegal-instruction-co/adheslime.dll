/**
 * C Exports, DllMain, TLS Callback
 *
 * Legacy compatibility layer + DLL entry points.
 */
#include "Detection.h"

// ============================================================
// C EXPORTS (legacy compat + DLL boundary)
// ============================================================
extern "C" {

ADHESLIME_API void RunFullSuite() {
    if (!g_initialized) {
        adheslime::SDK::Get().Init({});
    }
    adheslime::SDK::Get().Tick();
}

ADHESLIME_API int IsUserBanned() {
    return adheslime::SDK::Get().IsBanned() ? 1 : 0;
}

ADHESLIME_API void TriggerSelfTamper() {
    DWORD old;
    VirtualProtect((void*)g_nativeDispatch, sizeof(g_nativeDispatch[0]) * 10, PAGE_EXECUTE_READWRITE, &old);
}

ADHESLIME_API void StartBackgroundDetection() {
    thread([]() {
        if (!g_initialized) adheslime::SDK::Get().Init({});
        while (!g_banned) {
            adheslime::SDK::Get().Tick();
            this_thread::sleep_for(chrono::seconds(2));
        }
    }).detach();
}

} // extern "C"

// ============================================================
// TLS CALLBACK
// ============================================================
#pragma section(".CRT$XLB", read)
static void NTAPI TlsCallback(PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        if (IsDebuggerPresent()) ExitProcess(0xDEAD);
    }
}
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK pTlsCallback = TlsCallback;

// ============================================================
// DLLMAIN
// ============================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(hModule);
    return TRUE;
}
