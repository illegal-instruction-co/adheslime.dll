#include "Detection.h"
#include "StealthImport.h"

static BigBro_BanCallbackFn g_cBanCallback = nullptr;
static BigBro_LogCallbackFn g_cLogCallback = nullptr;

extern "C" {

void BigBro_SetBanCallback(BigBro_BanCallbackFn cb) {
    g_cBanCallback = cb;
}

void BigBro_SetLogCallback(BigBro_LogCallbackFn cb) {
    g_cLogCallback = cb;
}

int BigBro_Init(uint32_t flags, const char* encryptionKey, const char* rulesDir) {
    bigbro::Config cfg{};
    cfg.flags = static_cast<bigbro::Flag>(flags);
    if (encryptionKey) cfg.encryptionKey = encryptionKey;
    if (rulesDir)      cfg.rulesDirectory = rulesDir;

    if (g_cBanCallback) {
        cfg.onBan = [](const bigbro::BanEvent& e) {
            g_cBanCallback(e.code, e.reason.c_str());
        };
    }
    if (g_cLogCallback) {
        cfg.onLog = [](const bigbro::LogEvent& e) {
            g_cLogCallback(e.message.c_str());
        };
    }

    return bigbro::SDK::Get().Init(cfg);
}

int BigBro_Tick() {
    return bigbro::SDK::Get().Tick();
}

void BigBro_Shutdown() {
    bigbro::SDK::Get().Shutdown();
}

int BigBro_IsBanned() {
    return bigbro::SDK::Get().IsBanned() ? 1 : 0;
}

int BigBro_LoadRule(const char* jsPath) {
    if (!jsPath) return -1;
    return bigbro::SDK::Get().LoadRule(jsPath);
}

void BigBro_ProtectVariable(const char* name, const void* ptr, uint32_t size) {
    if (!name) return;
    bigbro::SDK::Get().ProtectVariable(name, ptr, size);
}

void BigBro_UnprotectVariable(const char* name) {
    if (!name) return;
    bigbro::SDK::Get().UnprotectVariable(name);
}

void BigBro_UpdateProtectedVariable(const char* name) {
    if (!name) return;
    bigbro::SDK::Get().UpdateProtectedVariable(name);
}

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

uint32_t GetBgThreadId() {
    if (!g_bgThread.joinable()) return 0;
    return (uint32_t)GetThreadId(g_bgThread.native_handle());
}

extern int BigBro_Challenge_Impl(const uint8_t* nonce, uint32_t nonceLen,
                                  uint8_t* sigOut, uint32_t sigBufLen);
int BigBro_Challenge(const uint8_t* nonce, uint32_t nonceLen,
                     uint8_t* sigOut, uint32_t sigBufLen) {
    return BigBro_Challenge_Impl(nonce, nonceLen, sigOut, sigBufLen);
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
