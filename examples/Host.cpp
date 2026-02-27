/**
 * BigBro SDK - Integration Demo (C API / Ordinal-Only)
 *
 * Shows how to:
 *   1. Load the DLL at runtime (no import lib needed)
 *   2. Resolve exports by ordinal only
 *   3. Set callbacks, init, tick loop, shutdown
 */

#include <cstdio>
#include <cstdint>
#include <windows.h>

// ============================================================
// Ordinal-based function pointer types
// ============================================================
typedef void  (*SetBanCb_t)(void(*)(uint32_t, const char*));
typedef void  (*SetLogCb_t)(void(*)(const char*));
typedef int   (*Init_t)(uint32_t, const char*, const char*);
typedef int   (*Tick_t)();
typedef void  (*Shutdown_t)();
typedef int   (*IsBanned_t)();

// ============================================================
// Callbacks
// ============================================================
static void __cdecl OnBan(uint32_t code, const char* reason) {
    printf("\n  [BANNED] Code: 0x%04X | Reason: %s\n\n", code, reason);
}

static void __cdecl OnLog(const char* message) {
    printf("  [log] %s\n", message);
}

int main() {
    printf("=== BigBro SDK Demo (C API) ===\n\n");

    // --- Load DLL ---
    HMODULE hDll = LoadLibraryA("bigbro.dll");
    if (!hDll) {
        printf("Failed to load bigbro.dll (error %lu)\n", GetLastError());
        return 1;
    }

    // --- Resolve by ordinal ---
    auto SetBanCb = (SetBanCb_t)GetProcAddress(hDll, MAKEINTRESOURCEA(12));
    auto SetLogCb = (SetLogCb_t)GetProcAddress(hDll, MAKEINTRESOURCEA(13));
    auto Init     = (Init_t)    GetProcAddress(hDll, MAKEINTRESOURCEA(7));
    auto Tick     = (Tick_t)    GetProcAddress(hDll, MAKEINTRESOURCEA(8));
    auto Shutdown = (Shutdown_t)GetProcAddress(hDll, MAKEINTRESOURCEA(9));
    auto IsBanned = (IsBanned_t)GetProcAddress(hDll, MAKEINTRESOURCEA(10));

    if (!Init || !Tick || !Shutdown || !IsBanned) {
        printf("Failed to resolve exports\n");
        FreeLibrary(hDll);
        return 2;
    }

    // --- Set callbacks before Init ---
    if (SetBanCb) SetBanCb(OnBan);
    if (SetLogCb) SetLogCb(OnLog);

    // --- Init (flags=0, default key, no rules dir) ---
    int ret = Init(0, "bigbro-default-key", nullptr);
    if (ret != 0) {
        printf("Init failed: %d\n", ret);
        FreeLibrary(hDll);
        return 3;
    }

    // --- Game Loop ---
    printf("\n  Starting detection loop (5 ticks)...\n\n");
    for (int i = 0; i < 5; i++) {
        printf("  Tick %d/5: ", i + 1);
        int result = Tick();
        if (result == 1)       { printf("BANNED\n"); break; }
        else if (result < 0)   { printf("ERROR (%d)\n", result); }
        else                   { printf("CLEAN\n"); }
        Sleep(1000);
    }

    Shutdown();
    FreeLibrary(hDll);
    printf("\nDone.\n");
    return 0;
}
