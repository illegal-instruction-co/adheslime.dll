/**
 * BigBro SDK - Integration Demo (C API / Ordinal-Only)
 *
 * Shows how to:
 *   1. Load the DLL at runtime (no import lib needed)
 *   2. Resolve exports by ordinal only
 *   3. Set callbacks, init, tick loop, shutdown
 *   4. Verify DLL authenticity via ECDSA attestation
 */

#include <cstdio>
#include <cstdint>
#include <windows.h>
#include <bcrypt.h>
#include "bigbro/attestation_pubkey.h"

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

// ============================================================
// Ordinal-based function pointer types
// ============================================================
typedef void  (*SetBanCb_t)(void(*)(uint32_t, const char*));
typedef void  (*SetLogCb_t)(void(*)(const char*));
typedef int   (*Init_t)(uint32_t, const char*, const char*);
typedef int   (*Tick_t)();
typedef void  (*Shutdown_t)();
typedef int   (*IsBanned_t)();
typedef int   (*Challenge_t)(const uint8_t*, uint32_t, uint8_t*, uint32_t);

// ============================================================
// Callbacks
// ============================================================
static void __cdecl OnBan(uint32_t code, const char* reason) {
    printf("\n  [BANNED] Code: 0x%04X | Reason: %s\n\n", code, reason);
}

static void __cdecl OnLog(const char* message) {
    printf("  [log] %s\n", message);
}

// ============================================================
// DLL Attestation — verify the loaded DLL is genuine
// ============================================================
static bool VerifyDll(HMODULE hDll) {
    auto Challenge = (Challenge_t)GetProcAddress(hDll, MAKEINTRESOURCEA(17));
    if (!Challenge) {
        printf("  [ATTEST] Challenge export not found!\n");
        return false;
    }

    // Generate random nonce
    uint8_t nonce[32];
    BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // Ask DLL to sign the nonce
    uint8_t signature[64];
    int sigLen = Challenge(nonce, sizeof(nonce), signature, sizeof(signature));
    if (sigLen <= 0) {
        printf("  [ATTEST] DLL failed to sign nonce (err=%d)\n", sigLen);
        return false;
    }

    // Verify signature with embedded public key
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0)))
        return false;

    if (!NT_SUCCESS(BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hKey,
                                        (PUCHAR)kAttestationPubKey, sizeof(kAttestationPubKey), 0))) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Hash the nonce
    BCRYPT_ALG_HANDLE hHashAlg = nullptr;
    BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    uint8_t hash[32];
    BCryptHash(hHashAlg, NULL, 0, nonce, sizeof(nonce), hash, sizeof(hash));
    BCryptCloseAlgorithmProvider(hHashAlg, 0);

    // Verify
    NTSTATUS status = BCryptVerifySignature(hKey, NULL, hash, sizeof(hash),
                                            signature, (ULONG)sigLen, 0);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return NT_SUCCESS(status);
}

int main() {
    printf("=== BigBro SDK Demo (C API) ===\n\n");

    // --- Load DLL ---
    HMODULE hDll = LoadLibraryA("bigbro.dll");
    if (!hDll) {
        printf("Failed to load bigbro.dll (error %lu)\n", GetLastError());
        return 1;
    }

    // --- DLL Attestation ---
    printf("  [ATTEST] Verifying DLL authenticity... ");
    if (VerifyDll(hDll)) {
        printf("GENUINE\n\n");
    } else {
        printf("FAILED — DLL may be tampered!\n");
        FreeLibrary(hDll);
        return 99;
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

    // --- Init ---
    int ret = Init(0, "bigbro-default-key", nullptr);
    if (ret != 0) {
        printf("Init failed: %d\n", ret);
        FreeLibrary(hDll);
        return 3;
    }

    // --- Game Loop ---
    printf("  Starting detection loop (ticks)...\n\n");
    for (int i = 0; true; i++) {
        printf("  Tick %d: ", i + 1);
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
