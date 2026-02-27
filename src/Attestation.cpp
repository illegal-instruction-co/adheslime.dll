#include <windows.h>

#include <bcrypt.h>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

static constexpr uint8_t kObfKey = 0xA7;

#include "attestation_key.gen.h"

static void DeobfuscateKey(uint8_t* out, const uint8_t* enc, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = enc[i] ^ (kObfKey + (uint8_t)(i * 0x37));
    }
}

extern "C" int BigBro_Challenge_Impl(const uint8_t* nonce, uint32_t nonceLen,
                          uint8_t* sigOut, uint32_t sigBufLen) {
    if (!nonce || nonceLen == 0 || !sigOut || sigBufLen < 64) return -1;

    uint8_t privBlob[sizeof(kEncPrivateKey)];
    DeobfuscateKey(privBlob, kEncPrivateKey, sizeof(kEncPrivateKey));

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) { return -2; }

    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                 &hKey, privBlob, sizeof(privBlob), 0);
    SecureZeroMemory(privBlob, sizeof(privBlob));

    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -3;
    }

    BCRYPT_ALG_HANDLE hHashAlg = nullptr;
    status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -4;
    }

    uint8_t hash[32];
    ULONG hashLen = 0;
    ULONG resultLen = 0;
    BCryptGetProperty(hHashAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &resultLen, 0);

    status = BCryptHash(hHashAlg, NULL, 0, (PUCHAR)nonce, nonceLen, hash, sizeof(hash));
    BCryptCloseAlgorithmProvider(hHashAlg, 0);

    if (!NT_SUCCESS(status)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return -5;
    }

    ULONG sigLen = 0;
    status = BCryptSignHash(hKey, NULL, hash, sizeof(hash),
                            sigOut, sigBufLen, &sigLen, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!NT_SUCCESS(status)) return -6;
    return (int)sigLen;
}
