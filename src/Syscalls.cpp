#include "Syscalls.h"
#include "StealthImport.h"

static __forceinline DWORD ExtractSyscallNumber(const BYTE* pFunc) {
    if (!pFunc) return 0;

    if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1 && pFunc[3] == 0xB8) {
        return *(DWORD*)(pFunc + 4);
    }

    for (int i = 0; i < 32; i++) {
        if (pFunc[i] == 0xB8 && pFunc[i+3] == 0x00 && pFunc[i+4] == 0x00) {
            DWORD candidate = *(DWORD*)(pFunc + i + 1);
            if (candidate > 0 && candidate < 0x2000) {
                return candidate;
            }
        }
    }

    return 0;
}

static __forceinline bool ResolveSyscall(const char* funcName, DWORD& outNumber) {
    HMODULE hNtdll = Stealth::FindModule(X("ntdll.dll").c_str());
    if (!hNtdll) return false;

    auto pFunc = (const BYTE*)Stealth::FindExport(hNtdll, funcName);
    if (!pFunc) return false;

    outNumber = ExtractSyscallNumber(pFunc);
    return outNumber != 0;
}

bool SyscallInit() {
    bool allOk = true;

    struct { const char* name; DWORD* target; } syscalls[] = {
        { "NtQueryInformationProcess",  &g_sysNtQueryInformationProcess },
        { "NtQueryInformationThread",   &g_sysNtQueryInformationThread },
        { "NtGetContextThread",         &g_sysNtGetContextThread },
        { "NtSetContextThread",         &g_sysNtSetContextThread },
        { "NtQueryVirtualMemory",       &g_sysNtQueryVirtualMemory },
        { "NtOpenThread",               &g_sysNtOpenThread },
        { "NtSuspendThread",            &g_sysNtSuspendThread },
        { "NtResumeThread",             &g_sysNtResumeThread },
        { "NtClose",                    &g_sysNtClose },
    };

    for (auto& sc : syscalls) {
        if (!ResolveSyscall(sc.name, *sc.target)) {
            allOk = false;
            InternalLog(("syscall_resolve_failed: " + string(sc.name)).c_str());
        }
    }

    if (allOk) InternalLog(X("syscall_init: all syscall numbers resolved").c_str());

    const char* dangerousNames[] = {
        "NtTerminateProcess",
        "NtTerminateThread",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtSuspendProcess",
        "NtResumeProcess",
        "NtSuspendThread",
        "NtResumeThread",
        "NtSetContextThread",
        "NtAllocateVirtualMemory",
        "NtFreeVirtualMemory",
        "NtCreateThread",
        "NtCreateThreadEx",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "NtSetInformationProcess",
    };
    g_blacklistCount = 0;
    for (const auto& name : dangerousNames) {
        DWORD num = 0;
        if (ResolveSyscall(name, num) && g_blacklistCount < 32) {
            g_syscallBlacklist[g_blacklistCount++] = num;
        }
    }
    InternalLog(("syscall_blacklist: " + to_string(g_blacklistCount) + " dangerous syscalls blocked").c_str());
    const char* safeNames[] = {
        "NtQueryInformationProcess",
        "NtQueryVirtualMemory",
        "NtQueryInformationThread",
    };
    g_whitelistCount = 0;
    for (const auto& name : safeNames) {
        DWORD num = 0;
        if (ResolveSyscall(name, num) && g_whitelistCount < 16) {
            g_syscallWhitelist[g_whitelistCount++] = num;
        }
    }

    return allOk;
}

static uint8_t  g_aesKey[32] = {};  
static bool     g_aesKeyReady = false;

static __forceinline bool AesGcmEncrypt(const uint8_t* plain, size_t plainLen, vector<uint8_t>& out) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return false;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)g_aesKey, 32, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    uint8_t iv[12];
    BCryptGenRandom(nullptr, iv, sizeof(iv), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    uint8_t tag[16] = {};
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = iv;
    authInfo.cbNonce = sizeof(iv);
    authInfo.pbTag = tag;
    authInfo.cbTag = sizeof(tag);

    ULONG cbResult = 0;
    vector<uint8_t> cipher(plainLen);

    NTSTATUS status = BCryptEncrypt(hKey, (PUCHAR)plain, (ULONG)plainLen,
                                     &authInfo, nullptr, 0,
                                     cipher.data(), (ULONG)cipher.size(), &cbResult, 0);
    if (status == 0) {
        out.clear();
        out.insert(out.end(), iv, iv + 12);
        out.insert(out.end(), cipher.begin(), cipher.begin() + cbResult);
        out.insert(out.end(), tag, tag + 16);
        ok = true;
    }

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

static __forceinline bool AesGcmDecrypt(const vector<uint8_t>& enc, vector<uint8_t>& out) {
    if (enc.size() < 12 + 16) return false;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0) return false;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)g_aesKey, 32, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    const uint8_t* iv   = enc.data();
    size_t cipherLen     = enc.size() - 12 - 16;
    const uint8_t* cipher = enc.data() + 12;
    uint8_t tag[16];
    memcpy(tag, enc.data() + enc.size() - 16, 16);

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv;
    authInfo.cbNonce = 12;
    authInfo.pbTag = tag;
    authInfo.cbTag = 16;

    out.resize(cipherLen);
    ULONG cbResult = 0;

    NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)cipher, (ULONG)cipherLen,
                                     &authInfo, nullptr, 0,
                                     out.data(), (ULONG)out.size(), &cbResult, 0);
    ok = (status == 0);
    if (ok) out.resize(cbResult);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

#pragma pack(push, 1)
struct StatePlain {
    uint8_t initialized;
    uint8_t banned;
    uint8_t textBaselineSet;
    uint8_t dispatchHashSet;
    uint8_t iatBaselineSet;

    uint64_t onBanPtr; 
    uint64_t dukPtr; 
    uint32_t ruleCount; 
    uint32_t dispatchCount;
};
#pragma pack(pop)

static vector<uint8_t> g_shadowCipher;

static __forceinline void WriteShadow() {
    StatePlain sp = {};
    sp.initialized     = (uint8_t)g_initialized.load();
    sp.banned          = (uint8_t)g_banned.load();
    sp.textBaselineSet = (uint8_t)g_textBaselineSet;
    sp.dispatchHashSet = (uint8_t)g_dispatchHashSet;
    sp.iatBaselineSet  = (uint8_t)g_iatBaselineSet;
    // Extended fields
    sp.onBanPtr       = g_config.onBan ? (uint64_t)&g_config.onBan : 0;
    sp.dukPtr         = (uint64_t)(uintptr_t)g_duk;
    sp.ruleCount      = (uint32_t)g_ruleScripts.size();
    sp.dispatchCount  = 18;
    AesGcmEncrypt(reinterpret_cast<uint8_t*>(&sp), sizeof(sp), g_shadowCipher);
}

void ShadowStateInit() {
    BCRYPT_ALG_HANDLE hRng = nullptr;
    if (BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, nullptr, 0) == 0) {
        BCryptGenRandom(hRng, g_aesKey, 32, 0);
        BCryptCloseAlgorithmProvider(hRng, 0);
    } else {
        uint64_t tsc = __rdtsc();
        if (tsc == 0) tsc = 0xDEADBEEFCAFEBABEull;
        Sha256Digest keyHash;
        CalculateSHA256(reinterpret_cast<const uint8_t*>(&tsc), sizeof(tsc), keyHash);
        memcpy(g_aesKey, keyHash.data(), 32);
    }
    g_aesKeyReady = true;

    WriteShadow();
}

void ShadowStateUpdate() {
    if (!g_aesKeyReady) return;
    WriteShadow();
}

void ShadowStateVerify() {
    if (!g_aesKeyReady) return;

    vector<uint8_t> plain;
    if (!AesGcmDecrypt(g_shadowCipher, plain)) {
        InternalBan(0xA014, X("shadow_state_corrupted").c_str());
        return;
    }

    if (plain.size() != sizeof(StatePlain)) {
        InternalBan(0xA014, X("shadow_state_size_mismatch").c_str());
        return;
    }

    auto* sp = reinterpret_cast<const StatePlain*>(plain.data());

    if ((bool)g_initialized.load() != (bool)sp->initialized) {
        InternalBan(0xA014, X("g_initialized_tampered").c_str());
        return;
    }
    if ((bool)g_banned.load() != (bool)sp->banned) {
        InternalBan(0xA014, X("g_banned_tampered").c_str());
        return;
    }
    if (g_textBaselineSet != (bool)sp->textBaselineSet) {
        InternalBan(0xA014, X("baseline_flags_tampered").c_str());
        return;
    }
    if (g_dispatchHashSet != (bool)sp->dispatchHashSet) {
        InternalBan(0xA014, X("baseline_flags_tampered").c_str());
        return;
    }
    if (g_iatBaselineSet != (bool)sp->iatBaselineSet) {
        InternalBan(0xA014, X("baseline_flags_tampered").c_str());
        return;
    }

    if (sp->dukPtr != (uint64_t)(uintptr_t)g_duk) {
        InternalBan(0xA014, X("js_engine_ptr_tampered").c_str());
        return;
    }
    if (sp->ruleCount != (uint32_t)g_ruleScripts.size()) {
        InternalBan(0xA014, X("rule_count_tampered").c_str());
        return;
    }

    WriteShadow();
}

static map<string, ProtectedVar> g_protectedVars;

void ProtectedVarRegister(string_view name, const void* ptr, size_t size) {
    if (!ptr || size == 0 || !g_aesKeyReady) return;

    ProtectedVar pv;
    pv.ptr = ptr;
    pv.size = size;

    AesGcmEncrypt(reinterpret_cast<const uint8_t*>(ptr), size, pv.shadow);

    g_protectedVars[string(name)] = move(pv);
}

void ProtectedVarUnregister(string_view name) {
    g_protectedVars.erase(string(name));
}

void ProtectedVarUpdate(string_view name) {
    auto it = g_protectedVars.find(string(name));
    if (it == g_protectedVars.end()) return;

    auto& pv = it->second;
    AesGcmEncrypt(reinterpret_cast<const uint8_t*>(pv.ptr), pv.size, pv.shadow);
}

void ProtectedVarVerifyAll() {
    if (!g_aesKeyReady) return;

    for (auto& [name, pv] : g_protectedVars) {
        vector<uint8_t> decoded;
        if (!AesGcmDecrypt(pv.shadow, decoded)) {
            InternalBan(0xA015, ("protected_var_shadow_corrupted:" + name).c_str());
            return;
        }
        if (decoded.size() != pv.size ||
            memcmp(decoded.data(), pv.ptr, pv.size) != 0) {
            InternalBan(0xA015, ("protected_var_tampered:" + name).c_str());
            return;
        }
    }
}

