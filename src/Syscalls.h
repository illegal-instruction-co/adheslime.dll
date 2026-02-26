#pragma once

#include "Common.h"

extern "C" {
    NTSTATUS DirectNtQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
    NTSTATUS DirectNtQueryInformationThread(HANDLE, ULONG, PVOID, ULONG, PULONG);
    NTSTATUS DirectNtGetContextThread(HANDLE, PCONTEXT);
    NTSTATUS DirectNtSetContextThread(HANDLE, PCONTEXT);
    NTSTATUS DirectNtQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
    NTSTATUS DirectNtOpenThread(PHANDLE, ACCESS_MASK, PVOID, PVOID);
    NTSTATUS DirectNtSuspendThread(HANDLE, PULONG);
    NTSTATUS DirectNtResumeThread(HANDLE, PULONG);
    NTSTATUS DirectNtClose(HANDLE);

    NTSTATUS GenericSyscall(DWORD num, ...);

    extern DWORD g_sysNtQueryInformationProcess;
    extern DWORD g_sysNtQueryInformationThread;
    extern DWORD g_sysNtGetContextThread;
    extern DWORD g_sysNtSetContextThread;
    extern DWORD g_sysNtQueryVirtualMemory;
    extern DWORD g_sysNtOpenThread;
    extern DWORD g_sysNtSuspendThread;
    extern DWORD g_sysNtResumeThread;
    extern DWORD g_sysNtClose;
}

bool SyscallInit();

inline DWORD g_syscallBlacklist[32] = {};
inline int   g_blacklistCount = 0;

inline DWORD g_syscallWhitelist[16] = {};
inline int   g_whitelistCount = 0;

__forceinline bool IsSyscallBlacklisted(DWORD num) {
    for (int i = 0; i < g_blacklistCount; i++) {
        if (g_syscallBlacklist[i] == num) return true;
    }
    return false;
}

__forceinline bool IsSyscallWhitelisted(DWORD num) {
    for (int i = 0; i < g_whitelistCount; i++) {
        if (g_syscallWhitelist[i] == num) return true;
    }
    return false;
}

struct StateSnapshot {
    bool     initialized;
    bool     banned;
    bool     textBaselineSet;
    bool     dispatchHashSet;
    bool     iatBaselineSet;
    uint64_t heartbeatTick;

    Sha256Digest hash;
};

void ShadowStateInit();

void ShadowStateVerify();

void ShadowStateUpdate();

struct ProtectedVar {
    const void*         ptr;
    size_t              size;
    std::vector<uint8_t> shadow; 
};

void ProtectedVarRegister(std::string_view name, const void* ptr, size_t size);
void ProtectedVarUnregister(std::string_view name);
void ProtectedVarUpdate(std::string_view name);
void ProtectedVarVerifyAll();
