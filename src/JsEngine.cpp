#include "JsEngine.h"
#include "Syscalls.h"
#include "StealthImport.h"
#include "Obfuscation.h"

#include "engine/duktape.h"

#include <TlHelp32.h>

static duk_ret_t js_isDebuggerPresent(duk_context* ctx) {
    auto pIsDbg = Stealth::Resolve<BOOL(WINAPI*)()>(
        X("kernel32.dll").c_str(), X("IsDebuggerPresent").c_str());
    duk_push_boolean(ctx, pIsDbg && pIsDbg()); return 1;
}
static duk_ret_t js_findWindow(duk_context* ctx) {
    auto pFindWindow = Stealth::Resolve<HWND(WINAPI*)(LPCSTR, LPCSTR)>(
        X("user32.dll").c_str(), X("FindWindowA").c_str());
    if (!pFindWindow) { duk_push_boolean(ctx, 0); return 1; }
    duk_push_boolean(ctx, pFindWindow(NULL, duk_require_string(ctx, 0)) != NULL); return 1;
}
static duk_ret_t js_checkTimingAnomaly(duk_context* ctx) {
    LARGE_INTEGER f, s, e; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&s);
    Sleep(5); QueryPerformanceCounter(&e);
    duk_push_boolean(ctx, (double)(e.QuadPart - s.QuadPart) / f.QuadPart * 1000.0 > 50.0); return 1;
}
static duk_ret_t js_verifyTextIntegrity(duk_context* ctx) {
    HMODULE hMod = Stealth::FindModule(X("bigbro.dll").c_str());
    if (!hMod || !g_textBaselineSet) { duk_push_boolean(ctx, 1); return 1; }
    auto* dos = (PIMAGE_DOS_HEADER)hMod;
    auto* nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sec[i].Name, ".text") == 0) {
            Sha256Digest current;
            if (!CalculateSHA256((uint8_t*)hMod + sec[i].VirtualAddress,
                                sec[i].Misc.VirtualSize, current)) {
                duk_push_boolean(ctx, 1); return 1;
            }
            duk_push_boolean(ctx, current == g_textBaseline);
            return 1;
        }
    }
    duk_push_boolean(ctx, 1); return 1;
}

static duk_ret_t js_checkHardwareBreakpoints(duk_context* ctx) {
    struct HwbpCheckData {
        HANDLE targetThread;
        bool   found;
    };

    HANDLE hCurrent = nullptr;
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                    GetCurrentProcess(), &hCurrent, 0, FALSE, DUPLICATE_SAME_ACCESS);
    if (!hCurrent) { duk_push_boolean(ctx, 0); return 1; }

    HwbpCheckData data{hCurrent, false};

    HANDLE hChecker = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        auto* d = (HwbpCheckData*)param;
        SuspendThread(d->targetThread);
        CONTEXT c = {}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(d->targetThread, &c)) {
            d->found = (c.Dr0 || c.Dr1 || c.Dr2 || c.Dr3);
        }
        ResumeThread(d->targetThread);
        return 0;
    }, &data, 0, nullptr);

    if (hChecker) {
        WaitForSingleObject(hChecker, 2000);
        CloseHandle(hChecker);
    }
    CloseHandle(hCurrent);

    duk_push_boolean(ctx, data.found);
    return 1;
}

static duk_ret_t js_scanNtapiHooks(duk_context* ctx) {
    auto h = Stealth::FindModule(X("ntdll.dll").c_str());
    if (!h) { duk_push_boolean(ctx, 0); return 1; }

    const char* functions[] = {
        "NtOpenProcess", "NtReadVirtualMemory", "NtWriteVirtualMemory",
    };
    for (const char* fn : functions) {
        auto p = (BYTE*)Stealth::FindExport(h, fn);
        if (!p) continue;
        if (p[0] == 0xE9) { duk_push_boolean(ctx, 1); return 1; }
        if (p[0] == 0xFF && p[1] == 0x25) { duk_push_boolean(ctx, 1); return 1; }
        if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0)
            { duk_push_boolean(ctx, 1); return 1; }
        if (p[0] != 0x4C || p[1] != 0x8B || p[2] != 0xD1 || p[3] != 0xB8)
            { duk_push_boolean(ctx, 1); return 1; }
    }
    duk_push_boolean(ctx, 0); return 1;
}
static duk_ret_t js_reportBan(duk_context* ctx) {
    InternalBan((uint32_t)duk_require_number(ctx, 0), duk_require_string(ctx, 1)); return 0;
}
static duk_ret_t js_log(duk_context* ctx) {
    InternalLog(duk_require_string(ctx, 0)); return 0;
}

static duk_ret_t js_readMemory(duk_context* ctx) {
    uint64_t addr = (uint64_t)duk_require_number(ctx, 0);
    int size = duk_require_int(ctx, 1);
    if (size <= 0 || size > 4096) { duk_push_null(ctx); return 1; }

    void* buf = duk_push_fixed_buffer(ctx, size);
    __try {
        memcpy(buf, (void*)addr, size);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        duk_pop(ctx);
        duk_push_null(ctx);
    }
    return 1;
}

static duk_ret_t js_getModules(duk_context* ctx) {
    duk_push_array(ctx);
    int idx = 0;

#ifdef _WIN64
    auto peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<PEB*>(__readfsdword(0x30));
#endif
    auto ldr = peb->Ldr;
    auto head = &ldr->InMemoryOrderModuleList;

    for (auto entry = head->Flink; entry != head; entry = entry->Flink) {
        auto mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!mod->FullDllName.Buffer) continue;

        UNICODE_STRING* baseName = reinterpret_cast<UNICODE_STRING*>(
            reinterpret_cast<BYTE*>(mod) + offsetof(LDR_DATA_TABLE_ENTRY, FullDllName) + sizeof(UNICODE_STRING));

        char name[256] = {};
        if (baseName->Buffer) {
            for (int i = 0; i < baseName->Length / 2 && i < 255; i++)
                name[i] = (char)baseName->Buffer[i];
        }

        duk_push_object(ctx);
        duk_push_string(ctx, name);
        duk_put_prop_string(ctx, -2, "name");
        duk_push_number(ctx, (double)(uintptr_t)mod->DllBase);
        duk_put_prop_string(ctx, -2, "base");
        auto sizeOfImage = (uintptr_t)mod->Reserved3[1];
        duk_push_number(ctx, (double)sizeOfImage);
        duk_put_prop_string(ctx, -2, "size");
        duk_put_prop_index(ctx, -2, idx++);
    }
    return 1;
}

static duk_ret_t js_getThreads(duk_context* ctx) {
    duk_push_array(ctx);
    int idx = 0;
    DWORD pid = GetCurrentProcessId();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 1;

    THREADENTRY32 te = {}; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                duk_push_object(ctx);
                duk_push_number(ctx, (double)te.th32ThreadID);
                duk_put_prop_string(ctx, -2, "tid");
                duk_push_number(ctx, (double)te.tpBasePri);
                duk_put_prop_string(ctx, -2, "priority");
                duk_put_prop_index(ctx, -2, idx++);
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return 1;
}

static duk_ret_t js_syscall(duk_context* ctx) {
    int nargs = duk_get_top(ctx);
    if (nargs < 1) { duk_push_null(ctx); return 1; }

    DWORD num = (DWORD)duk_require_number(ctx, 0);

    if (IsSyscallBlacklisted(num) || !IsSyscallWhitelisted(num)) {
        InternalBan(OBF_U32(0xA016), X("js_dangerous_syscall").c_str());
        duk_push_object(ctx);
        duk_push_number(ctx, -1);
        duk_put_prop_string(ctx, -2, "status");
        return 1;
    }

    uint64_t a1 = nargs > 1 ? (uint64_t)duk_require_number(ctx, 1) : 0;
    uint64_t a2 = nargs > 2 ? (uint64_t)duk_require_number(ctx, 2) : 0;
    uint64_t a3 = nargs > 3 ? (uint64_t)duk_require_number(ctx, 3) : 0;
    uint64_t a4 = nargs > 4 ? (uint64_t)duk_require_number(ctx, 4) : 0;
    uint64_t a5 = nargs > 5 ? (uint64_t)duk_require_number(ctx, 5) : 0;
    uint64_t a6 = nargs > 6 ? (uint64_t)duk_require_number(ctx, 6) : 0;

    NTSTATUS status = GenericSyscall(num, a1, a2, a3, a4, a5, a6);

    duk_push_object(ctx);
    duk_push_number(ctx, (double)(int32_t)status);
    duk_put_prop_string(ctx, -2, "status");
    return 1;
}

void InitJSEngine() {
    g_duk = duk_create_heap_default();
    if (!g_duk) return;

    duk_push_global_object(g_duk);
    duk_push_object(g_duk);
    const duk_function_list_entry funcs[] = {
        { "isDebuggerPresent",       js_isDebuggerPresent,       0 },
        { "findWindow",              js_findWindow,              1 },
        { "checkTimingAnomaly",      js_checkTimingAnomaly,      0 },
        { "verifyTextIntegrity",     js_verifyTextIntegrity,     0 },
        { "checkHardwareBreakpoints", js_checkHardwareBreakpoints, 0 },
        { "scanNtapiHooks",          js_scanNtapiHooks,          0 },
        { "reportBan",               js_reportBan,               2 },
        { "log",                     js_log,                     1 },
        // New: syscall-backed bindings
        { "readMemory",              js_readMemory,              2 },
        { "getModules",              js_getModules,              0 },
        { "getThreads",              js_getThreads,              0 },
        { "syscall",                 js_syscall,              DUK_VARARGS },
        { NULL, NULL, 0 }
    };
    duk_put_function_list(g_duk, -1, funcs);
    duk_put_prop_string(g_duk, -2, "native");
    duk_pop(g_duk);
}

void ShutdownJSEngine() {
    if (g_duk) { duk_destroy_heap(g_duk); g_duk = nullptr; }
}

void RunScriptChecks() {
    if (!g_duk || g_ruleScripts.empty()) return;
    if (g_config.flags & bigbro::Flag::NoScripts) return;
    for (const auto& script : g_ruleScripts) {
        if (duk_peval_string(g_duk, script.c_str()) != 0) {
            InternalLog(("Script error: " + string(duk_safe_to_string(g_duk, -1))).c_str());
        }
        duk_pop(g_duk);
    }
}
