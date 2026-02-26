#include "JsEngine.h"
#include "engine/duktape.h"

// ============================================================
// DUKTAPE NATIVE BINDINGS
// ============================================================
static duk_ret_t js_isDebuggerPresent(duk_context* ctx) {
    duk_push_boolean(ctx, IsDebuggerPresent()); return 1;
}
static duk_ret_t js_findWindow(duk_context* ctx) {
    duk_push_boolean(ctx, FindWindowA(NULL, duk_require_string(ctx, 0)) != NULL); return 1;
}
static duk_ret_t js_checkTimingAnomaly(duk_context* ctx) {
    LARGE_INTEGER f, s, e; QueryPerformanceFrequency(&f); QueryPerformanceCounter(&s);
    Sleep(5); QueryPerformanceCounter(&e);
    duk_push_boolean(ctx, (double)(e.QuadPart - s.QuadPart) / f.QuadPart * 1000.0 > 500.0); return 1;
}
static duk_ret_t js_verifyTextIntegrity(duk_context* ctx) {
    HMODULE hMod = GetModuleHandleA("adheslime.dll");
    if (!hMod || g_textBaseline == 0) { duk_push_boolean(ctx, 1); return 1; }
    auto* dos = (PIMAGE_DOS_HEADER)hMod;
    auto* nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sec[i].Name, ".text") == 0) {
            duk_push_boolean(ctx, CalculateCRC32((BYTE*)hMod + sec[i].VirtualAddress, sec[i].Misc.VirtualSize) == g_textBaseline);
            return 1;
        }
    }
    duk_push_boolean(ctx, 1); return 1;
}
static duk_ret_t js_checkHardwareBreakpoints(duk_context* ctx) {
    CONTEXT c = {}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &c);
    duk_push_boolean(ctx, c.Dr0 || c.Dr1 || c.Dr2 || c.Dr3); return 1;
}
static duk_ret_t js_scanNtapiHooks(duk_context* ctx) {
    auto p = (BYTE*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
    duk_push_boolean(ctx, p && *p == 0xE9); return 1;
}
static duk_ret_t js_reportBan(duk_context* ctx) {
    InternalBan((uint32_t)duk_require_number(ctx, 0), duk_require_string(ctx, 1)); return 0;
}
static duk_ret_t js_log(duk_context* ctx) {
    InternalLog(duk_require_string(ctx, 0)); return 0;
}

// ============================================================
// JS ENGINE LIFECYCLE
// ============================================================
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
    if (g_config.flags & adheslime::Flag::NoScripts) return;
    for (const auto& script : g_ruleScripts) {
        if (duk_peval_string(g_duk, script.c_str()) != 0) {
            InternalLog(("Script error: " + string(duk_safe_to_string(g_duk, -1))).c_str());
        }
        duk_pop(g_duk);
    }
}
