#pragma once

#include <cstdint>

#include <Windows.h>
#include <winternl.h>

namespace Stealth {

__forceinline HMODULE FindModule(const char* moduleName) {
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

        wchar_t* wName = baseName->Buffer;
        if (!wName) continue;

        const char* p = moduleName;
        wchar_t* w = wName;
        bool match = true;
        while (*p && *w) {
            char c1 = (*p >= 'A' && *p <= 'Z') ? (*p + 32) : *p;
            char c2 = (*w >= 'A' && *w <= 'Z') ? (char)(*w + 32) : (char)*w;
            if (c1 != c2) { match = false; break; }
            p++; w++;
        }
        if (match && *p == 0 && *w == 0) {
            return reinterpret_cast<HMODULE>(mod->DllBase);
        }
    }
    return nullptr;
}

__forceinline FARPROC FindExport(HMODULE hModule, const char* funcName) {
    if (!hModule || !funcName) return nullptr;

    auto base = reinterpret_cast<BYTE*>(hModule);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    auto& exportDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0) return nullptr;

    auto exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + exportDir.VirtualAddress);
    auto names    = reinterpret_cast<DWORD*>(base + exports->AddressOfNames);
    auto funcs    = reinterpret_cast<DWORD*>(base + exports->AddressOfFunctions);
    auto ordinals = reinterpret_cast<WORD*>(base + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        auto name = reinterpret_cast<const char*>(base + names[i]);

        const char* a = funcName;
        const char* b = name;
        while (*a && *b && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0) {
            DWORD rva = funcs[ordinals[i]];
            if (rva >= exportDir.VirtualAddress &&
                rva < exportDir.VirtualAddress + exportDir.Size) {
                return nullptr;
            }
            return reinterpret_cast<FARPROC>(base + rva);
        }
    }
    return nullptr;
}

template<typename FuncType>
__forceinline FuncType Resolve(const char* moduleName, const char* funcName) {
    auto hMod = FindModule(moduleName);
    if (!hMod) return nullptr;
    return reinterpret_cast<FuncType>(FindExport(hMod, funcName));
}

#define STEALTH_CALL(retType, mod, func) \
    Stealth::Resolve<retType(WINAPI*)(...)>(X(mod).c_str(), X(func).c_str())

} // namespace Stealth
