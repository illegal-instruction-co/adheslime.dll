# adheslime

Open-source anti-cheat SDK for game developers. C++20. Single DLL.

Embedded JS rule engine, AES-256-GCM encrypted VFS, component system, fiber-based scheduling.

## Quick Start

```cpp
#include <adheslime/Sdk.h>

class SpeedHackDetector final : public adheslime::Component {
public:
    const char* GetName() const override { return "MyGame::SpeedHack"; }
    void OnTick() override { /* your detection logic */ }
};

int main() {
    auto& sdk = adheslime::SDK::Get();

    sdk.Components().Register(std::make_shared<SpeedHackDetector>());

    sdk.Init({
        .encryptionKey = "your-key-here",
        .onBan = [](const adheslime::BanEvent& e) {
            printf("BANNED: 0x%X %s\n", e.code, e.reason.c_str());
        },
    });

    while (running) {
        sdk.Tick();  // 0 = clean, 1 = banned
    }

    sdk.Shutdown();
}
```

## Features

- **C++20 API** -- `adheslime::SDK` singleton, designated initializers, `std::function` callbacks
- **Component system** -- extend `adheslime::Component`, register via `SDK::Components()`
- **Encrypted rule engine** -- AES-256-GCM VFS, developer-controlled encryption key
- **Embedded JS engine** (Duktape 2.7.0) -- scriptable detection rules (ES5)
- **Typed component lookup** -- `Components().Find<MyComponent>()`
- **10 native detections** -- debugger, timing, HWBP, integrity, ntapi hooks, VM, blacklisted windows
- **Retpoline dispatch** -- Spectre v2 hardened indirect calls
- **Fiber-based scheduling** -- cooperative detection execution
- **XorStr obfuscation** -- all sensitive strings encrypted at compile time
- **TLS callback** -- early anti-debug before DllMain
- **.adhdata watchdog** -- dispatch table memory protection monitoring

## API

```cpp
adheslime::SDK::Get()                    // global singleton
    .Init(config)                        // init with Config struct
    .Tick()                              // run detection cycle → 0=clean, 1=banned
    .Shutdown()                          // cleanup
    .LoadRule("path.js")                 // load JS rule at runtime
    .IsBanned()                          // check ban status
    .Components()                        // access ComponentRegistry
        .Register(shared_ptr)            // register component
        .Find("name")                    // find by name
        .Find<Type>()                    // find by type
        .List()                          // list all names
        .Count()                         // component count
```

## Config

```cpp
struct Config {
    std::string     rulesDirectory;     // JS rules folder (dev mode)
    std::string     encryptionKey;      // passphrase for AES-256-GCM
    BanCallback     onBan;              // ban event handler
    LogCallback     onLog;              // log handler (optional)
    Flag            flags;              // see below
};

// Flags
Flag::None               // default: embedded VFS + all detections
Flag::VerboseLog         // extra logging
Flag::NoNative           // skip native detections, JS only
Flag::NoScripts          // skip JS rules, native only
Flag::UseFilesystemRules // load JS from disk (development mode)
```

## JS Native Bindings

```javascript
native.isDebuggerPresent()        // → bool
native.findWindow("x64dbg")      // → bool
native.checkTimingAnomaly()       // → bool
native.verifyTextIntegrity()      // → bool
native.checkHardwareBreakpoints() // → bool
native.scanNtapiHooks()          // → bool
native.reportBan(0xA00A, "msg")  // trigger ban
native.log("message")            // log to host
```

## Native Detection Routines

| Routine | Ban Code | What it checks |
|---|---|---|
| `IsDebuggerPresent` | `0xA00A` | Win32 debugger API |
| `DebuggerLatency` | `0xA001` | SEH timing > 500ms |
| `TimingAnomaly` | `0xA002` | KUSER_SHARED_DATA time freeze |
| `QPCAnomaly` | `0xA00B` | QueryPerformanceCounter drift |
| `TickAnomaly` | `0xA00C` | GetTickCount drift |
| `ThreadsAndHWBP` | `0xA003` | DR0-DR3 registers + RIP correction |
| `TextIntegrity` | `0xA005` | .text section CRC32 |
| `NtapiHooks` | `0xA006` | NtOpenProcess JMP hook |
| `BlacklistedWindows` | `0xA007` | x64dbg, Cheat Engine, Process Hacker |
| `CPUID` | `0xA00D` | KVM hypervisor detection |

## Security Layers

| Layer | How it works |
|---|---|
| **AES-256-GCM VFS** | JS rules encrypted in DLL with per-rule nonce + auth tag |
| **CRC32 post-decrypt** | Detects wrong key or binary patches on rules |
| **XorStr** | Compile-time string encryption, no plaintext in binary |
| **Retpoline** | Spectre v2 mitigated dispatch of detection functions |
| **.adhdata watchdog** | Monitors dispatch table memory protection changes |
| **.text CRC baseline** | Captures baseline at init, checks every tick |
| **TLS callback** | Pre-DllMain debugger check → ExitProcess(0xDEAD) |
| **SecureZeroMemory** | AES key wiped from RAM after decryption |

## Project Structure (Pitchfork)

```
adheslime/
├── include/adheslime/
│   └── Sdk.h                  Public C++20 API
├── src/
│   ├── Common.h               XorStr, CRC32, globals (internal)
│   ├── Detection.h/.cpp       10 native detections + dispatch table
│   ├── JsEngine.h/.cpp        Duktape engine + 8 native bindings
│   ├── Vfs.h/.cpp             AES-256-GCM decrypt + rule loading
│   ├── Sdk.cpp                SDK lifecycle + ComponentRegistry
│   ├── Exports.cpp            C exports + DllMain + TLS callback
│   └── retpoline.asm          x64 Spectre v2 thunks
├── tests/
│   └── Tester.cpp             13 subprocess-isolated tests
├── examples/
│   └── Host.cpp               Integration demo
├── engine/                    Duktape 2.7.0 amalgamation
├── rules/                     JS detection scripts
├── tools/
│   └── pack_rules.py          AES-256-GCM rule packer
└── .github/workflows/ci.yml   Build + test + release
```

## Build

```bash
# with custom encryption key
cmake -B build -G "Visual Studio 17 2022" -A x64 \
      -DADHESLIME_PACK_KEY="your-encryption-key"
cmake --build build --config Release
```

Requires Python 3 + `pycryptodome` for rule encryption.

## Test

```
cd build/Release && tester.exe
→ 13/13 passed
```

## License

MIT
