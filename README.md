# adheslime.dll

production anti-cheat SDK. embedded JS engine. component system. callback-driven.

## quick start

```cpp
#include "adheslime_api.h"

// your custom detection module
class SpeedHackDetector final : public adheslime::Component {
public:
    const char* GetName() const override { return "MyGame::SpeedHack"; }
    void OnTick() override { /* your detection logic */ }
};

int main() {
    auto& sdk = adheslime::SDK::Get();

    // register custom components
    sdk.Components().Register(std::make_shared<SpeedHackDetector>());

    // init with callbacks
    sdk.Init({
        .rulesDirectory = "./rules",
        .onBan = [](const adheslime::BanEvent& e) {
            printf("BANNED: 0x%X %s\n", e.code, e.reason.c_str());
        },
    });

    // game loop
    while (running) {
        sdk.Tick();
    }

    sdk.Shutdown();
}
```

## features

- **C++20 API** — `adheslime::SDK` singleton, designated initializers, `std::function` callbacks
- **component system** — extend `adheslime::Component`, register via `SDK::Components()`
- **embedded JS engine** (Duktape 2.7.0) — scriptable detection rules
- **typed component lookup** — `Components().Find<MyComponent>()`
- **native detection** — debugger, timing, HWBP, integrity, ntapi hooks
- **retpoline dispatch** — Spectre v2 hardened indirect calls
- **fiber-based scheduling** — cooperative detection execution
- **xorstr obfuscation** — all strings encrypted at compile time
- **TLS callback** — early anti-debug before DllMain
- **.adhdata watchdog** — dispatch table memory protection monitoring

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

## JS native bindings

```javascript
native.isDebuggerPresent()       // → bool
native.findWindow("x64dbg")     // → bool
native.checkTimingAnomaly()      // → bool
native.verifyTextIntegrity()     // → bool
native.checkHardwareBreakpoints()// → bool
native.scanNtapiHooks()         // → bool
native.reportBan(0xA00A, "msg") // trigger ban
native.log("message")           // log to host
```

## build

```
cmake -B build -G "Visual Studio 18 2026" -A x64
cmake --build build --config Release
```

## test

```
cd build/Release && tester.exe
```

13 subprocess-isolated tests: API, components, JS engine, callbacks, integrity, tamper.

## files

| file | what |
|---|---|
| `adheslime_api.h` | C++20 public API (SDK, Component, ComponentRegistry) |
| `Adheslime.cpp` | implementation |
| `engine/` | Duktape 2.7.0 amalgamation |
| `retpoline.asm` | x64 retpoline thunks |
| `rules/*.js` | JavaScript detection rules |
| `host.cpp` | integration demo with custom component |
| `tester.cpp` | 13-test validation suite |
