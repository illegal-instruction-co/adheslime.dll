# adheslime.dll

reverse engineered a thing mimicked. rebuilt from scratch.

## what it does

- thread hijack detection + rip correction via `SetThreadContext`
- hardware breakpoint clearing (dr0-3)
- module integrity checks (crc32 on .text)
- ntdll hook detection
- timing anomaly checks
- fiber-based scheduling
- xorstr on everything
- tls callback for early init
- retpoline dispatch (spectre v2 mitigation) + `/Qspectre`
- single `CreateComponent` export (original pattern)

all strings obfuscated. no console output. opaque ban codes only.

## build

```
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

## test

```
cd build/Release
./tester.exe
```

automated tests, each runs in isolated subprocess so bans dont crash the harness.

## files

| file | what |
|---|---|
| `Adheslime.cpp` | everything |
| `host.cpp` | game mode demo |
| `tester.cpp` | validation suite |
| `*.hpp` | vfs, hwid, component system |

## ci

pushes to main auto-build, auto-test, auto-release if green.

## note

the real thing loads most detection rules as v8 scripts at runtime. we cant see those. native layer is fully replicated tho.
