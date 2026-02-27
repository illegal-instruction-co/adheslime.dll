#pragma once

/**
 * bigbro SDK - C++20 Public API
 *
 * Modern, component-driven anti-cheat SDK. Register your own detection
 * modules, load JS rules, and handle ban events via callbacks.
 *
 * Quick start:
 *   bigbro::SDK::Get().Init({
 *       .rulesDirectory = "./rules",
 *       .onBan = [](const bigbro::BanEvent& e) { ... },
 *   });
 *
 *   // game loop
 *   bigbro::SDK::Get().Tick();
 *
 *   bigbro::SDK::Get().Shutdown();
 *
 * Protected variables:
 *   int playerHealth = 100;
 *   bigbro::SDK::Get().ProtectVariable("health", &playerHealth, sizeof(playerHealth));
 *   // Now if anyone WriteProcessMemory's playerHealth, the next Tick() bans.
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <functional>
#include <map>

// Internal linkage only — no C++ symbols exported from DLL.
// Public API is C-only via ordinal exports (see bigbro.def).

namespace bigbro {

// ============================================================
// Events
// ============================================================

struct BanEvent {
    uint32_t    code;       // Opaque ban code (0xA000 range)
    std::string reason;     // Machine-readable reason
};

struct LogEvent {
    std::string message;
};

// ============================================================
// Callbacks - std::function for maximum flexibility
// ============================================================

using BanCallback = std::function<void(const BanEvent&)>;
using LogCallback = std::function<void(const LogEvent&)>;

// ============================================================
// Configuration - uses C++20 designated initializers
// ============================================================

enum class Flag : uint32_t {
    None               = 0x00,
    VerboseLog         = 0x01,
    NoNative           = 0x02,   // Skip native detection, JS only
    NoScripts          = 0x04,   // Skip JS rules, native only
    UseFilesystemRules = 0x08,   // Load JS from disk (dev mode). Default: embedded VFS
    NoBgThread         = 0x10,   // Don't auto-start background detection thread
};

inline Flag operator|(Flag a, Flag b) { return static_cast<Flag>(static_cast<uint32_t>(a) | static_cast<uint32_t>(b)); }
inline bool operator&(Flag a, Flag b) { return (static_cast<uint32_t>(a) & static_cast<uint32_t>(b)) != 0; }

struct Config {
    std::string     rulesDirectory;     // Path to JS rules folder (dev mode)
    std::string     encryptionKey;      // Passphrase for embedded rule decryption
    BanCallback     onBan;              // REQUIRED: ban event handler
    LogCallback     onLog;              // OPTIONAL: log handler
    Flag            flags = Flag::None;
};

// ============================================================
// Component - extend this to create your own detection module
// ============================================================

class Component {
public:
    virtual ~Component() = default;

    /** Unique component name, e.g. "MyGame::AntiSpeedHack" */
    virtual const char* GetName() const = 0;

    /** Called once during SDK::Init() */
    virtual void OnInit() {}

    /** Called every SDK::Tick() cycle */
    virtual void OnTick() {}

    /** Called during SDK::Shutdown() */
    virtual void OnShutdown() {}
};

// ============================================================
// ComponentRegistry - register and query detection modules
// ============================================================

class ComponentRegistry final {
public:
    /** Register a component. Takes ownership via shared_ptr. */
    void Register(std::shared_ptr<Component> component);

    /** Find component by name. Returns nullptr if not found. */
    Component* Find(std::string_view name) const;

    /** Find component by type. Returns nullptr if not found. */
    template<typename T>
    T* Find() const {
        for (const auto& [_, comp] : _components) {
            if (auto* p = dynamic_cast<T*>(comp.get())) return p;
        }
        return nullptr;
    }

    /** List all registered component names. */
    std::vector<std::string> List() const;

    /** Number of registered components. */
    size_t Count() const { return _components.size(); }

private:
    std::map<std::string, std::shared_ptr<Component>> _components;
};

// ============================================================
// SDK - main entry point (singleton)
// ============================================================

class SDK final {
public:
    /** Global SDK instance. */
    static SDK& Get();

    /** Initialize with config. Returns 0 on success. */
    int Init(const Config& config);

    /** Run one detection cycle. Returns 0=clean, 1=banned, <0=error. */
    int Tick();

    /** Shutdown and release all resources. */
    void Shutdown();

    /** Load an additional JS rule at runtime. */
    int LoadRule(std::string_view jsPath);

    /** Check if a ban has been triggered. */
    bool IsBanned() const;

    /** Access the component registry to register/find modules. */
    ComponentRegistry& Components() { return _registry; }

    // ============================================================
    // Protected Variables - register game data for tamper detection
    //
    // The SDK keeps a shadow copy of your data. Each Tick, it
    // compares the live value against the shadow. If they differ
    // and you didn't call UpdateProtectedVariable(), it's tampering.
    //
    // Usage:
    //   int health = 100;
    //   SDK::Get().ProtectVariable("health", &health, sizeof(health));
    //   health = 80;  // legitimate change
    //   SDK::Get().UpdateProtectedVariable("health"); // sync shadow
    // ============================================================

    /** Register a memory region for tamper detection. */
    void ProtectVariable(std::string_view name, const void* ptr, size_t size);

    /** Remove a protected variable. */
    void UnprotectVariable(std::string_view name);

    /** Call after legitimate changes to resync the shadow copy. */
    void UpdateProtectedVariable(std::string_view name);

    // --- Internal (used by native bindings, not for public use) ---
    void ReportBan(uint32_t code, std::string_view reason);
    void ReportLog(std::string_view message);

private:
    SDK() = default;
    ~SDK() = default;
    SDK(const SDK&) = delete;
    SDK& operator=(const SDK&) = delete;

    ComponentRegistry _registry;
};

} // namespace bigbro

// ============================================================
// C API — ordinal-only exports (no symbol names in PE)
// Host loads via LoadLibrary + GetProcAddress(MAKEINTRESOURCEA(N))
// ============================================================
extern "C" {
    // Callbacks (set BEFORE Init)
    typedef void (*BigBro_BanCallbackFn)(uint32_t code, const char* reason);
    typedef void (*BigBro_LogCallbackFn)(const char* message);
    void  BigBro_SetBanCallback(BigBro_BanCallbackFn cb);   // @12
    void  BigBro_SetLogCallback(BigBro_LogCallbackFn cb);   // @13

    // Lifecycle
    int   BigBro_Init(uint32_t flags, const char* encryptionKey, const char* rulesDir); // @7
    int   BigBro_Tick();                                    // @8
    void  BigBro_Shutdown();                                // @9
    int   BigBro_IsBanned();                                // @10
    int   BigBro_LoadRule(const char* jsPath);              // @11

    // Protected variables
    void  BigBro_ProtectVariable(const char* name, const void* ptr, uint32_t size);  // @14
    void  BigBro_UnprotectVariable(const char* name);       // @15
    void  BigBro_UpdateProtectedVariable(const char* name); // @16

    // DLL attestation (ECDSA P-256)
    int   BigBro_Challenge(const uint8_t* nonce, uint32_t nonceLen,
                           uint8_t* sigOut, uint32_t sigBufLen);  // @17

    // Legacy compat
    void  RunFullSuite();                                   // @1
    int   IsUserBanned();                                   // @2
    void  TriggerSelfTamper();                              // @3
    void  StartBackgroundDetection();                       // @4
    void  RunHeavyChecksExport();                           // @5
    uint32_t GetBgThreadId();                                  // @6
}
