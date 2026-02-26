#pragma once

/**
 * adheslime SDK — C++20 Public API
 *
 * Modern, component-driven anti-cheat SDK. Register your own detection
 * modules, load JS rules, and handle ban events via callbacks.
 *
 * Quick start:
 *   adheslime::SDK::Get().Init({
 *       .rulesDirectory = "./rules",
 *       .onBan = [](const adheslime::BanEvent& e) { ... },
 *   });
 *
 *   // game loop
 *   adheslime::SDK::Get().Tick();
 *
 *   adheslime::SDK::Get().Shutdown();
 */

#include <cstdint>
#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <functional>
#include <map>

#ifdef ADHESLIME_EXPORTS
    #define ADHESLIME_API __declspec(dllexport)
#else
    #define ADHESLIME_API __declspec(dllimport)
#endif

namespace adheslime {

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
// Callbacks — std::function for maximum flexibility
// ============================================================

using BanCallback = std::function<void(const BanEvent&)>;
using LogCallback = std::function<void(const LogEvent&)>;

// ============================================================
// Configuration — uses C++20 designated initializers
// ============================================================

enum class Flag : uint32_t {
    None               = 0x00,
    VerboseLog         = 0x01,
    NoNative           = 0x02,   // Skip native detection, JS only
    NoScripts          = 0x04,   // Skip JS rules, native only
    UseFilesystemRules = 0x08,   // Load JS from disk (dev mode). Default: embedded VFS
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
// Component — extend this to create your own detection module
// ============================================================

class ADHESLIME_API Component {
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
// ComponentRegistry — register and query detection modules
// ============================================================

class ADHESLIME_API ComponentRegistry final {
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
// SDK — main entry point (singleton)
// ============================================================

class ADHESLIME_API SDK final {
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

} // namespace adheslime

// ============================================================
// C exports (for DLL boundary + legacy compatibility)
// ============================================================
extern "C" {
    ADHESLIME_API void RunFullSuite();
    ADHESLIME_API int  IsUserBanned();
    ADHESLIME_API void TriggerSelfTamper();
    ADHESLIME_API void StartBackgroundDetection();
}
