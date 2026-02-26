/**
 * SDK + ComponentRegistry Implementation
 */
#include "Detection.h"
#include "JsEngine.h"
#include "Vfs.h"

// ============================================================
// GLOBAL STATE DEFINITIONS (declared in Common.h)
// ============================================================
adheslime::Config g_config;
duk_context*      g_duk = nullptr;
atomic<bool>      g_initialized{false};
atomic<bool>      g_banned{false};
mutex             g_mutex;
vector<string>    g_ruleScripts;
uint32_t          g_textBaseline = 0;
DWORD             g_dispatchProtect = 0;

// ============================================================
// SDK — ReportBan / ReportLog
// ============================================================
namespace adheslime {

void SDK::ReportBan(uint32_t code, string_view reason) {
    if (g_banned.exchange(true)) return;
    if (g_config.onBan) {
        g_config.onBan(BanEvent{ code, string(reason) });
    }
}

void SDK::ReportLog(string_view message) {
    if (g_config.onLog) {
        g_config.onLog(LogEvent{ string(message) });
    }
}

// ============================================================
// COMPONENT TICKS
// ============================================================
static void RunComponentTicks() {
    auto& reg = SDK::Get().Components();
    for (const auto& name : reg.List()) {
        if (auto* comp = reg.Find(name)) comp->OnTick();
    }
}

// ============================================================
// FIBER SCHEDULER
// ============================================================
static LPVOID g_mainFiber = nullptr;
static LPVOID g_detectionFiber = nullptr;

static void CALLBACK DetectionFiberProc(LPVOID) {
    RunNativeChecks();
    RunScriptChecks();
    RunComponentTicks();
    if (g_mainFiber) SwitchToFiber(g_mainFiber);
}

// ============================================================
// COMPONENT REGISTRY
// ============================================================
void ComponentRegistry::Register(shared_ptr<Component> component) {
    _components[component->GetName()] = move(component);
}

Component* ComponentRegistry::Find(string_view name) const {
    if (auto it = _components.find(string(name)); it != _components.end())
        return it->second.get();
    return nullptr;
}

vector<string> ComponentRegistry::List() const {
    vector<string> names;
    names.reserve(_components.size());
    for (const auto& [name, _] : _components) names.push_back(name);
    return names;
}

// ============================================================
// SDK LIFECYCLE
// ============================================================
SDK& SDK::Get() {
    static SDK instance;
    return instance;
}

int SDK::Init(const Config& config) {
    lock_guard<mutex> lock(g_mutex);
    if (g_initialized) return -1;

    g_config = config;
    g_banned = false;
    g_textBaseline = 0;
    g_dispatchProtect = 0;
    g_ruleScripts.clear();

    CaptureDetectionBaselines();

    InitJSEngine();
    if (!g_duk) { ReportLog("JS engine init failed"); return -3; }

    if (config.flags & Flag::UseFilesystemRules) {
        if (!config.rulesDirectory.empty()) {
            LoadRulesFromDirectory(config.rulesDirectory);
        }
    } else {
        LoadEmbeddedRules();
    }

    for (const auto& name : _registry.List()) {
        if (auto* comp = _registry.Find(name)) comp->OnInit();
    }

    g_initialized = true;
    ReportLog("adheslime initialized");
    return 0;
}

int SDK::Tick() {
    if (!g_initialized) return -1;
    if (g_banned) return 1;

    g_mainFiber = ConvertThreadToFiber(nullptr);
    if (g_mainFiber) {
        g_detectionFiber = CreateFiber(0, DetectionFiberProc, nullptr);
        if (g_detectionFiber) {
            SwitchToFiber(g_detectionFiber);
            DeleteFiber(g_detectionFiber);
            g_detectionFiber = nullptr;
        }
        ConvertFiberToThread();
        g_mainFiber = nullptr;
    } else {
        RunNativeChecks();
        RunScriptChecks();
        RunComponentTicks();
    }

    return g_banned ? 1 : 0;
}

void SDK::Shutdown() {
    lock_guard<mutex> lock(g_mutex);
    if (!g_initialized) return;

    for (const auto& name : _registry.List()) {
        if (auto* comp = _registry.Find(name)) comp->OnShutdown();
    }

    ShutdownJSEngine();
    g_ruleScripts.clear();
    g_initialized = false;
    g_banned = false;
    ReportLog("adheslime shutdown");
}

int SDK::LoadRule(string_view jsPath) {
    if (!g_initialized || !g_duk) return -1;
    return LoadRuleFromFile(jsPath);
}

bool SDK::IsBanned() const {
    return g_banned;
}

} // namespace adheslime
