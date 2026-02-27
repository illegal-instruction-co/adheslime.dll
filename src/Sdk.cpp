#include "Detection.h"
#include "JsEngine.h"
#include "Vfs.h"
#include "Syscalls.h"
#include "StealthImport.h"
#include "Obfuscation.h"

extern void RegisterCustomComponents(bigbro::ComponentRegistry& registry);

bigbro::Config g_config;
duk_context*      g_duk = nullptr;
atomic<bool>      g_initialized{false};
atomic<bool>      g_banned{false};
shared_mutex      g_mutex;
vector<string>    g_ruleScripts;
Sha256Digest      g_textBaseline{};
bool              g_textBaselineSet = false;
Sha256Digest      g_dispatchHash{};
bool              g_dispatchHashSet = false;
DWORD             g_dispatchProtect = 0;

atomic<bool>      g_bgStop{false};
thread            g_bgThread;

atomic<uint64_t>  g_heartbeatTick{0};
atomic<DWORD>     g_tickThreadId{0};
bool              g_heartbeatArmed = false;

Sha256Digest      g_iatBaseline{};
bool              g_iatBaselineSet = false;

namespace bigbro {

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
}

static void RunComponentTicks() {
    auto& reg = bigbro::SDK::Get().Components();
    for (const auto& name : reg.List()) {
        if (auto* comp = reg.Find(name)) comp->OnTick();
    }
}

LPVOID g_mainFiber = nullptr;
static LPVOID g_detectionFiber = nullptr;

static void CALLBACK DetectionFiberProc(LPVOID) {
    RunNativeChecks();
    RunScriptChecks();
    RunComponentTicks();
    if (g_mainFiber) SwitchToFiber(g_mainFiber);
}

namespace bigbro {

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

SDK& SDK::Get() {
    static SDK instance;
    return instance;
}

int SDK::Init(const Config& config) {
    unique_lock<shared_mutex> lock(g_mutex);
    if (g_initialized) return -1;

    g_config = config;
    g_banned = false;
    g_textBaseline = {};
    g_textBaselineSet = false;
    g_dispatchHash = {};
    g_dispatchHashSet = false;
    g_dispatchProtect = 0;
    g_heartbeatTick = 0;
    g_tickThreadId = 0;
    g_heartbeatArmed = false;
    g_iatBaseline = {};
    g_iatBaselineSet = false;
    g_ruleScripts.clear();

    SyscallInit();

    auto hSelf = Stealth::FindModule(X("bigbro.dll").c_str());
    if (hSelf) {
        using LdrAddRefDll_t = NTSTATUS(NTAPI*)(ULONG, PVOID);
        auto pLdr = Stealth::Resolve<LdrAddRefDll_t>(
            X("ntdll.dll").c_str(), X("LdrAddRefDll").c_str());
        if (pLdr) {
            for (int i = 0; i < 100; i++) pLdr(0, hSelf);
        }
    }

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

    RegisterCustomComponents(_registry);

    for (const auto& name : _registry.List()) {
        if (auto* comp = _registry.Find(name)) comp->OnInit();
    }

    g_initialized = true;
    ShadowStateInit();
    ReportLog("bigbro initialized");

    if (!(config.flags & Flag::NoNative) && !(config.flags & Flag::NoBgThread)) {
        g_bgStop = false;
        if (!g_bgThread.joinable()) {
            g_bgThread = thread([]() {
                using NtSIT_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
                auto pNtSIT = Stealth::Resolve<NtSIT_t>(
                    X("ntdll.dll").c_str(), X("NtSetInformationThread").c_str());
                if (pNtSIT) pNtSIT(GetCurrentThread(), 0x11, NULL, 0);

                int bgIteration = 0;
                while (!g_bgStop && !g_banned && g_initialized) {
                    extern atomic<uint64_t> g_bgHeartbeat;
                    g_bgHeartbeat.fetch_add(1, memory_order_relaxed);
                    RunNativeChecks();
                    if (++bgIteration % 3 == 0) RunHeavyChecks();
                    for (int i = 0; i < 20 && !g_bgStop; ++i)
                        this_thread::sleep_for(chrono::milliseconds(100));
                }
            });
        }
    }

    return 0;
}

int SDK::Tick() {
    if (!g_initialized) return -1;
    if (g_banned) return 1;

    if (!Stealth::FindModule(X("bigbro.dll").c_str())) {
        ReportBan(0xA01B, "self_unload_detected");
        return 1;
    }

    ShadowStateVerify();
    ProtectedVarVerifyAll();

    bool wasAlreadyFiber = IsThreadAFiber();
    if (wasAlreadyFiber) {
        g_mainFiber = GetCurrentFiber();
    } else {
        g_mainFiber = ConvertThreadToFiber(nullptr);
    }

    if (g_mainFiber) {
        g_detectionFiber = CreateFiber(0, DetectionFiberProc, nullptr);
        if (g_detectionFiber) {
            SwitchToFiber(g_detectionFiber);
            DeleteFiber(g_detectionFiber);
            g_detectionFiber = nullptr;
        }
        if (!wasAlreadyFiber) {
            ConvertFiberToThread();
        }
        g_mainFiber = nullptr;
    } else {
        RunNativeChecks();
        RunScriptChecks();
        RunComponentTicks();
    }

    ShadowStateUpdate();
    return g_banned ? 1 : 0;
}

void SDK::Shutdown() {
    g_bgStop = true;
    if (g_bgThread.joinable()) {
        g_bgThread.join();
    }

    unique_lock<shared_mutex> lock(g_mutex);
    if (!g_initialized) return;

    for (const auto& name : _registry.List()) {
        if (auto* comp = _registry.Find(name)) comp->OnShutdown();
    }

    ShutdownJSEngine();
    g_ruleScripts.clear();
    g_initialized = false;
    g_banned = false;
    ReportLog("bigbro shutdown");
}

int SDK::LoadRule(string_view jsPath) {
    if (!g_initialized || !g_duk) return -1;
    return LoadRuleFromFile(jsPath);
}

bool SDK::IsBanned() const {
    return g_banned;
}

} // namespace bigbro

namespace bigbro {

void SDK::ProtectVariable(std::string_view name, const void* ptr, size_t size) {
    ProtectedVarRegister(name, ptr, size);
}

void SDK::UnprotectVariable(std::string_view name) {
    ProtectedVarUnregister(name);
}

void SDK::UpdateProtectedVariable(std::string_view name) {
    ProtectedVarUpdate(name);
}

} // namespace bigbro
