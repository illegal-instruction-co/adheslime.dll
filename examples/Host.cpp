/**
 * Adheslime SDK — Integration Demo
 *
 * Shows how to:
 *   1. Configure the SDK with callbacks
 *   2. Register a custom detection component
 *   3. Run the detection loop
 */

#include <adheslime/Sdk.h>
 
#include <cstdio>
 
#include <windows.h>

using namespace std;

// ============================================================
// Example: Custom Detection Component
// Game developers extend adheslime::Component to add game-specific checks
// ============================================================
class SpeedHackDetector final : public adheslime::Component {
    DWORD _lastTickCount = 0;

public:
    const char* GetName() const override { return "MyGame::SpeedHackDetector"; }

    void OnInit() override {
        _lastTickCount = GetTickCount();
        printf("  [component] SpeedHackDetector initialized\n");
    }

    void OnTick() override {
        DWORD now = GetTickCount();
        // Example: detect if someone is accelerating game time
        // In a real game you'd compare against expected frame delta
        _lastTickCount = now;
    }

    void OnShutdown() override {
        printf("  [component] SpeedHackDetector shutdown\n");
    }
};

// ============================================================
// Callbacks
// ============================================================
int main() {
    printf("=== Adheslime SDK Demo ===\n\n");

    auto& sdk = adheslime::SDK::Get();

    // --- Register custom component BEFORE Init ---
    sdk.Components().Register(make_shared<SpeedHackDetector>());

    // --- Configure & Init ---
    int ret = sdk.Init({
        .encryptionKey = "adheslime-default-key",
        .onBan = [](const adheslime::BanEvent& e) {
            printf("\n  [BANNED] Code: 0x%04X | Reason: %s\n\n", e.code, e.reason.c_str());
        },
        .onLog = [](const adheslime::LogEvent& e) {
            printf("  [log] %s\n", e.message.c_str());
        },
    });

    if (ret != 0) {
        printf("Init failed: %d\n", ret);
        return 1;
    }

    // --- Check registered components ---
    printf("\n  Registered components: %zu\n", sdk.Components().Count());
    for (const auto& name : sdk.Components().List()) {
        printf("    - %s\n", name.c_str());
    }

    // --- Find component by type ---
    if (auto* shd = sdk.Components().Find<SpeedHackDetector>()) {
        printf("  Found SpeedHackDetector via Find<T>()\n");
    }

    // --- Game Loop ---
    printf("\n  Starting detection loop (5 ticks)...\n\n");
    for (int i = 0; i < 5; i++) {
        printf("  Tick %d/5: ", i + 1);
        int result = sdk.Tick();
        if (result == 1)       { printf("BANNED\n"); break; }
        else if (result < 0)   { printf("ERROR (%d)\n", result); }
        else                   { printf("CLEAN\n"); }
        Sleep(1000);
    }

    sdk.Shutdown();
    printf("\nDone.\n");
    return 0;
}
