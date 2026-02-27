/**
 * CustomComponents.cpp — Add your own detection modules here.
 *
 * Since bigbro ships as a DLL with ordinal-only exports (no C++ symbols),
 * custom components must be compiled INTO the DLL from source.
 * Extend bigbro::Component, then register in RegisterCustomComponents().
 *
 * Example:
 *
 *   class SpeedHackDetector final : public bigbro::Component {
 *       DWORD _lastTick = 0;
 *   public:
 *       const char* GetName() const override { return "MyGame::SpeedHack"; }
 *       void OnInit() override    { _lastTick = GetTickCount(); }
 *       void OnTick() override    { _lastTick = GetTickCount(); }
 *       void OnShutdown() override {}
 *   };
 *
 * Then add to RegisterCustomComponents():
 *   registry.Register(std::make_shared<SpeedHackDetector>());
 */

#include <bigbro/Sdk.h>
#include <memory>

void RegisterCustomComponents(bigbro::ComponentRegistry& registry) {
    // --- Add your components here ---
    // registry.Register(std::make_shared<YourDetector>());
}
