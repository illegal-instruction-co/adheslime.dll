#pragma once
#include <windows.h>
#include <intrin.h>

namespace adheslime {

class HardwareProfiler final {
public:
    static void ProfileCPUID() {
        int cpuInfo[4];

        // EAX = 0: Vendor ID
        __cpuid(cpuInfo, 0);
        char vendor[13];
        memcpy(vendor, &cpuInfo[1], 4);
        memcpy(vendor + 4, &cpuInfo[3], 4);
        memcpy(vendor + 8, &cpuInfo[2], 4);
        vendor[12] = '\0';

        // EAX = 1: Feature Bits  Hypervisor bit (ECX bit 31)
        __cpuid(cpuInfo, 1);
        bool isVM = (cpuInfo[2] >> 31) & 1;

        if (isVM) {
            // EAX = 0x40000000: Hypervisor Vendor
            __cpuid(cpuInfo, 0x40000000);
            // Silently note  real AC would log this server-side
        }
    }
};

} // namespace adheslime
