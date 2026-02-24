#include <iostream>
#include <windows.h>
#include <string>
#include <thread>
#include <chrono>

typedef void (*StartBackgroundDetection_t)();

void GameLoop() {
    int gold = 0;
    int level = 1;
    
    std::cout << "[Game] Welcome to Adheslime Adventure!\n";
    std::cout << "[Game] Anti-Cheat is ACTIVE.\n\n";

    while (true) {
        gold += 10;
        if (gold % 100 == 0) level++;
        
        std::cout << "\r[Game] Level: " << level << " | Gold: " << gold << " | Status: SECURE" << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

int main() {
    SetConsoleTitleA("Adheslime Game Mode");
    
    HMODULE hDll = LoadLibraryA("adheslime.dll");
    if (!hDll) {
        DWORD err = GetLastError();
        std::cerr << "[Host] Platform failure. Error: 0x" << std::hex << err << "\n";
        return 1;
    }

    auto StartBackgroundDetection = (StartBackgroundDetection_t)GetProcAddress(hDll, "StartBackgroundDetection");
    if (!StartBackgroundDetection) {
        std::cerr << "[Host] Export resolution failed.\n";
        return 1;
    }

    StartBackgroundDetection();
    GameLoop();

    return 0;
}
