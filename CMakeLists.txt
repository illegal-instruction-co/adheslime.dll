cmake_minimum_required(VERSION 3.20)
project(adheslime LANGUAGES CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# DLL Implementation (Mimic) — includes MASM retpoline thunks
add_library(adheslime SHARED Adheslime.cpp retpoline.asm)
target_compile_definitions(adheslime PRIVATE ADHESLIME_EXPORTS)
target_link_libraries(adheslime PRIVATE ntdll) # For NtRaiseException etc if available

# Host Application (Game Mode)
add_executable(host host.cpp)
target_link_libraries(host PRIVATE adheslime)

# Tester Application (Validation Suite)
add_executable(tester tester.cpp)
target_link_libraries(tester PRIVATE adheslime)

# CFG, Spectre mitigation, and Security flags for MSVC
if(MSVC)
    target_compile_options(adheslime PRIVATE /guard:cf /Qspectre)
    target_link_options(adheslime PRIVATE /GUARD:CF)
endif()
