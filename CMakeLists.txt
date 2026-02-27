cmake_minimum_required(VERSION 3.20)
project(bigbro LANGUAGES C CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================
# DLL - Core SDK
# ============================================================
add_library(bigbro SHARED
    src/Sdk.cpp
    src/Detection.cpp
    src/JsEngine.cpp
    src/Vfs.cpp
    src/Exports.cpp
    src/Syscalls.cpp
    src/CustomComponents.cpp
    src/Attestation.cpp
    engine/duktape.c
    src/retpoline.asm
    src/syscalls.asm
    src/bigbro.def
)

target_include_directories(bigbro
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(bigbro PRIVATE ntdll bcrypt)

# ============================================================
# Host Application (Integration Demo)
# ============================================================
add_executable(host examples/Host.cpp)
target_include_directories(host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(host PRIVATE bcrypt)

# ============================================================
# Tester Application (Validation Suite)
# ============================================================
add_executable(tester tests/Tester.cpp)
target_include_directories(tester PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(tester PRIVATE bcrypt)

# ============================================================
# MSVC Compiler + Linker Hardening (anti-reverse-engineering)
# ============================================================
if(MSVC)
    # --- Release-only: aggressive optimization + obfuscation ---
    target_compile_options(bigbro PRIVATE
        $<$<CONFIG:Release>:
            /GL             # Whole Program Optimization
            /Ob3            # Maximum inlining
            /Gw             # Global data optimization
            /GS             # Buffer security checks
            /Oy             # Omit frame pointer
            /Oi             # Intrinsic functions
        >
    )

    # --- Release linker flags ---
    target_link_options(bigbro PRIVATE
        $<$<CONFIG:Release>:
            /LTCG                   # Link-Time Code Generation
            /OPT:REF                # Remove unreferenced functions
            /OPT:ICF                # Fold identical COMDATs
            /DYNAMICBASE            # ASLR
            /NXCOMPAT               # DEP
            /HIGHENTROPYVA          # High entropy ASLR (64-bit)
            /DEBUG:NONE             # Zero debug info
        >
    )

    set_source_files_properties(engine/duktape.c PROPERTIES COMPILE_FLAGS "/W1")

    # MASM can't create nested obj dirs when sources are in subdirs (src/)
    add_custom_command(TARGET bigbro PRE_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory
            "${CMAKE_CURRENT_BINARY_DIR}/bigbro.dir/$<CONFIG>/src"
        COMMENT "Creating MASM output directory..."
    )
    set_source_files_properties(src/retpoline.asm src/syscalls.asm PROPERTIES
        COMPILE_FLAGS "/W0"
    )
endif()

# ============================================================
# Pack JS rules into AES-256-GCM encrypted C++ header (pre-build)
# Override key: cmake -DBIGBRO_PACK_KEY="your-secret" ..
# ============================================================
set(BIGBRO_PACK_KEY "bigbro-default-key" CACHE STRING "Encryption passphrase for JS rules")
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_FOUND)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/src/packed_rules.gen.h
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/pack_rules.py
            ${CMAKE_CURRENT_SOURCE_DIR}/rules
            ${CMAKE_CURRENT_SOURCE_DIR}/src/packed_rules.gen.h
            --key ${BIGBRO_PACK_KEY}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/rules/check_debugger.js
            ${CMAKE_CURRENT_SOURCE_DIR}/rules/check_processes.js
            ${CMAKE_CURRENT_SOURCE_DIR}/rules/check_integrity.js
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/pack_rules.py
        COMMENT "Packing and encrypting detection rules..."
    )
    add_custom_target(pack_rules DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/packed_rules.gen.h)
    add_dependencies(bigbro pack_rules)
endif()

# Copy JS rules to output (for dev mode: Flag::UseFilesystemRules)
add_custom_command(TARGET bigbro POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/rules
        $<TARGET_FILE_DIR:bigbro>/rules
    COMMENT "Copying detection rules (dev mode)..."
)

# Post-build PE obfuscation (erase toolchain fingerprints)
# Non-fatal: if DLL is locked (e.g. by IDA), build still succeeds.
# Re-run manually: python tools/obfuscate_pe.py build2/Release/bigbro.dll
if(Python3_FOUND)
    add_custom_command(TARGET bigbro POST_BUILD
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/obfuscate_pe.py
            $<TARGET_FILE:bigbro> || (exit /b 0)
        COMMENT "Applying PE obfuscation..."
    )
endif()
