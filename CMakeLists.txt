cmake_minimum_required(VERSION 3.20)
project(adheslime LANGUAGES C CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ============================================================
# DLL — Core SDK
# ============================================================
add_library(adheslime SHARED
    src/Sdk.cpp
    src/Detection.cpp
    src/JsEngine.cpp
    src/Vfs.cpp
    src/Exports.cpp
    engine/duktape.c
    src/retpoline.asm
)
target_compile_definitions(adheslime PRIVATE ADHESLIME_EXPORTS)
target_include_directories(adheslime
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(adheslime PRIVATE ntdll bcrypt)

# ============================================================
# Host Application (Integration Demo)
# ============================================================
add_executable(host examples/Host.cpp)
target_include_directories(host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(host PRIVATE adheslime)

# ============================================================
# Tester Application (Validation Suite)
# ============================================================
add_executable(tester tests/Tester.cpp)
target_include_directories(tester PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(tester PRIVATE adheslime)

# ============================================================
# MSVC: CFG + lower warnings for Duktape C code
# ============================================================
if(MSVC)
    target_compile_options(adheslime PRIVATE /guard:cf)
    target_link_options(adheslime PRIVATE /GUARD:CF)
    set_source_files_properties(engine/duktape.c PROPERTIES COMPILE_FLAGS "/W1")
endif()

# ============================================================
# Pack JS rules into AES-256-CBC encrypted C++ header (pre-build)
# Override key: cmake -DADHESLIME_PACK_KEY="your-secret" ...
# ============================================================
set(ADHESLIME_PACK_KEY "adheslime-default-key" CACHE STRING "Encryption passphrase for JS rules")
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_FOUND)
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/packed_rules.gen.h
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/pack_rules.py
            ${CMAKE_CURRENT_SOURCE_DIR}/rules
            ${CMAKE_CURRENT_SOURCE_DIR}/packed_rules.gen.h
            --key ${ADHESLIME_PACK_KEY}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/rules/check_debugger.js
            ${CMAKE_CURRENT_SOURCE_DIR}/rules/check_processes.js
            ${CMAKE_CURRENT_SOURCE_DIR}/rules/check_integrity.js
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/pack_rules.py
        COMMENT "Packing and encrypting detection rules..."
    )
    add_custom_target(pack_rules DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/packed_rules.gen.h)
    add_dependencies(adheslime pack_rules)
endif()

# Copy JS rules to output (for dev mode: Flag::UseFilesystemRules)
add_custom_command(TARGET adheslime POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/rules
        $<TARGET_FILE_DIR:adheslime>/rules
    COMMENT "Copying detection rules (dev mode)..."
)
