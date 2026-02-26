#pragma once

#include <cstdint>
#include <intrin.h>

static __forceinline bool OpaqueTrue() {
    volatile uint32_t x = (uint32_t)__rdtsc();
    volatile uint32_t y = x * (x + 1);
    return (y % 2 == 0);
}

static __forceinline bool OpaqueFalse() {
    volatile int32_t x = (int32_t)(__rdtsc() | 1);
    volatile int32_t r = x & 0x7FFFFFFF;
    return (r < 0);
}

static __forceinline uint32_t HideU32(uint32_t encoded, uint32_t key) {
    volatile uint32_t v_enc = encoded;
    volatile uint32_t v_key = key;
    return v_enc ^ v_key;
}


#define OBF_KEY_FOR(ctr) ((uint32_t)((ctr) * 0x45D9F3B7u + 0x7B3D9F1Eu))
#define OBF_U32(val) [](){ constexpr uint32_t k = OBF_KEY_FOR(__COUNTER__); return HideU32((uint32_t)(val) ^ k, k); }()
#define OBF_I32(val) ((int32_t)[](){ constexpr uint32_t k = OBF_KEY_FOR(__COUNTER__); return HideU32((uint32_t)(int32_t)(val) ^ k, k); }())
#define OBF_DWORD(val) ((DWORD)[](){ constexpr uint32_t k = OBF_KEY_FOR(__COUNTER__); return HideU32((uint32_t)(val) ^ k, k); }())

static __forceinline int64_t HideI64(int64_t encoded, int64_t key) {
    volatile int64_t v_enc = encoded;
    volatile int64_t v_key = key;
    return v_enc ^ v_key;
}
#define OBF_KEY64 0x4A2C8E6F5D1B7A39LL
#define OBF_I64(val) HideI64((int64_t)(val) ^ OBF_KEY64, OBF_KEY64)

static __forceinline uintptr_t HidePtr(uintptr_t encoded, uintptr_t key) {
    volatile uintptr_t v_enc = encoded;
    volatile uintptr_t v_key = key;
    return v_enc ^ v_key;
}
#define OBF_PTR(val) HidePtr((uintptr_t)(val) ^ (uintptr_t)OBF_KEY64, (uintptr_t)OBF_KEY64)

inline volatile uint32_t g_obf_sink = 0;

#define JUNK_BRANCH do {                                      \
    if (OpaqueFalse()) {                                      \
        volatile uint32_t _jb = (uint32_t)__rdtsc();          \
        g_obf_sink = _jb ^ 0xDEADBEEFu;                      \
    }                                                         \
} while(0)

static __forceinline bool ObfCmpGtU32(uint32_t a, uint32_t b) {
    volatile uint32_t va = a;
    volatile uint32_t vb = b;
    volatile uint32_t diff = va - vb;
    volatile uint32_t zero = (uint32_t)(__rdtsc() & 0u);
    diff += zero;
    return (diff > 0) && (va > vb);
}

static __forceinline bool ObfCmpGtDbl(double a, double b) {
    volatile double va = a;
    volatile double vb = b;
    return (va - vb) > 0.0;
}

static __forceinline bool ObfCmpLtI64(int64_t a, int64_t b) {
    volatile int64_t va = a;
    volatile int64_t vb = b;
    return (va - vb) < 0;
}

#define DETECT_BEGIN do {                                      \
    JUNK_BRANCH;                                              \
    if (OpaqueTrue()) {

#define DETECT_END                                            \
    }                                                         \
    JUNK_BRANCH;                                              \
} while(0)

