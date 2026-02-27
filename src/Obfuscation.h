#pragma once

#include <cstdint>
#include <intrin.h>

#define OBF_KEY_FOR(ctr) ((uint32_t)((ctr) * 0x45D9F3B7u + 0x7B3D9F1Eu))

#define OBF_U32(val) [](){ constexpr uint32_t k = OBF_KEY_FOR(__COUNTER__); \
    volatile uint32_t e = (uint32_t)(val) ^ k; return e ^ k; }()

#define OBF_I32(val) ((int32_t)OBF_U32((uint32_t)(int32_t)(val)))

#define OBF_DWORD(val) ((DWORD)OBF_U32((uint32_t)(val)))

#define OBF_I64(val) [](){ volatile int64_t k = 0x4A2C8E6F5D1B7A39LL; \
    volatile int64_t e = (int64_t)(val) ^ k; return e ^ k; }()

#define OBF_PTR(val) [](){ volatile uintptr_t k = (uintptr_t)0x4A2C8E6F5D1B7A39ULL; \
    volatile uintptr_t e = (uintptr_t)(val) ^ k; return e ^ k; }()

template <typename T>
class __declspec(novtable) ObfVar {
    volatile uint8_t _data[sizeof(T)];
    volatile uint32_t _key;

    static __forceinline uint32_t rotl(uint32_t v, int n) {
        return (v << n) | (v >> (32 - n));
    }
    __forceinline void encrypt(const T& val) {
        const uint8_t* src = reinterpret_cast<const uint8_t*>(&val);
        uint32_t k = _key;
        for (size_t i = 0; i < sizeof(T); i++) {
            _data[i] = src[i] ^ (uint8_t)(k >> (8 * (i & 3)));
            k = rotl(k, 7) + 0x9E3779B9u;
        }
    }
    __forceinline T decrypt() const {
        T result;
        uint8_t* dst = reinterpret_cast<uint8_t*>(&result);
        uint32_t k = _key;
        for (size_t i = 0; i < sizeof(T); i++) {
            dst[i] = _data[i] ^ (uint8_t)(k >> (8 * (i & 3)));
            k = rotl(k, 7) + 0x9E3779B9u;
        }
        return result;
    }
public:
    __forceinline ObfVar() : _key((uint32_t)__rdtsc()) { T z{}; encrypt(z); }
    __forceinline ObfVar(const T& val) : _key((uint32_t)__rdtsc()) { encrypt(val); }
    __forceinline void set(const T& val) { _key = rotl(_key, 13) ^ (uint32_t)__rdtsc(); encrypt(val); }
    __forceinline T get() const { return decrypt(); }
    __forceinline operator T() const { return get(); }
    __forceinline ObfVar& operator=(const T& val) { set(val); return *this; }
};

#define OBF_VAR(type, name, val) ObfVar<type> name(val)
