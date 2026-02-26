#include "Vfs.h"
#include "packed_rules.gen.h"

// ============================================================
// AES-256-CBC DECRYPTION (Windows BCrypt)
// ============================================================
static bool AesDecrypt(const unsigned char* key32, const unsigned char* iv16,
                       const unsigned char* ciphertext, size_t cipherLen,
                       vector<unsigned char>& plaintext) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return false;
    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0) != 0) goto cleanup;
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                   (PUCHAR)key32, 32, 0) != 0) goto cleanup;

    {
        ULONG cbResult = 0;
        ULONG cbPlain = 0;

        unsigned char ivCopy[16];
        memcpy(ivCopy, iv16, 16);
        if (BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)cipherLen,
                          NULL, ivCopy, 16, NULL, 0, &cbPlain, BCRYPT_BLOCK_PADDING) != 0)
            goto cleanup;

        plaintext.resize(cbPlain);
        memcpy(ivCopy, iv16, 16);
        if (BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)cipherLen,
                          NULL, ivCopy, 16, plaintext.data(), cbPlain,
                          &cbResult, BCRYPT_BLOCK_PADDING) != 0)
            goto cleanup;

        plaintext.resize(cbResult);
        ok = true;
    }

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// ============================================================
// SHA-256 KEY DERIVATION
// ============================================================
static bool DeriveKey(const string& passphrase, unsigned char out[32]) {
    BCRYPT_ALG_HANDLE hHash = nullptr;
    BCRYPT_HASH_HANDLE hHashObj = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&hHash, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0) return false;
    if (BCryptCreateHash(hHash, &hHashObj, NULL, 0, NULL, 0, 0) != 0) goto cleanup;
    if (BCryptHashData(hHashObj, (PUCHAR)passphrase.data(), (ULONG)passphrase.size(), 0) != 0) goto cleanup;
    if (BCryptFinishHash(hHashObj, out, 32, 0) != 0) goto cleanup;
    ok = true;

cleanup:
    if (hHashObj) BCryptDestroyHash(hHashObj);
    if (hHash) BCryptCloseAlgorithmProvider(hHash, 0);
    return ok;
}

// ============================================================
// EMBEDDED RULE LOADING (AES-256-CBC + CRC32 verify)
// ============================================================
void LoadEmbeddedRules() {
    using namespace adheslime::vfs;

    unsigned char aesKey[32];
    if (!DeriveKey(g_config.encryptionKey, aesKey)) {
        InternalBan(0xA00F, "key_derivation_failed");
        return;
    }

    for (size_t i = 0; i < kPackedRuleCount; i++) {
        const auto& rule = kPackedRules[i];

        vector<unsigned char> plaintext;
        if (!AesDecrypt(aesKey, rule.iv, rule.ciphertext, rule.ciphertextSize, plaintext)) {
            InternalBan(0xA00E, "rule_decrypt_failed");
            SecureZeroMemory(aesKey, 32);
            return;
        }

        uint32_t crc = CalculateCRC32(plaintext.data(), plaintext.size());
        if (crc != rule.crc32) {
            InternalBan(0xA00E, "rule_integrity_fail");
            SecureZeroMemory(aesKey, 32);
            return;
        }

        string script(plaintext.begin(), plaintext.end());
        g_ruleScripts.push_back(move(script));
        InternalLog(("VFS: loaded " + string(rule.name)).c_str());
    }

    SecureZeroMemory(aesKey, 32);
    InternalLog(("VFS: " + to_string(kPackedRuleCount) + " rule(s) decrypted").c_str());
}

// ============================================================
// FILESYSTEM RULE LOADING (dev mode)
// ============================================================
int LoadRuleFromFile(string_view path) {
    ifstream file(string(path), ios::binary);
    if (!file.is_open()) {
        InternalLog(("Failed to load rule: " + string(path)).c_str());
        return -1;
    }
    string source((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
    g_ruleScripts.push_back(move(source));
    InternalLog(("Loaded rule: " + string(path)).c_str());
    return 0;
}

int LoadRulesFromDirectory(string_view dir) {
    error_code ec;
    if (!fs::exists(string(dir), ec)) return -1;
    int count = 0;
    for (const auto& entry : fs::directory_iterator(string(dir), ec)) {
        if (entry.path().extension() == ".js") {
            if (LoadRuleFromFile(entry.path().string()) == 0) count++;
        }
    }
    InternalLog(("Loaded " + to_string(count) + " rule(s) from disk").c_str());
    return count;
}
