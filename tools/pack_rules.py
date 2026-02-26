import os
import sys
import hashlib
import zlib

try:
    from Crypto.Cipher import AES
except ImportError:
    print("ERROR: pycryptodome required. Install: pip install pycryptodome")
    sys.exit(1)


def derive_key(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def encrypt_rule(data: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce, ciphertext, tag


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def sanitize_varname(name: str) -> str:
    out = []
    for ch in name:
        out.append(ch if (ch.isalnum() or ch == "_") else "_")
    return "".join(out)


def usage(argv0: str) -> str:
    return f"Usage: {argv0} <rules_dir> <output_header> --key <passphrase>"


def parse_args(argv: list[str]) -> tuple[str, str, str]:
    if len(argv) < 4 or "--key" not in argv:
        raise ValueError(usage(argv[0]))
    key_idx = argv.index("--key") + 1
    if key_idx >= len(argv):
        raise ValueError(usage(argv[0]))
    return argv[1], argv[2], argv[key_idx]


def read_rule_file(path: str) -> bytes:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().encode("utf-8")


def collect_rules(rules_dir: str, key: bytes) -> list[tuple[str, bytes, bytes, bytes, int, int]]:
    rules: list[tuple[str, bytes, bytes, bytes, int, int]] = []
    for filename in sorted(os.listdir(rules_dir)):
        if not filename.endswith(".js"):
            continue
        raw = read_rule_file(os.path.join(rules_dir, filename))
        checksum = crc32(raw)
        nonce, ciphertext, tag = encrypt_rule(raw, key)
        rules.append((filename, nonce, ciphertext, tag, checksum, len(raw)))
    return rules


def write_bytes_array(out, name: str, data: bytes, columns: int) -> None:
    out.write(f"static constexpr unsigned char {name}[] = {{\n    ")
    for i, b in enumerate(data):
        out.write(f"0x{b:02X},")
        if columns > 0 and (i + 1) % columns == 0:
            out.write("\n    ")
    out.write("\n};\n")


def write_header(output: str, rules: list[tuple[str, bytes, bytes, bytes, int, int]]) -> None:
    with open(output, "w", encoding="utf-8") as out:
        out.write("#pragma once\n")
        out.write("#include <cstdint>\n")
        out.write("#include <cstddef>\n\n")
        out.write("namespace adheslime::vfs {\n\n")

        for name, nonce, ciphertext, tag, _, _ in rules:
            varname = sanitize_varname(name)
            write_bytes_array(out, f"kNonce_{varname}", nonce, 0)
            write_bytes_array(out, f"kTag_{varname}", tag, 0)
            write_bytes_array(out, f"kRule_{varname}", ciphertext, 20)
            out.write("\n")

        out.write("struct PackedRule {\n")
        out.write("    const char*          name;\n")
        out.write("    const unsigned char* nonce;\n")
        out.write("    const unsigned char* tag;\n")
        out.write("    const unsigned char* ciphertext;\n")
        out.write("    size_t               ciphertextSize;\n")
        out.write("    size_t               plaintextSize;\n")
        out.write("    uint32_t             crc32;\n")
        out.write("};\n\n")

        out.write("static constexpr PackedRule kPackedRules[] = {\n")
        for name, _, _, _, checksum, original_size in rules:
            varname = sanitize_varname(name)
            out.write(
                f"    {{ \"{name}\", kNonce_{varname}, kTag_{varname}, kRule_{varname}, "
                f"sizeof(kRule_{varname}), {original_size}, 0x{checksum:08X}u }},\n"
            )
        out.write("};\n")
        out.write(f"static constexpr size_t kPackedRuleCount = {len(rules)};\n\n")
        out.write("} \n")


def main() -> None:
    try:
        rules_dir, output, passphrase = parse_args(sys.argv)
    except ValueError as e:
        print(str(e))
        sys.exit(1)

    key = derive_key(passphrase)
    rules = collect_rules(rules_dir, key)
    write_header(output, rules)
    print(f"AES-256-GCM: packed {len(rules)} rule(s) into {output}")


if __name__ == "__main__":
    main()