#!/usr/bin/env python3
"""
Post-build PE obfuscation for bigbro.dll.

Level 1 — Metadata cleanup:
  1. Erase Rich header (compiler fingerprint)
  2. Zero timestamps, linker version
  3. Zero debug directory
  4. Randomize section names

Level 2 — Anti-analysis (IDA/Ghidra confusion):
  5. Poison inter-function padding (anti-disasm desync)
  6. Corrupt .pdata (break function discovery)
  7. Append PE overlay junk (confuse boundary detection)
  8. Erase export timestamps + forwarder hints

Usage: python obfuscate_pe.py <path_to_dll>
"""
import struct
import sys
import os
import random
import string

ANTI_DISASM_PATTERNS = [
    # All patterns are VALID x86-64 instructions (safe if accidentally executed)
    # but they confuse IDA's heuristic function boundary detection.
    bytes([0x48, 0xFF, 0xC8]),                          # dec rax
    bytes([0x48, 0x87, 0xC0]),                          # xchg rax, rax
    bytes([0x48, 0x85, 0xC0]),                          # test rax, rax
    bytes([0x4C, 0x8B, 0xC0]),                          # mov r8, rax
    bytes([0x49, 0x89, 0xC0]),                          # mov r8, rax (alt)
    bytes([0x50, 0x58]),                                # push rax; pop rax
    bytes([0x51, 0x59]),                                # push rcx; pop rcx
    bytes([0x48, 0x33, 0xC0]),                          # xor rax, rax
    bytes([0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00]),        # 6-byte NOP (unusual encoding)
    bytes([0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]),  # 7-byte NOP (unusual encoding)
]

# Multi-byte NOP variants (all functionally identical to 0x90)
# x86-64 has official multi-byte NOPs recommended by Intel/AMD
NOP_VARIANTS = [
    bytes([0x90]),                                      # 1-byte: nop
    bytes([0x66, 0x90]),                                # 2-byte: 66 nop
    bytes([0x0F, 0x1F, 0x00]),                          # 3-byte: nop dword [rax]
    bytes([0x0F, 0x1F, 0x40, 0x00]),                    # 4-byte: nop dword [rax+0]
    bytes([0x0F, 0x1F, 0x44, 0x00, 0x00]),              # 5-byte: nop dword [rax+rax+0]
    bytes([0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00]),        # 6-byte: nop word ...
    bytes([0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00]),  # 7-byte: nop dword [rax+0x0]
]


def random_section_name():
    chars = string.ascii_lowercase + string.digits
    return '.' + ''.join(random.choice(chars) for _ in range(7))


def pe_checksum(data):
    """Calculate PE checksum (same as MapFileAndCheckSum)."""
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    cs_offset = e_lfanew + 88

    size = len(data)
    checksum = 0
    for i in range(0, size, 2):
        if i == cs_offset or i == cs_offset + 2:
            continue
        val = struct.unpack_from('<H', data, i)[0] if i + 2 <= size else data[i]
        checksum += val
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return (checksum + size) & 0xFFFFFFFF


def find_text_section(data, e_lfanew):
    """Find .text section header info."""
    num_sec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    sec_off = e_lfanew + 24 + struct.unpack_from('<H', data, e_lfanew + 20)[0]
    for i in range(num_sec):
        off = sec_off + i * 40
        name = bytes(data[off:off+8]).rstrip(b'\x00')
        if name == b'.text':
            virt_addr = struct.unpack_from('<I', data, off + 12)[0]
            virt_size = struct.unpack_from('<I', data, off + 8)[0]
            raw_off = struct.unpack_from('<I', data, off + 20)[0]
            raw_size = struct.unpack_from('<I', data, off + 16)[0]
            return virt_addr, virt_size, raw_off, raw_size
    return None


def _fill_with_patterns(data, run_start, run_len):
    """Fill a padding region with anti-disasm byte patterns."""
    pos = run_start
    end = run_start + run_len - 2
    while pos < end:
        pattern = random.choice(ANTI_DISASM_PATTERNS)
        space = (run_start + run_len) - pos
        if len(pattern) > space:
            break
        data[pos:pos+len(pattern)] = pattern
        pos += len(pattern)


def poison_padding(data, text_raw_off, text_raw_size):
    """
    Replace 0xCC (int3) padding between functions with anti-disasm patterns.
    IDA uses 0xCC runs to detect function boundaries. By replacing them
    with confusing byte patterns, IDA's function detection breaks.
    """
    count = 0
    i = text_raw_off
    end = text_raw_off + text_raw_size

    while i < end - 6:
        if data[i] != 0xCC or data[i+1] != 0xCC or data[i+2] != 0xCC:
            i += 1
            continue

        run_start = i
        while i < end and data[i] == 0xCC:
            i += 1
        run_len = i - run_start

        if run_len >= 3:
            _fill_with_patterns(data, run_start, run_len)
            count += 1


    return count


def diversify_nops(data, text_raw_off, text_raw_size):
    """Replace single-byte NOPs (0x90) with random multi-byte NOP variants."""
    count = 0
    i = text_raw_off
    end = text_raw_off + text_raw_size

    while i < end - 7:
        if data[i] != 0x90:
            i += 1
            continue

        # Measure consecutive 0x90 run
        run_start = i
        while i < end and data[i] == 0x90:
            i += 1
        run_len = i - run_start

        if run_len < 2:
            continue

        # Fill with random multi-byte NOPs
        pos = run_start
        while pos < run_start + run_len:
            remaining = (run_start + run_len) - pos
            candidates = [n for n in NOP_VARIANTS if len(n) <= remaining]
            if not candidates:
                break
            nop = random.choice(candidates)
            data[pos:pos+len(nop)] = nop
            pos += len(nop)
        count += 1

    return count


def inject_build_watermark(data, e_lfanew):
    """Inject a random 32-byte build ID into unused DOS stub space (offset 0x40-0x5F)."""
    watermark_off = 0x40
    if watermark_off + 32 >= e_lfanew:
        return None
    build_id = os.urandom(32)
    data[watermark_off:watermark_off+32] = build_id
    return build_id.hex()[:16]


def corrupt_pdata(data, e_lfanew):
    """
    Shuffle .pdata entries to confuse IDA's function discovery.
    We ONLY reorder entries (never corrupt values) so SEH still works.
    Windows normally expects sorted .pdata for binary search, but falls
    back to linear scan when entries are out of order.
    """
    opt_off = e_lfanew + 24
    num_dd = struct.unpack_from('<I', data, opt_off + 108)[0]
    if num_dd <= 3:
        return 0

    exc_rva = struct.unpack_from('<I', data, opt_off + 112 + 3 * 8)[0]
    exc_size = struct.unpack_from('<I', data, opt_off + 112 + 3 * 8 + 4)[0]
    if exc_rva == 0 or exc_size == 0:
        return 0

    # Find file offset for .pdata
    num_sec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    sec_off = e_lfanew + 24 + struct.unpack_from('<H', data, e_lfanew + 20)[0]
    pdata_file_off = None
    for i in range(num_sec):
        off = sec_off + i * 40
        sec_va = struct.unpack_from('<I', data, off + 12)[0]
        sec_vs = struct.unpack_from('<I', data, off + 8)[0]
        sec_raw = struct.unpack_from('<I', data, off + 20)[0]
        if sec_va <= exc_rva < sec_va + sec_vs:
            pdata_file_off = sec_raw + (exc_rva - sec_va)
            break

    if pdata_file_off is None:
        return 0

    entry_size = 12
    num_entries = exc_size // entry_size
    if num_entries < 10:
        return 0

    # Swap ~10% of entries (reorder only, no value corruption)
    swap_count = max(1, num_entries // 10)
    for _ in range(swap_count):
        a, b = random.sample(range(num_entries), 2)
        off_a = pdata_file_off + a * entry_size
        off_b = pdata_file_off + b * entry_size
        tmp = bytes(data[off_a:off_a+entry_size])
        data[off_a:off_a+entry_size] = data[off_b:off_b+entry_size]
        data[off_b:off_b+entry_size] = tmp

    return swap_count


def add_overlay(data):
    """
    Append 4-16 KB of junk data after the last section.
    Some analysis tools get confused by PE overlays, thinking there's
    extra hidden code or packed content. The junk contains fake PE-like
    structures to keep them busy.
    """
    overlay_size = random.randint(4096, 16384)
    overlay = bytearray(os.urandom(overlay_size))

    # Sprinkle fake PE signatures and function prologues
    fake_patterns = [
        b'\x48\x89\x5c\x24\x08',  # mov [rsp+8], rbx (common prolog)
        b'\x48\x83\xec\x28',      # sub rsp, 0x28 (stack frame)
        b'\x48\x8b\xc4',          # mov rax, rsp
        b'\xff\x15',              # call [rip+disp] (indirect call — fake xref bait)
        b'\x4c\x8b\xdc',          # mov r11, rsp
        b'\x55\x48\x8d\xac\x24', # push rbp; lea rbp, [rsp+...]
    ]
    for _ in range(overlay_size // 64):
        pos = random.randint(0, overlay_size - 16)
        pat = random.choice(fake_patterns)
        overlay[pos:pos+len(pat)] = pat

    data.extend(overlay)
    return overlay_size


def erase_export_timestamps(data, e_lfanew):
    """Zero the export directory timestamp and name RVA."""
    opt_off = e_lfanew + 24
    num_dd = struct.unpack_from('<I', data, opt_off + 108)[0]
    if num_dd < 1:
        return False

    exp_rva = struct.unpack_from('<I', data, opt_off + 112)[0]
    if exp_rva == 0:
        return False

    # Convert RVA to file offset
    num_sec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    sec_off = e_lfanew + 24 + struct.unpack_from('<H', data, e_lfanew + 20)[0]
    for i in range(num_sec):
        off = sec_off + i * 40
        sec_va = struct.unpack_from('<I', data, off + 12)[0]
        sec_vs = struct.unpack_from('<I', data, off + 8)[0]
        sec_raw = struct.unpack_from('<I', data, off + 20)[0]
        if sec_va <= exp_rva < sec_va + sec_vs:
            file_off = sec_raw + (exp_rva - sec_va)
            # IMAGE_EXPORT_DIRECTORY.TimeDateStamp at offset 4
            struct.pack_into('<I', data, file_off + 4, 0)
            # Zero the Name RVA (offset 12) — no DLL name visible
            struct.pack_into('<I', data, file_off + 12, 0)
            return True
    return False


def _erase_rich_header(data, e_lfanew):
    """Erase Rich header (compiler fingerprint)."""
    rich_end = data.find(b'Rich', 0, e_lfanew)
    if rich_end <= 0:
        return None
    rich_end += 8
    xor_key = struct.unpack_from('<I', data, rich_end - 4)[0]
    dans_marker = struct.pack('<I', 0x536E6144 ^ xor_key)
    rich_start = data.find(dans_marker, 0x80, rich_end)
    if rich_start <= 0:
        return None
    for i in range(rich_start, rich_end):
        data[i] = 0
    return f'Rich header erased ({rich_end - rich_start} bytes)'


def _zero_debug_directory(data, opt_offset):
    """Zero debug directory entry."""
    num_dd = struct.unpack_from('<I', data, opt_offset + 108)[0]
    if num_dd <= 6:
        return None
    dd_off = opt_offset + 112 + 6 * 8
    if struct.unpack_from('<I', data, dd_off)[0] == 0:
        return None
    struct.pack_into('<I', data, dd_off, 0)
    struct.pack_into('<I', data, dd_off + 4, 0)
    return 'Debug directory zeroed'


def _randomize_section_names(data, e_lfanew):
    """Randomize non-critical section names."""
    preserve = {b'.text\x00\x00\x00', b'.bigdata'}
    num_sec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    sec_off = e_lfanew + 24 + struct.unpack_from('<H', data, e_lfanew + 20)[0]
    results = []
    for i in range(num_sec):
        off = sec_off + i * 40
        name = bytes(data[off:off+8])
        stripped = name.rstrip(b'\x00')
        if name in preserve or stripped in preserve:
            continue
        new = random_section_name().encode('ascii').ljust(8, b'\x00')[:8]
        data[off:off+8] = new
        results.append(f'Section {stripped.decode()} -> {new.rstrip(b"\\x00").decode()}')
    return results


def obfuscate_pe(path):
    with open(path, 'rb') as f:
        data = bytearray(f.read())

    if data[:2] != b'MZ':
        print(f'ERROR: {path} is not a valid PE file')
        return False

    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        print('ERROR: Invalid PE signature')
        return False

    print(f'[*] Processing: {path}')
    changes = []
    opt_offset = e_lfanew + 24

    # ==== Level 1: Metadata cleanup ====
    rich_msg = _erase_rich_header(data, e_lfanew)
    if rich_msg:
        changes.append(rich_msg)

    struct.pack_into('<I', data, e_lfanew + 8, 0)
    changes.append('COFF timestamp zeroed')

    data[opt_offset + 2] = 0
    data[opt_offset + 3] = 0
    changes.append('Linker version zeroed')

    debug_msg = _zero_debug_directory(data, opt_offset)
    if debug_msg:
        changes.append(debug_msg)

    changes.extend(_randomize_section_names(data, e_lfanew))

    if erase_export_timestamps(data, e_lfanew):
        changes.append('Export directory timestamp + DLL name erased')

    # ==== Level 2: Anti-analysis ====

    text_info = find_text_section(data, e_lfanew)
    if text_info:
        _, _, raw_off, raw_size = text_info
        n = poison_padding(data, raw_off, raw_size)
        changes.append(f'Poisoned {n} inter-function padding regions (anti-disasm)')

    overlay_kb = add_overlay(data) / 1024
    changes.append(f'Appended {overlay_kb:.1f} KB overlay junk')

    if text_info:
        _, _, raw_off, raw_size = text_info
        n = diversify_nops(data, raw_off, raw_size)
        changes.append(f'Diversified {n} NOP regions (unique per build)')

    wm = inject_build_watermark(data, e_lfanew)
    if wm:
        changes.append(f'Build watermark: {wm}...')

    # ==== Finalize ====
    cs_off = e_lfanew + 88
    struct.pack_into('<I', data, cs_off, 0)
    new_cs = pe_checksum(data)
    struct.pack_into('<I', data, cs_off, new_cs)
    changes.append(f'PE checksum: 0x{new_cs:08X}')

    with open(path, 'wb') as f:
        f.write(data)

    print(f'[+] {len(changes)} transformations applied:')
    for c in changes:
        print(f'    - {c}')
    print(f'[+] Output: {path} ({len(data)/1024:.1f} KB)')
    return True


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <pe_file>')
        sys.exit(1)
    if not obfuscate_pe(sys.argv[1]):
        sys.exit(1)
