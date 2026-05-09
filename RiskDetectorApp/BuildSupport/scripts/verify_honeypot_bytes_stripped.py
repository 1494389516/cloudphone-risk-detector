#!/usr/bin/env python3
# v7.7 audit-fix F12: acceptance test for HoneypotConflictFieldProvider.expectedVendorB().
#
# 蜜罐期望值 expectedVendorB() 通过 XOR-decode 10 字节种子 + key 0x42 在运行时重组为
# "Konami_x42"。VMP `full` 已覆盖该函数的执行路径，但**输入字节数组本身**作为
# `[UInt8]` 字面量编译后落在 `__const` / `__data_const` 段，VMP 防 derivation 不防
# source bytes。
#
# 攻击者只要 `xxd` armored binary 找到这 10 字节序列，XOR 0x42 即可还原 "Konami_x42"，
# 蜜罐双边比对（observed == expected）就此被绕过。
#
# 这个脚本就是用来挡住"上述字节没被 StringEncryptor / SegmentEncryptor 覆盖到"
# 的回归。
#
# 用法:
#   python3 verify_honeypot_bytes_stripped.py <path-to-armored-mach-o>
#
# 退出码:
#   0 — 字节序列未出现，验证通过
#   1 — 字节序列出现，验证失败（armor pipeline 未覆盖到此 .rodata 字面量）
#   2 — 命令行用法错误
#
# CI 集成:
#   armor pipeline 完成后调用，例如:
#     python3 BuildSupport/scripts/verify_honeypot_bytes_stripped.py \
#       build/Release-iphoneos/CloudPhoneRiskKit.framework/CloudPhoneRiskKit
#   非零退出 → fail build。

import os
import sys

# expectedVendorB 的 10 字节 XOR 输入数组（见 HoneypotConflictFieldProvider.swift:46）。
# XOR 0x42 后还原为 "Konami_x42" (0x4B 0x6F 0x6E 0x61 0x6D 0x69 0x5F 0x78 0x34 0x32)。
HONEYPOT_XOR_INPUT = bytes([0x09, 0x2D, 0x2C, 0x23, 0x2F, 0x2B, 0x1D, 0x3A, 0x76, 0x70])

# 同时检查 plaintext "Konami_x42" 也未在 armored binary 中出现 — observedVendorBLiteral
# 是另一面攻击窗口，应被 StringEncryptor 关键词路径（"konami"，v7.7 audit-fix F3）覆盖。
HONEYPOT_OBSERVED_PLAINTEXT = b"Konami_x42"


def find_byte_sequence(haystack: bytes, needle: bytes) -> list[int]:
    """Return all offsets where needle occurs in haystack."""
    offsets = []
    pos = 0
    while True:
        idx = haystack.find(needle, pos)
        if idx == -1:
            break
        offsets.append(idx)
        pos = idx + 1
    return offsets


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(
            f"usage: {argv[0]} <path-to-armored-mach-o>",
            file=sys.stderr,
        )
        return 2

    binary_path = argv[1]
    if not os.path.isfile(binary_path):
        print(f"error: {binary_path} is not a file", file=sys.stderr)
        return 2

    with open(binary_path, "rb") as f:
        data = f.read()

    failures: list[str] = []

    xor_hits = find_byte_sequence(data, HONEYPOT_XOR_INPUT)
    if xor_hits:
        hex_pattern = " ".join(f"{b:02X}" for b in HONEYPOT_XOR_INPUT)
        failures.append(
            f"FAIL: expectedVendorB XOR-input bytes [{hex_pattern}] found at "
            f"{len(xor_hits)} offset(s) (first: 0x{xor_hits[0]:08X}). "
            "VMP full on expectedVendorB() does NOT protect this .rodata array; "
            "extend StringEncryptor / DataSegmentEncryptor to cover __const "
            "fixed-size [UInt8] literals, OR refactor expectedVendorB() to derive "
            "the bytes from a higher-entropy source (e.g. white-box PRF)."
        )

    plaintext_hits = find_byte_sequence(data, HONEYPOT_OBSERVED_PLAINTEXT)
    if plaintext_hits:
        failures.append(
            f"FAIL: observedVendorBLiteral plaintext 'Konami_x42' found at "
            f"{len(plaintext_hits)} offset(s) (first: 0x{plaintext_hits[0]:08X}). "
            "StringEncryptor 'konami' keyword (v7.7 audit-fix F3) should have "
            "caught this — verify cprisk-armor pipeline ran Pass 1 successfully."
        )

    if failures:
        for line in failures:
            print(line, file=sys.stderr)
        print(
            f"\nverify_honeypot_bytes_stripped: 2/{2} checks failed against {binary_path}"
            if len(failures) == 2
            else f"\nverify_honeypot_bytes_stripped: {len(failures)}/2 check(s) failed "
            f"against {binary_path}",
            file=sys.stderr,
        )
        return 1

    print(
        f"verify_honeypot_bytes_stripped: PASS — both honeypot byte patterns absent "
        f"from {binary_path} ({len(data):,} bytes scanned)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
