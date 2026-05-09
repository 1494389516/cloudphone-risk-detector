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
#   python3 verify_honeypot_bytes_stripped.py [--armored] <path-to-mach-o>
#
# 选项:
#   --armored    断言输入是 armored binary。开启后:
#                  - 找到字节序列 → exit 1 (FAIL，回归)
#                  - 未找到 → exit 0 (PASS)
#                未开启时（默认）:
#                  - 找到字节序列 → exit 0 + warning to stderr (debug binary 预期会有)
#                  - 未找到 → exit 0 (PASS)
#                防止误把 unarmored debug binary 跑出"FAIL"造成混淆 (audit fix N1
#                + F12 post-1st-pass)。
#
# 退出码:
#   0 — 验证通过 (或 non-armored 模式下找到也算通过)
#   1 — armored 模式下字节序列出现，验证失败 (armor pipeline 未覆盖此 .rodata)
#   2 — 命令行用法错误
#
# CI 集成:
#   armor pipeline 完成后调用 (cprisk-armor --verify-honeypot 已自动调用此脚本):
#     python3 BuildSupport/scripts/verify_honeypot_bytes_stripped.py --armored \
#       build/Release-iphoneos/CloudPhoneRiskKit.framework/CloudPhoneRiskKit

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
    armored_mode = False
    positional: list[str] = []
    for arg in argv[1:]:
        if arg == "--armored":
            armored_mode = True
        elif arg.startswith("-"):
            print(f"error: unknown option {arg}", file=sys.stderr)
            return 2
        else:
            positional.append(arg)

    if len(positional) != 1:
        print(
            f"usage: {argv[0]} [--armored] <path-to-mach-o>",
            file=sys.stderr,
        )
        return 2

    binary_path = positional[0]
    if not os.path.isfile(binary_path):
        print(f"error: {binary_path} is not a file", file=sys.stderr)
        return 2

    with open(binary_path, "rb") as f:
        data = f.read()

    findings: list[str] = []

    xor_hits = find_byte_sequence(data, HONEYPOT_XOR_INPUT)
    if xor_hits:
        hex_pattern = " ".join(f"{b:02X}" for b in HONEYPOT_XOR_INPUT)
        findings.append(
            f"expectedVendorB XOR-input bytes [{hex_pattern}] found at "
            f"{len(xor_hits)} offset(s) (first: 0x{xor_hits[0]:08X}). "
            "VMP full on expectedVendorB() does NOT protect this .rodata array; "
            "extend StringEncryptor / DataSegmentEncryptor to cover __const "
            "fixed-size [UInt8] literals, OR refactor expectedVendorB() to derive "
            "the bytes from a higher-entropy source (e.g. white-box PRF)."
        )

    plaintext_hits = find_byte_sequence(data, HONEYPOT_OBSERVED_PLAINTEXT)
    if plaintext_hits:
        findings.append(
            f"observedVendorBLiteral plaintext 'Konami_x42' found at "
            f"{len(plaintext_hits)} offset(s) (first: 0x{plaintext_hits[0]:08X}). "
            "StringEncryptor 'konami' keyword (v7.7 audit-fix F3) should have "
            "caught this — verify cprisk-armor pipeline ran Pass 1 successfully."
        )

    if findings:
        prefix = "FAIL" if armored_mode else "WARN"
        for line in findings:
            print(f"{prefix}: {line}", file=sys.stderr)
        if armored_mode:
            print(
                f"\nverify_honeypot_bytes_stripped: armored mode — "
                f"{len(findings)}/2 check(s) failed against {binary_path}",
                file=sys.stderr,
            )
            return 1
        else:
            print(
                f"\nverify_honeypot_bytes_stripped: non-armored mode — "
                f"{len(findings)}/2 finding(s) in {binary_path} (expected for unarmored "
                f"debug binaries; pass --armored to enforce)",
                file=sys.stderr,
            )
            return 0

    suffix = " (armored mode)" if armored_mode else ""
    print(
        f"verify_honeypot_bytes_stripped: PASS{suffix} — both honeypot byte patterns "
        f"absent from {binary_path} ({len(data):,} bytes scanned)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
