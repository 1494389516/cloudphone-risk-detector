import CRiskCore
import Darwin
import Foundation

// MARK: - Frida Gum Trampoline Detection
//
// Detects Frida Gum Interceptor's inline hook trampoline patterns on ARM64.
// Frida's Interceptor replaces the prologue of target functions with branch
// trampolines (LDR X16, #8; BR X16; <addr>) or ADRP+ADD+BR sequences.
// The detector inspects a curated list of high-value system functions,
// reads their first few instructions, and checks for known hook signatures.
// It also follows the branch target to verify that the destination is in
// anonymous memory (a strong indicator of Frida's trampoline pages).

// ARM64 instruction encodings for known hook patterns
private enum HookPattern {
    // LDR X16, #8  (literal load of 8 bytes forward into X16)
    static let ldrX16: UInt32 = 0x58000050

    // BR X16  (branch to register X16)
    static let brX16: UInt32 = 0xD61F0200

    // BR X17
    static let brX17: UInt32 = 0xD61F0220

    // RET
    static let ret: UInt32 = 0xD65F03C0

    // NOP
    static let nop: UInt32 = 0xD503201F

    // STP X29, X30, [SP, #-16]!  (typical frame setup — Frida trampoline prologue)
    static let stpX29X30Neg16: UInt32 = 0xA9BF7BFD

    // STP X29, X30, [SP, #-32]!
    static let stpX29X30Neg32: UInt32 = 0xA9BF7BFD &+ 0x00000020

    // MOV X29, SP
    static let movX29SP: UInt32 = 0x910003FD

    // ADRP instruction mask (bits [31:24] = 1xx1 0000)
    static let adrpMask: UInt32 = 0x9F000000
    static let adrpValue: UInt32 = 0x90000000

    // ADD Xn, Xn, #imm mask
    static let addMask: UInt32 = 0xFFC00000
    static let addX17Value: UInt32 = 0x91000031  // ADD X17, X17, #imm

    // B instruction mask (unconditional branch, bits [31:26] = 000101)
    static let bMask: UInt32 = 0xFC000000
    static let bValue: UInt32 = 0x14000000
}

/// Result of checking a single symbol's prologue for trampoline hooks.
private struct TrampolineCheckResult {
    let symbolName: String
    let isHooked: Bool
    let branchTarget: UnsafeRawPointer?
    let targetInAnonymousMemory: Bool
    let pattern: String
    let score: Double
}

/// Detects Frida Gum Interceptor trampoline code patterns on critical system functions.
///
/// Frida 17.x Interceptor uses LDR+BR trampolines at function entry points.
/// This detector:
/// 1. Resolves high-value system function addresses via dlsym
/// 2. Reads the first 4 instructions (16 bytes) of each function
/// 3. Checks for known inline hook patterns (LDR X16, BR X16, etc.)
/// 4. Follows branch targets and checks if they land in anonymous memory
/// 5. Detects hook chains (multiple functions hooked to the same region)
struct GumTrampolineDetector: Detector {

    /// System critical functions frequently targeted by Frida Interceptor.
    private static let criticalSymbols: [(name: String, library: String)] = [
        // Process/thread
        ("pthread_create", "/usr/lib/system/libsystem_pthread.dylib"),
        ("pthread_kill", "/usr/lib/system/libsystem_pthread.dylib"),
        ("fork", "/usr/lib/system/libsystem_kernel.dylib"),
        ("posix_spawn", "/usr/lib/system/libsystem_kernel.dylib"),

        // Memory management
        ("mmap", "/usr/lib/system/libsystem_kernel.dylib"),
        ("mprotect", "/usr/lib/system/libsystem_kernel.dylib"),
        ("mach_vm_read", "/usr/lib/system/libsystem_kernel.dylib"),
        ("mach_vm_write", "/usr/lib/system/libsystem_kernel.dylib"),

        // dyld
        ("dlopen", "/usr/lib/system/libdyld.dylib"),
        ("dlsym", "/usr/lib/system/libdyld.dylib"),
        ("dladdr", "/usr/lib/system/libdyld.dylib"),

        // File I/O
        ("open", "/usr/lib/system/libsystem_kernel.dylib"),
        ("access", "/usr/lib/system/libsystem_kernel.dylib"),
        ("stat", "/usr/lib/system/libsystem_kernel.dylib"),

        // Network
        ("socket", "/usr/lib/system/libsystem_kernel.dylib"),
        ("connect", "/usr/lib/system/libsystem_kernel.dylib"),
        ("recvmsg", "/usr/lib/system/libsystem_kernel.dylib"),

        // sysctl
        ("sysctl", "/usr/lib/system/libsystem_kernel.dylib"),
        ("sysctlbyname", "/usr/lib/system/libsystem_kernel.dylib"),

        // ObjC runtime
        ("objc_msgSend", "/usr/lib/libobjc.A.dylib"),
        ("objc_getClass", "/usr/lib/libobjc.A.dylib"),

        // Crypto
        ("CC_SHA256", "/System/Library/Frameworks/Security.framework/Security"),
        ("CCCrypt", "/System/Library/Frameworks/Security.framework/Security"),
    ]

    /// Number of 32-bit instructions to read from each function prologue.
    private static let instructionCount = 4

    @inline(never)
    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["gum_trampoline:unavailable_simulator"])
#else
        return detectKernel()
#endif
    }

    /// Keep the VMP-targeted `detect()` entry narrow and stable in optimized builds.
    @inline(never)
    private func detectKernel() -> DetectorResult {
        var totalScore: Double = 0
        var methods: [String] = []
        var hookedSymbols: [TrampolineCheckResult] = []
        var branchTargets: [UnsafeRawPointer: Int] = [:]  // target -> count for chain detection

        for symbol in Self.criticalSymbols {
            let result = checkSymbolTrampoline(symbol.name, library: symbol.library)
            if result.isHooked {
                hookedSymbols.append(result)
                totalScore += result.score
                methods.append("gum_trampoline:\(result.symbolName):\(result.pattern)")

                if let target = result.branchTarget {
                    branchTargets[target, default: 0] += 1
                }
            }
        }

        // Bonus: hook chain detection — multiple functions pointing to same anonymous region
        let chainCount = branchTargets.values.filter { $0 >= 2 }.count
        if chainCount > 0 {
            totalScore += Double(chainCount) * 15
            methods.append("gum_trampoline:hook_chain:\(chainCount)_targets")
        }

        // Cap the total score
        return DetectorResult(score: min(totalScore, 90), methods: methods)
    }

    // MARK: - Per-Symbol Trampoline Check

    private func checkSymbolTrampoline(_ name: String, library: String) -> TrampolineCheckResult {
        // Resolve symbol address via dlsym
        guard let handle = dlopen(library, RTLD_LAZY | RTLD_NOLOAD),
              let symPtr = dlsym(handle, name) else {
            return TrampolineCheckResult(
                symbolName: name,
                isHooked: false,
                branchTarget: nil,
                targetInAnonymousMemory: false,
                pattern: "unresolved",
                score: 0
            )
        }

        // Verify the address actually belongs to the expected library via dladdr
        var info = Dl_info()
        guard dladdr(symPtr, &info) != 0 else {
            return TrampolineCheckResult(
                symbolName: name,
                isHooked: false,
                branchTarget: nil,
                targetInAnonymousMemory: false,
                pattern: "dladdr_failed",
                score: 0
            )
        }

        // Read first N instructions
        let instructions = readInstructions(at: symPtr, count: Self.instructionCount)
        guard !instructions.isEmpty else {
            return TrampolineCheckResult(
                symbolName: name,
                isHooked: false,
                branchTarget: nil,
                targetInAnonymousMemory: false,
                pattern: "read_failed",
                score: 0
            )
        }

        // Check for known hook patterns
        let (isHooked, patternName) = isKnownHookPattern(instructions)

        if isHooked {
            // Resolve branch target
            let target = resolveBranchTarget(instructions, base: symPtr)
            var targetIsAnon = false

            if let target = target {
                targetIsAnon = isAddressInAnonymousMemory(target)

                // Extra: verify the target is not in a known system image
                let inImage = cprisk_addr_in_any_image(target) != 0
                if inImage && !targetIsAnon {
                    // Target is in a known image — likely not Frida, reduce confidence
                    return TrampolineCheckResult(
                        symbolName: name,
                        isHooked: false,
                        branchTarget: nil,
                        targetInAnonymousMemory: false,
                        pattern: patternName,
                        score: 0
                    )
                }
            }

            // Score: base + anonymous memory bonus
            var score = 8.0
            if targetIsAnon {
                score = 12.0
            }

            return TrampolineCheckResult(
                symbolName: name,
                isHooked: true,
                branchTarget: target,
                targetInAnonymousMemory: targetIsAnon,
                pattern: patternName,
                score: score
            )
        }

        return TrampolineCheckResult(
            symbolName: name,
            isHooked: false,
            branchTarget: nil,
            targetInAnonymousMemory: false,
            pattern: "clean",
            score: 0
        )
    }

    // MARK: - Pattern Matching

    /// Checks if the instruction sequence matches a known Frida hook trampoline pattern.
    /// Returns (isHooked, patternName).
    private func isKnownHookPattern(_ instructions: [UInt32]) -> (Bool, String) {
        guard instructions.count >= 2 else { return (false, "too_short") }

        // Pattern 1: LDR X16, #8; BR X16  (standard Frida Gum short trampoline)
        if instructions[0] == HookPattern.ldrX16 && instructions[1] == HookPattern.brX16 {
            return (true, "ldr_x16_br_x16")
        }

        // Pattern 2: ADRP X17, ...; ADD X17, X17, ...; BR X17  (Dobby/Substrate style)
        if instructions.count >= 3 {
            let isAdrpAddBr =
                (instructions[0] & HookPattern.adrpMask) == HookPattern.adrpValue &&
                (instructions[1] & HookPattern.addMask) == HookPattern.addX17Value &&
                instructions[2] == HookPattern.brX17
            if isAdrpAddBr {
                return (true, "adrp_add_br_x17")
            }
        }

        // Pattern 3: B <offset> (unconditional relative branch to trampoline)
        if (instructions[0] & HookPattern.bMask) == HookPattern.bValue {
            // Verify it is not a branch to a nearby location within the function
            // (which could be a normal function prologue). Frida's trampoline
            // branches are typically long-range.
            let imm26 = instructions[0] & 0x03FFFFFF
            let signExtended = signExtend(imm26, bits: 26)
            // If the branch offset is > 1MB, it's very likely a hook trampoline
            if abs(signExtended) > 0x100000 {
                return (true, "b_long_range")
            }
        }

        // Pattern 4: LDR X16, #8; BR X16 with NOP padding
        // Some Frida variants insert NOPs before or after
        if instructions.count >= 3 {
            if instructions[0] == HookPattern.nop && instructions[1] == HookPattern.ldrX16 && instructions[2] == HookPattern.brX16 {
                return (true, "nop_ldr_x16_br_x16")
            }
        }

        // Pattern 5: BR X16 directly (rare, but seen in some hook implementations)
        if instructions[0] == HookPattern.brX16 {
            return (true, "br_x16_direct")
        }

        // Pattern 6: BR X17 directly
        if instructions[0] == HookPattern.brX17 {
            return (true, "br_x17_direct")
        }

        return (false, "clean")
    }

    // MARK: - Branch Target Resolution

    /// Resolves the target address of a branch trampoline from the instruction sequence.
    private func resolveBranchTarget(_ instructions: [UInt32], base: UnsafeRawPointer) -> UnsafeRawPointer? {
        guard instructions.count >= 2 else { return nil }

        // LDR X16, #8; BR X16 pattern — target is embedded as a literal after the BR
        if instructions[0] == HookPattern.ldrX16 && instructions[1] == HookPattern.brX16 {
            // The 8-byte address literal starts at offset 8 (after LDR + BR)
            let addrPtr = base.advanced(by: 8).assumingMemoryBound(to: UInt64.self)
            let targetAddr = addrPtr.pointee
            return UnsafeRawPointer(bitPattern: UInt(targetAddr))
        }

        // ADRP+ADD+BR X17 pattern
        if instructions.count >= 3 &&
           (instructions[0] & HookPattern.adrpMask) == HookPattern.adrpValue &&
           (instructions[1] & HookPattern.addMask) == HookPattern.addX17Value &&
           instructions[2] == HookPattern.brX17 {

            let baseAddr = UInt(bitPattern: base)
            // Decode ADRP: page-aligned PC-relative offset
            let adrpImmhi = (instructions[0] >> 5) & 0x7FFFF
            let adrpImmlo = (instructions[0] >> 29) & 0x3
            let adrpImm = (adrpImmhi << 2) | adrpImmlo
            let adrpOffset = signExtend(adrpImm, bits: 21) << 12
            let adrpResult = (baseAddr & ~UInt(0xFFF)) &+ UInt(bitPattern: Int(adrpOffset))

            // Decode ADD X17, X17, #imm12
            let addImm12 = (instructions[1] >> 10) & 0xFFF
            let shift = (instructions[1] >> 22) & 0x3
            let addOffset = shift == 1 ? addImm12 << 12 : addImm12

            let finalAddr = adrpResult &+ UInt(addOffset)
            return UnsafeRawPointer(bitPattern: finalAddr)
        }

        // B (unconditional branch) — PC-relative
        if (instructions[0] & HookPattern.bMask) == HookPattern.bValue {
            let imm26 = instructions[0] & 0x03FFFFFF
            let offset = signExtend(imm26, bits: 26) << 2
            let baseAddr = UInt(bitPattern: base)
            let targetAddr = baseAddr &+ UInt(bitPattern: Int(offset))
            return UnsafeRawPointer(bitPattern: targetAddr)
        }

        return nil
    }

    // MARK: - Memory Checks

    /// Checks whether the given address resides in anonymous memory (not backed by any image).
    private func isAddressInAnonymousMemory(_ addr: UnsafeRawPointer) -> Bool {
        // First check: cprisk_addr_in_any_image covers dyld_all_image_infos
        let inImage = cprisk_addr_in_any_image(addr) != 0
        if inImage {
            return false
        }

        // Second check: dladdr as additional verification
        var info = Dl_info()
        if dladdr(addr, &info) != 0 && info.dli_fname != nil {
            // Address resolves to a known image — not anonymous
            return false
        }

        // Third check: vm_region to see if the region is truly anonymous
        var targetAddr = vm_address_t(UInt(bitPattern: addr))
        var size: vm_size_t = 0
        var objectName: mach_port_t = 0
        var basicInfo = vm_region_basic_info_data_64_t()
        var basicCount = mach_msg_type_number_t(
            MemoryLayout<vm_region_basic_info_data_64_t>.stride / MemoryLayout<natural_t>.stride
        )

        let result = withUnsafeMutablePointer(to: &basicInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(basicCount)) { rebound in
                vm_region_64(
                    mach_task_self_,
                    &targetAddr,
                    &size,
                    VM_REGION_BASIC_INFO_64,
                    rebound,
                    &basicCount,
                    &objectName
                )
            }
        }

        guard result == KERN_SUCCESS, size > 0 else { return false }

        // Check extended info for user_tag (anonymous mappings use specific tags)
        var extInfo = vm_region_extended_info_data_t()
        var extCount = mach_msg_type_number_t(
            MemoryLayout<vm_region_extended_info_data_t>.stride / MemoryLayout<natural_t>.stride
        )
        var extAddress = vm_address_t(UInt(bitPattern: addr))
        var extSize: vm_size_t = 0

        let extResult = withUnsafeMutablePointer(to: &extInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(extCount)) { rebound in
                vm_region_64(
                    mach_task_self_,
                    &extAddress,
                    &extSize,
                    VM_REGION_EXTENDED_INFO,
                    rebound,
                    &extCount,
                    &objectName
                )
            }
        }

        if extResult == KERN_SUCCESS {
            // Share mode 0 (SM_COW) or 1 (SM_PRIVATE) with no mapped file = anonymous
            let shareMode = UInt32(extInfo.share_mode)
            if shareMode == 0 || shareMode == 1 || shareMode == 3 {
                return true
            }
        }

        // Fallback: not in any image + not resolved by dladdr = likely anonymous
        return true
    }

    // MARK: - Helpers

    /// Reads `count` 32-bit ARM64 instructions from the given address.
    private func readInstructions(at ptr: UnsafeRawPointer, count: Int) -> [UInt32] {
        var instructions: [UInt32] = []
        instructions.reserveCapacity(count)

        let wordPtr = ptr.assumingMemoryBound(to: UInt32.self)
        for i in 0..<count {
            let addr = UnsafeRawPointer(wordPtr + i)
            // Use vm_read_overwrite for a safer read that is harder to hook
            var bytesRead: vm_size_t = 0
            var value: UInt32 = 0
            let readResult = withUnsafeMutablePointer(to: &value) { buf in
                vm_read_overwrite(
                    mach_task_self_,
                    vm_address_t(UInt(bitPattern: addr)),
                    vm_size_t(MemoryLayout<UInt32>.size),
                    vm_address_t(UInt(bitPattern: buf)),
                    &bytesRead
                )
            }

            if readResult == KERN_SUCCESS && bytesRead == vm_size_t(MemoryLayout<UInt32>.size) {
                instructions.append(value)
            } else {
                // Fallback to direct read if vm_read_overwrite fails
                instructions.append(wordPtr[i])
            }
        }

        return instructions
    }

    /// Sign-extends a value from `bits` width to Int64.
    private func signExtend(_ value: UInt32, bits: Int) -> Int64 {
        let signBit = UInt32(1) << (bits - 1)
        if value & signBit != 0 {
            // Negative: fill upper bits with 1s
            let mask = (UInt32(1) << bits) - 1
            let inverted = ~value & ~mask
            return Int64(bitPattern: UInt64(value) | UInt64(inverted))
        }
        return Int64(value)
    }
}

// MARK: - Signal Conversion

extension GumTrampolineDetector {
    func asSignals() throws -> [RiskSignal] {
        let result = try detect()
        guard result.score > 0 else { return [] }

        var signals: [RiskSignal] = []

        let hookedMethods = result.methods.filter { $0.hasPrefix("gum_trampoline:") && !$0.contains("hook_chain") }
        if !hookedMethods.isEmpty {
            let hookCount = hookedMethods.count
            let confidence = min(Double(hookCount) / Double(Self.criticalSymbols.count), 1.0)

            signals.append(RiskSignal(
                id: "gum_trampoline_detected",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: min(Double(hookCount) * 8, 50),
                evidence: [
                    "detail": hookedMethods.joined(separator: ","),
                    "hooked_count": "\(hookCount)",
                    "total_checked": "\(Self.criticalSymbols.count)",
                ],
                state: .soft(confidence: confidence),
                layer: 2,
                weightHint: 70
            ))
        }

        let chainMethods = result.methods.filter { $0.contains("hook_chain") }
        if !chainMethods.isEmpty {
            signals.append(RiskSignal(
                id: "gum_trampoline_chain",
                category: ObfuscatedConstants.categoryAntiTamper,
                score: 25,
                evidence: ["detail": chainMethods.joined(separator: ",")],
                state: .tampered,
                layer: 2,
                weightHint: 75
            ))
        }

        return signals
    }
}
