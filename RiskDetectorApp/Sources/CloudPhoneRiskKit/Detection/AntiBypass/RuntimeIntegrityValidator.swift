import Darwin
import Foundation
import MachO

/// Runtime integrity validation that detects bypass tool interference.
///
/// Performs four categories of checks that are difficult for hooking frameworks
/// (Frida, Substrate, substitute, etc.) to defeat:
///
/// 1. **Selector existence cross-validation** - Verifies that key ObjC selectors
///    resolve to the expected classes. Bypass tools can hook methods but rarely
///    replicate the full class hierarchy perfectly.
///
/// 2. **Instruction pattern validation** - Inspects function prologues of key
///    security functions to detect inline hooks (branch instructions at the
///    start of a function body).
///
/// 3. **Symbol table consistency** - Verifies that key symbols resolve to
///    addresses within the expected image bounds.
///
/// 4. **Stack frame validation** - Checks that the call stack contains no
///    unexpected frames from injected libraries.
struct RuntimeIntegrityValidator: Detector {

    func detect() throws -> DetectorResult {
        #if targetEnvironment(simulator)
        return .empty
        #else
        var score: Double = 0
        var methods: [String] = []

        // 1. Selector existence cross-validation
        let selectorResult = validateSelectorIntegrity()
        if selectorResult.anomalyDetected {
            score += 20
            methods.append(contentsOf: selectorResult.methods)
        }

        // 2. Instruction pattern validation (inline hook detection)
        let instructionResult = validateInstructionPatterns()
        if instructionResult.anomalyDetected {
            score += 25
            methods.append(contentsOf: instructionResult.methods)
        }

        // 3. Symbol table consistency
        let symbolResult = validateSymbolTableConsistency()
        if symbolResult.anomalyDetected {
            score += 20
            methods.append(contentsOf: symbolResult.methods)
        }

        // 4. Stack frame validation
        let stackResult = validateStackFrames()
        if stackResult.anomalyDetected {
            score += 15
            methods.append(contentsOf: stackResult.methods)
        }

        // Cap at 90
        score = min(score, 90)

        return DetectorResult(score: score, methods: methods)
        #endif
    }

    // MARK: - Check Result

    private struct CheckResult {
        let anomalyDetected: Bool
        let methods: [String]
    }

    // MARK: - 1. Selector Existence Cross-Validation

    /// Verifies that well-known ObjC selectors resolve to the expected classes.
    /// Bypass tools hook individual methods but typically cannot perfectly
    /// replicate the class hierarchy. If a selector that should belong to
    /// NSFileManager resolves to a different class (or fails to resolve),
    /// something has been tampered with.
    private func validateSelectorIntegrity() -> CheckResult {
        var anomalies: [String] = []

        // Each entry: (selector name, expected class name)
        // (selectorName, expectedClassName, isClassMethod)
        let expectations: [(String, String, Bool)] = [
            ("fileExistsAtPath:", "NSFileManager", false),
            ("contentsOfDirectoryAtPath:error:", "NSFileManager", false),
            ("canOpenURL:", "UIApplication", false),
            ("dataWithContentsOfFile:", "NSData", true),  // class method, not instance method
        ]

        for (selectorName, expectedClassName, isClassMethod) in expectations {
            let sel = sel_getUid(selectorName)

            guard let expectedClass = NSClassFromString(expectedClassName) else {
                // If the class itself cannot be resolved, that is suspicious
                anomalies.append("runtime_integrity:selector_class_missing:\(expectedClassName)")
                continue
            }

            // For class methods, check on the metaclass
            let targetClass: AnyClass = isClassMethod ? object_getClass(expectedClass)! : expectedClass

            // Check that the class responds to the selector
            let responds = isClassMethod
                ? class_respondsToSelector(object_getClass(expectedClass), sel)
                : class_respondsToSelector(expectedClass, sel)
            if !responds {
                anomalies.append("runtime_integrity:selector_unresolved:\(selectorName)")
                continue
            }

            // Cross-validate: get the Method and verify its IMP is not nil
            // and that the implementation class matches expectations
            let method = isClassMethod
                ? class_getClassMethod(expectedClass, sel)
                : class_getInstanceMethod(expectedClass, sel)
            if let method {
                let imp = method_getImplementation(method)
                if imp == nil {
                    anomalies.append("runtime_integrity:selector_nil_imp:\(selectorName)")
                    continue
                }

                // Verify the IMP resides within a system framework image, not
                // in an injected dylib. We check that the IMP address falls
                // within one of the known system image ranges.
                if !isAddressInSystemImage(UnsafeRawPointer(imp)) {
                    anomalies.append("runtime_integrity:selector_imp_outside_system:\(selectorName)")
                }
            }
        }

        return CheckResult(
            anomalyDetected: !anomalies.isEmpty,
            methods: anomalies
        )
    }

    // MARK: - 2. Instruction Pattern Validation

    /// Inspects the first few bytes of key C function prologues for branch
    /// instructions that indicate inline hooking. On arm64, a legitimate
    /// function prologue typically starts with stack frame setup (STP, SUB SP),
    /// not an unconditional branch (B, BR) or a BRK.
    ///
    /// Common inline hook patterns on arm64:
    /// - `B <offset>` (unconditional branch): opcode starts with 0x14 or 0x17
    /// - `LDR Xn, #8; BR Xn` trampoline pattern
    /// - `BRK` instructions used by debugger breakpoints
    private func validateInstructionPatterns() -> CheckResult {
        var anomalies: [String] = []

        // Symbols to inspect — these are C functions commonly targeted by bypass tools
        let symbolsToCheck: [String] = [
            "_access",
            "_stat",
            "_open",
            "_dlopen",
            "_fopen",
        ]

        // dlopen(nil) returns a handle to the main program; do NOT dlclose it (POSIX UB)
        guard let handle = dlopen(nil, RTLD_NOW) else {
            return CheckResult(anomalyDetected: false, methods: [])
        }

        for symbolName in symbolsToCheck {
            guard let symAddr = dlsym(handle, String(symbolName.dropFirst())) else {
                continue
            }

            let ptr = UnsafeRawPointer(symAddr)

            if detectInlineHookAtAddress(ptr) {
                anomalies.append("runtime_integrity:inline_hook:\(symbolName)")
            }
        }

        return CheckResult(
            anomalyDetected: !anomalies.isEmpty,
            methods: anomalies
        )
    }

    /// Checks the first instruction at a function address for signs of inline hooking.
    ///
    /// On arm64, we look for:
    /// - Unconditional branch `B imm26`: top 6 bits = 000101 (opcode byte & 0xFC == 0x14)
    /// - Branch register `BR Xn`: fixed encoding 0xD61F0000 | (Rn << 5)
    /// - `BRK #imm16`: top 8 bits = 0xD4, bits [23:21] = 001, bit 0 = 0
    /// - `LDR Xn, #+8` followed by `BR Xn` (trampoline pattern)
    private func safeReadInstruction(at address: UnsafeRawPointer) -> UInt32? {
        var instruction: UInt32 = 0
        var outSize: vm_size_t = 0
        let kr = withUnsafeMutablePointer(to: &instruction) { ptr in
            vm_read_overwrite(
                mach_task_self_,
                vm_address_t(UInt(bitPattern: address)),
                vm_size_t(MemoryLayout<UInt32>.size),
                vm_address_t(UInt(bitPattern: ptr)),
                &outSize
            )
        }
        guard kr == KERN_SUCCESS, outSize == vm_size_t(MemoryLayout<UInt32>.size) else {
            return nil
        }
        return instruction
    }

    private func detectInlineHookAtAddress(_ address: UnsafeRawPointer) -> Bool {
        // Read first two instructions safely via vm_read_overwrite to avoid EXC_BAD_ACCESS
        guard let instruction0 = safeReadInstruction(at: address),
              let instruction1 = safeReadInstruction(at: address.advanced(by: 4)) else {
            return false
        }

        // Check for unconditional branch: B imm26
        // Encoding: [31:26] = 000101
        if (instruction0 >> 26) == 0b000101 {
            return true
        }

        // Check for BR Xn: [31:10] = 1101011000011111000000, [4:0] = 00000
        // Mask: 0xFFFFFC1F, expected: 0xD61F0000
        if (instruction0 & 0xFFFFFC1F) == 0xD61F0000 {
            return true
        }

        // Check for BRK #imm: [31:24] = 11010100, [23:21] = 001, [0] = 0
        // Simplified: top byte 0xD4, bit 21 set, bit 0 clear
        if (instruction0 & 0xFFE0001F) == 0xD4200000 {
            return true
        }

        // Check for LDR Xn, #+8 followed by BR Xn (trampoline)
        // LDR Xt, [PC, #8]: opc=01, 1 1 000 imm19=0x00002 Rt
        // encoding: 0x58000040 | Rt  (imm19 = 2 means +8 bytes)
        let ldrMask: UInt32 = 0xFFFFFFE0
        let ldrExpected: UInt32 = 0x58000040  // LDR Xn, [PC, #+8]
        if (instruction0 & ldrMask) == ldrExpected {
            let rt = instruction0 & 0x1F
            // Next should be BR Xn where n == rt
            let expectedBR = 0xD61F0000 | (rt << 5)
            if instruction1 == expectedBR {
                return true
            }
        }

        return false
    }

    // MARK: - 3. Symbol Table Consistency

    /// Verifies that key dynamically-resolved symbols point to addresses
    /// within the expected loaded image. If a symbol resolves to an address
    /// outside the bounds of the image that is supposed to contain it,
    /// it has likely been redirected by a hooking framework.
    private func validateSymbolTableConsistency() -> CheckResult {
        var anomalies: [String] = []

        // Resolve symbols and verify they fall within expected image bounds
        let symbolChecks: [(symbol: String, expectedImageSubstring: String)] = [
            ("_access", "libsystem_kernel"),
            ("_stat", "libsystem_kernel"),
            ("_dlopen", "libdyld"),
            ("_fopen", "libsystem_c"),
            ("_open", "libsystem_kernel"),
        ]

        // dlopen(nil) returns a handle to the main program; do NOT dlclose it (POSIX UB)
        guard let handle = dlopen(nil, RTLD_NOW) else {
            return CheckResult(anomalyDetected: false, methods: [])
        }

        for (symbol, expectedImage) in symbolChecks {
            guard let symAddr = dlsym(handle, String(symbol.dropFirst())) else {
                anomalies.append("runtime_integrity:symbol_missing:\(symbol)")
                continue
            }

            // Use dladdr to find which image this symbol actually lives in
            var info = Dl_info()
            guard dladdr(symAddr, &info) != 0, let fname = info.dli_fname else {
                anomalies.append("runtime_integrity:symbol_no_image:\(symbol)")
                continue
            }

            let imagePath = String(cString: fname)

            if !imagePath.lowercased().contains(expectedImage.lowercased()) {
                anomalies.append("runtime_integrity:symbol_redirected:\(symbol):\(imagePath)")
            }
        }

        return CheckResult(
            anomalyDetected: !anomalies.isEmpty,
            methods: anomalies
        )
    }

    // MARK: - 4. Stack Frame Validation

    /// Examines the current call stack for frames originating from known
    /// hooking or injection libraries. Legitimate call stacks should not
    /// contain frames from libraries like MobileSubstrate, substitute,
    /// FridaGadget, etc.
    private func validateStackFrames() -> CheckResult {
        var anomalies: [String] = []

        let callStack = Thread.callStackSymbols

        let suspiciousPatterns = [
            "MobileSubstrate",
            "SubstrateLoader",
            "substitute",
            "FridaGadget",
            "frida-agent",
            "cycript",
            "SSLKillSwitch",
            "libReveal",
            "Shadow.dylib",
            "TweakInject",
        ]

        for frame in callStack {
            for pattern in suspiciousPatterns {
                if frame.contains(pattern) {
                    anomalies.append("runtime_integrity:suspicious_stack_frame:\(pattern)")
                    break
                }
            }
        }

        // Additional check: look for an unusually deep call stack that could
        // indicate interposer chaining. A normal detect() call should not
        // produce extremely deep stacks.
        if callStack.count > 128 {
            anomalies.append("runtime_integrity:abnormal_stack_depth:\(callStack.count)")
        }

        return CheckResult(
            anomalyDetected: !anomalies.isEmpty,
            methods: anomalies
        )
    }

    // MARK: - Helpers

    /// Checks whether a given pointer falls within a system framework image
    /// (i.e., under /usr/lib or /System/Library).
    private func isAddressInSystemImage(_ address: UnsafeRawPointer) -> Bool {
        var info = Dl_info()
        guard dladdr(address, &info) != 0, let fname = info.dli_fname else {
            return false
        }
        let path = String(cString: fname)
        return path.hasPrefix("/usr/lib") || path.hasPrefix("/System/Library")
    }
}
