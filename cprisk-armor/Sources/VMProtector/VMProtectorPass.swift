import Foundation
import MachOKit

// MARK: - Policy (YAML subset)

public enum VMPolicyTier: String, Sendable {
    case full
    case partial
}

/// Optional anti-analysis knobs (M2). Omitted keys use safe defaults.
public struct VMPolicyAntiAnalysis: Equatable, Sendable {
    public let handlerDuplication: Bool

    public init(handlerDuplication: Bool = false) {
        self.handlerDuplication = handlerDuplication
    }
}

/// Optional opaque VPC encoding flag (M2). When enabled, the producer may tag `rawRegion` immediates (build-time contract).
public struct VMPolicyOpaqueVPCEncoding: Equatable, Sendable {
    public let enabled: Bool

    public init(enabled: Bool = false) {
        self.enabled = enabled
    }
}

/// Suggested CFF tier for VM interpreter symbols (Pass 13 advisory; consumed by `cff_policy.yaml` workflows).
public enum VMPInterpreterCffTier: String, Sendable, Equatable {
    case medium
    case heavy
    case light
}

/// M3 build-time hardening knobs (`hardening:` in `vmp_policy.yaml`). Omitted keys stay off / safe defaults.
public struct VMPolicyHardeningM3: Equatable, Sendable {
    /// When true, pass details list interpreter symbols recommended for the configured CFF tier (observable wiring).
    public let protectVmInterpreterWithCff: Bool
    /// Dispatch-table dead / decoy handler slots (raw→logical) + metadata tail.
    public let enableDeadHandlerInjection: Bool
    /// Emit VPC opaque predicate-chain constants in the M3 metadata tail (runtime may consume later).
    public let opaqueVpcPredicateChain: Bool
    /// Enable runtime interpreter self-integrity gate (requires runtime build-time expected hash config to be effective).
    public let interpreterSelfIntegrityCheck: Bool
    /// Tier label for the interpreter CFF advisory (default `.medium`).
    public let interpreterCffTier: VMPInterpreterCffTier
    /// XOR obfuscate the 256-byte dispatch class table (opt-in; requires CRiskCore decode when enabled).
    public let dispatchTableKeystream: Bool
    /// v3 bytecode immediate keystream (opt-in; requires CRiskCore v3 decode when enabled).
    public let bytecodeImmediateKeystream: Bool
    /// Emit `CPRISK_VMP_BC_FLAG_BC_SEG_RUNTIME_SHA256` for runtime bytecode segment SHA256 checks.
    public let bytecodeSegmentRuntimeSha256: Bool

    public init(
        protectVmInterpreterWithCff: Bool = false,
        enableDeadHandlerInjection: Bool = false,
        opaqueVpcPredicateChain: Bool = false,
        interpreterSelfIntegrityCheck: Bool = false,
        interpreterCffTier: VMPInterpreterCffTier = .medium,
        dispatchTableKeystream: Bool = false,
        bytecodeImmediateKeystream: Bool = false,
        bytecodeSegmentRuntimeSha256: Bool = false
    ) {
        self.protectVmInterpreterWithCff = protectVmInterpreterWithCff
        self.enableDeadHandlerInjection = enableDeadHandlerInjection
        self.opaqueVpcPredicateChain = opaqueVpcPredicateChain
        self.interpreterSelfIntegrityCheck = interpreterSelfIntegrityCheck
        self.interpreterCffTier = interpreterCffTier
        self.dispatchTableKeystream = dispatchTableKeystream
        self.bytecodeImmediateKeystream = bytecodeImmediateKeystream
        self.bytecodeSegmentRuntimeSha256 = bytecodeSegmentRuntimeSha256
    }
}

/// Build-time VMP policy (`vmp_policy.yaml` YAML subset).
public struct VMPolicyConfig: Equatable, Sendable {
    public let version: Int
    public let full: [String]
    public let partial: [String]
    public let never: [String]
    public let antiAnalysis: VMPolicyAntiAnalysis
    public let opaqueVpcEncoding: VMPolicyOpaqueVPCEncoding
    public let hardening: VMPolicyHardeningM3

    public init(
        version: Int,
        full: [String],
        partial: [String],
        never: [String],
        antiAnalysis: VMPolicyAntiAnalysis = VMPolicyAntiAnalysis(),
        opaqueVpcEncoding: VMPolicyOpaqueVPCEncoding = VMPolicyOpaqueVPCEncoding(),
        hardening: VMPolicyHardeningM3 = VMPolicyHardeningM3()
    ) {
        self.version = version
        self.full = full
        self.partial = partial
        self.never = never
        self.antiAnalysis = antiAnalysis
        self.opaqueVpcEncoding = opaqueVpcEncoding
        self.hardening = hardening
    }

    public func tier(for symbol: String) -> VMPolicyTier? {
        if never.contains(symbol) { return nil }
        if full.contains(symbol) { return .full }
        if partial.contains(symbol) { return .partial }
        return nil
    }

    /// Parses the supported `vmp_policy.yaml` subset (same grammar as CFF policy lists).
    public static func parse(_ yaml: String) -> VMPolicyConfig {
        VMPolicyParser.parse(yaml)
    }
}

enum VMPolicyParser {
    static func parse(_ contents: String) -> VMPolicyConfig {
        enum Section {
            case root
            case functions
            case antiAnalysis
            case opaqueVpcEncoding
            case hardening
        }

        var version = 1
        var full: [String] = []
        var partial: [String] = []
        var never: [String] = []
        var section: Section = .root
        /// Which list is receiving `- symbol` lines: `full`, `partial`, or `never`.
        var activeList: String?
        var handlerDuplication = false
        var opaqueVpcEnabled = false
        var protectInterpreterCff = false
        var deadHandlers = false
        var vpcPredicateChain = false
        var selfIntegrity = false
        var interpreterCffTier = VMPInterpreterCffTier.medium
        var dispatchTableKs = false
        var bytecodeImmKs = false
        var bytecodeSegSha256 = false

        for rawLine in contents.components(separatedBy: .newlines) {
            let sanitized = stripComment(rawLine).trimmingCharacters(in: .whitespaces)
            guard !sanitized.isEmpty else { continue }

            let indentation = rawLine.prefix { $0 == " " }.count

            switch indentation {
            case 0:
                activeList = nil
                switch sanitized {
                case "functions:":
                    section = .functions
                case "anti_analysis:":
                    section = .antiAnalysis
                case "opaque_vpc_encoding:":
                    section = .opaqueVpcEncoding
                case "hardening:":
                    section = .hardening
                default:
                    if sanitized.hasPrefix("version:") {
                        let value = sanitized.dropFirst("version:".count).trimmingCharacters(in: .whitespaces)
                        version = Int(value) ?? version
                    }
                    section = .root
                }
            case 2:
                switch section {
                case .functions:
                    let key = sanitized.replacingOccurrences(of: ":", with: "")
                    switch key {
                    case "full", "partial", "never":
                        activeList = key
                    default:
                        activeList = nil
                    }
                case .antiAnalysis:
                    parseBoolKey(sanitized, key: "handler_duplication", into: &handlerDuplication)
                case .opaqueVpcEncoding:
                    parseBoolKey(sanitized, key: "enabled", into: &opaqueVpcEnabled)
                case .hardening:
                    parseBoolKey(sanitized, key: "protect_vm_interpreter_with_cff", into: &protectInterpreterCff)
                    parseBoolKey(sanitized, key: "enable_dead_handler_injection", into: &deadHandlers)
                    parseBoolKey(sanitized, key: "opaque_vpc_predicate_chain", into: &vpcPredicateChain)
                    parseBoolKey(sanitized, key: "interpreter_self_integrity_check", into: &selfIntegrity)
                    parseBoolKey(sanitized, key: "dispatch_table_keystream", into: &dispatchTableKs)
                    parseBoolKey(sanitized, key: "bytecode_immediate_keystream", into: &bytecodeImmKs)
                    parseBoolKey(sanitized, key: "bytecode_segment_runtime_sha256", into: &bytecodeSegSha256)
                    parseTierKey(sanitized, into: &interpreterCffTier)
                default:
                    break
                }
            default:
                guard section == .functions, sanitized.hasPrefix("- ") else { continue }
                let symbol = String(sanitized.dropFirst(2)).trimmingCharacters(in: .whitespaces)
                guard !symbol.isEmpty, let list = activeList else { continue }
                switch list {
                case "full": full.append(symbol)
                case "partial": partial.append(symbol)
                case "never": never.append(symbol)
                default: break
                }
            }
        }

        return VMPolicyConfig(
            version: version,
            full: unique(full),
            partial: unique(partial),
            never: unique(never),
            antiAnalysis: VMPolicyAntiAnalysis(handlerDuplication: handlerDuplication),
            opaqueVpcEncoding: VMPolicyOpaqueVPCEncoding(enabled: opaqueVpcEnabled),
            hardening: VMPolicyHardeningM3(
                protectVmInterpreterWithCff: protectInterpreterCff,
                enableDeadHandlerInjection: deadHandlers,
                opaqueVpcPredicateChain: vpcPredicateChain,
                interpreterSelfIntegrityCheck: selfIntegrity,
                interpreterCffTier: interpreterCffTier,
                dispatchTableKeystream: dispatchTableKs,
                bytecodeImmediateKeystream: bytecodeImmKs,
                bytecodeSegmentRuntimeSha256: bytecodeSegSha256
            )
        )
    }

    private static func parseTierKey(_ line: String, into target: inout VMPInterpreterCffTier) {
        let prefix = "interpreter_cff_tier:"
        guard line.hasPrefix(prefix) else { return }
        let rest = line.dropFirst(prefix.count).trimmingCharacters(in: .whitespaces).lowercased()
        if rest == "heavy" {
            target = .heavy
        } else if rest == "light" {
            target = .light
        } else {
            target = .medium
        }
    }

    private static func parseBoolKey(_ line: String, key: String, into target: inout Bool) {
        let prefix = "\(key):"
        guard line.hasPrefix(prefix) else { return }
        let rest = line.dropFirst(prefix.count).trimmingCharacters(in: .whitespaces).lowercased()
        if rest == "true" || rest == "1" || rest == "yes" {
            target = true
        } else if rest == "false" || rest == "0" || rest == "no" {
            target = false
        }
    }

    private static func stripComment(_ line: String) -> String {
        guard let index = line.firstIndex(of: "#") else { return line }
        return String(line[..<index])
    }

    private static func unique(_ values: [String]) -> [String] {
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }
}

// MARK: - Pass

public final class VMProtectorPass: ArmorPass {
    public let name = "VM Protector"

    private let policyFilePath: String?

    public init(policyFilePath: String? = nil) {
        self.policyFilePath = policyFilePath
    }

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        guard let policyURL = Self.resolvePolicyURL(explicitPath: policyFilePath) else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: ["Skipped: vmp_policy.yaml not found (use --vmp-policy or place RiskDetectorApp/vmp_policy.yaml)"]
            )
        }

        let policyText = try String(contentsOf: policyURL, encoding: .utf8)
        let policy = VMPolicyConfig.parse(policyText)

        guard let textSection = try file.section(segment: "__TEXT", section: "__text") else {
            return PassResult(passName: name, itemsProcessed: 0, bytesModified: 0, details: ["Skipped: __TEXT.__text missing"])
        }

        let textStart = Int(textSection.offset)
        let textVMStart = textSection.address
        let textVMEnd = textSection.address + textSection.size

        let symbols = try file.readSymbols()
        let sortedTextAddrs = Self.sortedTextSymbolAddresses(symbols: symbols, textVMStart: textVMStart, textVMEnd: textVMEnd)

        let targets = Set(policy.full + policy.partial)
        guard !targets.isEmpty else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: ["policy: \(policyURL.path)", "no symbols listed under full/partial"]
            )
        }

        let seedMaterial = config.randomSeed ?? (config.buildSeed != 0 ? config.buildSeed : 1)
        let seedNonZero = seedMaterial == 0 ? 1 : seedMaterial
        let deadSpec: VMDeadHandlerSpec? = policy.hardening.enableDeadHandlerInjection
            ? VMDeadHandlerSpec(seed: seedNonZero ^ 0xDEAD_B300_0000_0001, budget: 0)
            : nil
        let opcodeTable = VMOpcodeTable(
            seed: seedNonZero,
            enableHandlerDuplication: policy.antiAnalysis.handlerDuplication,
            deadHandler: deadSpec
        )
        let m3Predicates: [UInt64] = policy.hardening.opaqueVpcPredicateChain
            ? VMBytecodeEmitter.generateVpcPredicateChain(seed: seedNonZero ^ UInt64(policy.version & 0xFFFF) << 40, count: 8)
            : []
        let m2Opts = VMM2EmitOptions(
            opaqueVpcCategoryHigh32: policy.opaqueVpcEncoding.enabled,
            handlerVariantSeed: seedNonZero ^ (UInt64(policy.version) << 48),
            m3: VMM3EmitOptions(
                vpcPredicateConstants: m3Predicates,
                enableDeadHandlers: policy.hardening.enableDeadHandlerInjection,
                enableOpaquePredicateChain: policy.hardening.opaqueVpcPredicateChain,
                enableSelfIntegrityCheck: policy.hardening.interpreterSelfIntegrityCheck,
                enableSelfIntegrityHmac: policy.hardening.interpreterSelfIntegrityCheck,
                bytecodeSegmentRuntimeSha256: policy.hardening.bytecodeSegmentRuntimeSha256
            ),
            dispatchTableKeystream: policy.hardening.dispatchTableKeystream,
            dispatchKeystreamMaterial: seedNonZero ^ UInt64(truncatingIfNeeded: policy.version & 0xFFFF),
            immediateKeystream: policy.hardening.bytecodeImmediateKeystream,
            immediateKeystreamMaterial: seedNonZero ^ 0x1CE0_00DE_F11E_0001,
            opcodeWireObfuscation: policy.hardening.bytecodeImmediateKeystream,
            opcodeKeystreamMaterial: seedNonZero ^ 0x0BC0_4D45_4D4D_3258
        )
        let lifter = ARM64Lifter()
        let emitter = VMBytecodeEmitter()

        var programs: [(functionId: UInt64, entryVMA: UInt64, tier: VMBytecodeFormat.TierCode, instructions: [VMInstruction])] = []
        var bytesModified = 0
        var items = 0
        var details: [String] = [
            "policy: \(policyURL.path)",
            "version: \(policy.version)",
            "full=\(policy.full.count) partial=\(policy.partial.count) never=\(policy.never.count)",
            String(format: "opcode_seed=0x%016llX", opcodeTable.seed),
            "m2: handler_dup=\(policy.antiAnalysis.handlerDuplication) opaque_vpc=\(policy.opaqueVpcEncoding.enabled)",
            "m3: interpreter_cff=\(policy.hardening.protectVmInterpreterWithCff) tier=\(policy.hardening.interpreterCffTier.rawValue) dead_handlers=\(policy.hardening.enableDeadHandlerInjection) vpc_pred=\(policy.hardening.opaqueVpcPredicateChain) self_integrity=\(policy.hardening.interpreterSelfIntegrityCheck)",
            "emit: dispatch_ks=\(policy.hardening.dispatchTableKeystream) imm_ks_v3=\(policy.hardening.bytecodeImmediateKeystream) opcode_ks_v3=\(policy.hardening.bytecodeImmediateKeystream) bc_seg_sha256=\(policy.hardening.bytecodeSegmentRuntimeSha256)"
        ]
        if policy.hardening.protectVmInterpreterWithCff {
            let tier = policy.hardening.interpreterCffTier.rawValue
            let syms = "cprisk_vm_entry, _cprisk_vm_entry, cprisk_vm_execute, _cprisk_vm_execute"
            details.append(
                "m3: interpreter_cff wiring — add VM interpreter symbols under cff_policy.yaml functions.\(tier) (Pass8/9 medium-tier output): \(syms)"
            )
        }
        if let dead = opcodeTable.deadHandlerInjection {
            details.append(
                "m3: dead_handler_budget=\(dead.budget) seed=0x\(String(dead.seed, radix: 16))"
            )
        }
        if !m3Predicates.isEmpty {
            details.append("m3: vpc_predicate_chain_constants=\(m3Predicates.count) (dispatch tail M3)")
        }

        for symbolName in targets.sorted() {
            guard let tier = policy.tier(for: symbolName) else { continue }
            guard let candidate = Self.findCandidateSymbol(named: symbolName, in: symbols) else {
                details.append("[skip] \(symbolName): not in symbol table")
                continue
            }

            let entryVMA = candidate.nlist.n_value
            guard entryVMA >= textVMStart, entryVMA < textVMEnd else {
                details.append("[skip] \(symbolName): not in __TEXT.__text")
                continue
            }

            let nextVMA = Self.nextSymbolAddress(after: entryVMA, sorted: sortedTextAddrs, end: textVMEnd)
            let functionSize = Int(nextVMA - entryVMA)
            guard functionSize > 0 else {
                details.append("[skip] \(symbolName): invalid size")
                continue
            }

            guard let entryFileOffU = try file.fileOffset(forVMAddress: entryVMA) else { continue }
            let entryFileOff = Int(entryFileOffU)
            let readLen = min(functionSize, 256)
            guard entryFileOff + readLen <= file.data.count else {
                details.append("[skip] \(symbolName): read out of bounds")
                continue
            }

            let rawSlice = Data(file.data[entryFileOff..<(entryFileOff + readLen)])
            let lifted = lifter.liftPrologue(bytes: rawSlice)

            let fnId = VMFunctionId.fnv1a64(symbol: symbolName)
            let tierCode: VMBytecodeFormat.TierCode = tier == .full ? .full : .partial
            programs.append((functionId: fnId, entryVMA: entryVMA, tier: tierCode, instructions: lifted))
            items += 1

            if tier == .full {
                let wantEntry = VMPatchRewriter.selectVmEntrySymbolName(functionId: fnId, buildSeed: seedNonZero)
                let vmAddr: UInt64
                let resolvedEntry: String
                if let s = symbols.first(where: { $0.name == wantEntry }) {
                    vmAddr = s.nlist.n_value
                    resolvedEntry = wantEntry
                } else if let s = symbols.first(where: { $0.name == "_cprisk_vm_entry" }) {
                    vmAddr = s.nlist.n_value
                    resolvedEntry = "_cprisk_vm_entry"
                    details.append("[full][vm entry fallback] \(symbolName): \(wantEntry) missing → _cprisk_vm_entry")
                } else {
                    details.append("[full][no patch] \(symbolName): VM entry symbols not linked")
                    continue
                }
                guard vmAddr != 0 else {
                    details.append("[full][no patch] \(symbolName): VM entry VMA is zero")
                    continue
                }
                guard functionSize >= VMPatchRewriter.trampolineByteLength else {
                    details.append("[full][no patch] \(symbolName): function too small (\(functionSize) bytes)")
                    continue
                }
                do {
                    let tpl = VMPatchRewriter.selectTrampolineTemplate(functionId: fnId, buildSeed: seedNonZero)
                    let stub = try VMPatchRewriter.buildTrampoline(
                        functionId: fnId,
                        functionEntryVMA: entryVMA,
                        vmEntryVMA: vmAddr,
                        template: tpl
                    )
                    try file.replaceBytes(at: UInt64(entryFileOff), with: stub)
                    bytesModified += stub.count
                    details.append("[full][patched] \(symbolName) id=0x\(String(fnId, radix: 16)) vm_entry=\(resolvedEntry) __text+0x\(String(entryFileOff - textStart, radix: 16))")
                } catch {
                    details.append("[full][no patch] \(symbolName): \(error.localizedDescription)")
                }
            } else {
                details.append("[partial] \(symbolName): bytecode only (no entry patch)")
            }
        }

        guard !programs.isEmpty else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: details + ["no matching symbols"]
            )
        }

        let payloads = emitter.emit(programs: programs, opcodeTable: opcodeTable, options: m2Opts)
        let slackDispatch = Self.vmpSlackMaterial(config: config, seed: seedNonZero, role: 0xD1)
        let slackBytecode = Self.vmpSlackMaterial(config: config, seed: seedNonZero, role: 0xB2)
        _ = try file.addOrUpdateSection(
            segment: VMBytecodeFormat.sectionSegment,
            section: VMBytecodeFormat.dispatchSection,
            content: payloads.dispatch,
            align: 4,
            flags: 0,
            slackPadding: .keyedPseudorandom(material: slackDispatch)
        )
        _ = try file.addOrUpdateSection(
            segment: VMBytecodeFormat.sectionSegment,
            section: VMBytecodeFormat.bytecodeSection,
            content: payloads.bytecode,
            align: 4,
            flags: 0,
            slackPadding: .keyedPseudorandom(material: slackBytecode)
        )

        details.append(
            "section \(VMBytecodeFormat.sectionSegment),\(VMBytecodeFormat.dispatchSection): \(payloads.dispatch.count) bytes"
        )
        details.append(
            "section \(VMBytecodeFormat.sectionSegment),\(VMBytecodeFormat.bytecodeSection): \(payloads.bytecode.count) bytes"
        )

        return PassResult(
            passName: name,
            itemsProcessed: items,
            bytesModified: bytesModified + payloads.dispatch.count + payloads.bytecode.count,
            details: details
        )
    }

    private static func resolvePolicyURL(explicitPath: String?) -> URL? {
        let fm = FileManager.default
        if let explicitPath, !explicitPath.isEmpty {
            let url = URL(fileURLWithPath: explicitPath)
            guard fm.fileExists(atPath: url.path) else { return nil }
            return url
        }

        let cwd = URL(fileURLWithPath: fm.currentDirectoryPath)
        let parent = cwd.deletingLastPathComponent()
        let grandParent = parent.deletingLastPathComponent()
        let candidates = [
            cwd.appendingPathComponent("RiskDetectorApp/vmp_policy.yaml"),
            cwd.appendingPathComponent("vmp_policy.yaml"),
            parent.appendingPathComponent("RiskDetectorApp/vmp_policy.yaml"),
            parent.appendingPathComponent("vmp_policy.yaml"),
            grandParent.appendingPathComponent("RiskDetectorApp/vmp_policy.yaml"),
            grandParent.appendingPathComponent("vmp_policy.yaml")
        ]
        return candidates.first { fm.fileExists(atPath: $0.path) }
    }

    private static func sortedTextSymbolAddresses(symbols: [SymbolEntry], textVMStart: UInt64, textVMEnd: UInt64) -> [UInt64] {
        var addresses = Set<UInt64>()
        for symbol in symbols {
            guard symbol.nlist.typeField == Nlist64Entry.N_SECT else { continue }
            let vm = symbol.nlist.n_value
            guard vm >= textVMStart, vm < textVMEnd else { continue }
            addresses.insert(vm)
        }
        return addresses.sorted()
    }

    private static func nextSymbolAddress(after entry: UInt64, sorted: [UInt64], end: UInt64) -> UInt64 {
        for addr in sorted where addr > entry {
            return addr
        }
        return end
    }

    private static func vmpSlackMaterial(config: PassConfig, seed: UInt64, role: UInt8) -> Data {
        var d = Data()
        if let k = config.encryptionKey {
            d.append(k)
        }
        var s = seed.littleEndian
        Swift.withUnsafeBytes(of: &s) { d.append(contentsOf: $0) }
        var b = config.buildSeed.littleEndian
        Swift.withUnsafeBytes(of: &b) { d.append(contentsOf: $0) }
        d.append(role)
        d.append(Data("pass13.vmp_slack.v1".utf8))
        return d
    }

    private static func normalizePolicySymbol(_ raw: String) -> [String] {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }
        var tokens = Set<String>()
        tokens.insert(trimmed)
        tokens.insert("_\(trimmed)")
        if let tail = trimmed.split(separator: ".").last {
            let t = String(tail)
            tokens.insert(t)
            tokens.insert("_\(t)")
        }
        return Array(tokens)
    }

    private static func findCandidateSymbol(named policyName: String, in symbols: [SymbolEntry]) -> SymbolEntry? {
        let candidates = symbols.filter { $0.nlist.typeField == Nlist64Entry.N_SECT }
        let aliases = normalizePolicySymbol(policyName)

        for alias in aliases {
            if let exact = candidates.first(where: { $0.name == alias }) {
                return exact
            }
        }

        for symbol in candidates {
            for alias in aliases where symbol.name.contains(alias) || symbol.name.hasSuffix(alias) {
                return symbol
            }
        }
        return nil
    }
}
