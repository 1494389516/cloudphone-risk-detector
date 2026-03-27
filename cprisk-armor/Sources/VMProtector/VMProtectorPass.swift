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

/// How producer-side synthetic `branchInd` instructions are materialized.
public enum VMSyntheticBranchIndMode: String, Sendable, Equatable {
    /// `branchRel` skips over an unreachable dead block that contains synthetic `branchInd` ops.
    case unreachableSkip = "unreachable_skip"
    /// `branchInd` uses a reserved fallthrough/identity immediate contract and is injected into the
    /// reachable stream; runtime treats the tagged op as a semantic no-op/fallthrough.
    case semiIdentity = "semi_identity"
    /// Like `semiIdentity` for observable control-flow, but immediates use the `0xA2` contract so the
    /// interpreter runs the full indirect-branch mix path before forcing the same single-step advance.
    case semiSemantic = "semi_semantic"
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
    /// Emit `CPRISK_VMP_BC_FLAG_ANTI_SYMBOLIC_HEAVY` (runtime anti-symbolic bait paths).
    public let antiSymbolicHeavy: Bool
    /// Control AArch64 `addLane` + `rolAcc` peephole fusion in the producer/lifter.
    public let fuseAddRolAcc: Bool
    /// Requested synthetic `branchInd` candidate count per function before rate / cap filtering.
    public let syntheticBranchIndBudget: Int
    /// Deterministic keep rate for synthetic `branchInd` candidates (0...1).
    public let syntheticBranchIndRate: Double
    /// Hard cap for synthetic `branchInd` insertions per function; 0 means "no extra cap".
    public let syntheticBranchIndMaxPerFunction: Int
    /// Injection mode for synthetic `branchInd`.
    public let syntheticBranchIndMode: VMSyntheticBranchIndMode
    /// Forward-span (sled length) override for `semiSemantic` mode; 0 = use producer default. Clamped to 0...16.
    public let syntheticBranchIndForwardSpan: UInt8

    public init(
        protectVmInterpreterWithCff: Bool = false,
        enableDeadHandlerInjection: Bool = false,
        opaqueVpcPredicateChain: Bool = false,
        interpreterSelfIntegrityCheck: Bool = false,
        interpreterCffTier: VMPInterpreterCffTier = .medium,
        dispatchTableKeystream: Bool = false,
        bytecodeImmediateKeystream: Bool = false,
        bytecodeSegmentRuntimeSha256: Bool = false,
        antiSymbolicHeavy: Bool = false,
        fuseAddRolAcc: Bool = true,
        syntheticBranchIndBudget: Int = 0,
        syntheticBranchIndRate: Double = 1.0,
        syntheticBranchIndMaxPerFunction: Int = 0,
        syntheticBranchIndMode: VMSyntheticBranchIndMode = .unreachableSkip,
        syntheticBranchIndForwardSpan: UInt8 = 0
    ) {
        self.protectVmInterpreterWithCff = protectVmInterpreterWithCff
        self.enableDeadHandlerInjection = enableDeadHandlerInjection
        self.opaqueVpcPredicateChain = opaqueVpcPredicateChain
        self.interpreterSelfIntegrityCheck = interpreterSelfIntegrityCheck
        self.interpreterCffTier = interpreterCffTier
        self.dispatchTableKeystream = dispatchTableKeystream
        self.bytecodeImmediateKeystream = bytecodeImmediateKeystream
        self.bytecodeSegmentRuntimeSha256 = bytecodeSegmentRuntimeSha256
        self.antiSymbolicHeavy = antiSymbolicHeavy
        self.fuseAddRolAcc = fuseAddRolAcc
        self.syntheticBranchIndBudget = max(0, syntheticBranchIndBudget)
        self.syntheticBranchIndRate = min(max(syntheticBranchIndRate, 0), 1)
        self.syntheticBranchIndMaxPerFunction = max(0, syntheticBranchIndMaxPerFunction)
        self.syntheticBranchIndMode = syntheticBranchIndMode
        self.syntheticBranchIndForwardSpan = min(syntheticBranchIndForwardSpan, 16)
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
        var antiSymbolicHeavy = false
        var fuseAddRolAcc = true
        var syntheticBranchIndBudget = 0
        var syntheticBranchIndRate = 1.0
        var syntheticBranchIndMaxPerFunction = 0
        var syntheticBranchIndMode = VMSyntheticBranchIndMode.unreachableSkip
        var syntheticBranchIndForwardSpan = 0

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
                    parseBoolKey(sanitized, key: "anti_symbolic_heavy", into: &antiSymbolicHeavy)
                    parseBoolKey(sanitized, key: "fuse_add_rol_acc", into: &fuseAddRolAcc)
                    parseIntKey(sanitized, key: "synthetic_branch_ind_budget", into: &syntheticBranchIndBudget)
                    parseDoubleKey(sanitized, key: "synthetic_branch_ind_rate", into: &syntheticBranchIndRate)
                    parseIntKey(sanitized, key: "synthetic_branch_ind_max_per_function", into: &syntheticBranchIndMaxPerFunction)
                    parseSyntheticBranchIndModeKey(sanitized, into: &syntheticBranchIndMode)
                    parseIntKey(sanitized, key: "synthetic_branch_ind_forward_span", into: &syntheticBranchIndForwardSpan)
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
                bytecodeSegmentRuntimeSha256: bytecodeSegSha256,
                antiSymbolicHeavy: antiSymbolicHeavy,
                fuseAddRolAcc: fuseAddRolAcc,
                syntheticBranchIndBudget: syntheticBranchIndBudget,
                syntheticBranchIndRate: syntheticBranchIndRate,
                syntheticBranchIndMaxPerFunction: syntheticBranchIndMaxPerFunction,
                syntheticBranchIndMode: syntheticBranchIndMode,
                syntheticBranchIndForwardSpan: UInt8(min(max(syntheticBranchIndForwardSpan, 0), 16))
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

    private static func parseIntKey(_ line: String, key: String, into target: inout Int) {
        let prefix = "\(key):"
        guard line.hasPrefix(prefix) else { return }
        let rest = line.dropFirst(prefix.count).trimmingCharacters(in: .whitespaces)
        guard let parsed = Int(rest) else { return }
        target = max(0, parsed)
    }

    private static func parseDoubleKey(_ line: String, key: String, into target: inout Double) {
        let prefix = "\(key):"
        guard line.hasPrefix(prefix) else { return }
        let rest = line.dropFirst(prefix.count).trimmingCharacters(in: .whitespaces)
        guard let parsed = Double(rest) else { return }
        target = min(max(parsed, 0), 1)
    }

    private static func parseSyntheticBranchIndModeKey(
        _ line: String,
        into target: inout VMSyntheticBranchIndMode
    ) {
        let prefix = "synthetic_branch_ind_mode:"
        guard line.hasPrefix(prefix) else { return }
        let rest = line.dropFirst(prefix.count).trimmingCharacters(in: .whitespaces).lowercased()
        switch rest {
        case VMSyntheticBranchIndMode.semiIdentity.rawValue:
            target = .semiIdentity
        case VMSyntheticBranchIndMode.semiSemantic.rawValue:
            target = .semiSemantic
        case VMSyntheticBranchIndMode.unreachableSkip.rawValue:
            target = .unreachableSkip
        default:
            break
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
            opcodeKeystreamMaterial: seedNonZero ^ 0x0BC0_4D45_4D4D_3258,
            antiSymbolicHeavy: policy.hardening.antiSymbolicHeavy
        )
        let liftConfig = ARMLiftConfig(
            maxInstructions: 24,
            termination: .atFirstRet,
            fuseAddRolAcc: policy.hardening.fuseAddRolAcc
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
            "function_id=fnv1a64(symbol)^splitmix(buildSeed) (per-build)",
            "m2: handler_dup=\(policy.antiAnalysis.handlerDuplication) opaque_vpc=\(policy.opaqueVpcEncoding.enabled)",
            "m3: interpreter_cff=\(policy.hardening.protectVmInterpreterWithCff) tier=\(policy.hardening.interpreterCffTier.rawValue) dead_handlers=\(policy.hardening.enableDeadHandlerInjection) vpc_pred=\(policy.hardening.opaqueVpcPredicateChain) self_integrity=\(policy.hardening.interpreterSelfIntegrityCheck)",
            "emit: dispatch_ks=\(policy.hardening.dispatchTableKeystream) imm_ks_v3=\(policy.hardening.bytecodeImmediateKeystream) opcode_ks_v3=\(policy.hardening.bytecodeImmediateKeystream) bc_seg_sha256=\(policy.hardening.bytecodeSegmentRuntimeSha256) anti_sym=\(policy.hardening.antiSymbolicHeavy)",
            "producer: fuse_add_rol_acc=\(policy.hardening.fuseAddRolAcc) synthetic_branch_ind_budget=\(policy.hardening.syntheticBranchIndBudget) synthetic_branch_ind_rate=\(policy.hardening.syntheticBranchIndRate) synthetic_branch_ind_max=\(policy.hardening.syntheticBranchIndMaxPerFunction) synthetic_branch_ind_mode=\(policy.hardening.syntheticBranchIndMode.rawValue) synthetic_branch_ind_forward_span=\(policy.hardening.syntheticBranchIndForwardSpan)"
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
            let tierCode: VMBytecodeFormat.TierCode = tier == .full ? .full : .partial
            let fnId = VMFunctionId.mixed(symbol: symbolName, buildSeed: seedNonZero)
            let lifted = lifter.lift(bytes: rawSlice, config: liftConfig)
            let hardened = Self.rewriteProducerInstructions(
                lifted,
                functionId: fnId,
                seed: seedNonZero,
                tier: tierCode,
                hardening: policy.hardening
            )
            programs.append((functionId: fnId, entryVMA: entryVMA, tier: tierCode, instructions: hardened.instructions))
            items += 1
            if hardened.syntheticBranchIndInserted > 0 {
                let budgetSource = hardened.autoBudgetApplied ? "auto_floor" : "policy_budget"
                details.append(
                    "[branch_ind] \(symbolName): mode=\(hardened.appliedMode.rawValue) inserted=\(hardened.syntheticBranchIndInserted) budget=\(hardened.effectiveBudget) source=\(budgetSource)"
                )
            }

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

    public struct ProducerRewriteResult: Sendable {
        public let instructions: [VMInstruction]
        public let syntheticBranchIndInserted: Int
        public let appliedMode: VMSyntheticBranchIndMode
        public let effectiveBudget: Int
        public let autoBudgetApplied: Bool
    }

    private static let vmInsnWidthBytes: UInt64 = 9
    private static let fullTierAutoSyntheticBranchIndBudget = 1

    private static func resolveSyntheticBranchIndBudget(
        tier: VMBytecodeFormat.TierCode,
        mode: VMSyntheticBranchIndMode,
        requestedBudget: Int
    ) -> (effectiveBudget: Int, autoApplied: Bool) {
        let explicit = max(0, requestedBudget)
        if explicit > 0 {
            return (explicit, false)
        }
        guard tier == .full else {
            return (0, false)
        }
        // Safe default: full-tier functions get one producer-side synthetic branchInd, regardless of mode.
        _ = mode
        return (fullTierAutoSyntheticBranchIndBudget, true)
    }

    public static func rewriteProducerInstructions(
        _ instructions: [VMInstruction],
        functionId: UInt64,
        seed: UInt64,
        tier: VMBytecodeFormat.TierCode,
        hardening: VMPolicyHardeningM3
    ) -> ProducerRewriteResult {
        let budget = resolveSyntheticBranchIndBudget(
            tier: tier,
            mode: hardening.syntheticBranchIndMode,
            requestedBudget: hardening.syntheticBranchIndBudget
        )
        let applied: (instructions: [VMInstruction], inserted: Int)
        switch hardening.syntheticBranchIndMode {
        case .unreachableSkip:
            applied = injectSyntheticBranchIndUnreachableBlock(
                instructions,
                functionId: functionId,
                seed: seed,
                budget: budget.effectiveBudget,
                rate: hardening.syntheticBranchIndRate,
                maxPerFunction: hardening.syntheticBranchIndMaxPerFunction
            )
        case .semiIdentity:
            applied = injectSyntheticBranchIndSemiIdentity(
                instructions,
                functionId: functionId,
                seed: seed,
                budget: budget.effectiveBudget,
                rate: hardening.syntheticBranchIndRate,
                maxPerFunction: hardening.syntheticBranchIndMaxPerFunction
            )
        case .semiSemantic:
            applied = injectSyntheticBranchIndSemiSemantic(
                instructions,
                functionId: functionId,
                seed: seed,
                budget: budget.effectiveBudget,
                rate: hardening.syntheticBranchIndRate,
                maxPerFunction: hardening.syntheticBranchIndMaxPerFunction,
                forwardSpanOverride: hardening.syntheticBranchIndForwardSpan
            )
        }
        return ProducerRewriteResult(
            instructions: applied.instructions,
            syntheticBranchIndInserted: applied.inserted,
            appliedMode: hardening.syntheticBranchIndMode,
            effectiveBudget: budget.effectiveBudget,
            autoBudgetApplied: budget.autoApplied
        )
    }

    // MARK: - Bytecode wire immediate decode (producer ↔ on-disk layout)

    /// Decodes per-instruction wire immediates for one bytecode entry (matches `VMBytecodeEmitter` on-disk layout).
    /// Returns `nil` when payloads are malformed or the dispatch class table is keystream-obfuscated (undecodable here).
    public static func decodeEntryWireImmediates(
        bytecodePayload: Data,
        dispatchPayload: Data,
        entryIndex: Int,
        functionId: UInt64,
        options: VMM2EmitOptions
    ) -> [UInt64]? {
        guard entryIndex >= 0 else { return nil }
        guard bytecodePayload.count >= 16, dispatchPayload.count >= 16 else { return nil }
        guard VMBytecodeFormat.readUInt32LE(bytecodePayload, offset: 0) == VMBytecodeFormat.bytecodeMagic else { return nil }
        guard VMBytecodeFormat.readUInt32LE(dispatchPayload, offset: 0) == VMBytecodeFormat.dispatchMagic else { return nil }

        let dispatchVersion = VMBytecodeFormat.readUInt32LE(dispatchPayload, offset: 4)
        let dispatchFlags = VMBytecodeFormat.readUInt32LE(dispatchPayload, offset: 12)
        if (dispatchFlags & VMBytecodeFormat.DispatchHeaderFlags.classTableKeystream) != 0 {
            return nil
        }
        let dispatchClassOffset = dispatchVersion >= VMBytecodeFormat.dispatchABIVersionV2
            ? (16 + VMBytecodeFormat.dispatchSeedBytes)
            : 16
        guard dispatchPayload.count >= dispatchClassOffset + VMBytecodeFormat.dispatchTableSize else { return nil }
        let dispatchTable = [UInt8](dispatchPayload[dispatchClassOffset..<(dispatchClassOffset + VMBytecodeFormat.dispatchTableSize)])

        let bytecodeVersion = VMBytecodeFormat.readUInt32LE(bytecodePayload, offset: 4)
        let entryCount = Int(VMBytecodeFormat.readUInt32LE(bytecodePayload, offset: 8))
        let bytecodeFlags = VMBytecodeFormat.readUInt32LE(bytecodePayload, offset: 12)
        guard entryIndex < entryCount else { return nil }
        let headerTotal = VMBytecodeEmitter.bytecodeHeaderTotalBytes(version: bytecodeVersion, flags: bytecodeFlags)
        let stride = VMBytecodeFormat.entryCoreSize
            + (((bytecodeFlags & VMBytecodeFormat.BytecodeFlags.perEntryVpc) != 0) ? VMBytecodeFormat.vpcAffineBytes : 0)
        let entryBase = headerTotal + entryIndex * stride
        guard bytecodePayload.count >= entryBase + stride else { return nil }

        let bytecodeOffset = Int(VMBytecodeFormat.readUInt32LE(bytecodePayload, offset: entryBase + 20))
        let bytecodeLength = Int(VMBytecodeFormat.readUInt32LE(bytecodePayload, offset: entryBase + 24))
        guard bytecodeOffset >= 0, bytecodeLength >= 0 else { return nil }
        guard bytecodePayload.count >= bytecodeOffset + bytecodeLength else { return nil }
        guard bytecodeLength % 9 == 0 else { return nil }

        let immKs = (bytecodeFlags & VMBytecodeFormat.BytecodeFlags.immediateKeystream) != 0
        let immRoot = immKs ? VMBytecodeEmitter.immediateKeystreamRoot(options: options) : 0

        let opCount = bytecodeLength / 9
        var out: [UInt64] = []
        out.reserveCapacity(opCount)
        for i in 0..<opCount {
            let raw = bytecodePayload[bytecodeOffset + i * 9]
            let logicalRaw = dispatchTable[Int(raw)]
            guard VMLogicalOp(rawValue: logicalRaw) != nil else { return nil }
            let immOff = bytecodeOffset + i * 9 + 1
            let wEnc = VMBytecodeFormat.readUInt64LE(bytecodePayload, offset: immOff)
            let w: UInt64
            if immKs {
                w = VMBytecodeEmitter.decodeWireImmediate(
                    encoded: wEnc,
                    functionId: functionId,
                    pcIndex: UInt32(i),
                    keystreamRoot: immRoot
                )
            } else {
                w = wEnc
            }
            out.append(w)
        }
        return out
    }

    static func injectSyntheticBranchIndUnreachableBlock(
        _ instructions: [VMInstruction],
        functionId: UInt64,
        seed: UInt64,
        budget: Int,
        rate: Double,
        maxPerFunction: Int
    ) -> (instructions: [VMInstruction], inserted: Int) {
        guard instructions.last?.op == .halt else { return (instructions, 0) }
        let injectedCount = syntheticBranchIndCount(
            functionId: functionId,
            seed: seed,
            budget: budget,
            rate: rate,
            maxPerFunction: maxPerFunction
        )
        guard injectedCount > 0 else { return (instructions, 0) }
        var out = Array(instructions.dropLast())
        out.append(VMInstruction(op: .branchRel, immediate: UInt64(injectedCount + 1) * vmInsnWidthBytes))
        var rng = VMProtectorSplitMix64(seed: functionId ^ seed ^ 0x4252_494E_445F_5331) // "BRIND_S1"
        for _ in 0..<injectedCount {
            out.append(VMInstruction(op: .branchInd, immediate: syntheticBranchIndImmediate(rng: &rng)))
        }
        out.append(VMInstruction(op: .halt))
        return (out, injectedCount)
    }

    static func injectSyntheticBranchIndSemiIdentity(
        _ instructions: [VMInstruction],
        functionId: UInt64,
        seed: UInt64,
        budget: Int,
        rate: Double,
        maxPerFunction: Int
    ) -> (instructions: [VMInstruction], inserted: Int) {
        guard instructions.last?.op == .halt else { return (instructions, 0) }
        let injectedCount = syntheticBranchIndCount(
            functionId: functionId,
            seed: seed,
            budget: budget,
            rate: rate,
            maxPerFunction: maxPerFunction
        )
        guard injectedCount > 0 else { return (instructions, 0) }
        var out = Array(instructions.dropLast())
        var rng = VMProtectorSplitMix64(seed: functionId ^ seed ^ 0x4252_494E_445F_4932) // "BRIND_I2"
        for _ in 0..<injectedCount {
            out.append(VMInstruction(op: .branchInd, immediate: syntheticBranchIndIdentityImmediate(rng: &rng)))
        }
        out.append(VMInstruction(op: .halt))
        return (out, injectedCount)
    }

    public static let semiSemanticDefaultForwardSpan: UInt8 = 2

    static func injectSyntheticBranchIndSemiSemantic(
        _ instructions: [VMInstruction],
        functionId: UInt64,
        seed: UInt64,
        budget: Int,
        rate: Double,
        maxPerFunction: Int,
        forwardSpanOverride: UInt8 = 0
    ) -> (instructions: [VMInstruction], inserted: Int) {
        guard instructions.last?.op == .halt else { return (instructions, 0) }
        let injectedCount = syntheticBranchIndCount(
            functionId: functionId,
            seed: seed,
            budget: budget,
            rate: rate,
            maxPerFunction: maxPerFunction
        )
        guard injectedCount > 0 else { return (instructions, 0) }
        let forwardSpan = forwardSpanOverride > 0 ? forwardSpanOverride : semiSemanticDefaultForwardSpan
        var out = Array(instructions.dropLast())
        var rng = VMProtectorSplitMix64(seed: functionId ^ seed ^ 0x4252_494E_445F_5333) // "BRIND_S3"
        for _ in 0..<injectedCount {
            out.append(VMInstruction(
                op: .branchInd,
                immediate: syntheticBranchIndSemanticImmediate(rng: &rng, forwardSpan: forwardSpan)
            ))
            for _ in 0..<Int(forwardSpan) {
                let pick = rng.next(upperBound: 5)
                if pick < 3 {
                    out.append(VMInstruction(op: .nop))
                } else {
                    out.append(VMInstruction(op: .rolAcc, immediate: 0))
                }
            }
        }
        out.append(VMInstruction(op: .halt))
        return (out, injectedCount)
    }

    static func syntheticBranchIndCount(
        functionId: UInt64,
        seed: UInt64,
        budget: Int,
        rate: Double,
        maxPerFunction: Int
    ) -> Int {
        guard budget > 0, rate > 0 else { return 0 }
        let cap = maxPerFunction > 0 ? min(budget, maxPerFunction) : budget
        guard cap > 0 else { return 0 }
        let clampedRate = min(max(rate, 0), 1)
        if clampedRate >= 1 {
            return cap
        }
        let threshold = UInt64((clampedRate * 10_000).rounded(.down))
        guard threshold > 0 else { return 0 }
        var rng = VMProtectorSplitMix64(seed: functionId ^ seed ^ 0x4252_5241_5445_5331) // "BRRATES1"
        var count = 0
        for _ in 0..<cap {
            if rng.next(upperBound: 10_000) < threshold {
                count += 1
            }
        }
        return count
    }

    static func syntheticBranchIndImmediate(rng: inout VMProtectorSplitMix64) -> UInt64 {
        let vregIndex = rng.next(upperBound: 8)
        let accBase = rng.next(upperBound: 32)
        return VMBranchIndImmediateContract.synthetic(vregIndex: vregIndex, accBase: accBase)
    }

    static func syntheticBranchIndIdentityImmediate(rng: inout VMProtectorSplitMix64) -> UInt64 {
        VMBranchIndImmediateContract.semiIdentity(entropy: rng.next())
    }

    /// `0xA2` contract: structured vreg/acc in low 8 bits, `forwardSpan` in bits 8..15, entropy above.
    static func syntheticBranchIndSemanticImmediate(
        rng: inout VMProtectorSplitMix64,
        forwardSpan: UInt8 = 0
    ) -> UInt64 {
        let structured = syntheticBranchIndImmediate(rng: &rng)
        let entropy = rng.next()
        let low56 = (entropy & 0x00FF_FFFF_FFFF_FF00) | (structured & 0xFF)
        return VMBranchIndImmediateContract.semiSemantic(entropy: low56, forwardSpan: forwardSpan)
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
