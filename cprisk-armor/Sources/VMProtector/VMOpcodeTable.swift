import Foundation

/// Request M3 dead-handler injection (`enable_dead_handler_injection` in policy). `budget == 0` uses a safe internal default.
public struct VMDeadHandlerSpec: Equatable, Sendable {
    public let seed: UInt64
    public let budget: UInt32

    public init(seed: UInt64, budget: UInt32 = 0) {
        self.seed = seed
        self.budget = budget
    }
}

/// One decoy raw opcode mapped to a logical handler id (`0...3`).
public struct VMDeadHandlerMapping: Equatable, Sendable {
    public let raw: UInt8
    public let logical: UInt8

    public init(raw: UInt8, logical: UInt8) {
        self.raw = raw
        self.logical = logical
    }
}

/// Built decoy dispatch mappings + seeds for metadata emission.
public struct VMDeadHandlerInjection: Equatable, Sendable {
    public let seed: UInt64
    public let budget: UInt32
    public let mappings: [VMDeadHandlerMapping]
}

/// Maps logical VM ops to one or more on-wire opcode bytes (handler variants). Seeded for polymorphism.
public struct VMOpcodeTable: Equatable, Sendable {
    public let seed: UInt64
    public let handlerDuplicationEnabled: Bool
    public let deadHandlerInjection: VMDeadHandlerInjection?
    /// For each logical opcode id, the ordered pool of equivalent raw bytes (non-empty).
    private let wirePools: [[UInt8]]

    public init(seed: UInt64, enableHandlerDuplication: Bool = false, deadHandler: VMDeadHandlerSpec? = nil) {
        let pools = Self.buildPools(seed: seed, enableHandlerDuplication: enableHandlerDuplication)
        let dead: VMDeadHandlerInjection?
        if let cfg = deadHandler {
            dead = Self.buildDeadInjection(seed: cfg.seed, requestedBudget: cfg.budget, wirePools: pools)
        } else {
            dead = nil
        }
        self.seed = seed
        self.handlerDuplicationEnabled = enableHandlerDuplication
        self.deadHandlerInjection = dead
        self.wirePools = pools
    }

    /// Picks a raw opcode byte for `logical` using `selector` (e.g. instruction index xor seed).
    public func wireByte(for logical: VMLogicalOp, selector: UInt64 = 0) -> UInt8 {
        let pool = wirePools[Int(logical.rawValue)]
        guard pool.count > 1 else { return pool[0] }
        let idx = Int(selector % UInt64(pool.count))
        return pool[idx]
    }

    /// Runtime dispatch table: raw opcode byte -> logical opcode id. Unassigned bytes are `0xFF` poison slots.
    ///
    /// On disk, `VMBytecodeEmitter` may XOR this 256-byte block when `VMM2EmitOptions.dispatchTableKeystream` is enabled
    /// (see `VMBytecodeFormat.DispatchHeaderFlags.classTableKeystream` + `VMBytecodeEmitter.decryptDispatchClassTable`).
    public func rawToLogicalTable() -> [UInt8] {
        var table = Array(repeating: UInt8(0xFF), count: 256)
        for logical in VMLogicalOp.allCases {
            for raw in wirePools[Int(logical.rawValue)] {
                let r = Int(raw)
                table[r] = logical.rawValue
            }
        }
        if let dead = deadHandlerInjection {
            for m in dead.mappings {
                table[Int(m.raw)] = m.logical
            }
        }
        return table
    }

    /// True when two different logical ops claim the same raw byte (should never happen for valid tables).
    public func hasRawMappingConflict() -> Bool {
        var owner = Array(repeating: UInt8?.none, count: 256)
        for logical in VMLogicalOp.allCases {
            for raw in wirePools[Int(logical.rawValue)] {
                let r = Int(raw)
                if let o = owner[r], o != logical.rawValue { return true }
                owner[r] = logical.rawValue
            }
        }
        if let dead = deadHandlerInjection {
            for m in dead.mappings {
                let r = Int(m.raw)
                if let o = owner[r], o != m.logical { return true }
                owner[r] = m.logical
            }
        }
        return false
    }

    /// All raw bytes used by this table (for coverage tests).
    public func assignedRawBytes() -> Set<UInt8> {
        var s = Set<UInt8>()
        for logical in VMLogicalOp.allCases {
            for raw in wirePools[Int(logical.rawValue)] { s.insert(raw) }
        }
        if let dead = deadHandlerInjection {
            for m in dead.mappings { s.insert(m.raw) }
        }
        return s
    }

    private static func buildDeadInjection(seed: UInt64, requestedBudget: UInt32, wirePools: [[UInt8]]) -> VMDeadHandlerInjection {
        var assigned = Set<UInt8>()
        for logical in VMLogicalOp.allCases {
            for raw in wirePools[Int(logical.rawValue)] { assigned.insert(raw) }
        }
        var free = [UInt8]()
        for b in UInt8.min...UInt8.max where !assigned.contains(b) {
            free.append(b)
        }
        let cap = free.count
        let want = requestedBudget == 0 ? UInt32(min(24, max(0, cap))) : min(requestedBudget, UInt32(cap))
        var rng = VMProtectorSplitMix64(seed: seed ^ 0xDEAD_484E_444C_5233) // "deadHndLR3"
        var pool = free
        let logicalChoices: [UInt8] = [0, 1, 2, 3]
        var mappings: [VMDeadHandlerMapping] = []
        var i: UInt32 = 0
        while i < want && pool.count > 1 {
            let j = Int(rng.next() % UInt64(pool.count))
            let raw = pool.remove(at: j)
            let log = logicalChoices[Int(rng.next() % 4)]
            mappings.append(VMDeadHandlerMapping(raw: raw, logical: log))
            i += 1
        }
        if want > 0, pool.count == 1, i < want {
            let raw = pool[0]
            let log = logicalChoices[Int(rng.next() % 4)]
            mappings.append(VMDeadHandlerMapping(raw: raw, logical: log))
        }
        return VMDeadHandlerInjection(seed: seed, budget: UInt32(mappings.count), mappings: mappings)
    }

    private static func buildPools(seed: UInt64, enableHandlerDuplication: Bool) -> [[UInt8]] {
        var rng = VMProtectorSplitMix64(seed: seed ^ 0x564D_5072_6F74_6563) // "VMProtec"
        var logicalOrder = Array(VMLogicalOp.allCases)
        if logicalOrder.count > 1 {
            var i = logicalOrder.count - 1
            while i > 0 {
                let j = Int(rng.next() % UInt64(i + 1))
                logicalOrder.swapAt(i, j)
                i -= 1
            }
        }

        var used = Set<UInt8>()
        var pools: [[UInt8]] = Array(repeating: [], count: VMLogicalOp.allCases.count)

        func takeUnused() -> UInt8 {
            for _ in 0..<4096 {
                let b = UInt8(truncatingIfNeeded: rng.next() & 0xFF)
                if !used.contains(b) {
                    used.insert(b)
                    return b
                }
            }
            for b in UInt8.min...UInt8.max where !used.contains(b) {
                used.insert(b)
                return b
            }
            preconditionFailure("VMOpcodeTable: exhausted raw bytes")
        }

        let variantsPerOp = enableHandlerDuplication ? 4 : 1
        for op in logicalOrder {
            var pool: [UInt8] = []
            for _ in 0..<variantsPerOp {
                pool.append(takeUnused())
            }
            pool.sort()
            pools[Int(op.rawValue)] = pool
        }

        return pools
    }
}

/// Minimal deterministic PRNG for opcode permutation.
struct VMProtectorSplitMix64: RandomNumberGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed == 0 ? 0xDEAD_BEEF_CAFE_BABE : seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    mutating func next(upperBound: UInt64) -> UInt64 {
        guard upperBound > 0 else { return 0 }
        return next() % upperBound
    }
}
