import CRiskCore
import Darwin
import Foundation
import MachO

private enum RandomizedDetectionCFF {
    static let detectConfig = CFFConfig.adaptive(
        functionSeed: 0x9D42_A3F1_56C8_2B17,
        protectionTier: .light,
        dispatcherStyle: .dualRail,
        codecStyle: .xorRotate
    )

    static func salt(config: RandomizedDetection.Config, selectedCount: Int, totalChecks: Int) -> UInt32 {
        CFFRuntimeSalt.derive(
            functionSeed: detectConfig.functionSeed,
            inputs: CFFRuntimeSaltInputs(
                extraWords: [
                    config.seed ?? 0,
                    UInt64(config.minDelayUs),
                    UInt64(config.maxDelayUs),
                    UInt64(selectedCount),
                    UInt64(totalChecks),
                    config.subsetRatio.bitPattern,
                ],
                strings: ["RandomizedDetection.detect"],
                flags: [config.enableShuffle, config.enableRandomDelay]
            )
        )
    }
}

struct RandomizedDetection: Detector {
    struct Config {
        var enableShuffle: Bool = true
        var enableRandomDelay: Bool = true
        var minDelayUs: UInt32 = 100
        var maxDelayUs: UInt32 = 1000
        var seed: UInt64? = nil
        var subsetRatio: Double = 1.0
    }

    private let config: Config

    init(config: Config = Config()) {
        // Guard against invalid delay range from server config (ClosedRange requires lower <= upper)
        var sanitized = config
        if sanitized.maxDelayUs < sanitized.minDelayUs {
            sanitized.maxDelayUs = sanitized.minDelayUs
        }
        self.config = sanitized
    }

    func detect() throws -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []
        var rng = SeededRandomGenerator(seed: config.seed ?? UInt64(Date().timeIntervalSince1970.bitPattern))

        let checks: [(String, () -> Bool)] = [
            ("env", quickEnvCheck),
            ("dyld", quickDyldCheck),
            ("path", quickPathCheck),
            ("parent", quickParentCheck)
        ]

        let selectedChecks = config.enableShuffle ? rng.shuffled(checks) : checks
        let count = max(1, Int(Double(selectedChecks.count) * max(0, min(config.subsetRatio, 1))))
        let cffConfig = RandomizedDetectionCFF.detectConfig
        let salt = RandomizedDetectionCFF.salt(config: config, selectedCount: count, totalChecks: selectedChecks.count)

        let entryState: UInt32 = 0x11
        let timingState: UInt32 = 0x12
        let clockState: UInt32 = 0x13
        let iterateState: UInt32 = 0x14
        let delayState: UInt32 = 0x15
        let executeState: UInt32 = 0x16
        let connectorState: UInt32 = 0x17
        let settleState: UInt32 = 0x18
        let finishState: UInt32 = 0x19

        let cffKey = CFFStateCodec.deriveSeed(function: "RandomizedDetection.detect", config: cffConfig)
        let effectiveSalt = cffConfig.enableRuntimeSalt ? salt : salt ^ 0x13579BDF

        func encodeState(_ rawState: UInt32) -> UInt32 {
            CFFStateCodec.encode(state: rawState, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        func decodeState(_ encoded: UInt32) -> UInt32 {
            CFFStateCodec.decode(state: encoded, key: cffKey, salt: effectiveSalt, style: cffConfig.codecStyle)
        }

        var sink = CFFReturnSink<DetectorResult>()
        var encodedState = encodeState(entryState)
        var checkIndex = 0
        var currentCheck: (String, () -> Bool)?
        var loopBudget = max(32, count * 6 + 12)

        func finalizeResult() -> DetectorResult {
            DetectorResult(score: score, methods: methods)
        }

        while !sink.isResolved {
            guard loopBudget > 0 else {
                sink.store(finalizeResult())
                break
            }
            loopBudget -= 1

            let decodedState = decodeState(encodedState)
            let dispatchPlan = CFFDispatcher.plan(encodedState: encodedState, salt: salt, config: cffConfig)
            let useIfElseRail = dispatchPlan.style == .ifElseChain
                || (dispatchPlan.usesSecondaryDispatcher && CFFOpaquePredicates.connectorGate(encodedState: encodedState, salt: salt))

            if useIfElseRail {
                if decodedState == entryState {
                    encodedState = encodeState(timingState)
                } else if decodedState == timingState {
                    if hasTimingAnomaly(using: &rng) {
                        score += 18
                        methods.append("timing:delay_anomaly")
                    }
                    encodedState = encodeState(clockState)
                } else if decodedState == clockState {
                    if hasClockReversal() {
                        score += 20
                        methods.append("timing:time_reversal")
                    }
                    encodedState = encodeState(iterateState)
                } else if decodedState == iterateState {
                    guard checkIndex < count else {
                        encodedState = encodeState(finishState)
                        continue
                    }
                    currentCheck = selectedChecks[checkIndex]
                    let nextState = config.enableRandomDelay ? delayState : executeState
                    encodedState = encodeState(nextState)
                } else if decodedState == delayState {
                    usleep(rng.randomInRange(config.minDelayUs...config.maxDelayUs))
                    encodedState = encodeState(executeState)
                } else if decodedState == executeState {
                    if let (name, check) = currentCheck, check() {
                        score += 8
                        methods.append("randomized_\(name)")
                    }
                    currentCheck = nil
                    checkIndex += 1
                    encodedState = encodeState(connectorState)
                } else if decodedState == connectorState {
                    let nextState = CFFOpaquePredicates.parityFence(UInt32(checkIndex) &+ decodedState, salt: salt) ? iterateState : settleState
                    encodedState = encodeState(nextState)
                } else if decodedState == settleState {
                    encodedState = encodeState(iterateState)
                } else if decodedState == finishState {
                    sink.store(finalizeResult())
                } else {
                    sink.store(finalizeResult())
                }
            } else {
                switch decodedState {
                case entryState:
                    encodedState = encodeState(timingState)
                case timingState:
                    if hasTimingAnomaly(using: &rng) {
                        score += 18
                        methods.append("timing:delay_anomaly")
                    }
                    encodedState = encodeState(clockState)
                case clockState:
                    if hasClockReversal() {
                        score += 20
                        methods.append("timing:time_reversal")
                    }
                    encodedState = encodeState(iterateState)
                case iterateState:
                    guard checkIndex < count else {
                        encodedState = encodeState(finishState)
                        continue
                    }
                    currentCheck = selectedChecks[checkIndex]
                    encodedState = encodeState(config.enableRandomDelay ? delayState : executeState)
                case delayState:
                    usleep(rng.randomInRange(config.minDelayUs...config.maxDelayUs))
                    encodedState = encodeState(executeState)
                case executeState:
                    if let (name, check) = currentCheck, check() {
                        score += 8
                        methods.append("randomized_\(name)")
                    }
                    currentCheck = nil
                    checkIndex += 1
                    encodedState = encodeState(connectorState)
                case connectorState:
                    let nextState = CFFDispatcher.branchKey(encodedState, salt: salt) & 1 == 0 ? iterateState : settleState
                    encodedState = encodeState(nextState)
                case settleState:
                    encodedState = encodeState(iterateState)
                case finishState:
                    sink.store(finalizeResult())
                default:
                    sink.store(finalizeResult())
                }
            }
        }

        return sink.resolve(or: finalizeResult())
    }

    private func hasTimingAnomaly(using rng: inout SeededRandomGenerator) -> Bool {
        guard config.enableRandomDelay else { return false }
        let delay = rng.randomInRange(config.minDelayUs...config.maxDelayUs)
        let before = DispatchTime.now().uptimeNanoseconds
        usleep(delay)
        let elapsed = DispatchTime.now().uptimeNanoseconds - before
        let expected = UInt64(delay) * 1_000
        return elapsed < expected / 2 || elapsed > expected * 4
    }

    private func hasClockReversal() -> Bool {
        let first = Date().timeIntervalSince1970
        usleep(10)
        let second = Date().timeIntervalSince1970
        return second < first
    }

    private func quickEnvCheck() -> Bool {
        ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"] != nil
    }

    private func quickDyldCheck() -> Bool {
        _dyld_image_count() > 450
    }

    private func quickPathCheck() -> Bool {
        guard let executable = Bundle.main.executablePath else { return false }
        return !executable.contains(".app/")
    }

    private func quickParentCheck() -> Bool {
        let ppid = cprisk_getppid_direct()
        guard ppid > 1 else { return false }
        guard let parent = processPath(for: ppid)?.lowercased() else { return false }
        return parent.contains(ObfuscatedConstants.keywordFrida) || parent.contains(ObfuscatedConstants.keywordLldb)
    }
}

private struct SeededRandomGenerator {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9e3779b97f4a7c15
        var z = state
        z = (z ^ (z >> 30)) &* 0xbf58476d1ce4e5b9
        z = (z ^ (z >> 27)) &* 0x94d049bb133111eb
        return z ^ (z >> 31)
    }

    mutating func randomInRange<T>(_ range: ClosedRange<T>) -> T where T: FixedWidthInteger {
        let lower = UInt64(range.lowerBound)
        let upper = UInt64(range.upperBound)
        // When upper - lower + 1 overflows (full range), size wraps to 0 → next() % 0 crashes.
        let size = upper &- lower &+ 1
        guard size != 0 else { return T(next()) }
        let value = next() % size
        return T(value &+ lower)
    }

    mutating func shuffled<T>(_ array: [T]) -> [T] {
        guard array.count > 1 else { return array }
        var result = array
        for index in stride(from: result.count - 1, through: 1, by: -1) {
            let randomIndex = Int(randomInRange(0...index))
            result.swapAt(index, randomIndex)
        }
        return result
    }
}
