import Darwin
import Foundation
import MachO

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
        self.config = config
    }

    func detect() -> DetectorResult {
        var score: Double = 0
        var methods: [String] = []
        var rng = SeededRandomGenerator(seed: config.seed ?? UInt64(Date().timeIntervalSince1970.bitPattern))

        if hasTimingAnomaly(using: &rng) {
            score += 18
            methods.append("timing:delay_anomaly")
        }

        if hasClockReversal() {
            score += 20
            methods.append("timing:time_reversal")
        }

        let checks: [(String, () -> Bool)] = [
            ("env", quickEnvCheck),
            ("dyld", quickDyldCheck),
            ("path", quickPathCheck),
            ("parent", quickParentCheck)
        ]

        let selectedChecks = config.enableShuffle ? rng.shuffled(checks) : checks
        let count = max(1, Int(Double(selectedChecks.count) * max(0, min(config.subsetRatio, 1))))

        for (name, check) in selectedChecks.prefix(count) {
            if config.enableRandomDelay {
                usleep(rng.randomInRange(config.minDelayUs...config.maxDelayUs))
            }
            if check() {
                score += 8
                methods.append("randomized_\(name)")
            }
        }

        return DetectorResult(score: score, methods: methods)
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
        let ppid = getppid()
        guard ppid > 1 else { return true }
        guard let parent = parentProcessPath(ppid)?.lowercased() else { return false }
        return parent.contains("frida") || parent.contains("lldb")
    }

    private func parentProcessPath(_ pid: pid_t) -> String? {
#if os(macOS)
        var pathBuffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        let result = proc_pidpath(pid, &pathBuffer, UInt32(PATH_MAX))
        guard result > 0 else { return nil }
        return String(cString: pathBuffer)
#else
        return nil
#endif
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
        let size = upper - lower + 1
        let value = next() % size
        return T(value + lower)
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
