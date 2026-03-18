#if os(iOS)
import CoreMotion
import Foundation

final class MotionSampler {
    static let shared = MotionSampler()
    private init() {}

    private let manager = CMMotionManager()
    private let queue = OperationQueue()
    private let lock = UnfairLock()

    private var started = false
    private var sampleCount = 0
    private var stillCount = 0
    private var energySum = 0.0
    private var series: [MotionSample] = []
    private let seriesMax = 3600

    private let minSnapshotInterval: TimeInterval = 5.0
    private var lastSnapshotTime: TimeInterval = 0
    private var cachedSnapshot: (metrics: MotionMetrics, series: [MotionSample])?

    func start() {
        let shouldStart: Bool = lock.withLock {
            guard !started else { return false }
            started = true
            return true
        }
        guard shouldStart, manager.isDeviceMotionAvailable else { return }
        manager.deviceMotionUpdateInterval = 1.0 / 20.0
        queue.qualityOfService = .utility

        manager.startDeviceMotionUpdates(to: queue) { [weak self] motion, _ in
            guard let self, let motion else { return }
            self.consume(motion: motion)
        }
    }

    func stop() {
        lock.withLock {
            started = false
            zeroSensitiveBuffersLocked()
        }
        manager.stopDeviceMotionUpdates()
    }

    func snapshot() -> MotionMetrics {
        lock.withLock {
            guard sampleCount > 0 else { return .empty }

            let stillness = Double(stillCount) / Double(sampleCount)
            let energy = energySum / Double(sampleCount)
            let metrics = MotionMetrics(sampleCount: sampleCount, stillnessRatio: stillness, motionEnergy: energy)
            Logger.log("behavior.motion: samples=\(metrics.sampleCount) stillness=\(metrics.stillnessRatio?.description ?? "nil") energy=\(metrics.motionEnergy?.description ?? "nil")")
            return metrics
        }
    }

    func snapshotAndReset() -> MotionMetrics {
        snapshotDetailAndReset().metrics
    }

    func snapshotDetailAndReset() -> (metrics: MotionMetrics, series: [MotionSample]) {
        lock.withLock {
            let now = ProcessInfo.processInfo.systemUptime
            if now - lastSnapshotTime < minSnapshotInterval, let cached = cachedSnapshot, sampleCount == 0 {
                return cached
            }

            guard sampleCount > 0 else { return (.empty, []) }

            let stillness = Double(stillCount) / Double(sampleCount)
            let energy = energySum / Double(sampleCount)
            let metrics = MotionMetrics(sampleCount: sampleCount, stillnessRatio: stillness, motionEnergy: energy)
            Logger.log("behavior.motion(reset): samples=\(metrics.sampleCount) stillness=\(metrics.stillnessRatio?.description ?? "nil") energy=\(metrics.motionEnergy?.description ?? "nil")")

            let outSeries = series
            sampleCount = 0
            stillCount = 0
            energySum = 0
            series.removeAll(keepingCapacity: true)

            lastSnapshotTime = now
            let result = (metrics, outSeries)
            cachedSnapshot = result
            return result
        }
    }

    func clearSensitiveData() {
        lock.withLock { zeroSensitiveBuffersLocked() }
    }

    private func zeroSensitiveBuffersLocked() {
        series.withUnsafeMutableBufferPointer { buf in
            guard let base = buf.baseAddress else { return }
            memset(base, 0, buf.count * MemoryLayout<MotionSample>.stride)
        }
        series.removeAll(keepingCapacity: false)
        sampleCount = 0
        stillCount = 0
        energySum = 0
        lastSnapshotTime = 0
        cachedSnapshot = nil
    }

    private func consume(motion: CMDeviceMotion) {
        let user = motion.userAcceleration
        let magnitude = sqrt(user.x * user.x + user.y * user.y + user.z * user.z)

        lock.withLock {
            guard started else { return }
            sampleCount += 1
            energySum += magnitude
            if magnitude < 0.02 { stillCount += 1 }
            series.append(MotionSample(timestamp: motion.timestamp, energy: magnitude))
            if series.count > seriesMax {
                series.removeFirst(series.count - seriesMax)
            }
        }
    }
}

#else
import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
final class MotionSampler {
    static let shared = MotionSampler()
    private init() {}
    func start() {}
    func stop() {}
    func clearSensitiveData() {}
    func snapshot() -> MotionMetrics { .empty }
    func snapshotAndReset() -> MotionMetrics { .empty }
    func snapshotDetailAndReset() -> (metrics: MotionMetrics, series: [MotionSample]) { (.empty, []) }
}
#endif
