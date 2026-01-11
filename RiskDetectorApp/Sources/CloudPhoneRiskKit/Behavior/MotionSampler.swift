#if os(iOS)
import CoreMotion
import Foundation

final class MotionSampler {
    static let shared = MotionSampler()
    private init() {}

    private let manager = CMMotionManager()
    private let queue = OperationQueue()
    private let lock = NSLock()

    private var started = false
    private var sampleCount = 0
    private var stillCount = 0
    private var energySum = 0.0
    private var series: [MotionSample] = []
    private let seriesMax = 2000

    func start() {
        lock.lock()
        defer { lock.unlock() }
        guard !started else { return }
        started = true

        guard manager.isDeviceMotionAvailable else { return }
        manager.deviceMotionUpdateInterval = 1.0 / 20.0
        queue.qualityOfService = .utility

        manager.startDeviceMotionUpdates(to: queue) { [weak self] motion, _ in
            guard let self, let motion else { return }
            self.consume(motion: motion)
        }
    }

    func stop() {
        lock.lock()
        started = false
        lock.unlock()
        manager.stopDeviceMotionUpdates()
    }

    func snapshot() -> MotionMetrics {
        lock.lock()
        defer { lock.unlock() }
        guard sampleCount > 0 else { return .empty }

        let stillness = Double(stillCount) / Double(sampleCount)
        let energy = energySum / Double(sampleCount)
        let metrics = MotionMetrics(sampleCount: sampleCount, stillnessRatio: stillness, motionEnergy: energy)
        Logger.log("behavior.motion: samples=\(metrics.sampleCount) stillness=\(metrics.stillnessRatio?.description ?? "nil") energy=\(metrics.motionEnergy?.description ?? "nil")")
        return metrics
    }

    func snapshotAndReset() -> MotionMetrics {
        snapshotDetailAndReset().metrics
    }

    func snapshotDetailAndReset() -> (metrics: MotionMetrics, series: [MotionSample]) {
        lock.lock()
        defer { lock.unlock() }
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
        return (metrics, outSeries)
    }

    private func consume(motion: CMDeviceMotion) {
        lock.lock()
        let isEnabled = started
        lock.unlock()
        guard isEnabled else { return }

        let user = motion.userAcceleration
        let magnitude = sqrt(user.x * user.x + user.y * user.y + user.z * user.z)

        lock.lock()
        sampleCount += 1
        energySum += magnitude
        if magnitude < 0.02 { stillCount += 1 }
        series.append(MotionSample(timestamp: motion.timestamp, energy: magnitude))
        if series.count > seriesMax {
            series.removeFirst(series.count - seriesMax)
        }
        lock.unlock()
    }
}

#else
import Foundation
import Darwin
final class MotionSampler {
    static let shared = MotionSampler()
    private init() {}
    func start() {}
    func stop() {}
    func snapshot() -> MotionMetrics { .empty }
    func snapshotAndReset() -> MotionMetrics { .empty }
    func snapshotDetailAndReset() -> (metrics: MotionMetrics, series: [MotionSample]) { (.empty, []) }
}
#endif
