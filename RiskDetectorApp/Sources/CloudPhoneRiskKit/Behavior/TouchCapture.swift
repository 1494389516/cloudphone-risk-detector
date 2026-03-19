import Foundation
#if canImport(UIKit)
import UIKit
import ObjectiveC.runtime

final class TouchCapture {
    static let shared = TouchCapture()
    private init() {}

    private let lock = UnfairLock()
    private var started = false
    private var touchPoints: [CGPoint] = []
    private var tapTimestamps: [TimeInterval] = []
    private var swipeLinearities: [Double] = []
    private var currentSwipePath: [CGPoint] = []
    private var swipeCount = 0
    private var tapCount = 0
    private var actionTimestamps: [TimeInterval] = []
    private var forces: [Double] = []
    private var majorRadii: [Double] = []

    private let minSnapshotInterval: TimeInterval = 5.0
    private var lastSnapshotTime: TimeInterval = 0
    private var cachedSnapshot: (metrics: TouchMetrics, actionTimestamps: [TimeInterval])?
    private var swipeSpeeds: [Double] = []
    private var currentSwipeStartTime: TimeInterval = 0

    func start() {
        lock.withLock {
            guard !started else { return }
            started = true
            UIApplicationSendEventSwizzler.swizzleOnce()
        }
    }

    func stop() {
        lock.withLock {
            started = false
            zeroSensitiveBuffersLocked()
        }
    }

    func process(event: UIEvent) {
        guard let touches = event.allTouches, !touches.isEmpty else { return }
        lock.withLock {
            guard started else { return }
            for touch in touches {
                record(touch: touch)
            }
        }
    }

    func snapshotAndReset() -> TouchMetrics {
        snapshotDetailAndReset().metrics
    }

    func snapshotDetailAndReset() -> (metrics: TouchMetrics, actionTimestamps: [TimeInterval]) {
        lock.withLock { _snapshotDetailAndResetLocked() }
    }

    private func _snapshotDetailAndResetLocked() -> (metrics: TouchMetrics, actionTimestamps: [TimeInterval]) {
        let now = ProcessInfo.processInfo.systemUptime
        if now - lastSnapshotTime < minSnapshotInterval, let cached = cachedSnapshot, touchPoints.isEmpty {
            return cached
        }

        let spread = TouchMath.coordinateSpread(points: touchPoints)
        let intervalCV = TouchMath.intervalCoefficientOfVariation(timestamps: tapTimestamps)
        let avgLinearity = swipeLinearities.isEmpty ? nil : (swipeLinearities.reduce(0, +) / Double(swipeLinearities.count))
        let forceVar = TouchMath.variance(values: forces)
        let radiusVar = TouchMath.variance(values: majorRadii)
        let speedCV = TouchMath.coefficientOfVariation(values: swipeSpeeds)

        let metrics = TouchMetrics(
            sampleCount: touchPoints.count,
            tapCount: tapCount,
            swipeCount: swipeCount,
            coordinateSpread: spread,
            intervalCV: intervalCV,
            averageLinearity: avgLinearity,
            forceVariance: forceVar,
            majorRadiusVariance: radiusVar,
            swipeSpeedCV: speedCV
        )
        #if DEBUG
        Logger.log("behavior.touch: samples=\(metrics.sampleCount) taps=\(metrics.tapCount) swipes=\(metrics.swipeCount) spread=\(metrics.coordinateSpread?.description ?? "nil") intervalCV=\(metrics.intervalCV?.description ?? "nil") avgLinearity=\(metrics.averageLinearity?.description ?? "nil")")
        #endif

        let actions = actionTimestamps

        touchPoints.removeAll(keepingCapacity: true)
        tapTimestamps.removeAll(keepingCapacity: true)
        swipeLinearities.removeAll(keepingCapacity: true)
        currentSwipePath.removeAll(keepingCapacity: true)
        swipeCount = 0
        tapCount = 0
        actionTimestamps.removeAll(keepingCapacity: true)
        forces.removeAll(keepingCapacity: true)
        majorRadii.removeAll(keepingCapacity: true)
        swipeSpeeds.removeAll(keepingCapacity: true)

        lastSnapshotTime = now
        let result = (metrics, actions)
        cachedSnapshot = result
        return result
    }

    func clearSensitiveData() {
        lock.withLock { zeroSensitiveBuffersLocked() }
    }

    private func zeroSensitiveBuffersLocked() {
        zeroBuffer(&touchPoints)
        zeroBuffer(&tapTimestamps)
        zeroBuffer(&swipeLinearities)
        zeroBuffer(&currentSwipePath)
        zeroBuffer(&actionTimestamps)
        zeroBuffer(&forces)
        zeroBuffer(&majorRadii)
        zeroBuffer(&swipeSpeeds)
        swipeCount = 0
        tapCount = 0
        currentSwipeStartTime = 0
        lastSnapshotTime = 0
        cachedSnapshot = nil
    }

    private func zeroBuffer<T>(_ array: inout [T]) {
        array.withUnsafeMutableBufferPointer { buf in
            guard let base = buf.baseAddress else { return }
            let stride = MemoryLayout<T>.stride
            let (byteCount, overflow) = buf.count.multipliedReportingOverflow(by: stride)
            if overflow { return }
            memset(base, 0, byteCount)
        }
        array.removeAll(keepingCapacity: false)
    }

    private func record(touch: UITouch) {
        // Avoid unbounded growth if the caller forgets to evaluate for a long time.
        if touchPoints.count > 10000 {
            touchPoints.removeFirst(touchPoints.count - 6000)
        }
        if tapTimestamps.count > 4000 {
            tapTimestamps.removeFirst(tapTimestamps.count - 2400)
        }
        if swipeLinearities.count > 4000 {
            swipeLinearities.removeFirst(swipeLinearities.count - 2400)
        }

        let p = touch.location(in: touch.view)
        touchPoints.append(p)

        switch touch.phase {
        case .began:
            currentSwipePath = [p]
            currentSwipeStartTime = touch.timestamp
        case .moved:
            if currentSwipePath.count < 500 {
                currentSwipePath.append(p)
            }
        case .ended:
            // Record per-action touch shape and pressure hints (best-effort; not all devices support force).
            if touch.force > 0 { forces.append(Double(touch.force)) }
            if touch.majorRadius > 0 { majorRadii.append(Double(touch.majorRadius)) }
            if currentSwipePath.count >= 2 {
                swipeCount += 1
                swipeLinearities.append(TouchMath.linearity(path: currentSwipePath) ?? 1.0)
                let duration = touch.timestamp - currentSwipeStartTime
                if let speed = TouchMath.averageSwipeSpeed(path: currentSwipePath, duration: duration) {
                    swipeSpeeds.append(speed)
                }
                actionTimestamps.append(touch.timestamp)
            } else {
                tapCount += 1
                tapTimestamps.append(touch.timestamp)
                actionTimestamps.append(touch.timestamp)
            }
            currentSwipePath.removeAll(keepingCapacity: true)
        default:
            break
        }
    }
}

private enum UIApplicationSendEventSwizzler {
    private static var didSwizzle = false

    static func swizzleOnce() {
        guard !didSwizzle else { return }
        didSwizzle = true

        let cls: AnyClass = UIApplication.self
        let originalSelector = #selector(UIApplication.sendEvent(_:))
        let swizzledSelector = #selector(UIApplication.cprk_sendEvent(_:))

        guard
            let originalMethod = class_getInstanceMethod(cls, originalSelector),
            let swizzledMethod = class_getInstanceMethod(cls, swizzledSelector)
        else {
            return
        }

        method_exchangeImplementations(originalMethod, swizzledMethod)
    }
}

extension UIApplication {
    @objc fileprivate func cprk_sendEvent(_ event: UIEvent) {
        TouchCapture.shared.process(event: event)
        self.cprk_sendEvent(event)
    }
}

private enum TouchMath {
    static func coordinateSpread(points: [CGPoint]) -> Double? {
        guard points.count >= 2 else { return nil }
        let meanX = points.map(\.x).reduce(0, +) / CGFloat(points.count)
        let meanY = points.map(\.y).reduce(0, +) / CGFloat(points.count)
        let distances = points.map { hypot($0.x - meanX, $0.y - meanY) }
        let avg = distances.reduce(0, +) / CGFloat(distances.count)
        return Double(avg)
    }

    static func intervalCoefficientOfVariation(timestamps: [TimeInterval]) -> Double? {
        guard timestamps.count >= 3 else { return nil }
        let sorted = timestamps.sorted()
        let intervals = zip(sorted.dropFirst(), sorted).map { $0.0 - $0.1 }.filter { $0 > 0 }
        guard intervals.count >= 2 else { return nil }
        let mean = intervals.reduce(0, +) / Double(intervals.count)
        guard mean > 0 else { return nil }
        let variance = intervals.map { pow($0 - mean, 2) }.reduce(0, +) / Double(intervals.count)
        let std = sqrt(variance)
        return std / mean
    }

    static func linearity(path: [CGPoint]) -> Double? {
        guard path.count >= 2 else { return nil }
        var actual: CGFloat = 0
        for i in 0..<(path.count - 1) {
            actual += hypot(path[i + 1].x - path[i].x, path[i + 1].y - path[i].y)
        }
        guard actual > 0 else { return nil }
        guard let first = path.first, let last = path.last else { return nil }
        let straight = hypot(last.x - first.x, last.y - first.y)
        return Double(straight / actual)
    }

    static func variance(values: [Double]) -> Double? {
        guard values.count >= 2 else { return nil }
        let mean = values.reduce(0, +) / Double(values.count)
        let v = values.map { pow($0 - mean, 2) }.reduce(0, +) / Double(values.count - 1)
        return v
    }

    static func coefficientOfVariation(values: [Double]) -> Double? {
        guard values.count >= 3 else { return nil }
        let mean = values.reduce(0, +) / Double(values.count)
        guard mean > 0 else { return nil }
        let variance = values.map { pow($0 - mean, 2) }.reduce(0, +) / Double(values.count)
        return sqrt(variance) / mean
    }

    static func averageSwipeSpeed(path: [CGPoint], duration: TimeInterval) -> Double? {
        guard path.count >= 2, duration > 0 else { return nil }
        var totalDistance: CGFloat = 0
        for i in 0..<(path.count - 1) {
            totalDistance += hypot(path[i + 1].x - path[i].x, path[i + 1].y - path[i].y)
        }
        return Double(totalDistance) / duration
    }
}
#else

final class TouchCapture {
    static let shared = TouchCapture()
    private init() {}
    func start() {}
    func stop() {}
    func clearSensitiveData() {}
    func snapshotAndReset() -> TouchMetrics {
        snapshotDetailAndReset().metrics
    }
    func snapshotDetailAndReset() -> (metrics: TouchMetrics, actionTimestamps: [TimeInterval]) {
        let metrics = TouchMetrics(
            sampleCount: 0,
            tapCount: 0,
            swipeCount: 0,
            coordinateSpread: nil,
            intervalCV: nil,
            averageLinearity: nil,
            forceVariance: nil,
            majorRadiusVariance: nil,
            swipeSpeedCV: nil
        )
        return (metrics, [])
    }
}
#endif
