#if os(iOS)
import Accelerate
import CoreMotion
import CryptoKit
import Foundation

final class IMUNoiseSpectrumProvider: RiskSignalProvider {
    static let shared = IMUNoiseSpectrumProvider()
    let id = "imu_noise_spectrum"

    private let sampleRate: Double = 100.0
    private let sampleCount = 256
    private let samplingTimeout: TimeInterval = 4.0

    private let lock = UnfairLock()
    private var cachedResult: CachedResult?
    private let cacheTTL: TimeInterval = 120

    private struct CachedResult {
        let signals: [RiskSignal]
        let time: TimeInterval
    }

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let now = ProcessInfo.processInfo.systemUptime
        let cached: [RiskSignal]? = lock.withLock {
            if let c = cachedResult, now - c.time < cacheTTL { return c.signals }
            return nil
        }
        if let cached { return cached }

        let result = collect()

        lock.withLock {
            cachedResult = CachedResult(signals: result, time: ProcessInfo.processInfo.systemUptime)
        }
        return result
    }

    private func collect() -> [RiskSignal] {
        let manager = CMMotionManager()
        guard manager.isAccelerometerAvailable else {
            return [RiskSignal(
                id: SignalID.imuNoiseUnavailable,
                category: SignalCategory.cloudphone,
                score: 0,
                evidence: ["detail": "accelerometer_unavailable"],
                state: .soft(confidence: 0.5),
                layer: 1,
                weightHint: 60
            )]
        }

        let requiredCount = sampleCount
        var samples = [Double]()
        samples.reserveCapacity(requiredCount)
        let semaphore = DispatchSemaphore(value: 0)
        let sampleLock = UnfairLock()
        let queue = OperationQueue()
        queue.qualityOfService = .userInitiated

        manager.accelerometerUpdateInterval = 1.0 / sampleRate
        manager.startAccelerometerUpdates(to: queue) { data, _ in
            guard let data else { return }
            let mag = sqrt(
                data.acceleration.x * data.acceleration.x +
                data.acceleration.y * data.acceleration.y +
                data.acceleration.z * data.acceleration.z
            )
            let done = sampleLock.withLock { () -> Bool in
                if samples.count < requiredCount {
                    samples.append(mag)
                }
                return samples.count >= requiredCount
            }
            if done { semaphore.signal() }
        }

        let timeout = DispatchTime.now() + samplingTimeout
        _ = semaphore.wait(timeout: timeout)
        manager.stopAccelerometerUpdates()

        let collectedSamples = sampleLock.withLock { Array(samples.prefix(requiredCount)) }

        guard collectedSamples.count >= requiredCount else {
            return [RiskSignal(
                id: SignalID.imuNoiseInsufficient,
                category: SignalCategory.cloudphone,
                score: 0,
                evidence: ["samples": "\(collectedSamples.count)"],
                state: .unavailable,
                layer: 3,
                weightHint: 50
            )]
        }

        let spectrum = fftMagnitude(signal: collectedSamples)
        guard !spectrum.isEmpty else {
            return [RiskSignal(
                id: SignalID.imuNoiseUnavailable,
                category: SignalCategory.cloudphone,
                score: 0,
                evidence: ["detail": "fft_failed"],
                state: .unavailable,
                layer: 3,
                weightHint: 50
            )]
        }

        let fp = spectrumFingerprint(spectrum: spectrum)
        let noiseFloor = spectrumNoiseFloor(spectrum: spectrum)

        var out = [RiskSignal]()

        out.append(RiskSignal(
            id: SignalID.imuNoiseFingerprint,
            category: SignalCategory.cloudphone,
            score: 0,
            evidence: [
                "fingerprint": fp,
                "noise_floor_db": String(format: "%.2f", noiseFloor),
            ],
            state: .hard(detected: false),
            layer: 1,
            weightHint: 75
        ))

        if noiseFloor < -80.0 {
            out.append(RiskSignal(
                id: SignalID.imuNoiseSynthetic,
                category: SignalCategory.cloudphone,
                score: 0,
                evidence: ["noise_floor_db": String(format: "%.2f", noiseFloor)],
                state: .soft(confidence: 0.8),
                layer: 1,
                weightHint: 80
            ))
        }

        return out
    }

    // MARK: - DSP

    private func fftMagnitude(signal: [Double]) -> [Double] {
        let n = signal.count
        guard n > 0, n & (n - 1) == 0 else { return [] }
        let log2n = vDSP_Length(log2(Double(n)))

        guard let fftSetup = vDSP_create_fftsetupD(log2n, FFTRadix(kFFTRadix2)) else {
            return []
        }
        defer { vDSP_destroy_fftsetupD(fftSetup) }

        var realPart = signal
        var imagPart = [Double](repeating: 0, count: n)
        let halfN = n / 2

        // Use withUnsafeMutableBufferPointer to guarantee pointer lifetime across vDSP calls
        let magnitudes: [Double] = realPart.withUnsafeMutableBufferPointer { realBuf in
            imagPart.withUnsafeMutableBufferPointer { imagBuf in
                var splitComplex = DSPDoubleSplitComplex(
                    realp: realBuf.baseAddress!,
                    imagp: imagBuf.baseAddress!
                )

                vDSP_fft_zipD(fftSetup, &splitComplex, 1, log2n, FFTDirection(kFFTDirection_Forward))

                var mags = [Double](repeating: 0, count: halfN)
                vDSP_zvmagsD(&splitComplex, 1, &mags, 1, vDSP_Length(halfN))

                var one: Double = 1.0
                vDSP_vdbconD(mags, 1, &one, &mags, 1, vDSP_Length(halfN), 0)

                return mags
            }
        }

        return magnitudes
    }

    private func spectrumFingerprint(spectrum: [Double]) -> String {
        guard !spectrum.isEmpty else { return "" }
        let binCount = 8
        let binSize = spectrum.count / binCount
        guard binSize > 0 else { return "" }

        var bins = [UInt8]()
        bins.reserveCapacity(binCount)
        for i in 0..<binCount {
            let start = i * binSize
            let end = min(start + binSize, spectrum.count)
            let slice = spectrum[start..<end]
            let avg = slice.reduce(0, +) / Double(slice.count)
            let quantized = UInt8(clamping: Int((avg + 100) * 2.55))
            bins.append(quantized)
        }

        let digest = SHA256.hash(data: Data(bins))
        return digest.prefix(16).map { String(format: "%02x", $0) }.joined()
    }

    private func spectrumNoiseFloor(spectrum: [Double]) -> Double {
        guard spectrum.count > 4 else { return -100 }
        let highFreq = Array(spectrum.suffix(spectrum.count / 4))
        guard !highFreq.isEmpty else { return -100 }
        let sorted = highFreq.sorted()
        let mid = sorted.count / 2
        if sorted.count % 2 == 0 {
            return (sorted[mid - 1] + sorted[mid]) / 2.0
        }
        return sorted[mid]
    }
}
#else
import Foundation

final class IMUNoiseSpectrumProvider: RiskSignalProvider {
    static let shared = IMUNoiseSpectrumProvider()
    let id = "imu_noise_spectrum"
    func signals(snapshot: RiskSnapshot) -> [RiskSignal] { [] }
}
#endif
