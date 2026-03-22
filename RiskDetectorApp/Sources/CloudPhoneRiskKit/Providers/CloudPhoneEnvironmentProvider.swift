import Foundation
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Cloud Phone Environment Detection
//
// Detects cloud phone environments through five orthogonal signal families:
//   1. Network latency patterns (unusually uniform RTT)
//   2. Screen resolution/scale factor anomalies
//   3. Thermal state invariance (always nominal)
//   4. Cloud phone management process names
//   5. Locale ↔ timezone inconsistency

public final class CloudPhoneEnvironmentProvider: RiskSignalProvider {
    static let shared = CloudPhoneEnvironmentProvider()

    public let id = "cloudphone_environment"

    /// Known cloud phone management process name fragments (lowercase).
    static let knownCloudProcessKeywords: [String] = [
        "cloudphoned",
        "armcloud",
        "redfinger",
        "bignox",
        "nowgg",
        "phonecloud",
        "remotefarm",
        "nbfarm",
        "thunder_cloud",
        "baidu_cloud_phone",
    ]

    /// Locale region → expected timezone prefix mapping for mismatch detection.
    static let regionTimezonePrefixes: [String: [String]] = [
        "US": ["America/"],
        "GB": ["Europe/London"],
        "CN": ["Asia/Shanghai", "Asia/Chongqing", "Asia/Harbin", "Asia/Urumqi"],
        "JP": ["Asia/Tokyo"],
        "KR": ["Asia/Seoul"],
        "DE": ["Europe/Berlin"],
        "FR": ["Europe/Paris"],
        "IN": ["Asia/Kolkata", "Asia/Calcutta"],
        "BR": ["America/Sao_Paulo", "America/Fortaleza", "America/Manaus", "America/Recife"],
        "AU": ["Australia/"],
    ]

    /// Atypical screen resolution/scale combinations commonly seen in cloud phone farms.
    /// Each entry is (width, height, scale).
    static let atypicalResolutions: [(Int, Int, Double)] = [
        (720, 1280, 1.0),
        (1080, 1920, 1.0),
        (1080, 2340, 1.0),
        (1440, 2560, 1.0),
        (720, 1280, 0.5),
        (1080, 1920, 0.5),
    ]

    public init() {}

    public func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let planner = MutationPlanner(
            strategy: activeMutationStrategy(),
            scope: id,
            deviceID: snapshot.deviceID
        )

        let checks: [() -> [RiskSignal]] = [
            { self.networkLatencySignals(snapshot: snapshot) },
            { self.screenResolutionSignals(snapshot: snapshot) },
            { self.thermalStateSignals() },
            { self.processNameSignals() },
            { self.localeTimezoneSignals(snapshot: snapshot) },
        ]

        var out: [RiskSignal] = []
        for check in planner.maybeShuffle(checks, salt: "cloudphone_env_checks") {
            out.append(contentsOf: check())
        }
        return planner.maybeShuffle(out, salt: "cloudphone_env_emit_order")
    }

    // MARK: - Private Checks

    /// 1. Network latency patterns — cloud phones often exhibit suspiciously uniform RTT.
    private func networkLatencySignals(snapshot: RiskSnapshot) -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return [
            RiskSignal(
                id: "network_latency_pattern",
                category: "environment",
                score: 0,
                evidence: ["detail": "simulator"],
                state: .unavailable,
                layer: 3,
                weightHint: 60
            ),
        ]
        #else
        let samples = measureRTTSamples(count: 6)
        guard samples.count >= 3 else {
            return [
                RiskSignal(
                    id: "network_latency_pattern",
                    category: "environment",
                    score: 0,
                    evidence: ["detail": "insufficient_samples"],
                    state: .unavailable,
                    layer: 3,
                    weightHint: 60
                ),
            ]
        }

        let variance = computeVariance(samples)
        let mean = samples.reduce(0, +) / Double(samples.count)
        let cv = mean > 0 ? (variance.squareRoot() / mean) : 1.0

        // Cloud phones typically show coefficient of variation < 0.02 (nearly identical RTTs).
        let confidence: Double
        if cv < 0.01 {
            confidence = 0.95
        } else if cv < 0.03 {
            confidence = 0.75
        } else if cv < 0.08 {
            confidence = 0.45
        } else {
            confidence = 0.15
        }

        Logger.log("CloudPhoneEnv: RTT cv=\(String(format: "%.4f", cv)), variance=\(String(format: "%.6f", variance)), samples=\(samples.count)")

        return [
            RiskSignal(
                id: "network_latency_pattern",
                category: "environment",
                score: 0,
                evidence: [
                    "rtt_cv": String(format: "%.6f", cv),
                    "rtt_variance": String(format: "%.6f", variance),
                    "rtt_mean_ms": String(format: "%.2f", mean),
                    "samples": "\(samples.count)",
                ],
                state: .soft(confidence: confidence),
                layer: 3,
                weightHint: 60
            ),
        ]
        #endif
    }

    /// 2. Screen resolution consistency — cloud phones may report atypical resolution/scale combos.
    private func screenResolutionSignals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let width = snapshot.device.screenWidth
        let height = snapshot.device.screenHeight
        let scale = snapshot.device.screenScale

        let isAtypical = Self.atypicalResolutions.contains { res in
            res.0 == width && res.1 == height && abs(res.2 - scale) < 0.01
        }

        // Scale factor of exactly 1.0 on a high-res screen is suspicious on iOS.
        let suspiciousScale = scale == 1.0 && (width > 640 || height > 1136)

        let confidence: Double
        if isAtypical {
            confidence = 0.85
        } else if suspiciousScale {
            confidence = 0.65
        } else {
            confidence = 0.1
        }

        Logger.log("CloudPhoneEnv: screen \(width)x\(height)@\(scale), atypical=\(isAtypical), suspiciousScale=\(suspiciousScale)")

        return [
            RiskSignal(
                id: "screen_resolution_anomaly",
                category: "environment",
                score: 0,
                evidence: [
                    "width": "\(width)",
                    "height": "\(height)",
                    "scale": String(format: "%.2f", scale),
                    "atypical_match": "\(isAtypical)",
                ],
                state: .soft(confidence: confidence),
                layer: 2,
                weightHint: 70
            ),
        ]
    }

    /// 3. Thermal state anomalies — cloud phones typically report nominal state without variation.
    private func thermalStateSignals() -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return [
            RiskSignal(
                id: "thermal_state_anomaly",
                category: "environment",
                score: 0,
                evidence: ["detail": "simulator"],
                state: .unavailable,
                layer: 2,
                weightHint: 55
            ),
        ]
        #elseif canImport(UIKit)
        let samples = collectThermalStateSamples(count: 5, interval: 0.2)
        let allNominal = !samples.isEmpty && samples.allSatisfy { $0 == ProcessInfo.ThermalState.nominal.rawValue }
        let noVariation = Set(samples).count <= 1

        let confidence: Double
        if samples.isEmpty {
            return [
                RiskSignal(
                    id: "thermal_state_anomaly",
                    category: "environment",
                    score: 0,
                    evidence: ["detail": "no_samples"],
                    state: .unavailable,
                    layer: 2,
                    weightHint: 55
                ),
            ]
        } else if allNominal && noVariation {
            confidence = 0.7
        } else if noVariation {
            confidence = 0.5
        } else {
            confidence = 0.1
        }

        Logger.log("CloudPhoneEnv: thermal samples=\(samples), allNominal=\(allNominal), noVariation=\(noVariation)")

        return [
            RiskSignal(
                id: "thermal_state_anomaly",
                category: "environment",
                score: 0,
                evidence: [
                    "all_nominal": "\(allNominal)",
                    "no_variation": "\(noVariation)",
                    "sample_count": "\(samples.count)",
                ],
                state: .soft(confidence: confidence),
                layer: 2,
                weightHint: 55
            ),
        ]
        #else
        return [
            RiskSignal(
                id: "thermal_state_anomaly",
                category: "environment",
                score: 0,
                evidence: ["detail": "platform_unsupported"],
                state: .unavailable,
                layer: 2,
                weightHint: 55
            ),
        ]
        #endif
    }

    /// 4. Process name patterns — look for cloud phone management daemons.
    private func processNameSignals() -> [RiskSignal] {
        #if targetEnvironment(simulator)
        return [
            RiskSignal(
                id: "cloud_process_detected",
                category: "environment",
                score: 0,
                evidence: ["detail": "simulator"],
                state: .unavailable,
                layer: 1,
                weightHint: 90
            ),
        ]
        #else
        let dynamicPatterns = PolicyManager.shared.activePolicy?.newVPhonePatterns.map { $0.lowercased() } ?? []
        let allPatterns = Self.knownCloudProcessKeywords + dynamicPatterns

        let suspiciousProcesses = detectSuspiciousProcesses(patterns: allPatterns)
        let detected = !suspiciousProcesses.isEmpty

        if detected {
            Logger.log("CloudPhoneEnv: suspicious processes found: \(suspiciousProcesses)")
        }

        return [
            RiskSignal(
                id: "cloud_process_detected",
                category: "environment",
                score: 0,
                evidence: [
                    "matched_processes": suspiciousProcesses.joined(separator: ","),
                    "pattern_count": "\(allPatterns.count)",
                ],
                state: detected ? .hard(detected: true) : .soft(confidence: 0.05),
                layer: 1,
                weightHint: 90
            ),
        ]
        #endif
    }

    /// 5. Locale/timezone inconsistency — locale region and timezone may be mismatched in cloud phones.
    private func localeTimezoneSignals(snapshot: RiskSnapshot) -> [RiskSignal] {
        let localeId = snapshot.device.localeIdentifier
        let timezoneId = snapshot.device.timeZoneIdentifier

        // Extract region code from locale (e.g., "en_US" → "US", "zh-Hans_CN" → "CN").
        let regionCode = extractRegionCode(from: localeId)

        guard let region = regionCode, let expectedPrefixes = Self.regionTimezonePrefixes[region] else {
            // Unknown region — cannot determine mismatch.
            return [
                RiskSignal(
                    id: "locale_timezone_mismatch",
                    category: "environment",
                    score: 0,
                    evidence: [
                        "locale": localeId,
                        "timezone": timezoneId,
                        "region": regionCode ?? "unknown",
                    ],
                    state: .soft(confidence: 0.1),
                    layer: 2,
                    weightHint: 65
                ),
            ]
        }

        let matches = expectedPrefixes.contains { timezoneId.hasPrefix($0) }

        let confidence: Double
        if !matches {
            confidence = 0.8
        } else {
            confidence = 0.05
        }

        Logger.log("CloudPhoneEnv: locale=\(localeId), tz=\(timezoneId), region=\(region), tzMatch=\(matches)")

        return [
            RiskSignal(
                id: "locale_timezone_mismatch",
                category: "environment",
                score: 0,
                evidence: [
                    "locale": localeId,
                    "timezone": timezoneId,
                    "region": region,
                    "tz_matches_region": "\(matches)",
                ],
                state: .soft(confidence: confidence),
                layer: 2,
                weightHint: 65
            ),
        ]
    }

    // MARK: - Helpers

    private func activeMutationStrategy() -> MutationStrategy? {
        guard let mutation = PolicyManager.shared.activePolicy?.mutation else { return nil }
        return MutationStrategy(
            seed: mutation.seed,
            shuffleChecks: mutation.shuffleChecks,
            thresholdJitterBps: mutation.thresholdJitterBps,
            scoreJitterBps: mutation.scoreJitterBps
        )
    }

    private func computeVariance(_ series: [Double]) -> Double {
        guard series.count > 1 else { return 0 }
        let mean = series.reduce(0, +) / Double(series.count)
        let squaredDiffs = series.map { pow($0 - mean, 2) }
        return squaredDiffs.reduce(0, +) / Double(series.count - 1)
    }

    /// Measure loopback RTT samples using a lightweight socket connection.
    private func measureRTTSamples(count: Int) -> [Double] {
        var results: [Double] = []
        for _ in 0..<count {
            let start = CFAbsoluteTimeGetCurrent()
            // Attempt a minimal TCP connection to loopback to measure scheduling/virtualization overhead.
            let sock = socket(AF_INET, SOCK_STREAM, 0)
            guard sock >= 0 else { continue }
            defer { close(sock) }

            // Set non-blocking with a short timeout.
            var timeout = timeval(tv_sec: 0, tv_usec: 50_000) // 50ms
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = UInt16(12345).bigEndian
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")

            withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                    _ = connect(sock, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }

            let elapsed = (CFAbsoluteTimeGetCurrent() - start) * 1000.0 // ms
            results.append(elapsed)
        }
        return results
    }

    #if canImport(UIKit)
    private func collectThermalStateSamples(count: Int, interval: TimeInterval) -> [Int] {
        var samples: [Int] = []
        for i in 0..<count {
            let state = ProcessInfo.processInfo.thermalState
            samples.append(state.rawValue)
            if i < count - 1 {
                Thread.sleep(forTimeInterval: interval)
            }
        }
        return samples
    }
    #endif

    /// Detect suspicious processes by scanning /proc or using sysctl.
    private func detectSuspiciousProcesses(patterns: [String]) -> [String] {
        var matched: [String] = []

        // Use sysctl KERN_PROC to enumerate visible process names.
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: Int = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0, size > 0 else {
            return matched
        }

        let count = size / MemoryLayout<kinfo_proc>.stride
        var procList = [kinfo_proc](repeating: kinfo_proc(), count: count)
        guard sysctl(&mib, UInt32(mib.count), &procList, &size, nil, 0) == 0 else {
            return matched
        }

        let actualCount = size / MemoryLayout<kinfo_proc>.stride
        for i in 0..<actualCount {
            var info = procList[i]
            let name = withUnsafePointer(to: &info.kp_proc.p_comm) { ptr in
                ptr.withMemoryRebound(to: CChar.self, capacity: Int(MAXCOMM)) {
                    String(cString: $0)
                }
            }
            let lower = name.lowercased()
            for pattern in patterns {
                if lower.contains(pattern) {
                    matched.append(name)
                    break
                }
            }
        }

        return matched
    }

    private func extractRegionCode(from localeIdentifier: String) -> String? {
        // Handle formats: "en_US", "zh-Hans_CN", "en_US@calendar=gregorian"
        let cleaned = localeIdentifier.components(separatedBy: "@").first ?? localeIdentifier
        let parts = cleaned.components(separatedBy: "_")
        guard parts.count >= 2 else { return nil }
        let candidate = parts.last!
        // Region codes are typically 2 uppercase letters.
        if candidate.count == 2 && candidate == candidate.uppercased() && candidate.allSatisfy({ $0.isLetter }) {
            return candidate
        }
        return nil
    }
}
