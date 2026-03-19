import Foundation

public enum DecoyFieldInjector {
    enum FieldGroup: String {
        case hardware = "A"
        case behavior = "B"
        case decoy = "C"
    }

    private static let decoyCountRange = 10...15
    private static let shortCodeChars = "abcdefghijklmnopqrstuvwxyz0123456789"

    public static func inject(into payload: inout [String: Any], seed: UInt64) {
        let decoys = generateDecoyFields(count: decoyCountForPayload(payload), seed: seed, existingKeys: Set(payload.keys))
        for (k, v) in decoys {
            payload[k] = v
        }
    }

    private static func decoyCountForPayload(_ payload: [String: Any]) -> Int {
        let realCount = payload.count
        let target = decoyCountRange.lowerBound + (realCount % (decoyCountRange.upperBound - decoyCountRange.lowerBound + 1))
        return min(max(target, decoyCountRange.lowerBound), decoyCountRange.upperBound)
    }

    private static func generateDecoyFields(count: Int, seed: UInt64, existingKeys: Set<String>) -> [String: Any] {
        var rng = SeededRNG(seed: seed)
        var result: [String: Any] = [:]
        var attempts = 0
        let maxAttempts = count * 3
        while result.count < count, attempts < maxAttempts {
            attempts += 1
            let name = randomShortCode(length: 4, rng: &rng)
            guard !existingKeys.contains(name), result[name] == nil else { continue }
            let value: Any
            switch rng.next() % 4 {
            case 0: value = rng.next() % 101
            case 1: value = rng.next() % 2 == 0
            case 2: value = Double(rng.next() % 10001) / 10000.0
            default: value = String(format: "%08X-%04X", rng.next() & 0xFFFFFFFF, rng.next() & 0xFFFF)
            }
            result[name] = value
        }
        return result
    }

    private static func randomShortCode(length: Int, rng: inout SeededRNG) -> String {
        let chars = Array(shortCodeChars)
        return (0..<length).map { _ in String(chars[Int(rng.next() % UInt64(chars.count))]) }.joined()
    }
}

public struct RuntimeFieldMapping {
    private static let semanticFields: [String] = [
        "\(ObfuscatedConstants.keywordJailbreak)_score", "vm_detected", "imu_variance",
        "battery_charge_counter", "drm_level", "mount_anomaly",
        "rwx_detected", ObfuscatedConstants.signalHookDetected, "timing_anomaly",
        "touch_entropy", "sensor_entropy", ObfuscatedConstants.requiredSignalVpnActive,
        "proxy_enabled", "device_model", "gpu_name",
        "kernel_version", "board_id", "score", "isHighRisk"
    ]

    private static let shortCodeChars = "abcdefghijklmnopqrstuvwxyz0123456789"

    public static func generate(seed: UInt64, version: String) -> PayloadFieldMapping {
        var rng = SeededRNG(seed: seed &+ UInt64(bitPattern: Int64(version.hashValue)))
        var mappings: [String: String] = [:]
        var usedCodes: Set<String> = []
        for field in semanticFields {
            var obfuscated: String
            var attempts = 0
            repeat {
                obfuscated = randomShortCode(length: 4, rng: &rng)
                attempts += 1
            } while usedCodes.contains(obfuscated) && attempts < 50
            usedCodes.insert(obfuscated)
            mappings[field] = obfuscated
        }
        return PayloadFieldMapping(version: version, mappings: mappings, expiresAtMillis: nil)
    }

    private static func randomShortCode(length: Int, rng: inout SeededRNG) -> String {
        let chars = Array(shortCodeChars)
        return (0..<length).map { _ in String(chars[Int(rng.next() % UInt64(chars.count))]) }.joined()
    }
}

private struct SeededRNG {
    private var state: UInt64

    init(seed: UInt64) {
        self.state = seed == 0 ? 1 : seed
    }

    mutating func next() -> UInt64 {
        state = state &* 6364136223846793005 &+ 1442695040888963407
        return state
    }
}
