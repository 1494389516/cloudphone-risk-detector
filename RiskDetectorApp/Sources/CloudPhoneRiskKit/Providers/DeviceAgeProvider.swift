import Foundation

final class DeviceAgeProvider: RiskSignalProvider {
    static let shared = DeviceAgeProvider()
    private init() {}

    let id = "device_age"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        guard let machine = snapshot.device.hardwareMachine else { return [] }
        guard let family = parseIPhoneFamily(machine) else { return [] }

        // Very rough: older families are more common for device farms/cloud phones.
        let score: Double
        switch family {
        case ..<10: score = 18  // iPhone X/8 and older
        case 10...11: score = 12
        case 12...13: score = 6
        default: score = 0
        }

        guard score > 0 else { return [] }
        return [
            RiskSignal(
                id: "old_device_model",
                category: "device",
                score: score,
                evidence: [
                    "machine": machine,
                    "family": "\(family)",
                ]
            ),
        ]
    }

    private func parseIPhoneFamily(_ machine: String) -> Int? {
        // e.g. iPhone10,6
        guard machine.hasPrefix("iPhone") else { return nil }
        let rest = machine.dropFirst("iPhone".count)
        var digits = ""
        for ch in rest {
            if ch.isNumber { digits.append(ch) } else { break }
        }
        return Int(digits)
    }
}

