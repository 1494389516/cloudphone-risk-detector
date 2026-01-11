import Foundation

final class DeviceHardwareProvider: RiskSignalProvider {
    static let shared = DeviceHardwareProvider()
    private init() {}

    let id = "device_hardware"

    func signals(snapshot: RiskSnapshot) -> [RiskSignal] {
        var out: [RiskSignal] = []

        if snapshot.device.isSimulator {
            out.append(
                RiskSignal(
                    id: "simulator",
                    category: "device",
                    score: 0,
                    evidence: ["machine": snapshot.device.hardwareMachine ?? "unknown"]
                )
            )
        }

        if let machine = snapshot.device.hardwareMachine, machine.isEmpty == false {
            out.append(
                RiskSignal(
                    id: "hw_machine",
                    category: "device",
                    score: 0,
                    evidence: ["machine": machine]
                )
            )
        }

        return out
    }
}

