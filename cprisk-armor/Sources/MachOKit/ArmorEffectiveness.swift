import Foundation

/// Fail-closed postconditions for transforms whose security value requires an
/// observable code mutation. Creating metadata or printing a pass banner is
/// not sufficient evidence that these passes took effect.
public func validateEffectiveArmorPasses(
    enabledPasses: Set<Int>,
    resultsByPass: [Int: [PassResult]]
) throws {
    let effectivenessRequired: [Int: String] = [
        8: "Instruction Substitution",
        9: "Control Flow Orchestrator",
        13: "VMProtector",
    ]

    for (passID, label) in effectivenessRequired where enabledPasses.contains(passID) {
        let results = resultsByPass[passID] ?? []
        let items = results.reduce(0) { $0 + $1.itemsProcessed }
        let bytes = results.reduce(0) { $0 + $1.bytesModified }
        guard items > 0, bytes > 0 else {
            throw MachOError.invalidData(
                "Pass \(passID) (\(label)) was enabled but made no effective transformation"
            )
        }
    }

    if enabledPasses.contains(13) {
        let metrics = (resultsByPass[13] ?? []).reduce(into: [String: Int]()) { aggregate, result in
            for (key, value) in result.metrics {
                aggregate[key, default: 0] += value
            }
        }
        if metrics["vmp.full_patched", default: 0] == 0 {
            throw MachOError.invalidData(
                "Pass 13 installed no native entry replacement; partial bytecode metadata is not effective code protection"
            )
        }
    }
}
