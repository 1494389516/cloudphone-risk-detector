import Foundation

enum ScenarioPolicySignalBridge {
    private static let idfvHistoryKey = "cprk_scenario_policy.idfv_history"
    private static let idfvWindow: TimeInterval = 30 * 24 * 3600
    private static let idfvTriggerCount = 2

    private struct IDFVHistory: Codable {
        var lastValue: String
        var changeTimestamps: [TimeInterval]
    }

    static func deriveSignals(
        snapshot: RiskSnapshot,
        existingSignals: [RiskSignal],
        defaults: UserDefaults = .standard,
        now: Date = Date()
    ) -> [RiskSignal] {
        var out: [RiskSignal] = []

        if let deviceTamper = deviceTamperSignal(from: existingSignals) {
            out.append(deviceTamper)
        }
        if let debugged = debuggedSignal(from: existingSignals) {
            out.append(debugged)
        }
        if let fridaPort = fridaPortSignal(from: existingSignals) {
            out.append(fridaPort)
        }
        if let dnsTunnel = dnsTunnelSignal(from: existingSignals) {
            out.append(dnsTunnel)
        }
        if let idfvReinstall = idfvReinstallSignal(snapshot: snapshot, defaults: defaults, now: now) {
            out.append(idfvReinstall)
        }
        if let mccMismatch = mccMismatchSignal(snapshot: snapshot) {
            out.append(mccMismatch)
        }

        return out
    }

    static func deviceTamperSignal(from existingSignals: [RiskSignal]) -> RiskSignal? {
        let drivers = existingSignals.filter {
            guard $0.id != SignalID.deviceTamperScore else { return false }
            return isDeviceTamperDriver($0)
        }

        guard !drivers.isEmpty else { return nil }

        let tamperedDrivers = drivers.filter {
            if case .tampered? = $0.state { return true }
            return false
        }
        let hardDetectedDrivers = drivers.filter {
            if case .hard(let detected)? = $0.state { return detected }
            return false
        }
        let strongestScore = drivers.map(\.score).max() ?? 0
        let shouldEmit = tamperedDrivers.isEmpty == false || strongestScore >= 25 || drivers.count >= 4
        guard shouldEmit else { return nil }

        let derivedScore = min(
            100,
            strongestScore * 0.7
                + Double(tamperedDrivers.count) * 10
                + Double(hardDetectedDrivers.count) * 5
        )
        let confidence = min(
            0.96,
            0.58
                + Double(min(tamperedDrivers.count, 4)) * 0.08
                + Double(min(drivers.count, 6)) * 0.03
        )
        let state: RiskSignalState = tamperedDrivers.isEmpty ? .soft(confidence: confidence) : .tampered
        let driverIDs = Array(drivers.map(\.id).sorted().prefix(8))

        return RiskSignal(
            id: SignalID.deviceTamperScore,
            category: "device",
            score: derivedScore,
            evidence: [
                "mode": "anti_tamper_bridge",
                "driver_count": "\(drivers.count)",
                "tampered_driver_count": "\(tamperedDrivers.count)",
                "hard_driver_count": "\(hardDetectedDrivers.count)",
                "strongest_score": String(format: "%.2f", strongestScore),
                "drivers": driverIDs.joined(separator: ","),
            ],
            state: state,
            layer: 3,
            weightHint: min(92, derivedScore + 18)
        )
    }

    static func debuggedSignal(from existingSignals: [RiskSignal]) -> RiskSignal? {
        let drivers = existingSignals.filter {
            guard $0.id != SignalID.isDebugged else { return false }
            return isDebugDriver($0)
        }
        guard !drivers.isEmpty else { return nil }

        let driverIDs = Array(drivers.map(\.id).sorted().prefix(8))
        let strongestScore = drivers.map(\.score).max() ?? 0
        let hardDetected = drivers.contains {
            if case .hard(let detected)? = $0.state { return detected }
            return false
        }
        let tampered = drivers.contains {
            if case .tampered? = $0.state { return true }
            return false
        }

        return RiskSignal(
            id: SignalID.isDebugged,
            category: "debugger",
            score: min(48, 20 + strongestScore * 0.4 + Double(drivers.count) * 3),
            evidence: [
                "mode": "debug_surface_bridge",
                "driver_count": "\(drivers.count)",
                "drivers": driverIDs.joined(separator: ","),
            ],
            state: tampered ? .tampered : .hard(detected: hardDetected || strongestScore >= 18),
            layer: 3,
            weightHint: 72
        )
    }

    static func fridaPortSignal(from existingSignals: [RiskSignal]) -> RiskSignal? {
        let drivers = existingSignals.filter {
            guard $0.id != SignalID.fridaPortOpen else { return false }
            return $0.id.hasPrefix("frida_port_")
        }
        guard !drivers.isEmpty else { return nil }

        let ports = drivers.compactMap { $0.evidence["listening_port"] ?? $0.id.split(separator: "_").last.map(String.init) }
        let strongestScore = drivers.map(\.score).max() ?? 0
        let tampered = drivers.contains {
            if case .tampered? = $0.state { return true }
            return false
        }

        return RiskSignal(
            id: SignalID.fridaPortOpen,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: min(40, 18 + strongestScore * 0.35 + Double(drivers.count) * 2),
            evidence: [
                "mode": "frida_port_bridge",
                "ports": ports.sorted().joined(separator: ","),
                "driver_count": "\(drivers.count)",
            ],
            state: tampered ? .tampered : .hard(detected: true),
            layer: 3,
            weightHint: 68
        )
    }

    static func dnsTunnelSignal(from existingSignals: [RiskSignal]) -> RiskSignal? {
        let drivers = existingSignals.filter {
            guard $0.id != SignalID.dnsTunnelDetected else { return false }
            return $0.id.contains("frida_anom_proto_") || $0.id.hasPrefix("suspicious_local_listen_")
        }
        guard !drivers.isEmpty else { return nil }

        let strongestScore = drivers.map(\.score).max() ?? 0
        let ports = drivers.compactMap {
            if let value = $0.evidence["listening_port"], !value.isEmpty { return value }
            let parts = $0.id.split(separator: "_").map(String.init)
            return parts.first(where: { $0.allSatisfy(\.isNumber) })
        }
        let tampered = drivers.contains {
            if case .tampered? = $0.state { return true }
            return false
        }

        return RiskSignal(
            id: SignalID.dnsTunnelDetected,
            category: "network",
            score: min(36, 16 + strongestScore * 0.4 + Double(drivers.count) * 2),
            evidence: [
                "mode": "anom_proto_local_listen_bridge",
                "driver_count": "\(drivers.count)",
                "ports": ports.sorted().joined(separator: ","),
                "drivers": drivers.map(\.id).sorted().prefix(8).joined(separator: ","),
            ],
            state: tampered ? .tampered : .soft(confidence: min(0.88, 0.62 + Double(drivers.count) * 0.06)),
            layer: 3,
            weightHint: 60
        )
    }

    static func idfvReinstallSignal(
        snapshot: RiskSnapshot,
        defaults: UserDefaults = .standard,
        now: Date = Date()
    ) -> RiskSignal? {
        guard let idfv = snapshot.device.identifierForVendor?.trimmingCharacters(in: .whitespacesAndNewlines),
              !idfv.isEmpty else {
            return nil
        }

        let nowTs = now.timeIntervalSince1970
        var history = loadIDFVHistory(defaults: defaults)
            ?? IDFVHistory(lastValue: idfv, changeTimestamps: [])
        history.changeTimestamps.removeAll { nowTs - $0 > idfvWindow }

        if history.lastValue != idfv {
            history.changeTimestamps.append(nowTs)
            history.lastValue = idfv
        }

        saveIDFVHistory(history, defaults: defaults)

        guard history.changeTimestamps.count >= idfvTriggerCount else { return nil }

        let confidence = min(0.92, 0.68 + Double(history.changeTimestamps.count - idfvTriggerCount) * 0.05)
        return RiskSignal(
            id: SignalID.idfvReinstallCount,
            category: "device",
            score: min(45, 18 + Double(history.changeTimestamps.count) * 6),
            evidence: [
                "reinstall_count_30d": "\(history.changeTimestamps.count)",
                "window_days": "30",
                "current_idfv_suffix": String(idfv.suffix(8)),
            ],
            state: .soft(confidence: confidence),
            layer: 2,
            weightHint: 48
        )
    }

    static func mccMismatchSignal(snapshot: RiskSnapshot) -> RiskSignal? {
        guard let mcc = snapshot.network.mcc?.trimmingCharacters(in: .whitespacesAndNewlines),
              !mcc.isEmpty else {
            return nil
        }

        guard let region = normalizedRegionCode(from: snapshot.device.localeIdentifier),
              let expectedMCCs = regionToMCCs[region] else {
            return nil
        }

        guard expectedMCCs.contains(mcc) == false else { return nil }

        return RiskSignal(
            id: SignalID.mccMismatch,
            category: "network",
            score: 22,
            evidence: [
                "region": region,
                "mcc": mcc,
                "expected_mccs": expectedMCCs.sorted().joined(separator: ","),
            ],
            state: .soft(confidence: 0.78),
            layer: 2,
            weightHint: 52
        )
    }

    private static func loadIDFVHistory(defaults: UserDefaults) -> IDFVHistory? {
        guard let data = defaults.data(forKey: idfvHistoryKey) else { return nil }
        return try? JSONDecoder().decode(IDFVHistory.self, from: data)
    }

    private static func saveIDFVHistory(_ history: IDFVHistory, defaults: UserDefaults) {
        guard let data = try? JSONEncoder().encode(history) else { return }
        defaults.set(data, forKey: idfvHistoryKey)
    }

    private static func isDeviceTamperDriver(_ signal: RiskSignal) -> Bool {
        if signal.category == ObfuscatedConstants.categoryAntiTamper || signal.category == "integrity" {
            return true
        }
        switch signal.id {
        case SignalID.antiDebugRuntimeConsensus,
             SignalID.signingChainConsensus,
             SignalID.fridaRuntimeConsensus,
             SignalID.signalSuppressionDetected:
            return true
        default:
            return false
        }
    }

    private static func isDebugDriver(_ signal: RiskSignal) -> Bool {
        if signal.id == SignalID.debuggerDetected
            || signal.id == SignalID.antiDebugRuntimeConsensus
            || signal.id == SignalID.antiDebugWatchdogTraced
            || signal.id == SignalID.antiDebugWatchdogAnomaly
            || signal.id == SignalID.csopsDebugged
            || signal.id == SignalID.signalProbeDebugger {
            return true
        }
        if signal.id.hasPrefix("debugger_port_") {
            return true
        }
        if signal.id.hasPrefix("anti_debug_watchdog_") {
            return true
        }
        return false
    }

    private static func normalizedRegionCode(from localeIdentifier: String) -> String? {
        let locale = Locale(identifier: localeIdentifier)
        if #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) {
            if let region = locale.region?.identifier, region.isEmpty == false {
                return region.uppercased()
            }
        }

        let separators = CharacterSet(charactersIn: "_-")
        let parts = localeIdentifier.components(separatedBy: separators)
        guard let last = parts.last, last.count == 2 else { return nil }
        return last.uppercased()
    }

    private static let regionToMCCs: [String: Set<String>] = [
        "AR": ["722"],
        "AT": ["232"],
        "AU": ["505"],
        "BE": ["206"],
        "BR": ["724"],
        "CA": ["302"],
        "CH": ["228"],
        "CL": ["730"],
        "CN": ["460", "461"],
        "CO": ["732"],
        "CZ": ["230"],
        "DE": ["262"],
        "DK": ["238"],
        "EG": ["602"],
        "ES": ["214"],
        "FI": ["244"],
        "FR": ["208"],
        "GB": ["234", "235"],
        "HK": ["454"],
        "HU": ["216"],
        "ID": ["510"],
        "IE": ["272"],
        "IN": ["404", "405", "406"],
        "IT": ["222"],
        "JP": ["440", "441"],
        "KR": ["450"],
        "MO": ["455"],
        "MX": ["334"],
        "MY": ["502"],
        "NL": ["204"],
        "NO": ["242"],
        "NZ": ["530"],
        "PE": ["716"],
        "PH": ["515"],
        "PL": ["260"],
        "PT": ["268"],
        "RO": ["226"],
        "RU": ["250"],
        "SA": ["420"],
        "SE": ["240"],
        "SG": ["525"],
        "TH": ["520"],
        "TR": ["286"],
        "TW": ["466"],
        "UA": ["255"],
        "US": ["310", "311", "312", "313", "314", "315", "316"],
        "VN": ["452"],
        "ZA": ["655"],
    ]
}
