import Foundation

public struct CloudPhoneLocalSignals: Codable, Sendable {
    public var device: CloudPhoneDeviceSignals
    public var behavior: CloudPhoneBehaviorSignals
    public var time: CloudPhoneTimeSignals

    public init(
        device: CloudPhoneDeviceSignals,
        behavior: CloudPhoneBehaviorSignals,
        time: CloudPhoneTimeSignals
    ) {
        self.device = device
        self.behavior = behavior
        self.time = time
    }
}

public struct CloudPhoneDeviceSignals: Codable, Sendable {
    public var isSimulator: DetectionSignal<[String: String]>
    public var oldDeviceModel: DetectionSignal<[String: String]>?

    public init(
        isSimulator: DetectionSignal<[String: String]>,
        oldDeviceModel: DetectionSignal<[String: String]>?
    ) {
        self.isSimulator = isSimulator
        self.oldDeviceModel = oldDeviceModel
    }
}

public struct CloudPhoneBehaviorSignals: Codable, Sendable {
    public var touchSpreadLow: DetectionSignal<[String: String]>
    public var touchSpreadHigh: DetectionSignal<[String: String]>
    public var touchIntervalTooRegular: DetectionSignal<[String: String]>
    public var touchIntervalTooChaotic: DetectionSignal<[String: String]>
    public var swipeTooLinear: DetectionSignal<[String: String]>
    public var swipeTooCurvy: DetectionSignal<[String: String]>
    public var motionTooStill: DetectionSignal<[String: String]>
    public var touchMotionWeakCoupling: DetectionSignal<[String: String]>

    public init(
        touchSpreadLow: DetectionSignal<[String: String]>,
        touchSpreadHigh: DetectionSignal<[String: String]>,
        touchIntervalTooRegular: DetectionSignal<[String: String]>,
        touchIntervalTooChaotic: DetectionSignal<[String: String]>,
        swipeTooLinear: DetectionSignal<[String: String]>,
        swipeTooCurvy: DetectionSignal<[String: String]>,
        motionTooStill: DetectionSignal<[String: String]>,
        touchMotionWeakCoupling: DetectionSignal<[String: String]>
    ) {
        self.touchSpreadLow = touchSpreadLow
        self.touchSpreadHigh = touchSpreadHigh
        self.touchIntervalTooRegular = touchIntervalTooRegular
        self.touchIntervalTooChaotic = touchIntervalTooChaotic
        self.swipeTooLinear = swipeTooLinear
        self.swipeTooCurvy = swipeTooCurvy
        self.motionTooStill = motionTooStill
        self.touchMotionWeakCoupling = touchMotionWeakCoupling
    }
}

public struct CloudPhoneTimeSignals: Codable, Sendable {
    public var highVolume24h: DetectionSignal<[String: String]>
    public var wideHourCoverage24h: DetectionSignal<[String: String]>
    public var nightActivityHigh24h: DetectionSignal<[String: String]>
    public var highFrequency24h: DetectionSignal<[String: String]>

    public init(
        highVolume24h: DetectionSignal<[String: String]>,
        wideHourCoverage24h: DetectionSignal<[String: String]>,
        nightActivityHigh24h: DetectionSignal<[String: String]>,
        highFrequency24h: DetectionSignal<[String: String]>
    ) {
        self.highVolume24h = highVolume24h
        self.wideHourCoverage24h = wideHourCoverage24h
        self.nightActivityHigh24h = nightActivityHigh24h
        self.highFrequency24h = highFrequency24h
    }
}

enum CloudPhoneLocalSignalsBuilder {
    static func build(device: DeviceFingerprint, behavior: BehaviorSignals, timePattern: TimePattern?) -> CloudPhoneLocalSignals {
        let deviceSignals = CloudPhoneDeviceSignals(
            isSimulator: DetectionSignal(
                detected: device.isSimulator,
                method: "targetEnvironment",
                evidence: compactMap([
                    "is_simulator": "\(device.isSimulator)",
                    "hw.machine": device.hardwareMachine,
                ]),
                confidence: .strong
            ),
            oldDeviceModel: oldDeviceModelSignal(machine: device.hardwareMachine)
        )

        let behaviorSignals = CloudPhoneBehaviorSignals(
            touchSpreadLow: touchSpreadLowSignal(behavior: behavior),
            touchSpreadHigh: touchSpreadHighSignal(behavior: behavior),
            touchIntervalTooRegular: touchIntervalTooRegularSignal(behavior: behavior),
            touchIntervalTooChaotic: touchIntervalTooChaoticSignal(behavior: behavior),
            swipeTooLinear: swipeTooLinearSignal(behavior: behavior),
            swipeTooCurvy: swipeTooCurvySignal(behavior: behavior),
            motionTooStill: motionTooStillSignal(behavior: behavior),
            touchMotionWeakCoupling: touchMotionWeakCouplingSignal(behavior: behavior)
        )

        let timeSignals = CloudPhoneTimeSignals(
            highVolume24h: highVolume24hSignal(pattern: timePattern),
            wideHourCoverage24h: wideHourCoverage24hSignal(pattern: timePattern),
            nightActivityHigh24h: nightActivityHigh24hSignal(pattern: timePattern),
            highFrequency24h: highFrequency24hSignal(pattern: timePattern)
        )

        return CloudPhoneLocalSignals(device: deviceSignals, behavior: behaviorSignals, time: timeSignals)
    }

    private static func oldDeviceModelSignal(machine: String?) -> DetectionSignal<[String: String]>? {
        guard let machine else { return nil }
        guard let family = parseIPhoneFamily(machine) else {
            return DetectionSignal(
                detected: false,
                method: "hw.machine_family",
                evidence: ["machine": machine, "note": "unparsed"],
                confidence: .weak
            )
        }

        // Rough heuristic for cloud phone device farms: older families are more common.
        // iPhone10.* == iPhone X/8 era; treat <= 11 as "old" for now.
        let detected = family <= 11
        return DetectionSignal(
            detected: detected,
            method: "hw.machine_family",
            evidence: [
                "machine": machine,
                "family": "\(family)",
                "threshold_family_le": "11",
            ],
            confidence: detected ? .medium : .weak
        )
    }

    private static func parseIPhoneFamily(_ machine: String) -> Int? {
        guard machine.hasPrefix("iPhone") else { return nil }
        let rest = machine.dropFirst("iPhone".count)
        var digits = ""
        for ch in rest {
            if ch.isNumber { digits.append(ch) } else { break }
        }
        return Int(digits)
    }

    private static func touchSpreadLowSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minTaps = 6
        let threshold = 2.0
        let spread = behavior.touch.coordinateSpread
        let detected = (spread ?? .greatestFiniteMagnitude) < threshold && behavior.touch.tapCount >= minTaps
        return DetectionSignal(
            detected: detected,
            method: "touch_spread",
            evidence: compactMap([
                "spread": spread.map(format),
                "tapCount": "\(behavior.touch.tapCount)",
                "threshold_lt": "\(threshold)",
                "minTapCount": "\(minTaps)",
            ]),
            confidence: .medium
        )
    }

    private static func touchSpreadHighSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minTaps = 6
        let threshold = 10.0
        let spread = behavior.touch.coordinateSpread
        let detected = (spread ?? 0) > threshold && behavior.touch.tapCount >= minTaps
        return DetectionSignal(
            detected: detected,
            method: "touch_spread",
            evidence: compactMap([
                "spread": spread.map(format),
                "tapCount": "\(behavior.touch.tapCount)",
                "threshold_gt": "\(threshold)",
                "minTapCount": "\(minTaps)",
            ]),
            confidence: .weak
        )
    }

    private static func touchIntervalTooRegularSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minTaps = 6
        let threshold = 0.2
        let cv = behavior.touch.intervalCV
        let detected = (cv ?? .greatestFiniteMagnitude) < threshold && behavior.touch.tapCount >= minTaps
        return DetectionSignal(
            detected: detected,
            method: "tap_interval_cv",
            evidence: compactMap([
                "cv": cv.map(format),
                "tapCount": "\(behavior.touch.tapCount)",
                "threshold_lt": "\(threshold)",
                "minTapCount": "\(minTaps)",
            ]),
            confidence: .medium
        )
    }

    private static func touchIntervalTooChaoticSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minTaps = 6
        let threshold = 0.6
        let cv = behavior.touch.intervalCV
        let detected = (cv ?? 0) > threshold && behavior.touch.tapCount >= minTaps
        return DetectionSignal(
            detected: detected,
            method: "tap_interval_cv",
            evidence: compactMap([
                "cv": cv.map(format),
                "tapCount": "\(behavior.touch.tapCount)",
                "threshold_gt": "\(threshold)",
                "minTapCount": "\(minTaps)",
            ]),
            confidence: .weak
        )
    }

    private static func swipeTooLinearSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minSwipes = 3
        let threshold = 0.98
        let lin = behavior.touch.averageLinearity
        let detected = (lin ?? 0) > threshold && behavior.touch.swipeCount >= minSwipes
        return DetectionSignal(
            detected: detected,
            method: "swipe_linearity",
            evidence: compactMap([
                "avgLinearity": lin.map(format),
                "swipeCount": "\(behavior.touch.swipeCount)",
                "threshold_gt": "\(threshold)",
                "minSwipeCount": "\(minSwipes)",
            ]),
            confidence: .medium
        )
    }

    private static func swipeTooCurvySignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minSwipes = 3
        let threshold = 0.90
        let lin = behavior.touch.averageLinearity
        let detected = (lin ?? 1) < threshold && behavior.touch.swipeCount >= minSwipes
        return DetectionSignal(
            detected: detected,
            method: "swipe_linearity",
            evidence: compactMap([
                "avgLinearity": lin.map(format),
                "swipeCount": "\(behavior.touch.swipeCount)",
                "threshold_lt": "\(threshold)",
                "minSwipeCount": "\(minSwipes)",
            ]),
            confidence: .weak
        )
    }

    private static func motionTooStillSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minActions = 10
        let threshold = 0.98
        let still = behavior.motion.stillnessRatio
        let actions = behavior.actionCount
        let detected = (still ?? 0) > threshold && actions >= minActions
        return DetectionSignal(
            detected: detected,
            method: "motion_stillness",
            evidence: compactMap([
                "stillnessRatio": still.map(format),
                "actionCount": "\(actions)",
                "threshold_gt": "\(threshold)",
                "minActionCount": "\(minActions)",
            ]),
            confidence: .medium
        )
    }

    private static func touchMotionWeakCouplingSignal(behavior: BehaviorSignals) -> DetectionSignal<[String: String]> {
        let minActions = 10
        let minStillness = 0.95
        let threshold = 0.10
        let corr = behavior.touchMotionCorrelation
        let still = behavior.motion.stillnessRatio
        let actions = behavior.actionCount
        let detected =
            (corr ?? .greatestFiniteMagnitude) < threshold &&
            actions >= minActions &&
            (still ?? 0) > minStillness
        return DetectionSignal(
            detected: detected,
            method: "touch_motion_correlation",
            evidence: compactMap([
                "corr": corr.map(format),
                "stillnessRatio": still.map(format),
                "actionCount": "\(actions)",
                "threshold_lt": "\(threshold)",
                "minStillness_gt": "\(minStillness)",
                "minActionCount": "\(minActions)",
            ]),
            confidence: .medium
        )
    }

    private static func highVolume24hSignal(pattern: TimePattern?) -> DetectionSignal<[String: String]> {
        guard let pattern else {
            return DetectionSignal(detected: false, method: "history_24h", evidence: ["note": "no_history"], confidence: .weak)
        }
        let high = 500
        let medium = 200
        let detected = pattern.events24h >= medium
        let confidence: SignalConfidence = pattern.events24h >= high ? .strong : (detected ? .medium : .weak)
        return DetectionSignal(
            detected: detected,
            method: "history_24h",
            evidence: [
                "events24h": "\(pattern.events24h)",
                "threshold_medium_ge": "\(medium)",
                "threshold_high_ge": "\(high)",
            ],
            confidence: confidence
        )
    }

    private static func wideHourCoverage24hSignal(pattern: TimePattern?) -> DetectionSignal<[String: String]> {
        guard let pattern else {
            return DetectionSignal(detected: false, method: "history_24h", evidence: ["note": "no_history"], confidence: .weak)
        }
        let minEvents = 80
        let threshold = 18
        let detected = pattern.uniqueHours24h >= threshold && pattern.events24h >= minEvents
        return DetectionSignal(
            detected: detected,
            method: "history_24h",
            evidence: [
                "uniqueHours24h": "\(pattern.uniqueHours24h)",
                "events24h": "\(pattern.events24h)",
                "threshold_uniqueHours_ge": "\(threshold)",
                "minEvents_ge": "\(minEvents)",
            ],
            confidence: detected ? .medium : .weak
        )
    }

    private static func nightActivityHigh24hSignal(pattern: TimePattern?) -> DetectionSignal<[String: String]> {
        guard let pattern else {
            return DetectionSignal(detected: false, method: "history_24h", evidence: ["note": "no_history"], confidence: .weak)
        }
        let minEvents = 80
        let threshold = 0.4
        let night = pattern.nightRatio24h
        let detected = (night ?? 0) > threshold && pattern.events24h >= minEvents
        return DetectionSignal(
            detected: detected,
            method: "history_24h",
            evidence: compactMap([
                "nightRatio24h": night.map(format),
                "events24h": "\(pattern.events24h)",
                "threshold_gt": "\(threshold)",
                "minEvents_ge": "\(minEvents)",
            ]),
            confidence: detected ? .medium : .weak
        )
    }

    private static func highFrequency24hSignal(pattern: TimePattern?) -> DetectionSignal<[String: String]> {
        guard let pattern else {
            return DetectionSignal(detected: false, method: "history_24h", evidence: ["note": "no_history"], confidence: .weak)
        }
        let minEvents = 80
        let threshold = 8.0
        let avg = pattern.averageIntervalSeconds24h
        let detected = (avg ?? .greatestFiniteMagnitude) < threshold && pattern.events24h >= minEvents
        return DetectionSignal(
            detected: detected,
            method: "history_24h",
            evidence: compactMap([
                "averageIntervalSeconds24h": avg.map(format),
                "events24h": "\(pattern.events24h)",
                "threshold_lt": "\(threshold)",
                "minEvents_ge": "\(minEvents)",
            ]),
            confidence: detected ? .medium : .weak
        )
    }

    private static func compactMap(_ kv: [String: String?]) -> [String: String] {
        var out: [String: String] = [:]
        for (k, v) in kv {
            guard let v else { continue }
            out[k] = v
        }
        return out
    }

    private static func format(_ d: Double) -> String {
        if d.isNaN || d.isInfinite { return "\(d)" }
        return String(format: "%.4f", d)
    }
}

