import Darwin
import Foundation

/// Audits task-port rights and exception-port ownership anomalies.
///
/// Focus:
/// - Exception ports where current task only holds send right (receiver likely external debugger/injector)
/// - Abnormal port-right distribution in port namespace
struct TaskPortAuditDetector: Detector {
    private typealias BootstrapLookupFn = @convention(c) (
        mach_port_t,
        UnsafePointer<CChar>,
        UnsafeMutablePointer<mach_port_t>?
    ) -> kern_return_t

    private static let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)

    private enum Keys {
        static let taskPortPrefix = ObfuscatedConstants.keywordTaskPort
        static let unavailableSimulator = StringDeobfuscator.base64Decode("dGFza19wb3J0OnVuYXZhaWxhYmxlX3NpbXVsYXRvcg==")
        static let clean = StringDeobfuscator.base64Decode("dGFza19wb3J0OmNsZWFu")
        static let taskForPidUnexpectedSuccess = StringDeobfuscator.base64Decode("dGFza19wb3J0OnRhc2tfZm9yX3BpZF91bmV4cGVjdGVkX3N1Y2Nlc3M=")
        static let debugserverServiceNames: [String] = [
            StringDeobfuscator.base64Decode("Y29tLmFwcGxlLmRlYnVnc2VydmVy"),
            StringDeobfuscator.base64Decode("Y29tLmFwcGxlLmR0LmRlYnVnc2VydmVy"),
            StringDeobfuscator.base64Decode("Y29tLmFwcGxlLmRlYnVnc2VydmVyLkRWVFNlY3VyZVNvY2tldFByb3h5"),
        ]
    }

    struct LLDBAuditHints {
        let sendOnlyExceptionPortCount: Int
        let taskForPidUnexpectedSuccess: Bool
        let debugserverMachServiceHits: Int

        static let empty = LLDBAuditHints(
            sendOnlyExceptionPortCount: 0,
            taskForPidUnexpectedSuccess: false,
            debugserverMachServiceHits: 0
        )
    }

    struct Snapshot {
        let totalPortNames: Int
        let sendRightCount: Int
        let receiveRightCount: Int
        let sendOnceRightCount: Int
        let deadNameCount: Int
        let sendOnlyExceptionPortCount: Int
        let unknownExceptionPortCount: Int
        let taskForPidUnexpectedSuccess: Bool
        let debugserverServiceHits: [String]
    }

    struct Assessment {
        let score: Double
        let methods: [String]
        let sendOnlyExceptionPortCount: Int
    }

    func detect() throws -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: [Keys.unavailableSimulator])
#else
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        return DetectorResult(score: assessment.score, methods: assessment.methods)
#endif
    }

    func assess(snapshot: Snapshot) -> Assessment {
        var score: Double = 0
        var methods: [String] = []

        if snapshot.sendOnlyExceptionPortCount > 0 {
            score += min(40 + Double(snapshot.sendOnlyExceptionPortCount - 1) * 12, 75)
            methods.append("\(Keys.taskPortPrefix):exception_send_only:\(snapshot.sendOnlyExceptionPortCount)")
        }

        if snapshot.unknownExceptionPortCount > 0 {
            score += min(8 + Double(snapshot.unknownExceptionPortCount) * 4, 20)
            methods.append("\(Keys.taskPortPrefix):exception_unknown_rights:\(snapshot.unknownExceptionPortCount)")
        }

        if snapshot.totalPortNames > 2048 {
            score += 10
            methods.append("\(Keys.taskPortPrefix):name_count_anomaly:\(snapshot.totalPortNames)")
        }

        let ratio = snapshot.receiveRightCount == 0
            ? Double(snapshot.sendRightCount)
            : Double(snapshot.sendRightCount) / Double(snapshot.receiveRightCount)
        if snapshot.sendRightCount > 1024 && ratio > 18 {
            score += 15
            methods.append("\(Keys.taskPortPrefix):send_receive_ratio:\(String(format: "%.2f", ratio))")
        }

        if snapshot.deadNameCount > 1500 {
            score += 6
            methods.append("\(Keys.taskPortPrefix):dead_name_burst:\(snapshot.deadNameCount)")
        }

        if snapshot.taskForPidUnexpectedSuccess {
            score += 55
            methods.append(Keys.taskForPidUnexpectedSuccess)
        }

        if !snapshot.debugserverServiceHits.isEmpty {
            let hitCount = snapshot.debugserverServiceHits.count
            score += min(28 + Double(hitCount - 1) * 9, 52)
            methods.append("\(Keys.taskPortPrefix):debugserver_mach_service:\(hitCount)")
        }

        if snapshot.taskForPidUnexpectedSuccess, !snapshot.debugserverServiceHits.isEmpty {
            score += 8
            methods.append("\(Keys.taskPortPrefix):debugserver_tfpid_correlation")
        }

        if snapshot.sendOnceRightCount > 800 {
            score += 5
            methods.append("\(Keys.taskPortPrefix):send_once_burst:\(snapshot.sendOnceRightCount)")
        }

        let finalScore = min(score, 90)
        let finalMethods = finalScore > 0 ? methods : [Keys.clean]
        return Assessment(
            score: finalScore,
            methods: finalMethods,
            sendOnlyExceptionPortCount: snapshot.sendOnlyExceptionPortCount
        )
    }

    private func collectSnapshot() -> Snapshot {
        var totalPortNames = 0
        var sendRightCount = 0
        var receiveRightCount = 0
        var sendOnceRightCount = 0
        var deadNameCount = 0

        var names: mach_port_name_array_t?
        var namesCount: mach_msg_type_number_t = 0
        var types: mach_port_type_array_t?
        var typesCount: mach_msg_type_number_t = 0

        let namesResult = mach_port_names(mach_task_self_, &names, &namesCount, &types, &typesCount)
        if namesResult == KERN_SUCCESS, let names {
            let count = Int(namesCount)
            totalPortNames = count

            for index in 0..<count {
                let portName = names[index]
                if hasRight(portName, MACH_PORT_RIGHT_SEND) {
                    sendRightCount += 1
                }
                if hasRight(portName, MACH_PORT_RIGHT_RECEIVE) {
                    receiveRightCount += 1
                }
                if hasRight(portName, MACH_PORT_RIGHT_SEND_ONCE) {
                    sendOnceRightCount += 1
                }
                if hasRight(portName, MACH_PORT_RIGHT_DEAD_NAME) {
                    deadNameCount += 1
                }
            }

            vm_deallocate(
                mach_task_self_,
                vm_address_t(UInt(bitPattern: names)),
                vm_size_t(Int(namesCount) * MemoryLayout<mach_port_name_t>.size)
            )
            if let types {
                vm_deallocate(
                    mach_task_self_,
                    vm_address_t(UInt(bitPattern: types)),
                    vm_size_t(Int(typesCount) * MemoryLayout<mach_port_type_t>.size)
                )
            }
        }

        var sendOnlyExceptionPortCount = 0
        var unknownExceptionPortCount = 0

        var masks = [exception_mask_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var ports = [mach_port_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var behaviors = [exception_behavior_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var flavors = [thread_state_flavor_t](repeating: 0, count: Int(EXC_TYPES_COUNT))
        var count = mach_msg_type_number_t(EXC_TYPES_COUNT)
        let mask = EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BREAKPOINT | EXC_MASK_SOFTWARE

        let exceptionResult = task_get_exception_ports(
            mach_task_self_,
            exception_mask_t(mask),
            &masks,
            &count,
            &ports,
            &behaviors,
            &flavors
        )

        if exceptionResult == KERN_SUCCESS {
            for index in 0..<Int(count) {
                let port = ports[index]
                if port == MACH_PORT_NULL || port == mach_port_t(bitPattern: -1) {
                    continue
                }

                let hasSend = hasRight(port, MACH_PORT_RIGHT_SEND)
                let hasReceive = hasRight(port, MACH_PORT_RIGHT_RECEIVE)

                if !hasSend && !hasReceive {
                    unknownExceptionPortCount += 1
                    continue
                }
                if hasSend && !hasReceive {
                    sendOnlyExceptionPortCount += 1
                }
            }
        }

        var taskForPidUnexpectedSuccess = false
        do {
            let nullPort = mach_port_name_t(MACH_PORT_NULL)
            var foreignTask: mach_port_name_t = nullPort
            let rc = DynamicSymbolResolver.taskForPid(mach_task_self_, 1, &foreignTask)
            if rc == KERN_SUCCESS, foreignTask != nullPort {
                taskForPidUnexpectedSuccess = true
                mach_port_deallocate(mach_task_self_, foreignTask)
            }
        }

        let debugserverServiceHits = probeDebugserverMachServices()

        return Snapshot(
            totalPortNames: totalPortNames,
            sendRightCount: sendRightCount,
            receiveRightCount: receiveRightCount,
            sendOnceRightCount: sendOnceRightCount,
            deadNameCount: deadNameCount,
            sendOnlyExceptionPortCount: sendOnlyExceptionPortCount,
            unknownExceptionPortCount: unknownExceptionPortCount,
            taskForPidUnexpectedSuccess: taskForPidUnexpectedSuccess,
            debugserverServiceHits: debugserverServiceHits
        )
    }

    func collectLLDBAuditHints() -> LLDBAuditHints {
#if targetEnvironment(simulator)
        return .empty
#else
        let snapshot = collectSnapshot()
        return LLDBAuditHints(
            sendOnlyExceptionPortCount: snapshot.sendOnlyExceptionPortCount,
            taskForPidUnexpectedSuccess: snapshot.taskForPidUnexpectedSuccess,
            debugserverMachServiceHits: snapshot.debugserverServiceHits.count
        )
#endif
    }

    private func probeDebugserverMachServices() -> [String] {
        var bootstrapPort: mach_port_t = mach_port_t(MACH_PORT_NULL)
        let bootstrapResult = task_get_special_port(
            mach_task_self_,
            Int32(TASK_BOOTSTRAP_PORT),
            &bootstrapPort
        )
        guard bootstrapResult == KERN_SUCCESS, bootstrapPort != mach_port_t(MACH_PORT_NULL) else {
            return []
        }
        defer {
            mach_port_deallocate(mach_task_self_, bootstrapPort)
        }

        var hits: [String] = []
        for serviceName in Keys.debugserverServiceNames {
            var servicePort: mach_port_t = mach_port_t(MACH_PORT_NULL)
            let lookupResult = Self.bootstrapLookUp(
                bootstrapPort: bootstrapPort,
                serviceName: serviceName,
                servicePort: &servicePort
            )

            if lookupResult == KERN_SUCCESS, servicePort != mach_port_t(MACH_PORT_NULL) {
                hits.append(serviceName)
                mach_port_deallocate(mach_task_self_, servicePort)
            }
        }
        return hits
    }

    private static func bootstrapLookUp(
        bootstrapPort: mach_port_t,
        serviceName: String,
        servicePort: UnsafeMutablePointer<mach_port_t>?
    ) -> kern_return_t {
        guard let symbol = "bootstrap_look_up".withCString({ cString in
            dlsym(rtldDefault, cString)
        }) else {
            return kern_return_t(KERN_FAILURE)
        }

        let function = unsafeBitCast(symbol, to: BootstrapLookupFn.self)
        return serviceName.withCString { cString in
            function(bootstrapPort, cString, servicePort)
        }
    }

    private func hasRight(_ port: mach_port_name_t, _ right: mach_port_right_t) -> Bool {
        var refs: mach_port_urefs_t = 0
        let result = mach_port_get_refs(mach_task_self_, port, right, &refs)
        return result == KERN_SUCCESS && refs > 0
    }
}

extension TaskPortAuditDetector {
    func asSignals() -> [RiskSignal] {
        let snapshot = collectSnapshot()
        let assessment = assess(snapshot: snapshot)
        guard assessment.score > 0 else { return [] }

        var signals: [RiskSignal] = []
        if assessment.sendOnlyExceptionPortCount > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.taskPortExceptionHijack,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(58 + Double(assessment.sendOnlyExceptionPortCount) * 8, 85),
                    evidence: [
                        "send_only_exception_ports": "\(assessment.sendOnlyExceptionPortCount)",
                        "total_ports": "\(snapshot.totalPortNames)",
                        "\(ObfuscatedConstants.keywordTaskForPid)_unexpected_success": snapshot.taskForPidUnexpectedSuccess ? "1" : "0",
                        "debugserver_mach_service_hits": "\(snapshot.debugserverServiceHits.count)",
                    ],
                    state: .tampered,
                    layer: 1,
                    weightHint: 93
                )
            )
        }

        let nonCriticalScore = assessment.sendOnlyExceptionPortCount > 0 ? max(0, assessment.score - 35) : assessment.score
        if nonCriticalScore > 0 {
            signals.append(
                RiskSignal(
                    id: SignalID.taskPortRightsAnomaly,
                    category: ObfuscatedConstants.categoryAntiTamper,
                    score: min(nonCriticalScore, 36),
                    evidence: [
                        "send_rights": "\(snapshot.sendRightCount)",
                        "receive_rights": "\(snapshot.receiveRightCount)",
                        "send_once_rights": "\(snapshot.sendOnceRightCount)",
                        "dead_name_count": "\(snapshot.deadNameCount)",
                        "\(ObfuscatedConstants.keywordTaskForPid)_unexpected_success": snapshot.taskForPidUnexpectedSuccess ? "1" : "0",
                        "debugserver_mach_services": snapshot.debugserverServiceHits.prefix(4).joined(separator: ","),
                        "methods": assessment.methods.joined(separator: ","),
                    ],
                    state: .soft(confidence: 0.72),
                    layer: 2,
                    weightHint: 62
                )
            )
        }

        return signals
    }
}
