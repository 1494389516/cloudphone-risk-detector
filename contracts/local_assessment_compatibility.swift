import CloudPhoneRiskKit
import Foundation

// External consumers must still be able to implement only the legacy requirement.
struct LegacyEngine: DecisionEngine {
    let result: RiskVerdict
    var supportedFeatures: [String] { ["fixture"] }
    func reset() async {}
    func decide(snapshot: RiskSnapshot, config: DecisionConfig) async -> RiskVerdict { result }
}

struct NativeEngine: LocalAssessmentEngine {
    let result: LocalAssessment
    var supportedFeatures: [String] { ["fixture"] }
    func reset() async {}
    func assess(snapshot: RiskSnapshot, config: LocalAssessmentConfig) async -> LocalAssessment { result }
}

// Type-check both existential dispatch paths without running device probes in CI.
func checkDispatch(snapshot: RiskSnapshot, result: LocalAssessment) async {
    let legacy: any DecisionEngine = LegacyEngine(result: result)
    let migrated: any LocalAssessmentEngine = legacy
    let old = await legacy.decide(snapshot: snapshot, config: DecisionConfig())
    let new = await migrated.assess(snapshot: snapshot, config: LocalAssessmentConfig())
    precondition(old.requestId == new.requestId)
    let native: any LocalAssessmentEngine = NativeEngine(result: result)
    let nativeResult = await native.assess(snapshot: snapshot, config: LocalAssessmentConfig())
    precondition(nativeResult.requestId == result.requestId)
    let adapter: LocalAssessmentAdapter = DecisionEngineAdapter.default()
    _ = adapter as any LocalAssessmentEngine
}

@main
struct CompatibilityCheck {
    static func main() throws {
        let states = [
            #"{"t":"hard","d":true}"#,
            #"{"t":"soft","c":0.75}"#,
            #"{"t":"serverRequired"}"#,
            #"{"t":"unavailable"}"#,
            #"{"t":"tampered"}"#,
        ]
        for state in states {
            // Pre-migration compact keys, enum raw values, and Foundation date format.
            let wire = """
            {"s":72,"il":"high","ia":2,"c":0.8,"pr":["fixture"],
             "sg":[{"i":"fixture","ca":"network","s":12,"ev":{"key":"value"},
                    "st":\(state),"l":2,"wh":4}],
             "sc":1,"cd":"AQID","mv":"v1","dm":{"origin":"fixture"},"ts":0,"ri":"fixed"}
            """.data(using: .utf8)!
            let result = try JSONDecoder().decode(LocalAssessment.self, from: wire)
            let legacy: RiskVerdict = result
            let protocolLegacy: ProtocolRiskVerdict = legacy
            let encoded = try JSONEncoder().encode(protocolLegacy)
            let before = try JSONSerialization.jsonObject(with: wire) as! NSDictionary
            let after = try JSONSerialization.jsonObject(with: encoded) as! NSDictionary
            precondition(before == after, "Legacy wire representation changed")
            precondition(result.internalAction == .stepUpAuth && result.action == .challenge)
            precondition(result.requestId == "fixed" && result.timestamp == Date(timeIntervalSinceReferenceDate: 0))
        }
        print("Local assessment compatibility: PASS (5 wire states; external API compilation)")
    }
}
