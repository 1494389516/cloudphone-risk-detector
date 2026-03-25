import Foundation
import XCTest
@testable import CloudPhoneRiskKit

final class RiskTypesTests: XCTestCase {

    /// ObjC runtime names from `@objc(CPR_…)` must stay stable for mixed ObjC / class-list tooling.
    func testPublicObjCRuntimeClassNames() {
        let pairs: [(AnyClass, String)] = [
            (CPRiskStore.self, "CPR_RiskStore"),
            (CPRiskKit.self, "CPR_RiskKit"),
            (CPRiskReport.self, "CPR_RiskReport"),
            (CPRiskSignal.self, "CPR_RiskSignal"),
            (CPRiskConfig.self, "CPR_RiskConfig"),
            (CertificatePinningSessionDelegate.self, "CPR_PinSessionDelegate"),
        ]
        for (cls, expected) in pairs {
            XCTAssertEqual(NSStringFromClass(cls), expected)
            XCTAssertTrue(cls === NSClassFromString(expected), "NSClassFromString(\(expected)) should resolve to \(cls)")
        }
    }

    // MARK: - RiskScenario

    func testRiskScenarioIdentifiers() {
        XCTAssertEqual(RiskScenario.login.identifier, "login")
        XCTAssertEqual(RiskScenario.payment.identifier, "payment")
        XCTAssertEqual(RiskScenario.register.identifier, "register")
        XCTAssertEqual(RiskScenario.query.identifier, "query")
        XCTAssertEqual(RiskScenario.default.identifier, "default")
        XCTAssertEqual(RiskScenario.accountChange.identifier, "account_change")
        XCTAssertEqual(RiskScenario.sensitiveAction.identifier, "sensitive_action")
        XCTAssertEqual(RiskScenario.apiAccess.identifier, "api_access")
    }

    func testRiskScenarioAllCases() {
        XCTAssertEqual(RiskScenario.allCases.count, 8)
    }

    func testRiskScenarioRawStringValueMatchesIdentifier() {
        for scenario in RiskScenario.allCases {
            XCTAssertEqual(scenario.rawStringValue, scenario.identifier)
        }
    }

    // MARK: - InternalRiskLevel

    func testInternalRiskLevelFromScore() {
        XCTAssertEqual(InternalRiskLevel.from(score: 0), .low)
        XCTAssertEqual(InternalRiskLevel.from(score: 15), .low)
        XCTAssertEqual(InternalRiskLevel.from(score: 29.9), .low)
        XCTAssertEqual(InternalRiskLevel.from(score: 30), .medium)
        XCTAssertEqual(InternalRiskLevel.from(score: 54.9), .medium)
        XCTAssertEqual(InternalRiskLevel.from(score: 55), .high)
        XCTAssertEqual(InternalRiskLevel.from(score: 79.9), .high)
        XCTAssertEqual(InternalRiskLevel.from(score: 80), .critical)
        XCTAssertEqual(InternalRiskLevel.from(score: 100), .critical)
    }

    func testInternalRiskLevelNumericOrdering() {
        XCTAssertLessThan(InternalRiskLevel.low.numericValue, InternalRiskLevel.medium.numericValue)
        XCTAssertLessThan(InternalRiskLevel.medium.numericValue, InternalRiskLevel.high.numericValue)
        XCTAssertLessThan(InternalRiskLevel.high.numericValue, InternalRiskLevel.critical.numericValue)
    }

    func testInternalRiskLevelToPublicMapping() {
        XCTAssertEqual(InternalRiskLevel.low.toPublicRiskLevel(), .low)
        XCTAssertEqual(InternalRiskLevel.medium.toPublicRiskLevel(), .medium)
        XCTAssertEqual(InternalRiskLevel.high.toPublicRiskLevel(), .high)
        XCTAssertEqual(InternalRiskLevel.critical.toPublicRiskLevel(), .high)
    }

    // MARK: - RiskAction

    func testRiskActionSeverityOrdering() {
        XCTAssertLessThan(RiskAction.allow.severity, RiskAction.challenge.severity)
        XCTAssertLessThan(RiskAction.challenge.severity, RiskAction.stepUpAuth.severity)
        XCTAssertLessThan(RiskAction.stepUpAuth.severity, RiskAction.block.severity)
    }

    func testRiskActionToPublicMapping() {
        XCTAssertEqual(RiskAction.allow.toPublicRiskAction(), .allow)
        XCTAssertEqual(RiskAction.challenge.toPublicRiskAction(), .challenge)
        XCTAssertEqual(RiskAction.stepUpAuth.toPublicRiskAction(), .challenge)
        XCTAssertEqual(RiskAction.block.toPublicRiskAction(), .block)
    }

    func testRiskActionAllCases() {
        XCTAssertEqual(RiskAction.allCases.count, 4)
    }

    // MARK: - PublicRiskLevel

    func testPublicRiskLevelAllCases() {
        XCTAssertEqual(PublicRiskLevel.allCases.count, 3)
    }

    // MARK: - PublicRiskAction

    func testPublicRiskActionAllCases() {
        XCTAssertEqual(PublicRiskAction.allCases.count, 3)
    }
}
