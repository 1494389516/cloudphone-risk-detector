import Foundation
import XCTest
@testable import VMProtector

final class VMPolicyStrictTests: XCTestCase {
    func testShippedPoliciesPreserveCompatibilitySemanticsAndFullGuard() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        for name in ["vmp_policy.yaml", "vmp_policy_appstore_safe.yaml"] {
            let text = try String(contentsOf: root.appendingPathComponent("RiskDetectorApp/" + name))
            let policy = try VMPolicyConfig.parseStrict(text)
            XCTAssertEqual(policy, VMPolicyConfig.parse(text))
            XCTAssertThrowsError(try policy.validateNativeReplacementSupport())
        }
    }

    func testRejectsInvalidPolicies() {
        let invalid = [
            "version: 2\nfunctions:", "version: typo\nfunctions:", "functions:",
            "version: 1\nversion: 1\nfunctions:", "version: 1\nunknown:\nfunctions:",
            "version: 1\nfunctions:\n  full:\n    - f\n  partial:\n    - f",
            "version: 1\nfunctions:\n  full:\n    - f\n    - f",
            "version: 1\nfunctions:\n  other:", "version: 1\nfunctions: []",
            "version: 1\nfunctions:\n  full:\n    - 'f'",
            "version: 1\nfunctions:\n  full:\n   - f",
            "version: 1\nfunctions:\nanti_analysis:\n  handler_duplication: yes",
            "version: 1\nfunctions:\nhardening:\n  synthetic_branch_ind_rate: NaN",
            "version: 1\nfunctions:\nhardening:\n  synthetic_branch_ind_rate: inf",
            "version: 1\nfunctions:\nhardening:\n  synthetic_branch_ind_rate: 1.1",
            "version: 1\nfunctions:\nhardening:\n  synthetic_branch_ind_forward_span: 17",
            "version: 1\nfunctions:\nhardening:\n  synthetic_branch_ind_budget: -1",
            "version: 1\nfunctions:\nhardening:\n  interpreter_cff_tier: max",
            "version: 1\nfunctions:\nhardening:\n  synthetic_branch_ind_mode: invalid",
            "version: 1\nfunctions:\nhardening:\n  typo: true",
            "version: 1\nfunctions:\nhardening:\n  fuse_add_rol_acc: true\n  fuse_add_rol_acc: false"
        ]
        for text in invalid {
            XCTAssertThrowsError(try VMPolicyConfig.parseStrict(text), text)
        }
    }

    func testValidPartialStillMeansMetadataOnly() throws {
        let policy = try VMPolicyConfig.parseStrict("version: 1\nfunctions:\n  partial:\n    - f")
        XCTAssertEqual(policy.tier(for: "f"), .partial)
        XCTAssertNoThrow(try policy.validateNativeReplacementSupport())
    }
}
