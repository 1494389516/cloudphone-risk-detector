import Foundation
import MachOKit
import XCTest

final class PassOrderingTests: XCTestCase {
    private final class StubPass: ArmorPass {
        let name: String

        init(_ name: String) {
            self.name = name
        }

        func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
            PassResult(passName: name, itemsProcessed: 0, bytesModified: 0, details: [])
        }
    }

    func testSecurityDependenciesOverrideRegistrationOrder() throws {
        let registered: [(Int, ArmorPass)] = [
            (3, StubPass("data")),
            (4, StubPass("anchor")),
            (11, StubPass("header")),
            (6, StubPass("symbols")),
            (13, StubPass("vmp")),
            (9, StubPass("cff")),
            (8, StubPass("substitution")),
            (12, StubPass("text-encryption")),
            (6, StubPass("exports")),
            (1, StubPass("strings")),
            (2, StubPass("metadata")),
            (5, StubPass("structure")),
            (7, StubPass("anti-debug")),
            (10, StubPass("imports")),
        ]

        let ordered = try resolveArmorPassOrder(registered)
        let names = ordered.map { $0.1.name }

        func assertBefore(_ lhs: String, _ rhs: String, file: StaticString = #filePath, line: UInt = #line) {
            XCTAssertLessThan(
                names.firstIndex(of: lhs)!,
                names.firstIndex(of: rhs)!,
                "\(lhs) must run before \(rhs)",
                file: file,
                line: line
            )
        }

        assertBefore("substitution", "cff")
        assertBefore("cff", "vmp")
        assertBefore("vmp", "anchor")
        assertBefore("anchor", "data")
        assertBefore("anchor", "text-encryption")
        assertBefore("text-encryption", "symbols")
        assertBefore("text-encryption", "exports")
        assertBefore("symbols", "header")
        assertBefore("exports", "header")
    }
}
