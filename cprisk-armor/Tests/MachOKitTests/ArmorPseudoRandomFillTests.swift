import Darwin
import XCTest
import MachOKit

final class ArmorPseudoRandomFillTests: XCTestCase {
    func testDeterministicForSameMaterial() {
        let m = Data("fixture-a".utf8)
        let a = ArmorPseudoRandomFill.bytes(count: 500, material: m)
        let b = ArmorPseudoRandomFill.bytes(count: 500, material: m)
        XCTAssertEqual(a, b)
    }

    func testDiffersAcrossMaterials() {
        let a = ArmorPseudoRandomFill.bytes(count: 256, material: Data("x".utf8))
        let b = ArmorPseudoRandomFill.bytes(count: 256, material: Data("y".utf8))
        XCTAssertNotEqual(a, b)
    }

    /// Shannon entropy (bits/byte) — high-entropy blob should be near 8 for long outputs.
    func testShannonEntropyReasonable() {
        let buf = ArmorPseudoRandomFill.bytes(count: 16_384, material: Data("entropy-check".utf8))
        var counts = [Int](repeating: 0, count: 256)
        for b in buf {
            counts[Int(b)] += 1
        }
        var h = 0.0
        let n = Double(buf.count)
        for c in counts where c > 0 {
            let p = Double(c) / n
            h -= p * (Darwin.log(p) / Darwin.log(2.0))
        }
        XCTAssertGreaterThan(h, 7.9, "Expected near-uniform byte distribution")
    }
}
