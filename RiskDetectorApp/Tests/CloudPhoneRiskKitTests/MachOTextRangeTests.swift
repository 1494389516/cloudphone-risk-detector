import XCTest
@testable import CloudPhoneRiskKit

final class MachOTextRangeTests: XCTestCase {
    func test_textRangeContainsMalloc() throws {
        guard let p = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "malloc") else {
            throw XCTSkip("malloc not found")
        }
        var info = Dl_info()
        guard dladdr(p, &info) != 0, let base = info.dli_fbase else {
            throw XCTSkip("dladdr failed")
        }
        guard let range = MachOTextRange.textRange(header: UnsafeRawPointer(base)) else {
            throw XCTSkip("textRange unavailable")
        }
        let addr = UInt64(UInt(bitPattern: p))
        XCTAssertTrue(addr >= range.lowerBound && addr < range.upperBound)
    }
}

