import CRiskCore
import Darwin
import XCTest
@testable import CloudPhoneRiskKit

final class DynamicSymbolResolverTests: XCTestCase {
    private let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)

    func testSysctlByNameResolvedPath() {
        var value: Int32 = 0
        var size = MemoryLayout<Int32>.size
        let rc = "hw.ncpu".withCString {
            DynamicSymbolResolver.sysctlByName($0, &value, &size, nil, 0)
        }

        XCTAssertEqual(rc, 0)
        XCTAssertGreaterThan(value, 0)
    }

    func testPacRoundTripForCloseSymbol() {
        let symbol = "close".withCString { dlsym(rtldDefault, $0) }
        XCTAssertNotNil(symbol)

        let discriminator: UInt = 0xC0DE_D00D
        let signed = cprisk_pac_sign_function_pointer(symbol, discriminator)
        XCTAssertNotNil(signed)

        let authed = cprisk_pac_auth_function_pointer(signed, discriminator)
        XCTAssertNotNil(authed)

        if cprisk_pac_is_arm64e_supported() != 0 {
            let mismatch = cprisk_pac_auth_function_pointer(signed, discriminator ^ 0x1357)
            XCTAssertNil(mismatch)
        }
    }

    func testSocketWrapperReturnsValidOrFailureFd() {
        let fd = DynamicSymbolResolver.socket(AF_INET, SOCK_STREAM, 0)
        if fd >= 0 {
            _ = DynamicSymbolResolver.close(fd)
        }
        XCTAssertGreaterThanOrEqual(fd, -1)
    }
}
