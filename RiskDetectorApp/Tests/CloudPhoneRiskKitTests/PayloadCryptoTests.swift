import XCTest
@testable import CloudPhoneRiskKit

final class PayloadCryptoTests: XCTestCase {
    func test_encryptDecrypt_roundTrip() throws {
        let plaintext = Data("hello".utf8)
        let key = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let encrypted = try PayloadCrypto.encrypt(plaintext, rawKey: key)
        let decrypted = try PayloadCrypto.decrypt(encrypted, rawKey: key)
        XCTAssertEqual(decrypted, plaintext)
    }
}

