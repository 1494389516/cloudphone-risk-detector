import XCTest
@testable import CloudPhoneRiskKit

final class CFFStateCodecTests: XCTestCase {

    func testEncodeDecodeRoundTripAcrossRepresentativeInputs() {
        let states: [UInt32] = [0, 1, 0x11, 0x1234_5678, 0x7FFF_FFFF, 0xFFFF_FFFF]
        let seeds: [UInt32] = [0x1, 0x1234_ABCD, 0x8000_0001, 0xFFFF_FFFE]
        let salts: [UInt32] = [0x0, 0x55AA_11EE, 0xA5A5_A5A5, 0xFFFF_FFFF]

        for state in states {
            for seed in seeds {
                for salt in salts {
                    let encoded = CFFStateCodec.encode(state, seed: seed, salt: salt)
                    let decoded = CFFStateCodec.decode(encoded, seed: seed, salt: salt)
                    XCTAssertEqual(
                        decoded,
                        state,
                        "round trip failed for state=\(state) seed=\(seed) salt=\(salt)"
                    )
                }
            }
        }
    }

    func testEncodeIsDeterministicForSameInputs() {
        let state: UInt32 = 0x1020_3040
        let seed: UInt32 = 0x5566_7788
        let salt: UInt32 = 0x99AA_BBCC

        let first = CFFStateCodec.encode(state, seed: seed, salt: salt)
        let second = CFFStateCodec.encode(state, seed: seed, salt: salt)

        XCTAssertEqual(first, second)
    }

    func testEncodeChangesWhenSeedOrSaltChanges() {
        let state: UInt32 = 0xDEAD_BEEF
        let base = CFFStateCodec.encode(state, seed: 0x1357_9BDF, salt: 0x2468_ACE0)
        let changedSeed = CFFStateCodec.encode(state, seed: 0x1357_9BDE, salt: 0x2468_ACE0)
        let changedSalt = CFFStateCodec.encode(state, seed: 0x1357_9BDF, salt: 0x2468_ACE1)

        XCTAssertNotEqual(base, changedSeed, "changing seed should perturb encoded state")
        XCTAssertNotEqual(base, changedSalt, "changing salt should perturb encoded state")
    }

    func testAllCodecStylesRoundTrip() {
        let styles: [CFFStateCodecStyle] = [.xorRotate, .addRotateXor, .affine]
        let state: UInt32 = 0xBEEF_2026
        let key: UInt32 = 0x1357_9BDF
        let salt: UInt32 = 0x2468_ACE0

        for style in styles {
            let encoded = CFFStateCodec.encode(state: state, key: key, salt: salt, style: style)
            let decoded = CFFStateCodec.decode(state: encoded, key: key, salt: salt, style: style)
            XCTAssertEqual(decoded, state, "codec style \(style.rawValue) must round-trip")
        }
    }
}
