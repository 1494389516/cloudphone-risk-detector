import CRiskCore
import XCTest
@testable import CloudPhoneRiskKit

final class CFFStateCodecTests: XCTestCase {

    /// Runtime S-box: SplitMix64 + Fisher–Yates bijection (aligned with CRiskCore + cprisk-armor).
    func testSpnSboxIsBijectionAndNotAesSubBytes() {
        let table = CFFSBoxRuntime.forwardTable()
        XCTAssertEqual(table.count, 256)
        XCTAssertEqual(Set(table).count, 256, "CFF S-box must be a permutation of 0...255")

        let aesPrefix: [UInt8] = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76]
        XCTAssertNotEqual(Array(table.prefix(aesPrefix.count)), aesPrefix, "CFF S-box must not regress to AES SubBytes")
    }

    func testSwiftRuntimeSboxMatchesCRiskCoreRuntimeTable() {
        let swiftTable = CFFSBoxRuntime.forwardTable()
        var coreTable = [UInt8](repeating: 0, count: 256)
        let rc = coreTable.withUnsafeMutableBufferPointer { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return -1 }
            return Int32(cprisk_cff_spn_sbox_copy_forward(base))
        }
        XCTAssertEqual(rc, 0)
        XCTAssertEqual(swiftTable, coreTable)
    }

    func testChainEntryVerifyFailsAfterForeignContextAdvancesChain() {
        cprisk_cff_chain_begin()

        var primary = cprisk_cff_context_t()
        var foreign = cprisk_cff_context_t()

        cprisk_cff_init_default(&primary, 0x1357_9BDF, 1)
        XCTAssertEqual(cprisk_cff_chain_entry_verify(&primary), 1)

        cprisk_cff_init_default(&foreign, 0x2468_ACE0, 7)
        cprisk_cff_set_state(&foreign, 9)

        XCTAssertEqual(cprisk_cff_chain_entry_verify(&primary), 0)
    }

    func testSetStatePoisonsWhenChainSnapshotIsStale() {
        cprisk_cff_chain_begin()

        var primary = cprisk_cff_context_t()
        var foreign = cprisk_cff_context_t()

        cprisk_cff_init_default(&primary, 0xA5A5_5A5A, 3)
        cprisk_cff_init_default(&foreign, 0x55AA_F00D, 11)
        cprisk_cff_set_state(&foreign, 13)

        cprisk_cff_set_state(&primary, 5)

        XCTAssertEqual(primary.iteration_budget, 0)
        let poisoned = cprisk_cff_current_state_fast(&primary)
        XCTAssertTrue(poisoned == 0xFFFF_0000 || poisoned == 0xFFFF_0001)
    }

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
        let styles: [CFFStateCodecStyle] = [.xorRotate, .addRotateXor, .affine, .feistelSpn]
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
