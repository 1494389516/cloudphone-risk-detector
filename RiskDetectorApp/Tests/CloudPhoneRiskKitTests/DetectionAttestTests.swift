import XCTest
import CryptoKit
import CRiskCore

/// P0a coverage — verify the C-side attestation chain produces stable,
/// non-replayable tags and detects missing record() calls.
final class DetectionAttestTests: XCTestCase {

    // MARK: - basic begin/record/finalize round-trip

    func testFinalizeReturnsStableCountForRecordedSlots() {
        var nonce = [UInt8](repeating: 0, count: 16)
        XCTAssertEqual(0, nonce.withUnsafeMutableBufferPointer { cprisk_attest_session_begin($0.baseAddress) })

        let h = Array(SHA256.hash(data: Data("methods-set-A".utf8)))
        XCTAssertEqual(h.count, 32)

        // Record three slots
        h.withUnsafeBufferPointer { buf in
            cprisk_attest_record(0x11, 0,    buf.baseAddress)
            cprisk_attest_record(0x37, 1500, buf.baseAddress)
            cprisk_attest_record(0x4D, 250,  buf.baseAddress)
        }

        var tag = [UInt8](repeating: 0, count: 32)
        var count: UInt32 = 0
        let rc = tag.withUnsafeMutableBufferPointer { tagBuf in
            cprisk_attest_session_finalize(tagBuf.baseAddress, &count)
        }
        XCTAssertEqual(rc, 0)
        XCTAssertEqual(count, 3)
        XCTAssertNotEqual(tag, [UInt8](repeating: 0, count: 32),
            "finalize tag must be non-zero after recording slots")
    }

    // MARK: - tag is sensitive to score perturbation

    func testTagChangesWhenAnyRecordedScoreDiffers() {
        let h = Array(SHA256.hash(data: Data("methods-set-B".utf8)))

        var nonceA = [UInt8](repeating: 0, count: 16)
        _ = nonceA.withUnsafeMutableBufferPointer { cprisk_attest_session_begin($0.baseAddress) }
        h.withUnsafeBufferPointer { buf in
            cprisk_attest_record(0x11, 100, buf.baseAddress)
            cprisk_attest_record(0x37, 200, buf.baseAddress)
        }
        var tagA = [UInt8](repeating: 0, count: 32)
        var cntA: UInt32 = 0
        _ = tagA.withUnsafeMutableBufferPointer { cprisk_attest_session_finalize($0.baseAddress, &cntA) }

        var nonceB = [UInt8](repeating: 0, count: 16)
        _ = nonceB.withUnsafeMutableBufferPointer { cprisk_attest_session_begin($0.baseAddress) }
        h.withUnsafeBufferPointer { buf in
            cprisk_attest_record(0x11, 100, buf.baseAddress)
            cprisk_attest_record(0x37, 201, buf.baseAddress) // off by one
        }
        var tagB = [UInt8](repeating: 0, count: 32)
        var cntB: UInt32 = 0
        _ = tagB.withUnsafeMutableBufferPointer { cprisk_attest_session_finalize($0.baseAddress, &cntB) }

        XCTAssertEqual(cntA, 2)
        XCTAssertEqual(cntB, 2)
        XCTAssertNotEqual(tagA, tagB,
            "tag must differ when any recorded score is perturbed by 1")
    }

    // MARK: - tag is sensitive to slot order (rolling chain, not Merkle)

    func testTagChangesWhenSlotOrderDiffers() {
        let h = Array(SHA256.hash(data: Data("methods-set-C".utf8)))

        var nonceA = [UInt8](repeating: 0, count: 16)
        _ = nonceA.withUnsafeMutableBufferPointer { cprisk_attest_session_begin($0.baseAddress) }
        h.withUnsafeBufferPointer { buf in
            cprisk_attest_record(0x11, 50, buf.baseAddress)
            cprisk_attest_record(0x37, 60, buf.baseAddress)
        }
        var tagOrdered = [UInt8](repeating: 0, count: 32)
        var cnt: UInt32 = 0
        _ = tagOrdered.withUnsafeMutableBufferPointer { cprisk_attest_session_finalize($0.baseAddress, &cnt) }

        var nonceB = [UInt8](repeating: 0, count: 16)
        _ = nonceB.withUnsafeMutableBufferPointer { cprisk_attest_session_begin($0.baseAddress) }
        h.withUnsafeBufferPointer { buf in
            cprisk_attest_record(0x37, 60, buf.baseAddress)
            cprisk_attest_record(0x11, 50, buf.baseAddress)
        }
        var tagSwapped = [UInt8](repeating: 0, count: 32)
        _ = tagSwapped.withUnsafeMutableBufferPointer { cprisk_attest_session_finalize($0.baseAddress, &cnt) }

        XCTAssertNotEqual(tagOrdered, tagSwapped,
            "tag must encode dispatch order — server replay must follow client order")
    }

    // MARK: - missing record() calls produce different count + tag

    func testMissingRecordCallProducesDifferentTag() {
        let h = Array(SHA256.hash(data: Data("methods-set-D".utf8)))

        var nonceA = [UInt8](repeating: 0, count: 16)
        _ = nonceA.withUnsafeMutableBufferPointer { cprisk_attest_session_begin($0.baseAddress) }
        h.withUnsafeBufferPointer { buf in
            cprisk_attest_record(0x11, 0, buf.baseAddress)
            cprisk_attest_record(0x37, 0, buf.baseAddress)
            cprisk_attest_record(0x4D, 0, buf.baseAddress)
        }
        var tagThree = [UInt8](repeating: 0, count: 32)
        var cnt3: UInt32 = 0
        _ = tagThree.withUnsafeMutableBufferPointer { cprisk_attest_session_finalize($0.baseAddress, &cnt3) }

        var nonceB = [UInt8](repeating: 0, count: 16)
        _ = nonceB.withUnsafeMutableBufferPointer { cprisk_attest_session_begin($0.baseAddress) }
        h.withUnsafeBufferPointer { buf in
            // Attacker bypassed two slots — only one record() actually fired.
            cprisk_attest_record(0x11, 0, buf.baseAddress)
        }
        var tagOne = [UInt8](repeating: 0, count: 32)
        var cnt1: UInt32 = 0
        _ = tagOne.withUnsafeMutableBufferPointer { cprisk_attest_session_finalize($0.baseAddress, &cnt1) }

        XCTAssertEqual(cnt3, 3)
        XCTAssertEqual(cnt1, 1)
        XCTAssertNotEqual(tagThree, tagOne,
            "skipping record() calls must produce a different tag — this is the core attack-detection property")
    }

    // MARK: - finalize without begin returns -1 and does not yield a usable tag

    func testFinalizeWithoutActiveSessionFails() {
        // Drain any prior session by finalizing once.
        var drainTag = [UInt8](repeating: 0, count: 32)
        var drainCnt: UInt32 = 0
        _ = drainTag.withUnsafeMutableBufferPointer {
            cprisk_attest_session_finalize($0.baseAddress, &drainCnt)
        }

        var tag = [UInt8](repeating: 0xAA, count: 32) // canary
        var count: UInt32 = 0xDEAD_BEEF
        let rc = tag.withUnsafeMutableBufferPointer { tagBuf in
            cprisk_attest_session_finalize(tagBuf.baseAddress, &count)
        }
        XCTAssertEqual(rc, -1)
        XCTAssertEqual(count, 0)
        XCTAssertEqual(tag, [UInt8](repeating: 0, count: 32),
            "finalize without active session must zero the output tag")
    }

    // MARK: - distinct sessions produce distinct nonces

    func testSessionNoncesAreUniquePerBegin() {
        var seen = Set<[UInt8]>()
        for _ in 0..<8 {
            var n = [UInt8](repeating: 0, count: 16)
            _ = n.withUnsafeMutableBufferPointer { cprisk_attest_session_begin($0.baseAddress) }
            // finalize so the next begin() gets a fresh state
            var t = [UInt8](repeating: 0, count: 32)
            var c: UInt32 = 0
            _ = t.withUnsafeMutableBufferPointer { cprisk_attest_session_finalize($0.baseAddress, &c) }
            XCTAssertFalse(seen.contains(n), "session nonce repeated — replay attack would succeed")
            seen.insert(n)
        }
    }
}
