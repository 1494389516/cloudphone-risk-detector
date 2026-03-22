import Foundation
import MachOKit
import XCTest

final class WhiteBoxProfileTests: XCTestCase {
    func testWhiteBoxPRFIsDeterministicForSameRootDomainAndInput() {
        let rootKey = Data(repeating: 0x5A, count: ArmorABI.keySize)
        let input = Data((0..<ArmorABI.hashSize).map { UInt8($0) })

        let bundleA = ArmorWhiteBox.build(rootKey: rootKey)
        let bundleB = ArmorWhiteBox.build(rootKey: rootKey)
        let outA = bundleA.prf(domain: .anchorTag, input: input)
        let outB = bundleA.prf(domain: .anchorTag, input: input)
        let outC = bundleB.prf(domain: .anchorTag, input: input)

        XCTAssertEqual(outA, outB)
        XCTAssertEqual(outA, outC)
        XCTAssertEqual(outA.count, ArmorABI.hashSize)
    }

    func testDifferentDomainsProduceDifferentOutputs() {
        let rootKey = Data(repeating: 0x7C, count: ArmorABI.keySize)
        let input = Data(repeating: 0x11, count: ArmorABI.hashSize)
        let bundle = ArmorWhiteBox.build(rootKey: rootKey)

        let outputs = ArmorABI.WhiteBox.Domain.allCases.map { bundle.prf(domain: $0, input: input) }
        XCTAssertEqual(Set(outputs).count, outputs.count, "each domain should yield a distinct PRF output")
    }

    func testWhiteBoxBundleSerializesMetadataDescriptorsAndTag() {
        let rootKey = Data(repeating: 0x33, count: ArmorABI.keySize)
        let bundle = ArmorWhiteBox.build(rootKey: rootKey)

        XCTAssertEqual(bundle.domains.count, ArmorABI.WhiteBox.Domain.allCases.count)
        XCTAssertEqual(bundle.whiteboxCode.count, ArmorABI.WhiteBox.Domain.allCases.count * 4 * 32 * 256)
        XCTAssertEqual(bundle.whiteboxData.count,
                       ArmorABI.WhiteBox.Domain.allCases.count * ArmorABI.WhiteBox.Descriptor.serializedSize)
        XCTAssertEqual(bundle.whiteboxTag.count, ArmorABI.hashSize)

        let expectedFlags = ArmorABI.WhiteBox.engineReadyFlag
            | ArmorABI.WhiteBox.signingPipelineFlag
            | ArmorABI.WhiteBox.enhancedDiffusionFlag
        XCTAssertEqual(bundle.metadata.flags, expectedFlags)
        XCTAssertEqual(bundle.metadata.payloadSize,
                       UInt32(bundle.whiteboxCode.count + bundle.whiteboxData.count),
                       "payloadSize must match the code+data payload consumed by CRiskCore")

        var expectedTagSeed = Data(ArmorABI.WhiteBox.tagContext.utf8)
        expectedTagSeed.append(bundle.whiteboxCode)
        expectedTagSeed.append(bundle.whiteboxData)
        XCTAssertEqual(bundle.whiteboxTag, ArmorWhiteBox.sha256(expectedTagSeed))

        var expectedConfigSeed = Data()
        expectedConfigSeed.append(bundle.whiteboxCode)
        expectedConfigSeed.append(bundle.whiteboxData)
        expectedConfigSeed.append(bundle.whiteboxTag)
        XCTAssertEqual(bundle.metadata.configDigest, ArmorWhiteBox.sha256(expectedConfigSeed))
        XCTAssertNotEqual(bundle.metadata.payloadSize,
                          UInt32(bundle.whiteboxCode.count + bundle.whiteboxData.count + bundle.whiteboxTag.count),
                          "payloadSize must exclude the detached tag section")

        var expectedOffset = 0
        for record in bundle.domains {
            XCTAssertEqual(record.descriptor.roundCount, ArmorABI.WhiteBox.roundCount)
            XCTAssertEqual(Int(record.descriptor.tableOffset), expectedOffset)
            XCTAssertEqual(Int(record.descriptor.tableLength), 4 * 32 * 256)
            expectedOffset += 4 * 32 * 256
        }
    }

    func testWhiteBoxBundleEnablesEnhancedDiffusionFlag() {
        let bundle = ArmorWhiteBox.build(rootKey: Data(repeating: 0x55, count: ArmorABI.keySize))
        XCTAssertNotEqual(
            bundle.metadata.flags & ArmorABI.WhiteBox.enhancedDiffusionFlag,
            0,
            "new bundles should advertise enhanced diffusion path"
        )
    }

    func testLegacyCompatibilityPathRemainsDeterministic() {
        let rootKey = Data(repeating: 0x19, count: ArmorABI.keySize)
        let input = Data((0..<ArmorABI.hashSize).map { UInt8(($0 * 11) & 0xFF) })
        let enhancedBundle = ArmorWhiteBox.build(rootKey: rootKey)

        let legacyHeader = ArmorABI.WhiteBox.Header(
            version: 1,
            flags: enhancedBundle.metadata.flags & ~ArmorABI.WhiteBox.enhancedDiffusionFlag,
            payloadSize: enhancedBundle.metadata.payloadSize,
            configDigest: enhancedBundle.metadata.configDigest
        )
        let legacyBundle = ArmorWhiteBoxBundle(
            domains: enhancedBundle.domains,
            metadata: legacyHeader,
            whiteboxCode: enhancedBundle.whiteboxCode,
            whiteboxData: enhancedBundle.whiteboxData,
            whiteboxTag: enhancedBundle.whiteboxTag
        )

        let legacyOutA = legacyBundle.prf(domain: ArmorABI.WhiteBox.Domain.runtimeMaterial, input: input)
        let legacyOutB = legacyBundle.prf(domain: ArmorABI.WhiteBox.Domain.runtimeMaterial, input: input)
        let enhancedOut = enhancedBundle.prf(domain: ArmorABI.WhiteBox.Domain.runtimeMaterial, input: input)

        XCTAssertEqual(legacyOutA, legacyOutB, "legacy path must remain deterministic")
        XCTAssertNotEqual(
            enhancedOut,
            legacyOutA,
            "enhanced diffusion should materially change PRF output relative to legacy path"
        )
    }
}
