import CryptoKit
import Foundation

package struct ArmorWhiteBoxBundle {
    package struct DomainRecord {
        package let domain: ArmorABI.WhiteBox.Domain
        package let descriptor: ArmorABI.WhiteBox.Descriptor
        fileprivate let tables: Data
    }

    package let domains: [DomainRecord]
    package let metadata: ArmorABI.WhiteBox.Header
    package let whiteboxCode: Data
    package let whiteboxData: Data
    package let whiteboxTag: Data

    package init(
        domains: [DomainRecord],
        metadata: ArmorABI.WhiteBox.Header,
        whiteboxCode: Data,
        whiteboxData: Data,
        whiteboxTag: Data
    ) {
        self.domains = domains
        self.metadata = metadata
        self.whiteboxCode = whiteboxCode
        self.whiteboxData = whiteboxData
        self.whiteboxTag = whiteboxTag
    }

    package var metadataSection: Data {
        metadata.serialized()
    }

    package func descriptor(for domain: ArmorABI.WhiteBox.Domain) -> ArmorABI.WhiteBox.Descriptor {
        record(for: domain).descriptor
    }

    package func prf(domain: ArmorABI.WhiteBox.Domain, input: Data) -> Data {
        precondition(input.count == ArmorABI.WhiteBox.stateSize, "white-box PRF input must be 32 bytes")

        let record = record(for: domain)
        let permutation = record.descriptor.permutation
        let finalMask = record.descriptor.finalMask
        let roundConstants = record.descriptor.roundConstants
        let tables = record.tables
        let enhancedDiffusionEnabled =
            (metadata.flags & ArmorABI.WhiteBox.enhancedDiffusionFlag) != 0

        var state = Array(input)
        for round in 0..<Int(ArmorABI.WhiteBox.roundCount) {
            var next = firstMixLayer(
                state: state,
                round: round,
                tables: tables,
                roundConstants: roundConstants
            )

            if enhancedDiffusionEnabled {
                next = strongByteMixLayer(next, round: round, roundConstants: roundConstants)
                next = secondMixLayer(
                    state: next,
                    round: round,
                    tables: tables,
                    roundConstants: roundConstants
                )
            }

            var permuted = [UInt8](repeating: 0, count: ArmorABI.WhiteBox.stateSize)
            for i in 0..<ArmorABI.WhiteBox.stateSize {
                permuted[i] = next[Int(permutation[i])]
            }
            state = permuted
        }

        return Data((0..<ArmorABI.WhiteBox.stateSize).map { state[$0] ^ finalMask[$0] })
    }

    private func firstMixLayer(
        state: [UInt8],
        round: Int,
        tables: Data,
        roundConstants: Data
    ) -> [UInt8] {
        var next = [UInt8](repeating: 0, count: ArmorABI.WhiteBox.stateSize)
        for i in 0..<ArmorABI.WhiteBox.stateSize {
            let tableBase = (round * ArmorABI.WhiteBox.stateSize * ArmorABI.WhiteBox.tableValueCount)
                + (i * ArmorABI.WhiteBox.tableValueCount)
            let tableValue = tables[tableBase + Int(state[i])]
            let mixed = tableValue
                ^ state[(i + 1) % ArmorABI.WhiteBox.stateSize]
                ^ roundConstants[(round * ArmorABI.WhiteBox.stateSize) + i]
            next[i] = ArmorWhiteBox.rotl8(mixed, by: ((i + round) % 7) + 1)
        }
        return next
    }

    private func secondMixLayer(
        state: [UInt8],
        round: Int,
        tables: Data,
        roundConstants: Data
    ) -> [UInt8] {
        var next = [UInt8](repeating: 0, count: ArmorABI.WhiteBox.stateSize)
        for i in 0..<ArmorABI.WhiteBox.stateSize {
            let tableBase = (round * ArmorABI.WhiteBox.stateSize * ArmorABI.WhiteBox.tableValueCount)
                + (i * ArmorABI.WhiteBox.tableValueCount)
            let tableValue = tables[tableBase + Int(state[i])]
            let mixed = tableValue
                ^ state[(i + 5) % ArmorABI.WhiteBox.stateSize]
                ^ roundConstants[(round * ArmorABI.WhiteBox.stateSize) + ((i + 13) % ArmorABI.WhiteBox.stateSize)]
            next[i] = ArmorWhiteBox.rotl8(mixed, by: ((i * 3 + round + 1) % 7) + 1)
        }
        return next
    }

    /// A deterministic MDS-like byte diffusion layer with local + distant taps.
    private func strongByteMixLayer(
        _ state: [UInt8],
        round: Int,
        roundConstants: Data
    ) -> [UInt8] {
        var mixed = [UInt8](repeating: 0, count: ArmorABI.WhiteBox.stateSize)
        for i in 0..<ArmorABI.WhiteBox.stateSize {
            let rc = roundConstants[(round * ArmorABI.WhiteBox.stateSize) + ((i * 7 + 3) % ArmorABI.WhiteBox.stateSize)]
            let lane0 = state[i]
            let lane1 = ArmorWhiteBox.rotl8(state[(i + 7) % ArmorABI.WhiteBox.stateSize], by: 1)
            let lane2 = ArmorWhiteBox.rotl8(state[(i + 13) % ArmorABI.WhiteBox.stateSize], by: 3)
            let lane3 = ArmorWhiteBox.rotl8(state[(i + 23) % ArmorABI.WhiteBox.stateSize], by: 5)
            mixed[i] = lane0 ^ lane1 ^ lane2 ^ lane3 ^ rc
        }
        return mixed
    }

    private func record(for domain: ArmorABI.WhiteBox.Domain) -> DomainRecord {
        guard let record = domains.first(where: { $0.domain == domain }) else {
            preconditionFailure("missing white-box domain \(domain.rawValue)")
        }
        return record
    }
}

package enum ArmorWhiteBox {
    package static func build(rootKey: Data?) -> ArmorWhiteBoxBundle {
        let normalizedRootKey = normalizedRootKey(rootKey)
        var records = [ArmorWhiteBoxBundle.DomainRecord]()
        var codeSection = Data()
        var dataSection = Data()

        for domain in ArmorABI.WhiteBox.Domain.allCases.sorted(by: { $0.rawValue < $1.rawValue }) {
            let domainKey = deriveDomainKey(rootKey: normalizedRootKey, domain: domain)
            let permutation = makePermutation(domainKey: domainKey)
            let finalMask = sha256(domainKey + Data("final".utf8))
            let roundConstants = makeRoundConstants(domainKey: domainKey)
            let tables = makeTables(domainKey: domainKey, roundConstants: roundConstants)

            var digestMaterial = Data()
            digestMaterial.append(tables)
            digestMaterial.append(permutation)
            digestMaterial.append(finalMask)
            digestMaterial.append(roundConstants)
            let recordDigest = sha256(digestMaterial)

            let descriptor = ArmorABI.WhiteBox.Descriptor(
                domainID: domain.rawValue,
                tableOffset: numericCast(codeSection.count),
                tableLength: numericCast(tables.count),
                permutation: permutation,
                finalMask: finalMask,
                roundConstants: roundConstants,
                recordDigest: recordDigest
            )

            codeSection.append(tables)
            dataSection.append(descriptor.serialized())
            records.append(.init(domain: domain, descriptor: descriptor, tables: tables))
        }

        var tagMaterial = Data(ArmorABI.WhiteBox.tagContext.utf8)
        tagMaterial.append(codeSection)
        tagMaterial.append(dataSection)
        let whiteboxTag = sha256(tagMaterial)

        var configMaterial = Data()
        configMaterial.append(codeSection)
        configMaterial.append(dataSection)
        configMaterial.append(whiteboxTag)
        let configDigest = sha256(configMaterial)

        let metadata = ArmorABI.WhiteBox.Header(
            flags: ArmorABI.WhiteBox.engineReadyFlag
                | ArmorABI.WhiteBox.signingPipelineFlag
                | ArmorABI.WhiteBox.enhancedDiffusionFlag,
            // payloadSize covers the executable white-box payload only. The tag is
            // authenticated separately via configDigest / whiteboxTag.
            payloadSize: numericCast(codeSection.count + dataSection.count),
            configDigest: configDigest
        )

        return ArmorWhiteBoxBundle(
            domains: records,
            metadata: metadata,
            whiteboxCode: codeSection,
            whiteboxData: dataSection,
            whiteboxTag: whiteboxTag
        )
    }

    package static func normalizedRootKey(_ rootKey: Data?) -> Data {
        var key = Data(repeating: 0, count: ArmorABI.keySize)
        guard let rootKey else { return key }
        let prefix = rootKey.prefix(ArmorABI.keySize)
        key.replaceSubrange(0..<prefix.count, with: prefix)
        return key
    }

    package static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    package static func rotl8(_ value: UInt8, by amount: Int) -> UInt8 {
        let shift = amount & 7
        guard shift != 0 else { return value }
        let widened = UInt16(value)
        return UInt8(((widened << shift) | (widened >> (8 - shift))) & 0xFF)
    }

    package static func rotl64(_ value: UInt64, by amount: Int) -> UInt64 {
        let shift = amount & 63
        guard shift != 0 else { return value }
        return (value << shift) | (value >> (64 - shift))
    }

    package static func appendLittleEndian(_ value: UInt64, to data: inout Data) {
        var littleEndian = value.littleEndian
        withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
    }

    package static func littleEndianUInt64(from data: Data) -> UInt64 {
        precondition(data.count >= MemoryLayout<UInt64>.size, "need at least 8 bytes")
        var value: UInt64 = 0
        for (shift, byte) in data.prefix(8).enumerated() {
            value |= UInt64(byte) << (shift * 8)
        }
        return value
    }

    private static func deriveDomainKey(rootKey: Data, domain: ArmorABI.WhiteBox.Domain) -> Data {
        let label = Data("cprisk.whitebox.domain.\(domain.rawValue)".utf8)
        return ArmorABI.hmacSHA256(key: rootKey, message: label)
    }

    private static func makePermutation(domainKey: Data) -> Data {
        var values = (0..<ArmorABI.WhiteBox.permutationSize).map(UInt8.init)
        var stream = DeterministicByteStream(domainKey: domainKey, label: "perm")

        for i in stride(from: values.count - 1, through: 1, by: -1) {
            let random = stream.nextUInt32()
            let j = Int(random % UInt32(i + 1))
            values.swapAt(i, j)
        }

        return Data(values)
    }

    private static func makeRoundConstants(domainKey: Data) -> Data {
        var stream = DeterministicByteStream(domainKey: domainKey, label: "round")
        return stream.read(count: ArmorABI.WhiteBox.roundConstantSize)
    }

    private static func makeTables(domainKey: Data, roundConstants: Data) -> Data {
        var tables = Data()
        tables.reserveCapacity(
            Int(ArmorABI.WhiteBox.roundCount)
                * ArmorABI.WhiteBox.stateSize
                * ArmorABI.WhiteBox.tableValueCount
        )

        for round in 0..<Int(ArmorABI.WhiteBox.roundCount) {
            for index in 0..<ArmorABI.WhiteBox.stateSize {
                var seed = Data()
                seed.append(domainKey)
                seed.append(Data("table".utf8))
                seed.append(UInt8(round))
                seed.append(UInt8(index))
                let tableSeed = sha256(seed)
                let mixByte = tableSeed[0]
                let maskByte = tableSeed[1]
                let rotation = Int(domainKey[(index + round) % ArmorABI.WhiteBox.stateSize] & 0x07) + 1
                let roundConstant = roundConstants[(round * ArmorABI.WhiteBox.stateSize) + index]
                for x in 0..<ArmorABI.WhiteBox.tableValueCount {
                    let s = UInt8(x) ^ domainKey[index] ^ mixByte
                    let y = rotl8(s, by: rotation) ^ maskByte ^ roundConstant
                    tables.append(y)
                }
            }
        }

        return tables
    }

    private struct DeterministicByteStream {
        let domainKey: Data
        let label: Data
        var counter: UInt32 = 0
        var buffer = Data()
        var offset = 0

        init(domainKey: Data, label: String) {
            self.domainKey = domainKey
            self.label = Data(label.utf8)
        }

        mutating func nextUInt32() -> UInt32 {
            var value: UInt32 = 0
            for shift in 0..<4 {
                value |= UInt32(nextByte()) << (shift * 8)
            }
            return value
        }

        mutating func read(count: Int) -> Data {
            var data = Data()
            data.reserveCapacity(count)
            for _ in 0..<count {
                data.append(nextByte())
            }
            return data
        }

        private mutating func nextByte() -> UInt8 {
            if offset >= buffer.count {
                refill()
            }
            let byte = buffer[offset]
            offset += 1
            return byte
        }

        private mutating func refill() {
            var material = Data()
            material.append(domainKey)
            material.append(label)
            var littleEndian = counter.littleEndian
            withUnsafeBytes(of: &littleEndian) { material.append(contentsOf: $0) }
            buffer = sha256(material)
            counter &+= 1
            offset = 0
        }
    }
}
