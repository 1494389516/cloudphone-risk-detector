import CryptoKit
import Foundation

private extension Data {
    mutating func appendLittleEndian(_ value: UInt32) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }

    mutating func appendLittleEndian(_ value: UInt64) {
        var le = value.littleEndian
        Swift.withUnsafeBytes(of: &le) { append(contentsOf: $0) }
    }
}

/// Shared producer-side binary ABI contract for cprisk-armor <-> CRiskCore.
///
/// The goal of this namespace is to freeze the section names and packed layout
/// semantics that the Swift producer emits and the C runtime consumes.
public enum ArmorABI {
    public static let version: UInt32 = 2
    public static let keySize = 32
    public static let hashSize = 32
    public static let nonceSize = 8
    public static let dataSegmentName = "__DATA"

    public enum Sections {
        public static let stringTable = "__swift5_types2"
        public static let loader = "__swift5_proto2"
        public static let protectedBlob = "__swift5_mpenum"
        public static let anchorA = "__swift5_aa"
        public static let anchorB = "__swift5_ab"
        public static let anchorC = "__swift5_ac"
        public static let anchorD = "__swift5_ad"
        public static let fullAnchorHash = "__swift5_acfun"
        public static let whiteboxMeta = "__swift5_awbm"
        public static let whiteboxCode = "__swift5_awbc"
        public static let whiteboxData = "__swift5_awbd"
        public static let whiteboxTag = "__swift5_awbt"
        public static let antiDebugPlan = "__cpr_adbg7"

        public static let splitAnchorSections = [
            anchorA,
            anchorB,
            anchorC,
            anchorD,
        ]

        public static let allCustom: Set<String> = [
            stringTable, loader, protectedBlob,
            anchorA, anchorB, anchorC, anchorD, fullAnchorHash,
            whiteboxMeta, whiteboxCode, whiteboxData, whiteboxTag,
            antiDebugPlan,
        ]
    }

    public enum AntiDebug {
        public static let abiVersion: UInt32 = 1
        public static let magic: UInt32 = 0x43504137
        public static let sectionName = Sections.antiDebugPlan
        public static let headerSize = 48
        public static let entrySize = 64
        public static let targetNameFieldSize = 32

        public static let flagHasSymbolTargets: UInt32 = 0x0000_0001
        public static let flagHasSyntheticTargets: UInt32 = 0x0000_0002
        public static let flagSeedFromConfig: UInt32 = 0x0000_0004
        public static let flagSeedFromBinary: UInt32 = 0x0000_0008

        public static let entryFlagSyntheticTarget: UInt32 = 0x0000_0001
        public static let entryFlagInlinePatchReserved: UInt32 = 0x0000_0002
        public static let entryFlagRuntimeGateReserved: UInt32 = 0x0000_0004

        public static let policyRuntimeGate: UInt32 = 0x0000_0001
        public static let policyCrashOnDebugger: UInt32 = 0x0000_0002
        public static let policyTrapOnTamper: UInt32 = 0x0000_0004
        public static let policyDelayResponse: UInt32 = 0x0000_0008
        public static let policyEscalateIntegrity: UInt32 = 0x0000_0010

        /// Packed layout:
        /// { magic, version, flags, header_size, seed, text_base_address,
        ///   probe_immediate, entry_count, entry_size, reserved }.
        public struct Header {
            public let magic: UInt32
            public let version: UInt32
            public let flags: UInt32
            public let headerSize: UInt32
            public let seed: UInt64
            public let textBaseAddress: UInt64
            public let probeImmediate: UInt32
            public let entryCount: UInt32
            public let entrySize: UInt32
            public let reserved: UInt32

            public init(
                magic: UInt32 = AntiDebug.magic,
                version: UInt32 = AntiDebug.abiVersion,
                flags: UInt32,
                headerSize: UInt32 = UInt32(AntiDebug.headerSize),
                seed: UInt64,
                textBaseAddress: UInt64,
                probeImmediate: UInt32,
                entryCount: UInt32,
                entrySize: UInt32 = UInt32(AntiDebug.entrySize),
                reserved: UInt32 = 0
            ) {
                self.magic = magic
                self.version = version
                self.flags = flags
                self.headerSize = headerSize
                self.seed = seed
                self.textBaseAddress = textBaseAddress
                self.probeImmediate = probeImmediate
                self.entryCount = entryCount
                self.entrySize = entrySize
                self.reserved = reserved
            }

            public func serialized() -> Data {
                var data = Data()
                data.appendLittleEndian(magic)
                data.appendLittleEndian(version)
                data.appendLittleEndian(flags)
                data.appendLittleEndian(headerSize)
                data.appendLittleEndian(seed)
                data.appendLittleEndian(textBaseAddress)
                data.appendLittleEndian(probeImmediate)
                data.appendLittleEndian(entryCount)
                data.appendLittleEndian(entrySize)
                data.appendLittleEndian(reserved)
                return data
            }
        }

        /// Packed layout:
        /// { identifier_hash, patch_site_vm_offset, patch_site_file_offset,
        ///   policy_bits, scatter_slot, entry_flags, target_name[32] }.
        public struct Entry {
            public let identifierHash: UInt64
            public let patchSiteVMOffset: UInt64
            public let patchSiteFileOffset: UInt32
            public let policyBits: UInt32
            public let scatterSlot: UInt32
            public let entryFlags: UInt32
            public let targetName: String

            public init(
                identifierHash: UInt64,
                patchSiteVMOffset: UInt64,
                patchSiteFileOffset: UInt32,
                policyBits: UInt32,
                scatterSlot: UInt32,
                entryFlags: UInt32 = 0,
                targetName: String
            ) {
                self.identifierHash = identifierHash
                self.patchSiteVMOffset = patchSiteVMOffset
                self.patchSiteFileOffset = patchSiteFileOffset
                self.policyBits = policyBits
                self.scatterSlot = scatterSlot
                self.entryFlags = entryFlags
                self.targetName = targetName
            }

            public func serialized() -> Data {
                var data = Data()
                data.appendLittleEndian(identifierHash)
                data.appendLittleEndian(patchSiteVMOffset)
                data.appendLittleEndian(patchSiteFileOffset)
                data.appendLittleEndian(policyBits)
                data.appendLittleEndian(scatterSlot)
                data.appendLittleEndian(entryFlags)

                var nameBytes = Array(targetName.utf8.prefix(AntiDebug.targetNameFieldSize))
                nameBytes.append(contentsOf: repeatElement(0, count: max(0, AntiDebug.targetNameFieldSize - nameBytes.count)))
                data.append(contentsOf: nameBytes)
                return data
            }
        }
    }

    public enum WhiteBox {
        public static let abiVersion: UInt32 = 1
        public static let magic: UInt32 = 0x43505742
        public static let engineReadyFlag: UInt32 = 0x0000_0001
        public static let signingPipelineFlag: UInt32 = 0x0000_0002
        public static let roundCount: UInt32 = 4
        public static let stateSize = ArmorABI.hashSize
        public static let permutationSize = ArmorABI.hashSize
        public static let roundConstantSize = Int(roundCount) * ArmorABI.hashSize
        public static let tableValueCount = 256
        public static let tagContext = "cprisk.whitebox.tag.v1"

        public static let capabilityDeriveKey: UInt32 = 0x0000_0001
        public static let capabilitySignHelper: UInt32 = 0x0000_0002
        public static let capabilityVerifyHelper: UInt32 = 0x0000_0004
        public static let capabilityFramework: UInt32 = 0x0000_0010
        public static let capabilitySectionLayout: UInt32 = 0x0000_0020

        public static let probeCompiledFlag: UInt32 = 0x0000_0001
        public static let probeMetadataPresentFlag: UInt32 = 0x0000_0002
        public static let probeMetadataValidFlag: UInt32 = 0x0000_0004
        public static let probeEngineReadyFlag: UInt32 = 0x0000_0008

        public static let hexEncodedHashSize = ArmorABI.hashSize * 2

        public enum Domain: UInt32, CaseIterable {
            case anchorTag = 1
            case pass1StringKey = 2
            case anchorAccumulatorSeed = 3
            case loaderKey = 4
            case runtimeMaterial = 5
        }

        public enum Sections {
            public static let metadata = ArmorABI.Sections.whiteboxMeta
            public static let code = ArmorABI.Sections.whiteboxCode
            public static let data = ArmorABI.Sections.whiteboxData
            public static let tag = ArmorABI.Sections.whiteboxTag

            public static let allReserved = [metadata, code, data, tag]
        }

        /// Packed layout:
        /// { magic, version, flags, payload_size, config_digest[32] }.
        /// `payload_size` only covers the white-box payload body (`code + data`).
        /// The detached `tag` section is authenticated independently and must
        /// not be folded into this field, otherwise the runtime validator will
        /// reject the bundle as ABI-inconsistent.
        public struct Header {
            public let magic: UInt32
            public let version: UInt32
            public let flags: UInt32
            public let payloadSize: UInt32
            public let configDigest: Data

            public init(
                magic: UInt32 = WhiteBox.magic,
                version: UInt32 = WhiteBox.abiVersion,
                flags: UInt32 = 0,
                payloadSize: UInt32 = 0,
                configDigest: Data = Data(repeating: 0, count: ArmorABI.hashSize)
            ) {
                precondition(configDigest.count == ArmorABI.hashSize, "configDigest must be 32 bytes")
                self.magic = magic
                self.version = version
                self.flags = flags
                self.payloadSize = payloadSize
                self.configDigest = configDigest
            }

            public func serialized() -> Data {
                var data = Data()
                data.appendLittleEndian(magic)
                data.appendLittleEndian(version)
                data.appendLittleEndian(flags)
                data.appendLittleEndian(payloadSize)
                data.append(configDigest)
                return data
            }
        }

        /// Packed layout:
        /// { domain_id, round_count, table_offset, table_length,
        ///   permutation[32], final_mask[32], round_constants[128],
        ///   record_digest[32] }.
        public struct Descriptor {
            public static let serializedSize = 16
                + WhiteBox.permutationSize
                + ArmorABI.hashSize
                + WhiteBox.roundConstantSize
                + ArmorABI.hashSize

            public let domainID: UInt32
            public let roundCount: UInt32
            public let tableOffset: UInt32
            public let tableLength: UInt32
            public let permutation: Data
            public let finalMask: Data
            public let roundConstants: Data
            public let recordDigest: Data

            public init(
                domainID: UInt32,
                roundCount: UInt32 = WhiteBox.roundCount,
                tableOffset: UInt32,
                tableLength: UInt32,
                permutation: Data,
                finalMask: Data,
                roundConstants: Data,
                recordDigest: Data
            ) {
                precondition(permutation.count == WhiteBox.permutationSize, "permutation must be 32 bytes")
                precondition(finalMask.count == ArmorABI.hashSize, "finalMask must be 32 bytes")
                precondition(roundConstants.count == WhiteBox.roundConstantSize,
                             "roundConstants must be 128 bytes")
                precondition(recordDigest.count == ArmorABI.hashSize, "recordDigest must be 32 bytes")
                self.domainID = domainID
                self.roundCount = roundCount
                self.tableOffset = tableOffset
                self.tableLength = tableLength
                self.permutation = permutation
                self.finalMask = finalMask
                self.roundConstants = roundConstants
                self.recordDigest = recordDigest
            }

            public func serialized() -> Data {
                var data = Data()
                data.appendLittleEndian(domainID)
                data.appendLittleEndian(roundCount)
                data.appendLittleEndian(tableOffset)
                data.appendLittleEndian(tableLength)
                data.append(permutation)
                data.append(finalMask)
                data.append(roundConstants)
                data.append(recordDigest)
                return data
            }
        }
    }

    public enum MetadataSections {
        public static let swiftTypes = "__swift5_types"
        public static let swiftReflectionStrings = "__swift5_reflstr"
        public static let objcMethodNames = "__objc_methname"
        public static let swiftFieldMetadata = "__swift5_fieldmd"
        public static let swiftBuiltinTypes = "__swift5_builtin"
        public static let swiftCapture = "__swift5_capture"
        public static let swiftAssocTypes = "__swift5_assocty"
        public static let swiftProtocols = "__swift5_proto"
        public static let swiftProtocolConformances = "__swift5_protos"

        public static let swiftTypeRef = "__swift5_typeref"

        public static let additionalScrubSections = [
            swiftFieldMetadata,
            swiftBuiltinTypes,
            swiftCapture,
            swiftAssocTypes,
            swiftProtocols,
            swiftProtocolConformances,
            swiftTypeRef,
        ]
    }

    public enum StringTable {
        /// Table guard sentinel in little-endian.
        public static let magic: UInt32 = 0x43505354
        public static let sectionName = Sections.stringTable
        public static let headerSize = 12
        public static let indexEntrySize = 52

        /// Packed layout: { magic, version, count }.
        public struct Header {
            public let magic: UInt32
            public let version: UInt32
            public let count: UInt32

            public init(
                magic: UInt32 = StringTable.magic,
                version: UInt32 = ArmorABI.version,
                count: UInt32
            ) {
                self.magic = magic
                self.version = version
                self.count = count
            }

            public func serialized() -> Data {
                var data = Data()
                data.appendLittleEndian(magic)
                data.appendLittleEndian(version)
                data.appendLittleEndian(count)
                return data
            }
        }

        /// Packed layout: { string_id, data_offset, data_length, nonce[8], hmac_tag[32] }.
        public struct IndexEntry {
            public let stringID: UInt32
            public let dataOffset: UInt32
            public let dataLength: UInt32
            public let nonce: Data
            public let hmacTag: Data

            public init(stringID: UInt32, dataOffset: UInt32, dataLength: UInt32,
                        nonce: Data, hmacTag: Data) {
                precondition(nonce.count == ArmorABI.nonceSize, "nonce must be 8 bytes")
                precondition(hmacTag.count == ArmorABI.hashSize, "hmacTag must be 32 bytes")
                self.stringID = stringID
                self.dataOffset = dataOffset
                self.dataLength = dataLength
                self.nonce = nonce
                self.hmacTag = hmacTag
            }

            public func serialized() -> Data {
                var data = Data()
                data.appendLittleEndian(stringID)
                data.appendLittleEndian(dataOffset)
                data.appendLittleEndian(dataLength)
                data.append(nonce)
                data.append(hmacTag)
                return data
            }
        }
    }

    public enum Loader {
        /// Descriptor guard sentinel in little-endian.
        public static let magic: UInt32 = 0x4350524B
        public static let sectionName = Sections.loader
        public static let protectedSectionName = Sections.protectedBlob
        public static let headerSize = 12
        public static let entrySize = 128

        /// Packed layout: { magic, version, count }.
        public struct Header {
            public let magic: UInt32
            public let version: UInt32
            public let count: UInt32

            public init(
                magic: UInt32 = Loader.magic,
                version: UInt32 = ArmorABI.version,
                count: UInt32
            ) {
                self.magic = magic
                self.version = version
                self.count = count
            }

            public func serialized() -> Data {
                var data = Data()
                data.appendLittleEndian(magic)
                data.appendLittleEndian(version)
                data.appendLittleEndian(count)
                return data
            }
        }

        /// Packed layout:
        /// { segment_name[16], section_name[16], key_id, flags, vm_addr, size,
        ///   content_hash[32], nonce[8], hmac_tag[32] }.
        public struct Entry {
            public let segmentName: String
            public let sectionName: String
            public let keyID: UInt32
            public let flags: UInt32
            public let vmAddress: UInt64
            public let size: UInt64
            public let contentHash: Data
            public let nonce: Data
            public let hmacTag: Data

            public init(
                segmentName: String,
                sectionName: String,
                keyID: UInt32,
                flags: UInt32 = 0,
                vmAddress: UInt64,
                size: UInt64,
                contentHash: Data,
                nonce: Data,
                hmacTag: Data
            ) {
                precondition(contentHash.count == ArmorABI.hashSize, "contentHash must be 32 bytes")
                precondition(nonce.count == ArmorABI.nonceSize, "nonce must be 8 bytes")
                precondition(hmacTag.count == ArmorABI.hashSize, "hmacTag must be 32 bytes")
                self.segmentName = segmentName
                self.sectionName = sectionName
                self.keyID = keyID
                self.flags = flags
                self.vmAddress = vmAddress
                self.size = size
                self.contentHash = contentHash
                self.nonce = nonce
                self.hmacTag = hmacTag
            }

            public func serialized() -> Data {
                var data = Data()
                var segmentBytes = Array(segmentName.utf8.prefix(16))
                segmentBytes.append(contentsOf: repeatElement(0, count: max(0, 16 - segmentBytes.count)))
                var sectionBytes = Array(sectionName.utf8.prefix(16))
                sectionBytes.append(contentsOf: repeatElement(0, count: max(0, 16 - sectionBytes.count)))
                data.append(contentsOf: segmentBytes)
                data.append(contentsOf: sectionBytes)
                data.appendLittleEndian(keyID)
                data.appendLittleEndian(flags)
                data.appendLittleEndian(vmAddress)
                data.appendLittleEndian(size)
                data.append(contentHash)
                data.append(nonce)
                data.append(hmacTag)
                return data
            }
        }
    }

    public enum DataEncryption {
        /// `__DATA` sections that Pass 3 is allowed to encrypt.
        public static let encryptableSections: Set<String> = [
            "__const",
            "__cfstring",
            "__swift5_fieldmd",
            "__swift5_assocty",
            Sections.protectedBlob,
        ]

        /// `__DATA` sections that must **never** be encrypted (dyld / ObjC runtime dependencies).
        public static let blacklistedSections: Set<String> = {
            var set: Set<String> = [
                "__objc_data",
                "__objc_const",
                "__la_symbol_ptr",
                "__nl_symbol_ptr",
                "__got",
                "__mod_init_func",
                "__objc_classlist",
                "__objc_catlist",
                "__objc_protolist",
            ]
            set.insert(Sections.stringTable)
            set.insert(Sections.loader)
            for s in Sections.splitAnchorSections {
                set.insert(s)
            }
            set.insert(Sections.fullAnchorHash)
            set.insert(Sections.whiteboxMeta)
            set.insert(Sections.whiteboxCode)
            set.insert(Sections.whiteboxData)
            set.insert(Sections.whiteboxTag)
            set.insert(Sections.antiDebugPlan)
            return set
        }()

        /// Returns `true` when a `__DATA` section with the given name may be encrypted.
        public static func isEncryptable(_ sectionName: String) -> Bool {
            encryptableSections.contains(sectionName) && !blacklistedSections.contains(sectionName)
        }
    }

    public enum Integrity {
        public static let splitSectionNames = Sections.splitAnchorSections
        public static let splitSectionCount = 4
        public static let splitLaneSize = 8
        public static let hmacFullHashSectionName = Sections.fullAnchorHash
        /// Alias for hmacFullHashSectionName (tests / legacy usage).
        public static let fullHashSectionName = hmacFullHashSectionName
        public static let hmacFullHashSectionSize = ArmorABI.hashSize
        /// Alias for legacy callers that used the v1 name.
        public static let fullHashSectionSize = hmacFullHashSectionSize

        /// Split anchor sections each store one contiguous 8-byte lane
        /// of the 32-byte anchor digest, in order.
        public static func splitAnchorLanes(for digest: Data) -> [Data] {
            precondition(digest.count == ArmorABI.hashSize, "digest must be 32 bytes")
            return stride(from: 0, to: digest.count, by: splitLaneSize).map { start in
                digest.subdata(in: start..<(start + splitLaneSize))
            }
        }

        /// `__swift5_acfun` stores the 32-byte anchor tag emitted by the
        /// white-box PRF for the `anchor_tag` domain.
        public static func anchorTagSection(_ anchorTag: Data) -> Data {
            precondition(anchorTag.count == ArmorABI.hashSize, "anchorTag must be 32 bytes")
            return anchorTag
        }
    }

    /// HMAC-SHA256 — used for authentication tags throughout the ABI.
    public static func hmacSHA256(key: Data, message: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let mac = HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey)
        return Data(mac)
    }

    /// Derive a single-byte salt XOR key from the root key.
    /// Replaces the former hardcoded 0xA7 constant.
    public static func deriveSaltXorKey(rootKey: Data) -> UInt8 {
        var seed = rootKey
        seed.append(Data("salt-xor".utf8))
        let hash = Data(SHA256.hash(data: seed))
        return hash[0]
    }
}
