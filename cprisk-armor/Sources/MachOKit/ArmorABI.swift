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
    public static let version: UInt32 = 1
    public static let keySize = 32
    public static let hashSize = 32
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

        public static let splitAnchorSections = [
            anchorA,
            anchorB,
            anchorC,
            anchorD,
        ]

        public static let allCustom: Set<String> = [
            stringTable, loader, protectedBlob,
            anchorA, anchorB, anchorC, anchorD, fullAnchorHash,
        ]
    }

    public enum MetadataSections {
        public static let swiftTypes = "__swift5_types"
        public static let swiftReflectionStrings = "__swift5_reflstr"
        public static let objcMethodNames = "__objc_methname"
    }

    public enum StringTable {
        /// Table guard sentinel in little-endian.
        public static let magic: UInt32 = 0x43505354
        public static let sectionName = Sections.stringTable
        public static let headerSize = 12
        public static let indexEntrySize = 12

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

        /// Packed layout: { string_id, data_offset, data_length }.
        public struct IndexEntry {
            public let stringID: UInt32
            public let dataOffset: UInt32
            public let dataLength: UInt32

            public init(stringID: UInt32, dataOffset: UInt32, dataLength: UInt32) {
                self.stringID = stringID
                self.dataOffset = dataOffset
                self.dataLength = dataLength
            }

            public func serialized() -> Data {
                var data = Data()
                data.appendLittleEndian(stringID)
                data.appendLittleEndian(dataOffset)
                data.appendLittleEndian(dataLength)
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
        public static let entrySize = 88

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
        /// { segment_name[16], section_name[16], key_id, flags, vm_addr, size, content_hash[32] }.
        ///
        /// `keyID` is the keystream domain separator shared with the runtime.
        /// `flags` is reserved for future pass expansion and currently emitted as 0.
        /// `vmAddress` is the unslid Mach-O vmaddr of the protected section.
        /// `size` is the encrypted payload size in bytes.
        /// `contentHash` is the SHA-256 of the post-decrypt plaintext section.
        public struct Entry {
            public let segmentName: String
            public let sectionName: String
            public let keyID: UInt32
            public let flags: UInt32
            public let vmAddress: UInt64
            public let size: UInt64
            public let contentHash: Data

            public init(
                segmentName: String,
                sectionName: String,
                keyID: UInt32,
                flags: UInt32 = 0,
                vmAddress: UInt64,
                size: UInt64,
                contentHash: Data
            ) {
                precondition(contentHash.count == ArmorABI.hashSize, "contentHash must be 32 bytes")
                self.segmentName = segmentName
                self.sectionName = sectionName
                self.keyID = keyID
                self.flags = flags
                self.vmAddress = vmAddress
                self.size = size
                self.contentHash = contentHash
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
        public static let fullHashSectionName = Sections.fullAnchorHash
        public static let fullHashMaskSize = ArmorABI.hashSize
        public static let fullHashSectionSize = ArmorABI.hashSize * 2

        /// Split anchor sections each store one contiguous 8-byte lane
        /// of the 32-byte anchor digest, in order.
        public static func splitAnchorLanes(for digest: Data) -> [Data] {
            precondition(digest.count == ArmorABI.hashSize, "digest must be 32 bytes")
            return stride(from: 0, to: digest.count, by: splitLaneSize).map { start in
                digest.subdata(in: start..<(start + splitLaneSize))
            }
        }

        /// Full anchor hash section stores { mask[32], maskedHash[32] } where
        /// `maskedHash[i] = fullHash[i] ^ mask[i]`.
        public static func maskedFullHashSection(mask: Data, fullHash: Data) -> Data {
            precondition(mask.count == ArmorABI.hashSize, "mask must be 32 bytes")
            precondition(fullHash.count == ArmorABI.hashSize, "fullHash must be 32 bytes")

            var data = Data()
            data.append(mask)
            data.append(Data(zip(mask, fullHash).map { $0 ^ $1 }))
            return data
        }
    }
}
