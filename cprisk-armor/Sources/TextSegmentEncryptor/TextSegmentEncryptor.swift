import CryptoKit
import Foundation
import MachOKit
import Security

private enum TextArmorSeed {
    static let accumulatorVersion: UInt32 = 2
    static let accumulatorRotation: UInt32 = 7
}

/// Pass 12: encrypts `__TEXT,__text` at page granularity and emits `__DATA` text-encryption metadata
/// (`ArmorABI.Sections.textEncryption`) for CRiskCore.
///
/// **Edges:** Historically the first and last 4K pages were left plaintext as a safety margin. When
/// possible, this pass now also encrypts those pages:
/// - **First page:** encrypted only if `LC_MAIN` exists and the entry **file offset** falls in
///   `__TEXT,__text` but **not** in the first 4 KiB (so the initial PC from dyld is not in ciphertext).
/// - **Last page:** encrypted when a symbol table is present (Pass 12 runs before Pass 6) **and**
///   every `N_SECT` symbol with a value in that page looks like a VM trampoline (`cprisk_vm_entry*`),
///   **or** there are no such symbols in that page. If there is no `LC_SYMTAB`, a full-size last page
///   stays plaintext (conservative).
/// - **Tail chunk:** `__text` is not always an exact multiple of 4 KiB. When the final chunk is a
///   partial page, it is encrypted independently from the "last full page" symbol policy unless
///   `LC_MAIN.entryoff` lands inside that tail chunk (rare, but guarded fail-safe).
///   Runtime validation/decrypt uses the emitted per-entry `size`.
public final class TextSegmentEncryptorPass: ArmorPass {
    public let name = "TextSegmentEncryptor"

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        let fullAnchorHash = try readFullAnchorHash(from: file)
        let integrityHash = sha256(fullAnchorHash + fullAnchorHash + fullAnchorHash)
        let whitebox = ArmorWhiteBox.build(rootKey: config.encryptionKey)
        let anchorAccumulator = anchorBoundAccumulator(
            whitebox: whitebox,
            fullAnchorHash: fullAnchorHash,
            integrityHash: integrityHash
        )
        let loaderKey = deriveLoaderKey(
            whitebox: whitebox,
            fullAnchorHash: fullAnchorHash,
            integrityHash: integrityHash,
            anchorAccumulator: anchorAccumulator
        )

        guard let textSection = try file.section(segment: "__TEXT", section: "__text") else {
            throw MachOError.sectionNotFound("__TEXT", "__text")
        }

        let pageSize = 4096
        let totalSize = Int(textSection.size)
        guard totalSize >= pageSize * 3 else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: ["Skipped: __text smaller than 3 pages (safe margin)"]
            )
        }

        let pageCount = (totalSize + pageSize - 1) / pageSize

        let encryptFirstPage = Self.shouldEncryptFirstTextPage(
            file: file,
            textSectionOffset: UInt64(textSection.offset),
            textSectionSize: UInt64(textSection.size)
        )
        let encryptLastPage = try Self.shouldEncryptLastTextPage(
            file: file,
            textVMA: textSection.address,
            textSize: UInt64(textSection.size),
            pageCount: pageCount,
            pageSize: pageSize
        )
        let lastChunkOffset = (pageCount - 1) * pageSize
        let lastChunkSize = Swift.max(0, totalSize - lastChunkOffset)
        let hasPartialTailChunk = lastChunkSize > 0 && lastChunkSize < pageSize
        let encryptLastChunk = hasPartialTailChunk
            ? Self.shouldEncryptPartialTailChunk(
                file: file,
                textSectionOffset: UInt64(textSection.offset),
                textSectionSize: UInt64(textSection.size),
                pageCount: pageCount,
                pageSize: pageSize
            )
            : encryptLastPage

        var pagesToEncrypt = [Int]()
        pagesToEncrypt.reserveCapacity(pageCount)
        for pageIdx in 0..<pageCount {
            if pageIdx == 0 && !encryptFirstPage { continue }
            if pageIdx == pageCount - 1 && !encryptLastChunk { continue }
            pagesToEncrypt.append(pageIdx)
        }

        guard !pagesToEncrypt.isEmpty else {
            return PassResult(
                passName: name,
                itemsProcessed: 0,
                bytesModified: 0,
                details: [
                    "Skipped: no encryptable __text pages (edges constrained; entry/symbols may cover page0/last)"
                ]
            )
        }

        let baseKeyID = stableKeyID(segment: "__TEXT", section: "__text")
        var entries = [TextEncryption.Entry]()
        var details = [String]()
        var bytesXor = 0

        for pageIdx in pagesToEncrypt {
            let chunkOffset = pageIdx * pageSize
            let chunkSize = Swift.min(pageSize, totalSize - chunkOffset)
            guard chunkSize > 0 else { continue }

            let offset = UInt64(textSection.offset) + UInt64(chunkOffset)
            let vmAddr = textSection.address + UInt64(chunkOffset)
            let start = Int(offset)
            let end = start + chunkSize
            let plaintext = file.data.subdata(in: start..<end)
            let contentHash = sha256(plaintext)
            let nonce = try generateNonce()
            let sectionIndex = TextEncryption.sectionIndexBase + UInt32(pageIdx)
            let sectionKey = TextSectionKeyDerivation.derive(
                parentKey: loaderKey,
                sectionIndex: sectionIndex,
                nonce: nonce,
                depth: 1,
                whitebox: whitebox
            )
            let keyID = baseKeyID &+ UInt32(pageIdx)
            let keystream = makeKeystream(key: sectionKey, keyID: keyID, nonce: nonce, length: chunkSize)
            let encrypted = xor(plaintext, keystream)
            try file.replaceBytes(at: offset, with: encrypted)

            // HMAC scope binds (section_index, nonce_len, nonce, ct_len, ciphertext)
            // — the previous `nonce || ciphertext` form let an attacker truncate
            // an encrypted page and update the size descriptor without
            // invalidating the tag (size was outside the HMAC scope). The C
            // verifier in cprisk_text_encrypt.c MUST mirror this canonical
            // encoding.
            //
            // Wire layout (little-endian):
            //   u32 section_index | u32 nonce_len | nonce[nonce_len] |
            //   u32 ct_len        | ciphertext[ct_len]
            var hmacMessage = Data()
            var sectionIndexLE = sectionIndex.littleEndian
            withUnsafeBytes(of: &sectionIndexLE) { hmacMessage.append(contentsOf: $0) }
            var nonceLenLE = UInt32(nonce.count).littleEndian
            withUnsafeBytes(of: &nonceLenLE) { hmacMessage.append(contentsOf: $0) }
            hmacMessage.append(nonce)
            var ctLenLE = UInt32(encrypted.count).littleEndian
            withUnsafeBytes(of: &ctLenLE) { hmacMessage.append(contentsOf: $0) }
            hmacMessage.append(encrypted)
            let hmacTag = ArmorABI.hmacSHA256(key: sectionKey, message: hmacMessage)

            entries.append(
                TextEncryption.Entry(
                    vmAddress: vmAddr,
                    size: UInt64(chunkSize),
                    keyID: keyID,
                    flags: 0,
                    nonce: nonce,
                    hmacTag: hmacTag,
                    contentHash: contentHash
                )
            )
            bytesXor += chunkSize
            details.append(
                "Encrypted __TEXT.__text page index \(pageIdx) size \(chunkSize) @ 0x\(String(vmAddr, radix: 16))"
            )
        }

        var payload = TextEncryption.Header(count: UInt32(entries.count)).serialized()
        for e in entries {
            payload.append(e.serialized())
        }

        var slackMat = Data()
        slackMat.append(loaderKey)
        var seed = config.buildSeed.littleEndian
        Swift.withUnsafeBytes(of: &seed) { slackMat.append(contentsOf: $0) }
        slackMat.append(Data("pass12.text_encrypt_slack.v1".utf8))
        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: TextEncryption.sectionName,
            content: payload,
            align: 3,
            slackPadding: .keyedPseudorandom(material: slackMat)
        )

        details.append(
            "Wrote \(entries.count) text encrypt descriptor entries to __DATA.\(TextEncryption.sectionName)"
        )

        details.insert(
            "Edge policy: encryptFirstPage=\(encryptFirstPage) encryptLastPage=\(encryptLastPage) encryptPartialTail=\(hasPartialTailChunk ? String(encryptLastChunk) : "n/a")",
            at: 0
        )

        return PassResult(
            passName: name,
            itemsProcessed: entries.count,
            bytesModified: bytesXor + payload.count,
            details: details
        )
    }

    // MARK: - Edge page policy (first / last __text 4K)

    private static func shouldEncryptFirstTextPage(
        file: MachOFile,
        textSectionOffset: UInt64,
        textSectionSize: UInt64
    ) -> Bool {
        let textEnd = textSectionOffset &+ textSectionSize
        for cmd in file.loadCommands {
            guard cmd.cmd == LoadCommand.LC_MAIN else { continue }
            guard cmd.cmdSize >= 24, cmd.rawData.count >= 16 else { continue }
            guard let entryOff = readUInt64LE(cmd.rawData, at: 8) else { continue }
            if entryOff < textSectionOffset || entryOff >= textEnd { return false }
            let rel = entryOff &- textSectionOffset
            let pageIdx = Int(rel / 4096)
            return pageIdx != 0
        }
        return false
    }

    private static func shouldEncryptLastTextPage(
        file: MachOFile,
        textVMA: UInt64,
        textSize: UInt64,
        pageCount: Int,
        pageSize: Int
    ) throws -> Bool {
        guard pageCount >= 1, pageSize > 0 else { return false }
        guard try file.findSymbolTable() != nil else { return false }

        let lastPageStart = textVMA &+ UInt64((pageCount - 1) * pageSize)
        let textEnd = textVMA &+ textSize
        let lastPageEnd = Swift.min(lastPageStart &+ UInt64(pageSize), textEnd)

        guard let ord = try sectionOrdinal1Based(in: file, segment: "__TEXT", section: "__text") else {
            return false
        }

        let symbols = try file.readSymbols()
        var namesInLast = [String]()
        for sym in symbols {
            if sym.nlist.isStab { continue }
            guard sym.nlist.typeField == Nlist64Entry.N_SECT else { continue }
            guard sym.nlist.n_sect == ord else { continue }
            let v = sym.nlist.n_value
            if v >= lastPageStart && v < lastPageEnd {
                namesInLast.append(sym.name)
            }
        }

        if namesInLast.isEmpty {
            return true
        }
        return namesInLast.allSatisfy { isVmTrampolineSymbol($0) }
    }

    /// Partial tail chunks are safe to encrypt by default: unlike the traditional "last full page"
    /// window, they are bounded by emitted `size` and often carry no dyld-critical startup path.
    /// Keep one hard guard: if LC_MAIN entryoff falls in this tail, leave it plaintext.
    private static func shouldEncryptPartialTailChunk(
        file: MachOFile,
        textSectionOffset: UInt64,
        textSectionSize: UInt64,
        pageCount: Int,
        pageSize: Int
    ) -> Bool {
        guard pageCount >= 1, pageSize > 0 else { return false }
        let tailStart = textSectionOffset &+ UInt64((pageCount - 1) * pageSize)
        let textEnd = textSectionOffset &+ textSectionSize
        guard tailStart < textEnd else { return false }
        for cmd in file.loadCommands {
            guard cmd.cmd == LoadCommand.LC_MAIN else { continue }
            guard cmd.cmdSize >= 24, cmd.rawData.count >= 16 else { continue }
            guard let entryOff = readUInt64LE(cmd.rawData, at: 8) else { continue }
            if entryOff >= tailStart && entryOff < textEnd {
                return false
            }
        }
        return true
    }

    private static func sectionOrdinal1Based(in file: MachOFile, segment: String, section: String) throws -> UInt8? {
        var idx: UInt8 = 0
        for seg in try file.segments() {
            for sec in seg.sections {
                guard idx < UInt8.max else { return nil }
                idx += 1
                if seg.name == segment && sec.sectionName == section {
                    return idx
                }
            }
        }
        return nil
    }

    /// Symbols that are VM dispatch stubs only; safe to encrypt with JIT decrypt like inner pages.
    private static func isVmTrampolineSymbol(_ name: String) -> Bool {
        let exact: Set<String> = [
            "_cprisk_vm_entry", "cprisk_vm_entry",
            "_cprisk_vm_entry_alt1", "cprisk_vm_entry_alt1",
            "_cprisk_vm_entry_alt2", "cprisk_vm_entry_alt2",
            "_cprisk_vm_execute", "cprisk_vm_execute"
        ]
        if exact.contains(name) { return true }
        if name.hasPrefix("_cprisk_vm_entry") || name.hasPrefix("cprisk_vm_entry") { return true }
        return false
    }

    private static func readUInt64LE(_ data: Data, at offset: Int) -> UInt64? {
        guard offset >= 0, offset + 8 <= data.count else { return nil }
        return data.withUnsafeBytes { buf in
            UInt64(littleEndian: buf.load(fromByteOffset: offset, as: UInt64.self))
        }
    }

    private func readFullAnchorHash(from file: MachOFile) throws -> Data {
        var digest = Data(repeating: 0, count: ArmorABI.hashSize)
        for (i, name) in ArmorABI.Integrity.splitSectionNames.enumerated() {
            guard let section = try file.section(
                segment: ArmorABI.dataSegmentName,
                section: name
            ) else {
                throw MachOError.sectionNotFound(ArmorABI.dataSegmentName, name)
            }
            let lane = try section.readContent(from: file.data)
            guard lane.count >= ArmorABI.Integrity.splitLaneSize else {
                throw MachOError.invalidData("Split anchor lane \(name) is truncated")
            }
            let offset = i * ArmorABI.Integrity.splitLaneSize
            digest.replaceSubrange(offset..<(offset + ArmorABI.Integrity.splitLaneSize),
                                   with: lane.prefix(ArmorABI.Integrity.splitLaneSize))
        }
        return digest
    }

    private func generateNonce() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: ArmorABI.nonceSize)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw MachOError.invalidData("SecRandomCopyBytes failed: \(status)")
        }
        return Data(bytes)
    }

    private func makeKeystream(key: Data, keyID: UInt32, nonce: Data, length: Int) -> Data {
        var seed = Data()
        seed.append(key)
        appendUInt32(keyID, to: &seed)
        seed.append(nonce)

        var block = sha256(seed)
        var output = Data()
        output.reserveCapacity(length)

        while output.count < length {
            let remaining = length - output.count
            output.append(block.prefix(remaining))
            if output.count < length {
                block = sha256(block)
            }
        }
        return output
    }

    private func xor(_ lhs: Data, _ rhs: Data) -> Data {
        Data(zip(lhs, rhs).map(^))
    }

    private func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    private func appendUInt32(_ value: UInt32, to data: inout Data) {
        var littleEndian = value.littleEndian
        withUnsafeBytes(of: &littleEndian) { data.append(contentsOf: $0) }
    }

    private func stableKeyID(segment: String, section: String) -> UInt32 {
        let bytes = Array("\(segment).\(section)".utf8)
        var hash: UInt32 = 2166136261
        for byte in bytes {
            hash ^= UInt32(byte)
            hash &*= 16777619
        }
        return hash
    }

    private func anchorBoundAccumulator(
        whitebox: ArmorWhiteBoxBundle,
        fullAnchorHash: Data,
        integrityHash: Data
    ) -> UInt64 {
        var digest = Data()
        digest.append(fullAnchorHash)
        digest.append(integrityHash)
        let accDigest = sha256(digest)
        let accSeed = whitebox.prf(domain: .anchorAccumulatorSeed, input: accDigest)
        let value = ArmorWhiteBox.littleEndianUInt64(from: accSeed)
        return ArmorWhiteBox.rotl64(value, by: Int(TextArmorSeed.accumulatorRotation))
    }

    private func deriveLoaderKey(
        whitebox: ArmorWhiteBoxBundle,
        fullAnchorHash: Data,
        integrityHash: Data,
        anchorAccumulator: UInt64
    ) -> Data {
        var digest = Data()
        digest.append(fullAnchorHash)
        digest.append(integrityHash)
        ArmorWhiteBox.appendLittleEndian(anchorAccumulator, to: &digest)
        let loaderDigest = sha256(digest)
        return whitebox.prf(domain: .loaderKey, input: loaderDigest)
    }

}

/// Text __TEXT encryption section keys: `chained_key XOR WB_PRF(loader domain, SHA256(mask_ctx))`.
/// Must stay byte-compatible with CRiskCore `cprisk_text_derive_section_key_i` (cprisk_text_encrypt.c).
enum TextSectionKeyDerivation {
    static func derive(
        parentKey: Data,
        sectionIndex: UInt32,
        nonce: Data,
        depth: UInt32,
        whitebox: ArmorWhiteBoxBundle
    ) -> Data {
        precondition(parentKey.count == ArmorABI.keySize, "parentKey must be 32 bytes")
        precondition(nonce.count == ArmorABI.nonceSize, "nonce must be 8 bytes")

        var material = Data()
        var sectionLe = sectionIndex.littleEndian
        withUnsafeBytes(of: &sectionLe) { material.append(contentsOf: $0) }
        material.append(nonce)

        var derived = ArmorABI.hmacSHA256(key: parentKey, message: material)
        if depth > 1 {
            for d in 1..<depth {
                derived = ArmorABI.hmacSHA256(
                    key: derived,
                    message: Data("cprisk.chained.v1.".utf8)
                )
                var depthMaterial = derived
                depthMaterial.append(UInt8(d))
                derived = ArmorABI.hmacSHA256(key: depthMaterial, message: depthMaterial)
            }
        }

        var maskMsg = Data()
        maskMsg.append(Data("CPRISK_WB_TEXT_MASK_v1".utf8))
        var sectionLe2 = sectionIndex.littleEndian
        withUnsafeBytes(of: &sectionLe2) { maskMsg.append(contentsOf: $0) }
        maskMsg.append(nonce)
        let maskIn = Data(SHA256.hash(data: maskMsg))
        let wbOut = whitebox.prf(domain: .loaderKey, input: maskIn)
        return Data(zip(derived, wbOut).map(^))
    }
}

private enum TextEncryption {
    static let magic: UInt32 = 0x45545043 /* "CPTE" LE */
    static let abiVersion: UInt32 = 1
    static let sectionName = ArmorABI.Sections.textEncryption
    static let sectionIndexBase: UInt32 = 100_000

    struct Header {
        let count: UInt32

        func serialized() -> Data {
            var data = Data()
            data.appendLittleEndian(magic)
            data.appendLittleEndian(abiVersion)
            data.appendLittleEndian(count)
            data.appendLittleEndian(UInt32(0))
            return data
        }
    }

    struct Entry {
        let vmAddress: UInt64
        let size: UInt64
        let keyID: UInt32
        let flags: UInt32
        let nonce: Data
        let hmacTag: Data
        let contentHash: Data

        func serialized() -> Data {
            precondition(nonce.count == ArmorABI.nonceSize)
            precondition(hmacTag.count == ArmorABI.hashSize)
            precondition(contentHash.count == ArmorABI.hashSize)
            var data = Data()
            data.appendLittleEndian(vmAddress)
            data.appendLittleEndian(size)
            data.appendLittleEndian(keyID)
            data.appendLittleEndian(flags)
            data.append(nonce)
            data.append(hmacTag)
            data.append(contentHash)
            return data
        }
    }
}

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
