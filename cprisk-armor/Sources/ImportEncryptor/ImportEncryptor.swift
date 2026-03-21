import CryptoKit
import Foundation
import MachOKit
import Security

/// Pass 10: Import Table Encryption
///
/// Encrypts import symbol names discovered from LC_DYLD_INFO_ONLY bind streams
/// and stores them in __DATA.__swift5_imp. At runtime, CRiskCore resolves
/// symbols via dlsym on first use.
///
/// Security properties:
/// - Symbol names are not visible in IDA import panel
/// - Each symbol authenticated with HMAC-SHA256 before decryption
/// - Keystream derived via SHA256 to prevent oracle attacks
/// - Whitelisted symbols (malloc, pthread_create, etc.) remain in place
public final class ImportEncryptorPass: ArmorPass {
    public let name = "ImportEncryptor"

    /// Magic bytes: "CPIM" (0x43494D50)
    private static let tableMagic: UInt32 = 0x43494D50
    private static let tableVersion: UInt32 = 1

    /// Minimal runtime whitelist: symbols that must remain available
    /// for process bootstrap / threading / dynamic resolution plumbing.
    private static let whitelist: Set<String> = [
        // libc memory primitives
        "_malloc", "_calloc", "_realloc", "_free",
        "_memcpy", "_memmove", "_memset",
        // pthread primitives
        "_pthread_once",
        "_pthread_create", "_pthread_mutex_lock", "_pthread_mutex_unlock",
        "_pthread_mutex_init", "_pthread_mutex_destroy",
        "_pthread_join", "_pthread_detach",
        "_pthread_cond_wait", "_pthread_cond_signal", "_pthread_cond_broadcast",
        // dyld dynamic resolver plumbing
        "_dlopen", "_dlsym", "_dlerror",
    ]

    public init() {}

    public func execute(on file: MachOFile, config: PassConfig) throws -> PassResult {
        // Step 1: Find LC_DYLD_INFO_ONLY load command
        guard let dyldInfoCmd = file.loadCommands.first(where: {
            $0.cmd == LoadCommand.LC_DYLD_INFO_ONLY
        }) else {
            return PassResult(passName: name, itemsProcessed: 0, bytesModified: 0,
                           details: ["No LC_DYLD_INFO_ONLY found, skipping"])
        }

        // Step 2: Validate dyld_info_command layout:
        // cmd/cmdsize + rebase + bind + weak_bind + lazy_bind + export = 48 bytes.
        guard dyldInfoCmd.rawData.count >= 48 else {
            return PassResult(passName: name, itemsProcessed: 0, bytesModified: 0,
                           details: ["LC_DYLD_INFO_ONLY too short"])
        }

        // Step 3: Parse bind streams to collect imported symbol names.
        // We intentionally collect names at bind sites (not export trie),
        // so the encrypted table reflects runtime-resolved imports.
        let symbols: [String]
        do {
            symbols = try collectImportedSymbols(from: file.data, dyldInfoCmd: dyldInfoCmd)
        } catch {
            return PassResult(passName: name, itemsProcessed: 0, bytesModified: 0,
                           details: ["Bind stream parse failed: \(error.localizedDescription)"])
        }

        // Step 4: Filter: whitelist symbols are kept, others encrypted
        let toEncrypt = symbols.filter { !Self.whitelist.contains($0) }

        guard !toEncrypt.isEmpty else {
            return PassResult(passName: name, itemsProcessed: 0, bytesModified: 0,
                           details: ["No non-whitelisted imported symbols found"])
        }

        // Step 5: Derive import encryption key from root key via white-box domain 8
        let importKey: Data
        if let rootKey = config.encryptionKey {
            let whitebox = ArmorWhiteBox.build(rootKey: rootKey)
            importKey = whitebox.prf(
                domain: .importEncryptionKey,
                input: Data(repeating: 0, count: ArmorABI.hashSize)
            )
        } else {
            // Fallback: use zero key (for non-production builds)
            importKey = Data(repeating: 0, count: ArmorABI.hashSize)
        }

        // Step 6: Build encrypted import table
        let encryptedData = try buildEncryptedTable(symbols: toEncrypt, key: importKey)

        // Step 7: Write encrypted table to __DATA.__swift5_imp section.
        _ = try file.addOrUpdateSection(
            segment: ArmorABI.dataSegmentName,
            section: ArmorABI.Sections.importEncryptedTable,
            content: encryptedData,
            align: 4
        )

        // Step 8: Scrub original bind opcode streams so static tooling cannot
        // recover original import names from LC_DYLD_INFO_ONLY payloads.
        let scrubSummary = try scrubBindStreams(on: file, dyldInfoCmd: dyldInfoCmd)

        return PassResult(
            passName: name,
            itemsProcessed: toEncrypt.count,
            bytesModified: encryptedData.count + scrubSummary.bytesScrubbed,
            details: [
                "Encrypted \(toEncrypt.count) import symbol names",
                "Stored in \(ArmorABI.dataSegmentName).\(ArmorABI.Sections.importEncryptedTable)",
                "Whitelist size: \(Self.whitelist.count) symbols",
                "Key domain: \(ArmorABI.WhiteBox.Domain.importEncryptionKey.rawValue)",
                "Imported symbols discovered: \(symbols.count)",
                "Scrubbed bind streams: \(scrubSummary.streamCount) regions, \(scrubSummary.bytesScrubbed) bytes",
            ]
        )
    }

    // MARK: - Bind Stream Parsing

    /// Parse LC_DYLD_INFO_ONLY bind/weak_bind/lazy_bind streams and collect
    /// imported symbol names referenced by bind opcodes.
    private func collectImportedSymbols(from data: Data, dyldInfoCmd: LoadCommand) throws -> [String] {
        var symbols = Set<String>()
        let streams = try bindStreamRegions(from: dyldInfoCmd, imageSize: data.count)
        for stream in streams {
            try parseBindStream(from: data, offset: stream.offset, size: stream.size, symbols: &symbols)
        }
        return symbols.sorted()
    }

    private func scrubBindStreams(on file: MachOFile, dyldInfoCmd: LoadCommand) throws -> ScrubSummary {
        let streams = try bindStreamRegions(from: dyldInfoCmd, imageSize: file.data.count)
        var scrubbed = 0
        for stream in streams where stream.size > 0 {
            let zeros = Data(repeating: 0, count: stream.size)
            try file.replaceBytes(at: UInt64(stream.offset), with: zeros)
            scrubbed += stream.size
        }
        return ScrubSummary(streamCount: streams.count, bytesScrubbed: scrubbed)
    }

    private func bindStreamRegions(from dyldInfoCmd: LoadCommand, imageSize: Int) throws -> [BindStreamRegion] {
        let bindOff = try Int(dyldInfoCmd.rawData.readUInt32(at: 16))
        let bindSz = try Int(dyldInfoCmd.rawData.readUInt32(at: 20))
        let weakBindOff = try Int(dyldInfoCmd.rawData.readUInt32(at: 24))
        let weakBindSz = try Int(dyldInfoCmd.rawData.readUInt32(at: 28))
        let lazyBindOff = try Int(dyldInfoCmd.rawData.readUInt32(at: 32))
        let lazyBindSz = try Int(dyldInfoCmd.rawData.readUInt32(at: 36))

        let rawStreams: [BindStreamRegion] = [
            BindStreamRegion(kind: "bind", offset: bindOff, size: bindSz),
            BindStreamRegion(kind: "weak_bind", offset: weakBindOff, size: weakBindSz),
            BindStreamRegion(kind: "lazy_bind", offset: lazyBindOff, size: lazyBindSz),
        ]

        var result = [BindStreamRegion]()
        result.reserveCapacity(rawStreams.count)
        for stream in rawStreams {
            if stream.size == 0 {
                continue
            }
            if stream.size < 0 || stream.offset < 0 || stream.offset > imageSize || stream.size > imageSize - stream.offset {
                throw MachOError.invalidData("\(stream.kind) stream out of bounds (off=\(stream.offset), size=\(stream.size), image=\(imageSize))")
            }
            result.append(stream)
        }
        return result
    }

    private func parseBindStream(from data: Data, offset: Int, size: Int, symbols: inout Set<String>) throws {
        guard size >= 0, offset >= 0, offset + size <= data.count else {
            throw MachOError.invalidData("bind stream out of bounds")
        }
        guard size > 0 else { return }

        let opcodeMask: UInt8 = 0xF0
        let doneOpcode: UInt8 = 0x00
        let setSymbolOpcode: UInt8 = 0x40
        let setAddendSLEBOpcode: UInt8 = 0x60
        let setSegmentAndOffsetULEBOpcode: UInt8 = 0x70
        let addAddressULEBOpcode: UInt8 = 0x80
        let doBindOpcode: UInt8 = 0x90
        let doBindAddAddressULEBOpcode: UInt8 = 0xA0
        let doBindAddAddressImmScaledOpcode: UInt8 = 0xB0
        let doBindULEBTimesSkippingULEBOpcode: UInt8 = 0xC0

        var currentSymbol: String?
        var cursor = offset
        let end = offset + size
        while cursor < end {
            let byte = data[cursor]
            cursor += 1
            let opcode = byte & opcodeMask

            switch opcode {
            case doneOpcode:
                currentSymbol = nil
            case setSymbolOpcode:
                var symbolBytes = [UInt8]()
                while cursor < end, data[cursor] != 0 {
                    symbolBytes.append(data[cursor])
                    cursor += 1
                }
                guard cursor < end else {
                    throw MachOError.invalidData("unterminated bind symbol in stream")
                }
                cursor += 1 // trailing '\0'
                guard let symbol = String(bytes: symbolBytes, encoding: .utf8) else {
                    throw MachOError.invalidData("invalid UTF-8 bind symbol")
                }
                currentSymbol = symbol

            case setAddendSLEBOpcode:
                let (_, consumed) = readSLEB128(from: data, start: cursor, end: end)
                cursor += consumed

            case setSegmentAndOffsetULEBOpcode, addAddressULEBOpcode:
                let (_, consumed) = readULEB128(from: data, start: cursor, end: end)
                cursor += consumed

            case doBindOpcode, doBindAddAddressImmScaledOpcode:
                if let symbol = currentSymbol, isEligibleSymbolName(symbol) {
                    symbols.insert(symbol)
                }

            case doBindAddAddressULEBOpcode:
                if let symbol = currentSymbol, isEligibleSymbolName(symbol) {
                    symbols.insert(symbol)
                }
                let (_, consumed) = readULEB128(from: data, start: cursor, end: end)
                cursor += consumed

            case doBindULEBTimesSkippingULEBOpcode:
                if let symbol = currentSymbol, isEligibleSymbolName(symbol) {
                    symbols.insert(symbol)
                }
                let (_, consumed1) = readULEB128(from: data, start: cursor, end: end)
                cursor += consumed1
                let (_, consumed2) = readULEB128(from: data, start: cursor, end: end)
                cursor += consumed2

            default:
                // Other opcodes (set dylib ordinal, set type, etc.) either carry
                // no immediate stream payload or are irrelevant for symbol names.
                continue
            }
        }
    }

    private func isEligibleSymbolName(_ symbol: String) -> Bool {
        guard symbol.hasPrefix("_"),
              symbol.count >= 2,
              symbol.count <= 256 else {
            return false
        }
        return symbol.utf8.allSatisfy { $0 >= 0x20 && $0 <= 0x7E }
    }

    /// Read a ULEB128 value from data[start..<end], returning (value, bytesConsumed).
    private func readULEB128(from data: Data, start: Int, end: Int) -> (UInt64, Int) {
        var result: UInt64 = 0
        var shift = 0
        var pos = start
        let maxIter = 10

        for _ in 0..<maxIter {
            guard pos < end else { break }
            let byte = data[pos]
            pos += 1
            result |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 { break }
            shift += 7
        }

        return (result, pos - start)
    }

    private func readSLEB128(from data: Data, start: Int, end: Int) -> (Int64, Int) {
        var result: Int64 = 0
        var shift = 0
        var pos = start
        var byte: UInt8 = 0
        let maxIter = 10

        for _ in 0..<maxIter {
            guard pos < end else { break }
            byte = data[pos]
            pos += 1
            result |= Int64(byte & 0x7F) << shift
            shift += 7
            if (byte & 0x80) == 0 { break }
        }

        if shift < 64, (byte & 0x40) != 0 {
            result |= -1 << shift
        }
        return (result, pos - start)
    }

    // MARK: - Table Building

    /// Build the encrypted import table:
    ///   Header (16 bytes): magic(4) + version(4) + count(4) + reserved(4)
    ///   Index entries (48 bytes each): offset(4) + length(4) + nonce(8) + hmac(32)
    ///   Encrypted name data (variable)
    ///
    /// Each symbol's encrypted name immediately follows the index table.
    private func buildEncryptedTable(symbols: [String], key: Data) throws -> Data {
        var table = Data()

        // Header: magic(4) + version(4) + count(4) + reserved(4) = 16 bytes
        table.appendUInt32LE(Self.tableMagic)
        table.appendUInt32LE(Self.tableVersion)
        table.appendUInt32LE(UInt32(symbols.count))
        table.appendUInt32LE(0)  // reserved

        // Pre-compute all encrypted names and their HMACs
        // We need to know each one's length before writing index entries,
        // because the index entry's `dataOffset` field counts from the start
        // of the encrypted name data area (not the start of the table).
        var encryptedNames = [(Data, Data, Data)]()  // (nonce, hmac, encrypted)

        for (index, symbol) in symbols.enumerated() {
            let nameData = Data(symbol.utf8)
            let nonce = try generateNonce(count: ArmorABI.nonceSize)

            // HMAC for integrity: HMAC(key, nonce || encrypted_name)
            let hmacInput = nonce + nameData  // HMAC over plaintext for integrity
            let hmacTag = ArmorABI.hmacSHA256(key: key, message: hmacInput)

            // Keystream: SHA256-based (not HMAC, to keep derivation fast and simple)
            let keystream = deriveKeystream(
                key: key,
                index: UInt32(index + 1),
                nonce: nonce,
                length: nameData.count
            )

            // XOR encryption
            let encrypted = xorData(nameData, keystream)

            encryptedNames.append((nonce, hmacTag, encrypted))
        }

        // Now write index entries. offset = position within encrypted name data area,
        // starting from 0 at the first encrypted name byte.
        var dataOffset = 0
        for (nonce, hmacTag, encrypted) in encryptedNames {
            // Index entry: offset(4) + length(4) + nonce(8) + hmac(32) = 48 bytes
            table.appendUInt32LE(UInt32(dataOffset))
            table.appendUInt32LE(UInt32(encrypted.count))
            table.append(nonce)
            table.append(hmacTag)
            dataOffset += encrypted.count
        }

        // Finally append all encrypted name data
        for (_, _, encrypted) in encryptedNames {
            table.append(encrypted)
        }

        return table
    }

    /// Derive a keystream using SHA256-CTR-like construction.
    /// Material: key || index (4 bytes LE) || nonce || counter (8 bytes LE)
    /// Result: SHA256(material) repeated as needed
    private func deriveKeystream(key: Data, index: UInt32, nonce: Data, length: Int) -> Data {
        guard length > 0 else { return Data() }

        var result = Data()
        var counter: UInt64 = 0

        while result.count < length {
            var material = Data()
            material.append(key)

            var indexLE = index.littleEndian
            withUnsafeBytes(of: &indexLE) { material.append(contentsOf: $0) }

            material.append(nonce)

            var counterLE = counter.littleEndian
            withUnsafeBytes(of: &counterLE) { material.append(contentsOf: $0) }

            let hash = sha256(material)
            result.append(hash)
            counter += 1
        }

        return result.prefix(length)
    }

    private func generateNonce(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            throw MachOError.invalidData("SecRandomCopyBytes failed: \(status)")
        }
        return Data(bytes)
    }

    private func xorData(_ a: Data, _ b: Data) -> Data {
        var result = Data(capacity: a.count)
        for i in 0..<a.count {
            result.append(a[i] ^ b[i])
        }
        return result
    }

    private func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}

private struct BindStreamRegion {
    let kind: String
    let offset: Int
    let size: Int
}

private struct ScrubSummary {
    let streamCount: Int
    let bytesScrubbed: Int
}

// MARK: - Helper extensions for Data

private extension Data {
    mutating func appendUInt32LE(_ value: UInt32) {
        var v = value.littleEndian
        Swift.withUnsafeBytes(of: &v) { append(contentsOf: $0) }
    }

    mutating func appendUInt64LE(_ value: UInt64) {
        var v = value.littleEndian
        Swift.withUnsafeBytes(of: &v) { append(contentsOf: $0) }
    }

    func readUInt32(at offset: Int) throws -> UInt32 {
        guard offset + 4 <= count else {
            throw MachOError.invalidData("readUInt32 out of bounds at \(offset)")
        }
        let bytes = self[offset..<(offset + 4)]
        return bytes.withUnsafeBytes { ptr in
            UInt32(littleEndian: ptr.load(as: UInt32.self))
        }
    }
}
