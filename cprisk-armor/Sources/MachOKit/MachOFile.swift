import Foundation

// MARK: - Errors

public enum MachOError: Error, CustomStringConvertible {
    case invalidHeader
    case invalidMagic
    case invalidLoadCommand
    case segmentNotFound(String)
    case sectionNotFound(String, String)
    case insufficientSpace
    case invalidData(String)
    case outOfBoundsRead(offset: Int, size: Int, dataSize: Int)
    case outOfBoundsWrite(offset: Int, size: Int, dataSize: Int)
    case integerOverflow(String)
    case malformedLoadCommands(String)
    case unsupportedMutation(String)
    case validationFailed(String)

    public var description: String {
        switch self {
        case .invalidHeader: return "Invalid Mach-O header"
        case .invalidMagic: return "Invalid Mach-O magic (expected MH_MAGIC_64)"
        case .invalidLoadCommand: return "Invalid load command"
        case .segmentNotFound(let name): return "Segment not found: \(name)"
        case .sectionNotFound(let seg, let sec): return "Section not found: \(seg),\(sec)"
        case .insufficientSpace: return "Insufficient space in load commands area for new section header"
        case .invalidData(let msg): return "Invalid data: \(msg)"
        case .outOfBoundsRead(let offset, let size, let dataSize):
            return "Out-of-bounds read at offset \(offset) for \(size) bytes (data size: \(dataSize))"
        case .outOfBoundsWrite(let offset, let size, let dataSize):
            return "Out-of-bounds write at offset \(offset) for \(size) bytes (data size: \(dataSize))"
        case .integerOverflow(let context):
            return "Integer overflow while processing \(context)"
        case .malformedLoadCommands(let msg):
            return "Malformed load commands: \(msg)"
        case .unsupportedMutation(let msg):
            return "Unsupported Mach-O mutation: \(msg)"
        case .validationFailed(let msg):
            return "Mach-O validation failed: \(msg)"
        }
    }
}

// MARK: - Data Reading Helpers (internal to MachOKit)

extension Data {
    fileprivate func checkedRange(at offset: Int, size: Int, forWrite: Bool) throws -> Range<Int> {
        guard offset >= 0, size >= 0 else {
            if forWrite {
                throw MachOError.outOfBoundsWrite(offset: offset, size: size, dataSize: count)
            }
            throw MachOError.outOfBoundsRead(offset: offset, size: size, dataSize: count)
        }

        let (end, overflow) = offset.addingReportingOverflow(size)
        guard !overflow, end <= count else {
            if forWrite {
                throw MachOError.outOfBoundsWrite(offset: offset, size: size, dataSize: count)
            }
            throw MachOError.outOfBoundsRead(offset: offset, size: size, dataSize: count)
        }

        return offset..<end
    }

    func readUInt32(at offset: Int) throws -> UInt32 {
        let range = try checkedRange(at: offset, size: MemoryLayout<UInt32>.size, forWrite: false)
        var value: UInt32 = 0
        Swift.withUnsafeMutableBytes(of: &value) { destination in
            copyBytes(to: destination, from: range)
        }
        return UInt32(littleEndian: value)
    }

    func readUInt64(at offset: Int) throws -> UInt64 {
        let range = try checkedRange(at: offset, size: MemoryLayout<UInt64>.size, forWrite: false)
        var value: UInt64 = 0
        Swift.withUnsafeMutableBytes(of: &value) { destination in
            copyBytes(to: destination, from: range)
        }
        return UInt64(littleEndian: value)
    }

    func readInt32(at offset: Int) throws -> Int32 {
        Int32(bitPattern: try readUInt32(at: offset))
    }

    /// Read a null-terminated C string from `offset`, up to `maxLength` bytes.
    func readCString(at offset: Int, maxLength: Int) throws -> String {
        guard maxLength >= 0 else {
            throw MachOError.invalidData("Negative maxLength for C string read: \(maxLength)")
        }
        guard offset >= 0, offset < count || maxLength == 0 else {
            throw MachOError.outOfBoundsRead(offset: offset, size: maxLength, dataSize: count)
        }

        let end = Swift.min(offset + maxLength, count)
        guard offset < end else { return "" }

        return withUnsafeBytes { buffer in
            var result = [UInt8]()
            for index in offset..<end {
                let byte = buffer[index]
                if byte == 0 { break }
                result.append(byte)
            }
            return String(bytes: result, encoding: .utf8) ?? ""
        }
    }
}

// MARK: - Data Writing Helpers (internal to MachOKit)

extension Data {
    mutating func writeUInt32(_ value: UInt32, at offset: Int) throws {
        let range = try checkedRange(at: offset, size: MemoryLayout<UInt32>.size, forWrite: true)
        var littleEndianValue = value.littleEndian
        let replacement = Swift.withUnsafeBytes(of: &littleEndianValue) { Data($0) }
        replaceSubrange(range, with: replacement)
    }

    mutating func writeUInt64(_ value: UInt64, at offset: Int) throws {
        let range = try checkedRange(at: offset, size: MemoryLayout<UInt64>.size, forWrite: true)
        var littleEndianValue = value.littleEndian
        let replacement = Swift.withUnsafeBytes(of: &littleEndianValue) { Data($0) }
        replaceSubrange(range, with: replacement)
    }

    mutating func writeCString(_ value: String, at offset: Int, length: Int) throws {
        guard length >= 0 else {
            throw MachOError.invalidData("Negative fixed string length: \(length)")
        }
        let bytes = Array(value.utf8)
        guard bytes.count <= length else {
            throw MachOError.invalidData("String '\(value)' exceeds fixed field of \(length) bytes")
        }

        let range = try checkedRange(at: offset, size: length, forWrite: true)
        for index in range {
            self[index] = 0
        }
        for (index, byte) in bytes.enumerated() {
            self[offset + index] = byte
        }
    }
}

// MARK: - ArmorPass Protocol

public protocol ArmorPass {
    var name: String { get }
    func execute(on file: MachOFile, config: PassConfig) throws -> PassResult
}

public struct PassConfig {
    public let verbose: Bool
    public let encryptionKey: Data?
    public let randomSeed: UInt64?

    public init(verbose: Bool = false, encryptionKey: Data? = nil, randomSeed: UInt64? = nil) {
        self.verbose = verbose
        self.encryptionKey = encryptionKey
        self.randomSeed = randomSeed
    }
}

public struct PassResult {
    public let passName: String
    public let itemsProcessed: Int
    public let bytesModified: Int
    public let details: [String]

    public init(passName: String, itemsProcessed: Int, bytesModified: Int, details: [String]) {
        self.passName = passName
        self.itemsProcessed = itemsProcessed
        self.bytesModified = bytesModified
        self.details = details
    }
}

public struct MachOValidationReport {
    public let numberOfCommands: UInt32
    public let sizeOfCommands: UInt32
    public let segmentCount: Int
    public let sectionCount: Int
    public let codeSignatureCommandCount: Int

    public init(
        numberOfCommands: UInt32,
        sizeOfCommands: UInt32,
        segmentCount: Int,
        sectionCount: Int,
        codeSignatureCommandCount: Int
    ) {
        self.numberOfCommands = numberOfCommands
        self.sizeOfCommands = sizeOfCommands
        self.segmentCount = segmentCount
        self.sectionCount = sectionCount
        self.codeSignatureCommandCount = codeSignatureCommandCount
    }
}

public struct MachOWriteValidation {
    public let outputURL: URL
    public let codeSignatureWasInvalidated: Bool
    public let report: MachOValidationReport

    public init(outputURL: URL, codeSignatureWasInvalidated: Bool, report: MachOValidationReport) {
        self.outputURL = outputURL
        self.codeSignatureWasInvalidated = codeSignatureWasInvalidated
        self.report = report
    }
}

// MARK: - Symbol Table Types

public struct SymbolTableInfo {
    public let symoff: UInt32
    public let nsyms: UInt32
    public let stroff: UInt32
    public let strsize: UInt32

    public init(symoff: UInt32, nsyms: UInt32, stroff: UInt32, strsize: UInt32) {
        self.symoff = symoff
        self.nsyms = nsyms
        self.stroff = stroff
        self.strsize = strsize
    }
}

public struct Nlist64Entry {
    public let fileOffset: Int
    public let n_strx: UInt32
    public let n_type: UInt8
    public let n_sect: UInt8
    public let n_desc: Int16
    public let n_value: UInt64

    public static let N_STAB: UInt8 = 0xE0
    public static let N_EXT: UInt8  = 0x01
    public static let N_TYPE_MASK: UInt8 = 0x0E
    public static let N_UNDF: UInt8 = 0x00
    public static let N_SECT: UInt8 = 0x0E
    public static let entrySize = 16

    public var isStab: Bool { (n_type & Self.N_STAB) != 0 }
    public var isExternal: Bool { (n_type & Self.N_EXT) != 0 }
    public var typeField: UInt8 { n_type & Self.N_TYPE_MASK }
    public var isDefinedLocal: Bool { !isStab && !isExternal && typeField == Self.N_SECT }
}

public struct SymbolEntry {
    public let nlist: Nlist64Entry
    public let name: String
    public let nameFileOffset: Int
    public let nameLength: Int
}

// MARK: - MachOFile

public final class MachOFile {
    public let url: URL
    public private(set) var data: Data
    public private(set) var header: MachOHeader
    public private(set) var loadCommands: [LoadCommand]

    public init(url: URL) throws {
        self.url = url
        self.data = try Data(contentsOf: url)

        let parsed = try Self.validateLayout(in: data)
        self.header = parsed.header
        self.loadCommands = parsed.loadCommands
    }

    // MARK: - Segment / Section Access

    public func segments() throws -> [Segment] {
        try loadCommands.compactMap { command in
            guard command.cmd == LoadCommand.LC_SEGMENT_64 else { return nil }
            return try Segment(from: data, commandOffset: command.offset)
        }
    }

    public func segment(named name: String) throws -> Segment? {
        try segments().first { $0.name == name }
    }

    public func section(segment segName: String, section secName: String) throws -> Section? {
        try self.segment(named: segName)?.sections.first { $0.sectionName == secName }
    }

    // MARK: - Symbol Table (LC_SYMTAB) Access

    /// Parse the LC_SYMTAB load command and return offsets/counts.
    public func findSymbolTable() throws -> SymbolTableInfo? {
        guard let cmd = loadCommands.first(where: { $0.cmd == LoadCommand.LC_SYMTAB }) else {
            return nil
        }
        let off = Int(cmd.offset)
        guard cmd.cmdSize >= 24 else {
            throw MachOError.invalidData("LC_SYMTAB command too small (\(cmd.cmdSize) < 24)")
        }
        let symoff = try data.readUInt32(at: off + 8)
        let nsyms = try data.readUInt32(at: off + 12)
        let stroff = try data.readUInt32(at: off + 16)
        let strsize = try data.readUInt32(at: off + 20)
        return SymbolTableInfo(symoff: symoff, nsyms: nsyms, stroff: stroff, strsize: strsize)
    }

    /// Read all symbol entries from the nlist64 array with their resolved names.
    public func readSymbols() throws -> [SymbolEntry] {
        guard let symtab = try findSymbolTable() else { return [] }

        let symoff = Int(symtab.symoff)
        let nsyms = Int(symtab.nsyms)
        let stroff = Int(symtab.stroff)
        let strsize = Int(symtab.strsize)

        guard symoff >= 0, nsyms >= 0 else { return [] }
        let tableEnd = symoff + nsyms * Nlist64Entry.entrySize
        guard tableEnd <= data.count else {
            throw MachOError.outOfBoundsRead(offset: symoff, size: nsyms * Nlist64Entry.entrySize, dataSize: data.count)
        }
        guard stroff >= 0, stroff + strsize <= data.count else {
            throw MachOError.outOfBoundsRead(offset: stroff, size: strsize, dataSize: data.count)
        }

        var results = [SymbolEntry]()
        results.reserveCapacity(nsyms)

        for i in 0..<nsyms {
            let entryOffset = symoff + i * Nlist64Entry.entrySize
            let n_strx = try data.readUInt32(at: entryOffset)
            let n_type = data[entryOffset + 4]
            let n_sect = data[entryOffset + 5]
            let descLow = UInt16(data[entryOffset + 6])
            let descHigh = UInt16(data[entryOffset + 7])
            let n_desc = Int16(bitPattern: descLow | (descHigh << 8))
            let n_value = try data.readUInt64(at: entryOffset + 8)

            let nlist = Nlist64Entry(
                fileOffset: entryOffset,
                n_strx: n_strx,
                n_type: n_type,
                n_sect: n_sect,
                n_desc: n_desc,
                n_value: n_value
            )

            let nameFileOffset = stroff + Int(n_strx)
            let maxLen = Swift.min(4096, stroff + strsize - Int(n_strx))
            let name: String
            let nameLength: Int
            if Int(n_strx) < strsize, nameFileOffset < data.count, maxLen > 0 {
                name = try data.readCString(at: nameFileOffset, maxLength: maxLen)
                nameLength = name.utf8.count
            } else {
                name = ""
                nameLength = 0
            }

            results.append(SymbolEntry(
                nlist: nlist,
                name: name,
                nameFileOffset: nameFileOffset,
                nameLength: nameLength
            ))
        }

        return results
    }

    /// Overwrite a symbol's name bytes in the string table with replacement data.
    /// The replacement must be exactly `entry.nameLength` bytes (does not touch the null terminator).
    public func obfuscateSymbolName(_ entry: SymbolEntry, with replacement: Data) throws {
        guard replacement.count == entry.nameLength else {
            throw MachOError.invalidData(
                "Replacement length \(replacement.count) != symbol name length \(entry.nameLength)"
            )
        }
        guard entry.nameLength > 0 else { return }
        try replaceBytes(at: UInt64(entry.nameFileOffset), with: replacement)
    }

    // MARK: - C String Scanning

    /// Scan __TEXT.__cstring and return all null-terminated C strings with their file offsets.
    public func findCStrings() throws -> [(offset: UInt64, value: String)] {
        guard let cStringSection = try section(segment: "__TEXT", section: "__cstring") else {
            return []
        }

        let content = try cStringSection.readContent(from: data)
        guard !content.isEmpty else { return [] }

        var results = [(offset: UInt64, value: String)]()
        var position = 0

        while position < content.count {
            var end = position
            while end < content.count && content[end] != 0 {
                end += 1
            }

            if end > position {
                let stringData = content.subdata(in: position..<end)
                if let string = String(data: stringData, encoding: .utf8) {
                    let fileOffset = UInt64(cStringSection.offset) + UInt64(position)
                    results.append((offset: fileOffset, value: string))
                }
            }

            position = end + 1
        }

        return results
    }

    // MARK: - Swift Type Metadata Scanning

    /// Scan __TEXT.__swift5_types and resolve type descriptors via relative pointers.
    public func findSwiftTypeMetadata() throws -> [SwiftTypeMetadata] {
        guard let typesSection = try section(segment: "__TEXT", section: "__swift5_types") else {
            return []
        }

        let sectionFileOffset = Int(typesSection.offset)
        let entryCount = Int(typesSection.size) / 4
        var results = [SwiftTypeMetadata]()

        for index in 0..<entryCount {
            let entryFileOffset = sectionFileOffset + index * 4
            let relativePointer = try data.readInt32(at: entryFileOffset)
            let descriptorFileOffset = entryFileOffset + Int(relativePointer)

            guard descriptorFileOffset >= 0, descriptorFileOffset + 12 <= data.count else { continue }

            let nameFieldOffset = descriptorFileOffset + 8
            let nameRelativePointer = try data.readInt32(at: nameFieldOffset)
            let nameFileOffset = nameFieldOffset + Int(nameRelativePointer)

            guard nameFileOffset >= 0, nameFileOffset < data.count else { continue }

            // Scan until \0 to get full type name; cap at 4096 to avoid pathological inputs.
            let maxLen = Swift.min(4096, data.count - nameFileOffset)
            let name = try data.readCString(at: nameFileOffset, maxLength: maxLen)
            results.append(SwiftTypeMetadata(
                offset: UInt64(descriptorFileOffset),
                nameOffset: UInt64(nameFileOffset),
                name: name,
                isPublic: !name.hasPrefix("_")
            ))
        }

        return results
    }

    // MARK: - Mutation

    public func replaceBytes(at offset: UInt64, with bytes: Data) throws {
        guard offset <= UInt64(Int.max) else {
            throw MachOError.integerOverflow("replaceBytes offset")
        }
        try MachOWriter.replaceBytes(in: &data, at: Int(offset), with: bytes)
    }

    public func insertSection(_ section: Section, inSegment segmentName: String) throws {
        try MachOWriter.insertSectionHeader(in: &data, section: section, segmentName: segmentName)
        try reparse()
    }

    @discardableResult
    public func addOrUpdateSection(
        segment segmentName: String,
        section sectionName: String,
        content: Data,
        align: UInt32 = 2,
        flags: UInt32 = 0
    ) throws -> Section {
        if let existing = try section(segment: segmentName, section: sectionName) {
            guard content.count <= Int(existing.size) else {
                throw MachOError.invalidData(
                    "Existing section \(segmentName).\(sectionName) is too small for updated content"
                )
            }

            var replacement = content
            if replacement.count < Int(existing.size) {
                replacement.append(Data(repeating: 0, count: Int(existing.size) - replacement.count))
            }
            try replaceBytes(at: UInt64(existing.offset), with: replacement)
            return existing
        }

        let targetSegment = try segment(named: segmentName)
        guard let targetSegment else {
            throw MachOError.segmentNotFound(segmentName)
        }

        let alignment = try Self.alignmentValue(fromExponent: align)
        if let placement = Self.findAvailableRange(in: targetSegment, contentLength: content.count, alignment: alignment) {
            try replaceBytes(at: UInt64(placement.fileOffset), with: content)
            let newSection = Section(
                sectionName: sectionName,
                segmentName: segmentName,
                address: placement.vmAddress,
                size: UInt64(content.count),
                offset: UInt32(placement.fileOffset),
                align: align,
                relocationOffset: 0,
                numberOfRelocations: 0,
                flags: flags,
                reserved1: 0,
                reserved2: 0,
                reserved3: 0
            )
            try insertSection(newSection, inSegment: segmentName)
            return newSection
        }

        let appendedSection = try MachOWriter.addSection(
            to: &data,
            segment: segmentName,
            section: sectionName,
            content: content,
            protection: targetSegment.initProt,
            flags: flags
        )
        try reparse()
        return appendedSection
    }

    @discardableResult
    public func validateStructure() throws -> MachOValidationReport {
        let parsed = try Self.validateLayout(in: data)
        header = parsed.header
        loadCommands = parsed.loadCommands
        return parsed.report
    }

    // MARK: - Write

    @discardableResult
    public func write(to url: URL, validateRoundTrip: Bool = true) throws -> MachOWriteValidation {
        let codeSignatureWasInvalidated = try MachOWriter.invalidateCodeSignatureIfPresent(in: &data)
        let inMemoryReport = try validateStructure()
        try data.write(to: url)

        guard validateRoundTrip else {
            return MachOWriteValidation(
                outputURL: url,
                codeSignatureWasInvalidated: codeSignatureWasInvalidated,
                report: inMemoryReport
            )
        }

        let reparsed = try MachOFile(url: url)
        let roundTripReport = try reparsed.validateStructure()
        return MachOWriteValidation(
            outputURL: url,
            codeSignatureWasInvalidated: codeSignatureWasInvalidated,
            report: roundTripReport
        )
    }

    // MARK: - Internal

    private func reparse() throws {
        let parsed = try Self.validateLayout(in: data)
        header = parsed.header
        loadCommands = parsed.loadCommands
    }

    private static func parseLoadCommands(from data: Data, header: MachOHeader) throws -> [LoadCommand] {
        let loadCommandsEnd = try loadCommandsRegionEnd(header: header, dataSize: data.count)
        var commands = [LoadCommand]()
        var offset = MachOHeader.size

        for index in 0..<Int(header.numberOfCommands) {
            guard offset + 8 <= loadCommandsEnd else {
                throw MachOError.malformedLoadCommands("command #\(index) header exceeds load-commands region")
            }

            let command = try LoadCommand(from: data, offset: UInt64(offset))
            let nextOffset = try checkedAdd(offset, Int(command.cmdSize), context: "load command #\(index) advance")
            guard nextOffset <= loadCommandsEnd else {
                throw MachOError.malformedLoadCommands("command #\(index) extends beyond sizeofcmds")
            }
            commands.append(command)
            offset = nextOffset
        }

        guard offset == loadCommandsEnd else {
            throw MachOError.malformedLoadCommands(
                "sizeofcmds mismatch: parsed \(offset - MachOHeader.size) bytes, header advertises \(header.sizeOfCommands)"
            )
        }

        return commands
    }

    private static func validateLayout(in data: Data) throws -> (
        header: MachOHeader,
        loadCommands: [LoadCommand],
        report: MachOValidationReport
    ) {
        guard data.count >= MachOHeader.size else {
            throw MachOError.invalidHeader
        }

        let header = try MachOHeader(from: data)
        guard header.isValid else {
            throw MachOError.invalidMagic
        }

        let loadCommands = try parseLoadCommands(from: data, header: header)
        var segmentCount = 0
        var sectionCount = 0
        var codeSignatureCommandCount = 0

        for command in loadCommands {
            if command.cmd == LoadCommand.LC_SEGMENT_64 {
                segmentCount += 1
                let segment = try Segment(from: data, commandOffset: command.offset)
                sectionCount += segment.sections.count
                try validateSections(of: segment, dataSize: data.count)
            } else if command.cmd == LoadCommand.LC_CODE_SIGNATURE {
                codeSignatureCommandCount += 1
                try validateLinkeditDataCommand(in: data, command: command, commandName: "LC_CODE_SIGNATURE")
            }
        }

        let report = MachOValidationReport(
            numberOfCommands: header.numberOfCommands,
            sizeOfCommands: header.sizeOfCommands,
            segmentCount: segmentCount,
            sectionCount: sectionCount,
            codeSignatureCommandCount: codeSignatureCommandCount
        )
        return (header: header, loadCommands: loadCommands, report: report)
    }

    private static func validateSections(of segment: Segment, dataSize: Int) throws {
        let segmentFileEnd = try checkedAdd(segment.fileOffset, segment.fileSize, context: "segment \(segment.name) file extent")

        for section in segment.sections where section.storesDataInFile && section.size > 0 {
            let sectionStart = UInt64(section.offset)
            let sectionEnd = try checkedAdd(sectionStart, section.size, context: "section \(segment.name),\(section.sectionName) extent")

            guard sectionEnd <= UInt64(dataSize) else {
                throw MachOError.validationFailed(
                    "section \(segment.name),\(section.sectionName) exceeds file size (\(sectionEnd) > \(dataSize))"
                )
            }
            guard sectionStart >= segment.fileOffset else {
                throw MachOError.validationFailed("section \(segment.name),\(section.sectionName) starts before segment file range")
            }
            guard sectionEnd <= segmentFileEnd else {
                throw MachOError.validationFailed("section \(segment.name),\(section.sectionName) extends past segment file range")
            }
        }
    }

    private static func validateLinkeditDataCommand(in data: Data, command: LoadCommand, commandName: String) throws {
        guard command.cmdSize >= 16 else {
            throw MachOError.invalidData("\(commandName) command too small: \(command.cmdSize)")
        }

        let commandOffset = Int(command.offset)
        let dataOffset = try data.readUInt32(at: commandOffset + 8)
        let dataSize = try data.readUInt32(at: commandOffset + 12)

        guard dataSize == 0 else {
            let end = try checkedAdd(Int(dataOffset), Int(dataSize), context: "\(commandName) data extent")
            guard end <= data.count else {
                throw MachOError.validationFailed("\(commandName) blob extends past end of file")
            }
            return
        }

        guard dataOffset == 0 else {
            throw MachOError.validationFailed("\(commandName) has zero size but non-zero data offset")
        }
    }

    private static func loadCommandsRegionEnd(header: MachOHeader, dataSize: Int) throws -> Int {
        let end = try checkedAdd(MachOHeader.size, Int(header.sizeOfCommands), context: "load commands extent")
        guard end <= dataSize else {
            throw MachOError.malformedLoadCommands("sizeofcmds (\(header.sizeOfCommands)) exceeds file size \(dataSize)")
        }
        return end
    }

    private static func alignUp(_ value: Int, to alignment: Int) throws -> Int {
        guard alignment > 0 else {
            throw MachOError.invalidData("Alignment must be positive")
        }
        guard alignment == 1 || alignment.nonzeroBitCount == 1 else {
            throw MachOError.invalidData("Alignment \(alignment) must be a power of two")
        }

        let mask = alignment - 1
        let (summed, overflow) = value.addingReportingOverflow(mask)
        guard !overflow else {
            throw MachOError.integerOverflow("alignment calculation")
        }
        return summed & ~mask
    }

    private static func alignmentValue(fromExponent exponent: UInt32) throws -> Int {
        guard exponent < 31 else {
            throw MachOError.unsupportedMutation("Alignment exponent \(exponent) is too large")
        }
        return 1 << exponent
    }

    private static func findAvailableRange(
        in segment: Segment,
        contentLength: Int,
        alignment: Int
    ) -> (fileOffset: Int, vmAddress: UInt64)? {
        guard contentLength > 0 else { return nil }
        guard segment.fileOffset <= UInt64(Int.max), segment.fileSize <= UInt64(Int.max) else {
            return nil
        }
        let segStart = Int(segment.fileOffset)
        let segSize = Int(segment.fileSize)
        let (segEnd, segOverflow) = segStart.addingReportingOverflow(segSize)
        guard !segOverflow, segEnd > segStart else { return nil }

        let occupied: [(start: Int, end: Int)] = segment.sections.compactMap { section in
            guard section.offset <= UInt64(Int.max), section.size <= UInt64(Int.max) else {
                return nil
            }
            let start = Int(section.offset)
            let sizeInt = Int(section.size)
            let (end, overflow) = start.addingReportingOverflow(sizeInt)
            guard !overflow, section.storesDataInFile, section.size > 0, start >= segStart, end <= segEnd else {
                return nil
            }
            return (start, end)
        }.sorted { $0.start < $1.start }

        var cursor = segStart
        for range in occupied {
            guard let aligned = try? alignUp(cursor, to: alignment) else { return nil }
            if aligned + contentLength <= range.start {
                let delta = aligned - segStart
                return (aligned, segment.vmAddress + UInt64(delta))
            }
            cursor = max(cursor, range.end)
        }

        guard let alignedTail = try? alignUp(cursor, to: alignment) else { return nil }
        if alignedTail + contentLength <= segEnd {
            let delta = alignedTail - segStart
            return (alignedTail, segment.vmAddress + UInt64(delta))
        }

        return nil
    }

    private static func checkedAdd(_ lhs: Int, _ rhs: Int, context: String) throws -> Int {
        let (result, overflow) = lhs.addingReportingOverflow(rhs)
        guard !overflow else {
            throw MachOError.integerOverflow(context)
        }
        return result
    }

    private static func checkedAdd(_ lhs: UInt64, _ rhs: UInt64, context: String) throws -> UInt64 {
        let (result, overflow) = lhs.addingReportingOverflow(rhs)
        guard !overflow else {
            throw MachOError.integerOverflow(context)
        }
        return result
    }
}
