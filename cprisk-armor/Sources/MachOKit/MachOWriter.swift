import Foundation

/// Utilities for modifying Mach-O binary data in place.
public final class MachOWriter {
    private struct SegmentCommandContext {
        let commandOffset: Int
        let commandSize: UInt32
        let segment: Segment
    }

    // MARK: - Byte-level Operations

    /// Replace bytes at a given file offset without changing the file size.
    public static func replaceBytes(in data: inout Data, at offset: Int, with replacement: Data) throws {
        guard offset >= 0 else {
            throw MachOError.outOfBoundsWrite(offset: offset, size: replacement.count, dataSize: data.count)
        }
        let (end, overflow) = offset.addingReportingOverflow(replacement.count)
        guard !overflow, end <= data.count else {
            throw MachOError.outOfBoundsWrite(offset: offset, size: replacement.count, dataSize: data.count)
        }
        data.replaceSubrange(offset..<(offset + replacement.count), with: replacement)
    }

    /// Update the ncmds and sizeofcmds fields in the mach_header_64.
    public static func updateHeader(in data: inout Data, numberOfCommands: UInt32, sizeOfCommands: UInt32) throws {
        try data.writeUInt32(numberOfCommands, at: 16)
        try data.writeUInt32(sizeOfCommands, at: 20)
    }

    // MARK: - Add Section (high-level)

    /// Append `content` to the file, create a section header inside the target segment,
    /// and update all relevant Mach-O metadata.
    ///
    /// Requires padding between the end of load commands and the first section content
    /// to hold an additional 80-byte section_64 header.
    @discardableResult
    public static func addSection(
        to data: inout Data,
        segment: String,
        section: String,
        content: Data,
        protection: UInt32
    ) throws -> Section {
        let header = try MachOHeader(from: data)
        guard header.isValid else {
            throw MachOError.invalidMagic
        }

        _ = protection

        let target = try locateSegment(in: data, header: header, named: segment)
        guard target.segment.sections.allSatisfy({ $0.sectionName != section }) else {
            throw MachOError.invalidData("Section \(segment),\(section) already exists")
        }

        let fileBackedTail = try highestFileBackedSegmentEnd(in: data, header: header)
        let targetSegmentEnd = try checkedAdd(target.segment.fileOffset, target.segment.fileSize, context: "segment \(segment) tail")
        guard targetSegmentEnd == fileBackedTail, targetSegmentEnd == UInt64(data.count) else {
            throw MachOError.unsupportedMutation(
                "Appending a new section is only supported for the last file-backed segment that reaches EOF"
            )
        }

        let alignment = try fileAlignment(forSectionAlign: target.segment.sections.last?.align ?? 0)
        let contentOffset = try align(UInt64(data.count), to: alignment)
        let paddingCount = try checkedInt(contentOffset - UInt64(data.count), context: "section padding")
        if paddingCount > 0 {
            data.append(Data(count: paddingCount))
        }
        data.append(content)

        guard target.segment.vmAddress >= target.segment.fileOffset else {
            throw MachOError.unsupportedMutation("Segment \(segment) has vmaddr < fileoff")
        }
        let addressBias = target.segment.vmAddress - target.segment.fileOffset
        let contentAddress = try checkedAdd(addressBias, UInt64(contentOffset), context: "new section vmaddr")

        let newSection = Section(
            sectionName: section, segmentName: segment,
            address: contentAddress, size: UInt64(content.count),
            offset: UInt32(contentOffset), align: target.segment.sections.last?.align ?? 0,
            relocationOffset: 0, numberOfRelocations: 0,
            flags: 0, reserved1: 0, reserved2: 0, reserved3: 0
        )

        try insertSectionHeader(in: &data, section: newSection, segmentName: segment)
        return newSection
    }

    // MARK: - Insert Section Header (low-level)

    /// Write an 80-byte section_64 header into the target segment's load command,
    /// shifting subsequent load commands into existing padding space.
    public static func insertSectionHeader(
        in data: inout Data,
        section: Section,
        segmentName: String
    ) throws {
        let header = try MachOHeader(from: data)
        guard header.isValid else {
            throw MachOError.invalidMagic
        }
        guard section.segmentName == segmentName else {
            throw MachOError.invalidData(
                "Section segment name \(section.segmentName) does not match target segment \(segmentName)"
            )
        }

        let target = try locateSegment(in: data, header: header, named: segmentName)
        guard target.segment.sections.allSatisfy({ $0.sectionName != section.sectionName }) else {
            throw MachOError.invalidData("Section \(segmentName),\(section.sectionName) already exists")
        }

        if section.storesDataInFile && section.size > 0 {
            let sectionEnd = try checkedAdd(UInt64(section.offset), section.size, context: "new section file extent")
            guard sectionEnd <= UInt64(data.count) else {
                throw MachOError.validationFailed("New section content exceeds end of file")
            }
        }
        guard section.address >= target.segment.vmAddress else {
            throw MachOError.validationFailed("New section vmaddr is before the target segment vmaddr")
        }
        guard UInt64(section.offset) >= target.segment.fileOffset else {
            throw MachOError.validationFailed("New section file offset is before the target segment file range")
        }
        let expectedAddressDelta = section.address - target.segment.vmAddress
        let expectedFileDelta = UInt64(section.offset) - target.segment.fileOffset
        guard expectedAddressDelta == expectedFileDelta else {
            throw MachOError.unsupportedMutation(
                "New section does not preserve the segment's vmaddr/fileoff mapping"
            )
        }

        // Verify padding: the area between end-of-load-commands and first section content
        // must have room for one more section_64 header (80 bytes).
        let currentLCEnd = MachOHeader.size + Int(header.sizeOfCommands)
        let neededEnd = currentLCEnd + Section.size
        let minContent = try findMinContentOffset(in: data, header: header)
        guard neededEnd <= minContent else {
            throw MachOError.insufficientSpace
        }

        let segOff = target.commandOffset
        let segEnd = segOff + Int(target.commandSize)

        // Shift any load commands after this segment to make room for the new section header.
        // This moves bytes within the load-command region into existing padding.
        if segEnd < currentLCEnd {
            let chunk = data.subdata(in: segEnd..<currentLCEnd)
            try replaceBytes(in: &data, at: segEnd + Section.size, with: chunk)
        }

        // Build and write the section header at the insert point
        let insertOffset = segOff + Segment.headerSize + Int(target.segment.numberOfSections) * Section.size
        let secHeader = try buildSectionHeaderData(section)
        try replaceBytes(in: &data, at: insertOffset, with: secHeader)

        let currentSegmentFileEnd = try checkedAdd(
            target.segment.fileOffset,
            target.segment.fileSize,
            context: "current segment file end"
        )
        let currentSegmentVMEnd = try checkedAdd(
            target.segment.vmAddress,
            target.segment.vmSize,
            context: "current segment vm end"
        )

        var updatedFileSize = target.segment.fileSize
        var updatedVMSize = target.segment.vmSize
        if section.storesDataInFile && section.size > 0 {
            let newSectionFileEnd = try checkedAdd(UInt64(section.offset), section.size, context: "new section file end")
            if UInt64(section.offset) < currentSegmentFileEnd && newSectionFileEnd > currentSegmentFileEnd {
                throw MachOError.unsupportedMutation(
                    "Partially extending an existing segment file range is not supported"
                )
            }
            if newSectionFileEnd > currentSegmentFileEnd {
                updatedFileSize = newSectionFileEnd - target.segment.fileOffset
            }
        }

        if section.size > 0 {
            let newSectionVMEnd = try checkedAdd(section.address, section.size, context: "new section vm end")
            if section.address < currentSegmentVMEnd && newSectionVMEnd > currentSegmentVMEnd {
                throw MachOError.unsupportedMutation(
                    "Partially extending an existing segment VM range is not supported"
                )
            }
            if newSectionVMEnd > currentSegmentVMEnd {
                updatedVMSize = newSectionVMEnd - target.segment.vmAddress
            }
        }

        // Update segment command: cmdsize and nsects
        try data.writeUInt32(target.commandSize + UInt32(Section.size), at: segOff + 4)
        try data.writeUInt32(target.segment.numberOfSections + 1, at: segOff + 64)
        try data.writeUInt64(updatedVMSize, at: segOff + 32)
        try data.writeUInt64(updatedFileSize, at: segOff + 48)

        // Update mach_header_64 sizeOfCommands
        try updateHeader(
            in: &data,
            numberOfCommands: header.numberOfCommands,
            sizeOfCommands: header.sizeOfCommands + UInt32(Section.size)
        )
    }

    @discardableResult
    public static func invalidateCodeSignatureIfPresent(in data: inout Data) throws -> Bool {
        let header = try MachOHeader(from: data)
        guard header.isValid else {
            throw MachOError.invalidMagic
        }

        var cmdOffset = MachOHeader.size
        var invalidated = false

        for index in 0..<Int(header.numberOfCommands) {
            let command = try LoadCommand(from: data, offset: UInt64(cmdOffset))
            if command.cmd == LoadCommand.LC_CODE_SIGNATURE {
                guard command.cmdSize >= 16 else {
                    throw MachOError.invalidData("LC_CODE_SIGNATURE command #\(index) too small")
                }

                let dataOffset = try data.readUInt32(at: cmdOffset + 8)
                let dataSize = try data.readUInt32(at: cmdOffset + 12)
                if dataOffset != 0 || dataSize != 0 {
                    try data.writeUInt32(0, at: cmdOffset + 8)
                    try data.writeUInt32(0, at: cmdOffset + 12)
                    invalidated = true
                }
            }
            cmdOffset += Int(command.cmdSize)
        }

        return invalidated
    }

    // MARK: - Private Helpers

    /// Serialize a `Section` into an 80-byte section_64 blob.
    private static func buildSectionHeaderData(_ sec: Section) throws -> Data {
        var d = Data(count: Section.size)
        try d.writeCString(sec.sectionName, at: 0, length: 16)
        try d.writeCString(sec.segmentName, at: 16, length: 16)
        try d.writeUInt64(sec.address, at: 32)
        try d.writeUInt64(sec.size, at: 40)
        try d.writeUInt32(sec.offset, at: 48)
        try d.writeUInt32(sec.align, at: 52)
        try d.writeUInt32(sec.relocationOffset, at: 56)
        try d.writeUInt32(sec.numberOfRelocations, at: 60)
        try d.writeUInt32(sec.flags, at: 64)
        try d.writeUInt32(sec.reserved1, at: 68)
        try d.writeUInt32(sec.reserved2, at: 72)
        try d.writeUInt32(sec.reserved3, at: 76)
        return d
    }

    /// Smallest file offset among all sections with actual content, used to determine
    /// how much padding exists after the load commands area.
    private static func findMinContentOffset(in data: Data, header: MachOHeader) throws -> Int {
        var minOffset = data.count
        var cmdOffset = MachOHeader.size

        for _ in 0..<header.numberOfCommands {
            let command = try LoadCommand(from: data, offset: UInt64(cmdOffset))
            if command.cmd == LoadCommand.LC_SEGMENT_64 {
                let segment = try Segment(from: data, commandOffset: UInt64(cmdOffset))
                for section in segment.sections where section.storesDataInFile && section.size > 0 {
                    let sectionFileOffset = Int(section.offset)
                    if sectionFileOffset > 0 && sectionFileOffset < minOffset {
                        minOffset = sectionFileOffset
                    }
                }
            }
            cmdOffset += Int(command.cmdSize)
        }

        return minOffset
    }

    private static func locateSegment(in data: Data, header: MachOHeader, named name: String) throws -> SegmentCommandContext {
        var cmdOffset = MachOHeader.size

        for _ in 0..<header.numberOfCommands {
            let command = try LoadCommand(from: data, offset: UInt64(cmdOffset))
            if command.cmd == LoadCommand.LC_SEGMENT_64 {
                let segment = try Segment(from: data, commandOffset: UInt64(cmdOffset))
                if segment.name == name {
                    return SegmentCommandContext(
                        commandOffset: cmdOffset,
                        commandSize: command.cmdSize,
                        segment: segment
                    )
                }
            }
            cmdOffset += Int(command.cmdSize)
        }

        throw MachOError.segmentNotFound(name)
    }

    private static func highestFileBackedSegmentEnd(in data: Data, header: MachOHeader) throws -> UInt64 {
        var highestEnd: UInt64 = 0
        var cmdOffset = MachOHeader.size

        for _ in 0..<header.numberOfCommands {
            let command = try LoadCommand(from: data, offset: UInt64(cmdOffset))
            if command.cmd == LoadCommand.LC_SEGMENT_64 {
                let segment = try Segment(from: data, commandOffset: UInt64(cmdOffset))
                let segmentEnd = try checkedAdd(segment.fileOffset, segment.fileSize, context: "segment \(segment.name) end")
                highestEnd = max(highestEnd, segmentEnd)
            }
            cmdOffset += Int(command.cmdSize)
        }

        return highestEnd
    }

    private static func fileAlignment(forSectionAlign alignExponent: UInt32) throws -> UInt64 {
        guard alignExponent < 63 else {
            throw MachOError.unsupportedMutation("Section alignment exponent \(alignExponent) is too large")
        }
        return alignExponent == 0 ? 1 : (1 << alignExponent)
    }

    private static func align(_ value: UInt64, to alignment: UInt64) throws -> UInt64 {
        guard alignment > 0 else {
            throw MachOError.invalidData("Alignment must be non-zero")
        }
        let remainder = value % alignment
        guard remainder != 0 else { return value }
        return try checkedAdd(value, alignment - remainder, context: "alignment")
    }

    private static func checkedAdd(_ lhs: UInt64, _ rhs: UInt64, context: String) throws -> UInt64 {
        let (result, overflow) = lhs.addingReportingOverflow(rhs)
        guard !overflow else {
            throw MachOError.integerOverflow(context)
        }
        return result
    }

    private static func checkedInt(_ value: UInt64, context: String) throws -> Int {
        guard value <= UInt64(Int.max) else {
            throw MachOError.integerOverflow(context)
        }
        return Int(value)
    }
}
