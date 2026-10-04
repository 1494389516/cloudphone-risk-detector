import Foundation

/// Pointer-free CPSV v2. Kept separate from v1 and the global armor ABI.
public enum CPSV2Manifest {
    public static let count = 58
    public static let byteCount = 32 + count * 16
    public struct Range: Codable, Sendable {
        public let name: String
        public let address: UInt64
        public let length: UInt32
        public init(name: String, address: UInt64, length: UInt32) {
            self.name = name; self.address = address; self.length = length
        }
    }
    /// Trusted build sidecar: bind final linker-map extents to the exact input image.
    /// Regenerate after code transformations; never infer lengths from arbitrary symbols.
    public struct Layout: Codable, Sendable {
        public let imageSHA256: String
        public let ranges: [Range]
    }
    public static let names: [String] = {
        let ops = ["nop", "ret", "raw_region", "halt", "add", "branch_rel",
                   "branch_cond", "call", "mov_wide", "adr_add", "cond_select",
                   "load_store", "xor_mix", "or_lane", "and_lane", "rol_acc",
                   "vm_call_func", "vreg_mov", "vreg_alu", "vreg_mem", "sub_lane",
                   "mul_lane", "add_rol_acc", "branch_ind", "poison", "unknown"]
        return ["cprisk_vm_execute", "cprisk_vm_interp_loop_a", "cprisk_vm_dispatch_lookup",
                "cprisk_vm_oph_post_handler_i", "cprisk_thread_run_a_i", "cprisk_thread_run_b_i"]
            + ["a", "b"].flatMap { lane in ops.map { "cprisk_thread_\(lane)_\($0)_i" } }
    }()
    public static func kind(_ index: Int) -> UInt32 {
        if index < 6 { return UInt32(index + 1) }
        let op = (index - 6) % 26, lane = (index - 6) / 26
        return UInt32((lane + 1) * 256 + (op < 24 ? op : op == 24 ? 255 : 254))
    }
    private static func fail(_ message: String) -> MachOError {
        .invalidData("CPSV v2: " + message)
    }
    private static func append(_ value: UInt64, bytes: Int, to data: inout Data) {
        for i in 0..<bytes { data.append(UInt8(truncatingIfNeeded: value >> (i * 8))) }
    }
    private static func read(_ data: Data, _ offset: Int, _ bytes: Int) -> UInt64 {
        var value: UInt64 = 0
        for i in 0..<bytes { value |= UInt64(data[offset+i]) << (i*8) }
        return value
    }
    public static func encode(uuid: Data, ranges: [Range], imageBase: UInt64,
                              textRVA: UInt64, textSize: UInt64) throws -> Data {
        guard uuid.count == 16, ranges.count == count else { throw fail("UUID/count") }
        var payload = Data()
        for v in [UInt64(0x56535043), 2, UInt64(count), 0] { append(v, bytes: 4, to: &payload) }
        payload.append(uuid)
        var rvas: [UInt64] = []
        for (i, range) in ranges.enumerated() {
            guard range.name == names[i], range.address >= imageBase else { throw fail("roster/address") }
            let rva = range.address - imageBase
            rvas.append(rva)
            append(rva, bytes: 8, to: &payload)
            append(UInt64(range.length), bytes: 4, to: &payload)
            append(UInt64(kind(i)), bytes: 4, to: &payload)
        }
        try validate(payload, uuid: uuid, expectedRVAs: rvas, textRVA: textRVA, textSize: textSize)
        return payload
    }
    /// Same bounded, ordered, overlap-rejecting rules as cprisk_vm_cpsv2.h.
    public static func validate(_ payload: Data, uuid: Data, expectedRVAs: [UInt64],
                                textRVA: UInt64, textSize: UInt64) throws {
        let p = Data(payload), id = Data(uuid)
        guard p.count == byteCount, id.count == 16, expectedRVAs.count == count,
              textSize <= UInt64.max - textRVA else { throw fail("extent/count") }
        guard read(p, 0, 4) == 0x56535043, read(p, 4, 4) == 2,
              read(p, 8, 4) == UInt64(count), read(p, 12, 4) == 0,
              p.subdata(in: 16..<32) == id, id.contains(where: { $0 != 0 }) else { throw fail("header/UUID") }
        var prior: [(UInt64, UInt64)] = [], total: UInt64 = 0
        for i in 0..<count {
            let o = 32 + i*16, rva = read(p, o, 8), length = read(p, o+8, 4)
            guard read(p, o+12, 4) == UInt64(kind(i)), rva == expectedRVAs[i],
                  rva & 3 == 0, length & 3 == 0, length > 0, length <= 65536,
                  rva >= textRVA, rva - textRVA <= textSize,
                  length <= textSize - (rva - textRVA), length <= 1048576 - total else {
                throw fail("invalid range \(i)")
            }
            guard !prior.contains(where: { rva < $0.1 && $0.0 < rva + length }) else { throw fail("overlap") }
            prior.append((rva, rva + length)); total += length
        }
    }
}
