import Foundation

enum Sysctl {
    static func string(_ name: String) -> String? {
        var size: size_t = 0
        if name.withCString({ DynamicSymbolResolver.sysctlByName($0, nil, &size, nil, 0) }) != 0 {
            return nil
        }
        guard size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: max(1, Int(size)))
        let readResult = buf.withUnsafeMutableBufferPointer { buffer in
            name.withCString {
                DynamicSymbolResolver.sysctlByName($0, buffer.baseAddress, &size, nil, 0)
            }
        }
        if readResult != 0 { return nil }
        guard size > 0, Int(size) <= buf.count else { return nil }
        if buf[Int(size) - 1] != 0 {
            buf.append(0)
        }
        return String(cString: buf)
    }

    static func int(_ name: String) -> Int? {
        if let value = int64(name) {
            return Int(value)
        }
        return nil
    }

    static func int64(_ name: String) -> Int64? {
        var value: Int64 = 0
        var size = MemoryLayout<Int64>.size
        if name.withCString({ DynamicSymbolResolver.sysctlByName($0, &value, &size, nil, 0) }) == 0 {
            return value
        }

        var value32: Int32 = 0
        var size32 = MemoryLayout<Int32>.size
        if name.withCString({ DynamicSymbolResolver.sysctlByName($0, &value32, &size32, nil, 0) }) == 0 {
            return Int64(value32)
        }

        return nil
    }
}
