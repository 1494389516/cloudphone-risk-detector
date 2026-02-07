import Foundation

enum Sysctl {
    static func string(_ name: String) -> String? {
        var size: size_t = 0
        if sysctlbyname(name, nil, &size, nil, 0) != 0 { return nil }
        var buf = [CChar](repeating: 0, count: max(1, Int(size)))
        if sysctlbyname(name, &buf, &size, nil, 0) != 0 { return nil }
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
        if sysctlbyname(name, &value, &size, nil, 0) == 0 {
            return value
        }

        var value32: Int32 = 0
        var size32 = MemoryLayout<Int32>.size
        if sysctlbyname(name, &value32, &size32, nil, 0) == 0 {
            return Int64(value32)
        }

        return nil
    }
}
