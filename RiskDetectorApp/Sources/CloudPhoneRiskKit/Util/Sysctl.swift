import Foundation

enum Sysctl {
    static func string(_ name: String) -> String? {
        var size: size_t = 0
        if sysctlbyname(name, nil, &size, nil, 0) != 0 { return nil }
        var buf = [CChar](repeating: 0, count: max(1, Int(size)))
        if sysctlbyname(name, &buf, &size, nil, 0) != 0 { return nil }
        return String(cString: buf)
    }
}

