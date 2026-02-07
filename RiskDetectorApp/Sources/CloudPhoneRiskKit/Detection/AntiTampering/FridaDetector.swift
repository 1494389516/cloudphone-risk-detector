import Darwin
import Foundation
import MachO

struct FridaDetector: Detector {
    private let knownPorts: [Int] = [27042, 27043]
    private let markers: [String] = ["frida", "gadget", "gum", "frida-server"]

    func detect() -> DetectorResult {
#if targetEnvironment(simulator)
        return DetectorResult(score: 0, methods: ["unavailable_simulator"])
#else
        var score: Double = 0
        var methods: [String] = []

        if let imageHit = detectFridaImage() {
            score += 35
            methods.append("frida:dylib:\(imageHit)")
        }

        if let envHit = detectFridaEnv() {
            score += 20
            methods.append("frida:env:\(envHit)")
        }

        if let port = detectOpenFridaPort() {
            score += 15
            methods.append("frida:port:\(port)")
        }

        if fileExists(path: "/usr/sbin/frida-server") || fileExists(path: "/var/jb/usr/sbin/frida-server") {
            score += 20
            methods.append("frida:file:server")
        }

        return DetectorResult(score: score, methods: methods)
#endif
    }

    private func detectFridaImage() -> String? {
        let count = _dyld_image_count()
        for index in 0..<count {
            guard let imageName = _dyld_get_image_name(index) else { continue }
            let name = String(cString: imageName).lowercased()
            if let marker = markers.first(where: { name.contains($0) }) {
                return marker
            }
        }
        return nil
    }

    private func detectFridaEnv() -> String? {
        let keys = ["FRIDA", "FRIDA_VERSION", "FRIDA_SCRIPT", "DYLD_INSERT_LIBRARIES"]
        for key in keys {
            guard let value = getenv(key) else { continue }
            let text = String(cString: value).lowercased()
            if text.contains("frida") || key.contains("FRIDA") {
                return key.lowercased()
            }
        }
        return nil
    }

    private func detectOpenFridaPort() -> Int? {
        for port in knownPorts where isPortOpen(port) {
            return port
        }
        return nil
    }

    private func isPortOpen(_ port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }

    private func fileExists(path: String) -> Bool {
        var st = stat()
        return stat(path, &st) == 0
    }
}
