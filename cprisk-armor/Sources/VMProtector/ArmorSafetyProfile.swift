import Foundation

/// 构建期安全档位：与 `cprisk-armor --safety-profile` 对应。
public enum ArmorSafetyProfile: String, Sendable {
    case standard
    case appStoreSafe = "appstore-safe"

    public init?(cliToken: String) {
        let t = cliToken.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        switch t {
        case "standard": self = .standard
        case "appstore-safe", "app_store_safe", "app-store-safe": self = .appStoreSafe
        default: return nil
        }
    }
}

/// 在未显式传入 `--cff-policy` / `--vmp-policy` 时，为不同安全档位解析默认 YAML 路径。
public enum ArmorPolicyPathResolver {
    public static func resolveDefaultCffPolicyPath(profile: ArmorSafetyProfile) -> String? {
        let relativeNames: [String]
        switch profile {
        case .standard:
            relativeNames = ["cff_policy.yaml", "RiskDetectorApp/cff_policy.yaml"]
        case .appStoreSafe:
            relativeNames = ["cff_policy_appstore_safe.yaml", "RiskDetectorApp/cff_policy_appstore_safe.yaml"]
        }
        return firstExisting(relativePaths: relativeNames)
    }

    public static func resolveDefaultVmpPolicyPath(profile: ArmorSafetyProfile) -> String? {
        let relativeNames: [String]
        switch profile {
        case .standard:
            relativeNames = ["RiskDetectorApp/vmp_policy.yaml", "vmp_policy.yaml"]
        case .appStoreSafe:
            relativeNames = ["RiskDetectorApp/vmp_policy_appstore_safe.yaml", "vmp_policy_appstore_safe.yaml"]
        }
        return firstExisting(relativePaths: relativeNames)
    }

    private static func firstExisting(relativePaths: [String]) -> String? {
        let fm = FileManager.default
        let cwd = URL(fileURLWithPath: fm.currentDirectoryPath)
        let roots = [
            cwd,
            cwd.deletingLastPathComponent(),
            cwd.deletingLastPathComponent().deletingLastPathComponent()
        ]
        for root in roots {
            for rel in relativePaths {
                let url = root.appendingPathComponent(rel)
                if fm.fileExists(atPath: url.path) {
                    return url.path
                }
            }
        }
        return nil
    }
}
