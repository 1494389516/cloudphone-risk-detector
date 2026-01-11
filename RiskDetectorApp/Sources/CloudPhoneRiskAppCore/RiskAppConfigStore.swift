import Foundation

public final class RiskAppConfigStore {
    public enum StoreError: Error {
        case encodeFailed
        case decodeFailed
    }

    private let defaults: UserDefaults
    private let key: String

    public init(defaults: UserDefaults = .standard, key: String = "cloudphone_risk_app_config_v1") {
        self.defaults = defaults
        self.key = key
    }

    public func load(default fallback: RiskAppConfig = .default) -> RiskAppConfig {
        guard let data = defaults.data(forKey: key) else { return fallback }
        return (try? JSONDecoder().decode(RiskAppConfig.self, from: data)) ?? fallback
    }

    public func save(_ config: RiskAppConfig) throws {
        guard let data = try? JSONEncoder().encode(config) else { throw StoreError.encodeFailed }
        defaults.set(data, forKey: key)
    }

    public func reset() {
        defaults.removeObject(forKey: key)
    }
}

