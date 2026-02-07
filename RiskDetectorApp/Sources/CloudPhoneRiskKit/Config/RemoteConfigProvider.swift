import Foundation

public final class RemoteConfigProvider: @unchecked Sendable {
    public typealias ConfigUpdateHandler = @Sendable (RemoteConfig) -> Void
    public typealias ConfigErrorHandler = @Sendable (Error) -> Void

    public let configURL: URL
    public let updateInterval: TimeInterval
    public let cacheValidityDuration: TimeInterval
    public let remoteEnabled: Bool

    private let lock = NSLock()
    private var _currentConfig: RemoteConfig
    private var _isFetching = false
    private let cache: ConfigCaching
    private var updateHandlers: [UUID: ConfigUpdateHandler] = [:]
    private var errorHandlers: [UUID: ConfigErrorHandler] = [:]
    private var timer: Timer?

    public var currentConfig: RemoteConfig {
        lock.lock()
        defer { lock.unlock() }
        return _currentConfig
    }

    public var isFetching: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _isFetching
    }

    public init(
        configURL: URL,
        updateInterval: TimeInterval = 3600,
        cacheValidityDuration: TimeInterval = 86400,
        remoteEnabled: Bool = true,
        cache: ConfigCaching = ConfigCache.shared,
        fallbackConfig: RemoteConfig = .default
    ) {
        self.configURL = configURL
        self.updateInterval = updateInterval
        self.cacheValidityDuration = cacheValidityDuration
        self.remoteEnabled = remoteEnabled
        self.cache = cache

        if let cached = cache.load(), !cached.isExpired(duration: cacheValidityDuration) {
            self._currentConfig = cached.config
        } else {
            self._currentConfig = fallbackConfig
        }

        if remoteEnabled {
            startPeriodicUpdates()
        }
    }

    deinit {
        timer?.invalidate()
    }

    public func fetchLatest(completion: @escaping @Sendable (Result<RemoteConfig, ConfigError>) -> Void) {
        guard remoteEnabled else {
            completion(.success(currentConfig))
            return
        }

        lock.lock()
        if _isFetching {
            lock.unlock()
            completion(.failure(.alreadyFetching))
            return
        }
        _isFetching = true
        lock.unlock()

        var request = URLRequest(url: configURL)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("CloudPhoneRiskKit/2.0", forHTTPHeaderField: "User-Agent")

        URLSession.shared.dataTask(with: request) { [weak self] data, response, error in
            guard let self else {
                completion(.failure(.providerDeallocated))
                return
            }

            defer {
                self.lock.lock()
                self._isFetching = false
                self.lock.unlock()
            }

            if let error {
                let wrapped = ConfigError.networkError(underlying: error)
                self.handleError(wrapped)
                completion(.failure(wrapped))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                self.handleError(ConfigError.invalidResponse)
                completion(.failure(.invalidResponse))
                return
            }

            guard httpResponse.statusCode == 200 else {
                let wrapped = ConfigError.httpError(statusCode: httpResponse.statusCode)
                self.handleError(wrapped)
                completion(.failure(wrapped))
                return
            }

            guard let data else {
                self.handleError(ConfigError.emptyResponse)
                completion(.failure(.emptyResponse))
                return
            }

            do {
                let config = try self.parseAndValidate(data: data)
                self.applyConfig(config)
                self.cache.save(config)
                self.notifyUpdate(config)
                completion(.success(config))
            } catch let configError as ConfigError {
                self.handleError(configError)
                completion(.failure(configError))
            } catch {
                let wrapped = ConfigError.decodeFailed(underlying: error)
                self.handleError(wrapped)
                completion(.failure(wrapped))
            }
        }.resume()
    }

    @discardableResult
    public func registerUpdate(handler: @escaping ConfigUpdateHandler) -> Token {
        lock.lock()
        defer { lock.unlock() }
        let id = UUID()
        updateHandlers[id] = handler
        return Token(id: id, owner: self)
    }

    @discardableResult
    public func registerErrorHandler(handler: @escaping ConfigErrorHandler) -> Token {
        lock.lock()
        defer { lock.unlock() }
        let id = UUID()
        errorHandlers[id] = handler
        return Token(id: id, owner: self)
    }

    public func unregister(token: Token) {
        lock.lock()
        defer { lock.unlock() }
        updateHandlers.removeValue(forKey: token.id)
        errorHandlers.removeValue(forKey: token.id)
    }

    public func resetToFallback() {
        applyConfig(.default)
    }

    public func experimentConfig(for experimentKey: String, deviceID: String) -> ExperimentVariant? {
        currentConfig.experiments.config(for: experimentKey, deviceID: deviceID)
    }

    public func isWhitelisted(deviceID: String) -> Bool {
        currentConfig.whitelist.contains(deviceID: deviceID)
    }

    public func isBlacklisted(deviceID: String) -> Bool {
        currentConfig.whitelist.isBlacklisted(deviceID: deviceID)
    }

    private func parseAndValidate(data: Data) throws -> RemoteConfig {
        let decoder = JSONDecoder()
        let config = try decoder.decode(RemoteConfig.self, from: data)
        let validator = ConfigValidator()
        try validator.validateVersion(config.version)
        try validator.validateRequiredFields(config)
        try validator.validateRanges(config)
        try validator.validateSecurity(config)
        return config
    }

    private func applyConfig(_ config: RemoteConfig) {
        lock.lock()
        defer { lock.unlock() }
        _currentConfig = config
    }

    private func notifyUpdate(_ config: RemoteConfig) {
        lock.lock()
        let handlers = Array(updateHandlers.values)
        lock.unlock()
        handlers.forEach { $0(config) }
    }

    private func handleError(_ error: Error) {
        lock.lock()
        let handlers = Array(errorHandlers.values)
        lock.unlock()
        handlers.forEach { $0(error) }
    }

    private func startPeriodicUpdates() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: updateInterval, repeats: true) { [weak self] _ in
            self?.fetchLatest { _ in }
        }
    }

    public struct Token {
        fileprivate let id: UUID
        fileprivate weak var owner: RemoteConfigProvider?

        public func unregister() {
            owner?.unregister(token: self)
        }
    }
}

private struct ConfigValidator {
    func validateVersion(_ version: Int) throws {
        guard version >= 0 else {
            throw ConfigError.invalidVersion(version: version)
        }
    }

    func validateRequiredFields(_ config: RemoteConfig) throws {
        guard config.policy.threshold >= 0 && config.policy.threshold <= 100 else {
            throw ConfigError.invalidRange(field: "policy.threshold", value: config.policy.threshold)
        }

        guard config.detector.jailbreakThreshold >= 0 && config.detector.jailbreakThreshold <= 100 else {
            throw ConfigError.invalidRange(field: "detector.jailbreakThreshold", value: config.detector.jailbreakThreshold)
        }
    }

    func validateRanges(_ config: RemoteConfig) throws {
        guard config.policy.timeWindow > 0 else {
            throw ConfigError.invalidRange(field: "policy.timeWindow", value: config.policy.timeWindow)
        }

        for experiment in config.experiments.active {
            guard experiment.traffic >= 0 && experiment.traffic <= 1 else {
                throw ConfigError.invalidRange(field: "experiment.traffic", value: experiment.traffic)
            }
        }
    }

    func validateSecurity(_ config: RemoteConfig) throws {
        if config.whitelist.deviceIDs.count > 10000 {
            throw ConfigError.validationFailed(
                underlying: NSError(domain: "RemoteConfigProvider", code: -1, userInfo: [
                    NSLocalizedDescriptionKey: "whitelist size too large"
                ])
            )
        }
    }
}

public enum ConfigError: Error, LocalizedError {
    case alreadyFetching
    case providerDeallocated
    case networkError(underlying: Error)
    case httpError(statusCode: Int)
    case invalidResponse
    case emptyResponse
    case decodeFailed(underlying: Error)
    case invalidVersion(version: Int)
    case invalidRange(field: String, value: Any)
    case validationFailed(underlying: Error)
    case cacheError(underlying: Error)

    public var errorDescription: String? {
        switch self {
        case .alreadyFetching:
            return "配置正在拉取中，请勿重复请求"
        case .providerDeallocated:
            return "配置提供者已被释放"
        case .networkError(let error):
            return "网络请求失败: \(error.localizedDescription)"
        case .httpError(let statusCode):
            return "HTTP 错误: \(statusCode)"
        case .invalidResponse:
            return "无效的响应"
        case .emptyResponse:
            return "空响应"
        case .decodeFailed(let error):
            return "配置解析失败: \(error.localizedDescription)"
        case .invalidVersion(let version):
            return "无效的配置版本: \(version)"
        case .invalidRange(let field, let value):
            return "配置字段 \(field) 的值超出范围: \(value)"
        case .validationFailed(let error):
            return "配置验证失败: \(error.localizedDescription)"
        case .cacheError(let error):
            return "缓存错误: \(error.localizedDescription)"
        }
    }
}
