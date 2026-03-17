import Foundation

public final class RemoteConfigProvider: @unchecked Sendable {
    public typealias ConfigUpdateHandler = @Sendable (RemoteConfig) -> Void
    public typealias ConfigErrorHandler = @Sendable (Error) -> Void

    public let configURL: URL
    public let updateInterval: TimeInterval
    public let cacheValidityDuration: TimeInterval
    public let remoteEnabled: Bool

    private let lock = UnfairLock()
    private var _currentConfig: RemoteConfig
    private var _isFetching = false
    private let cache: ConfigCaching
    private let fallbackConfig: RemoteConfig
    private var urlSession: URLSession
    private var updateHandlers: [UUID: ConfigUpdateHandler] = [:]
    private var errorHandlers: [UUID: ConfigErrorHandler] = [:]
    private var timer: Timer?
    private var _consecutiveFailures: Int = 0
    private var _circuitOpenUntil: TimeInterval = 0
    private var _lastSuccessfulFetchTime: TimeInterval = 0
    private var _configStalenessThreshold: TimeInterval
    private var _schedulingTimer: Bool = false
    private static let circuitBreakerThreshold: Int = 3
    private static let circuitBreakerCooldowns: [TimeInterval] = [30, 60, 120, 300]

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

    public var isConfigStale: Bool {
        lock.lock()
        defer { lock.unlock() }
        guard _lastSuccessfulFetchTime > 0 else { return true }
        return Date().timeIntervalSince1970 - _lastSuccessfulFetchTime > _configStalenessThreshold
    }

    public var configAge: TimeInterval {
        lock.lock()
        defer { lock.unlock() }
        guard _lastSuccessfulFetchTime > 0 else { return .infinity }
        return Date().timeIntervalSince1970 - _lastSuccessfulFetchTime
    }

    public init(
        configURL: URL,
        updateInterval: TimeInterval = 3600,
        cacheValidityDuration: TimeInterval = 86400,
        remoteEnabled: Bool = true,
        cache: ConfigCaching = ConfigCache.shared,
        fallbackConfig: RemoteConfig = .default,
        pinnedCertificateHashes: Set<String> = []
    ) {
        self.configURL = configURL
        self.updateInterval = updateInterval
        self.cacheValidityDuration = cacheValidityDuration
        self.remoteEnabled = remoteEnabled
        self.cache = cache
        self.fallbackConfig = fallbackConfig
        self._configStalenessThreshold = cacheValidityDuration
        self.urlSession = CertificatePinningSessionDelegate.pinnedSession(
            hashes: pinnedCertificateHashes,
            allowsSystemCA: false
        )

        if let cached = cache.load(), !cached.isExpired(duration: cacheValidityDuration) {
            self._currentConfig = Self.releaseHardenedConfig(cached.config)
            self._lastSuccessfulFetchTime = cached.cachedAt
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

    public func configurePinning(hashes: Set<String>) {
        lock.lock()
        urlSession.invalidateAndCancel()
        urlSession = CertificatePinningSessionDelegate.pinnedSession(
            hashes: hashes,
            allowsSystemCA: false
        )
        lock.unlock()
    }

    public func reloadCachedConfigTrustState() {
        if let cached = cache.load(), !cached.isExpired(duration: cacheValidityDuration) {
            applyConfig(Self.releaseHardenedConfig(cached.config))
            lock.lock()
            _lastSuccessfulFetchTime = cached.cachedAt
            lock.unlock()
        } else {
            applyConfig(fallbackConfig)
        }
    }

    public func fetchLatest(completion: @escaping @Sendable (Result<RemoteConfig, ConfigError>) -> Void) {
        guard remoteEnabled else {
            completion(.success(currentConfig))
            return
        }

        if isCircuitOpen() {
            Logger.log("remote_config.circuit_breaker: open, skipping fetch")
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
        let session = urlSession
        lock.unlock()

        var request = URLRequest(url: configURL)
        request.httpMethod = "GET"
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 15
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("CloudPhoneRiskKit/2.0", forHTTPHeaderField: "User-Agent")

        session.dataTask(with: request) { [weak self] data, response, error in
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
                self.recordFailure()
                self.handleError(wrapped)
                completion(.failure(wrapped))
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                self.recordFailure()
                self.handleError(ConfigError.invalidResponse)
                completion(.failure(.invalidResponse))
                return
            }

            guard httpResponse.statusCode == 200 else {
                let wrapped = ConfigError.httpError(statusCode: httpResponse.statusCode)
                self.recordFailure()
                self.handleError(wrapped)
                completion(.failure(wrapped))
                return
            }

            guard let data else {
                self.recordFailure()
                self.handleError(ConfigError.emptyResponse)
                completion(.failure(.emptyResponse))
                return
            }

            let signatureHex = httpResponse.value(forHTTPHeaderField: "X-Config-Signature") ?? ""
            let verification = ConfigSignatureVerifier.verify(payload: data, signatureHex: signatureHex)
            if !verification.isValid {
                let wrapped = ConfigError.signatureVerificationFailed(reason: verification.reason ?? "unknown")
                self.recordFailure()
                self.handleError(wrapped)
                completion(.failure(wrapped))
                return
            }

            do {
                let config = Self.releaseHardenedConfig(try self.parseAndValidate(data: data))
                self.applyConfig(config)
                let verifiedByServer = ConfigSignatureVerifier.isConfigured && verification.isValid
                if !verifiedByServer {
                    Logger.log("remote_config: server signing key not configured, cache entry will be marked unverified")
                }
                self.cache.save(config, verifiedByServer: verifiedByServer)
                self.lock.lock()
                self._lastSuccessfulFetchTime = Date().timeIntervalSince1970
                self.lock.unlock()
                self.notifyUpdate(config)
                self.recordSuccess()
                completion(.success(config))
            } catch let configError as ConfigError {
                self.recordFailure()
                self.handleError(configError)
                completion(.failure(configError))
            } catch {
                let wrapped = ConfigError.decodeFailed(underlying: error)
                self.recordFailure()
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

    public var isCircuitBreakerOpen: Bool {
        isCircuitOpen()
    }

    public func resetToFallback() {
        applyConfig(fallbackConfig)
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

    private func isCircuitOpen() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard _consecutiveFailures >= Self.circuitBreakerThreshold else { return false }
        return Date().timeIntervalSince1970 < _circuitOpenUntil
    }

    private func recordSuccess() {
        lock.lock()
        _consecutiveFailures = 0
        _circuitOpenUntil = 0
        lock.unlock()
    }

    private func recordFailure() {
        lock.lock()
        _consecutiveFailures += 1
        if _consecutiveFailures >= Self.circuitBreakerThreshold {
            let cooldownIndex = min(_consecutiveFailures - Self.circuitBreakerThreshold, Self.circuitBreakerCooldowns.count - 1)
            let cooldown = Self.circuitBreakerCooldowns[cooldownIndex]
            _circuitOpenUntil = Date().timeIntervalSince1970 + cooldown
            Logger.log("remote_config.circuit_breaker: open for \(cooldown)s (failures=\(_consecutiveFailures))")
        }
        lock.unlock()
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

    private static func releaseHardenedConfig(_ config: RemoteConfig) -> RemoteConfig {
#if DEBUG
        return config
#else
        return config.enforcingReleaseSecurityFloor()
#endif
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
        // 用 _schedulingTimer 标记"已提交调度"，防止在 async 派发期间被重复调用
        lock.lock()
        guard timer == nil && !_schedulingTimer else {
            lock.unlock()
            return
        }
        _schedulingTimer = true
        let interval = updateInterval
        lock.unlock()

        let schedule: () -> Void = { [weak self] in
            guard let self else { return }
            self.lock.lock()
            defer { self.lock.unlock() }
            // 二次检查：确保 Timer 仍未被创建（防止两次 async 同时执行）
            guard self.timer == nil else { return }
            let t = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
                guard let self else { return }
                self.fetchLatest { result in
                    if case .failure(let error) = result {
                        Logger.log("remote_config.periodic_update failed: \(error.localizedDescription)")
                        if self.isConfigStale {
                            Logger.log("remote_config: config is stale (age=\(Int(self.configAge))s), falling back to default")
                            self.reloadCachedConfigTrustState()
                        }
                    }
                }
            }
            RunLoop.main.add(t, forMode: .common)
            self.timer = t
            self._schedulingTimer = false
        }
        if Thread.isMainThread {
            schedule()
        } else {
            DispatchQueue.main.async(execute: schedule)
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

    /// 安全下限常量（防止远程配置将阈值调至 0 从而关闭检测）
    private static let minimumPolicyThreshold: Double = 15
    private static let minimumJailbreakThreshold: Double = 10

    func validateSecurity(_ config: RemoteConfig) throws {
        if config.whitelist.deviceIDs.count > 10000 {
            throw ConfigError.validationFailed(
                underlying: NSError(domain: "RemoteConfigProvider", code: -1, userInfo: [
                    NSLocalizedDescriptionKey: "whitelist size too large"
                ])
            )
        }

        // 阈值下限保护：阻止远程配置通过极高阈值变相关闭所有检测
        if config.policy.threshold < Self.minimumPolicyThreshold {
            throw ConfigError.validationFailed(
                underlying: NSError(domain: "RemoteConfigProvider", code: -2, userInfo: [
                    NSLocalizedDescriptionKey: "policy.threshold \(config.policy.threshold) below security floor \(Self.minimumPolicyThreshold)"
                ])
            )
        }

        if config.detector.jailbreakThreshold < Self.minimumJailbreakThreshold {
            throw ConfigError.validationFailed(
                underlying: NSError(domain: "RemoteConfigProvider", code: -3, userInfo: [
                    NSLocalizedDescriptionKey: "detector.jailbreakThreshold \(config.detector.jailbreakThreshold) below security floor \(Self.minimumJailbreakThreshold)"
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
    case signatureVerificationFailed(reason: String)

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
        case .signatureVerificationFailed(let reason):
            return "配置签名验证失败: \(reason)"
        }
    }
}
