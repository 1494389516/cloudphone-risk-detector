// MARK: - CPRiskKit+Reporting
//
// 从 CloudPhoneRiskKit.swift 拆分：Report building、secure upload、
// envelope signing、remote config management、certificate pinning。

import CryptoKit
import CRiskCore
import Foundation

extension CPRiskKit {

    // MARK: - Secure Report Envelope

    internal func buildSecureReportEnvelopeImpl(
        report: CPRiskReport,
        sessionToken: String,
        signingKey: String,
        keyId: String = "k1",
        attestationKeyId: String? = nil,
        requireArmor: Bool = true
    ) throws -> ReportEnvelope {
        let remoteConfig = currentRemoteConfig()
        let hardening = remoteConfig?.securityHardening ?? .default

        var mapping = remoteConfig?.payloadFieldMapping
        if let currentMapping = mapping, currentMapping.isExpired() {
            if hardening.enforcePayloadFieldMapping {
                throw SecureUploadError.payloadFieldMappingExpired(version: currentMapping.version)
            }
            mapping = nil
        }

        if hardening.enforcePayloadFieldMapping, mapping == nil {
            throw SecureUploadError.payloadFieldMappingRequired
        }

        var payloadData = report.unencryptedPayloadData(prettyPrinted: false)
        if !hardening.enableChallengeBinding {
            payloadData = try removingPayloadKey("challengeBinding", from: payloadData)
        }

        let effectiveKeyId: String
        if keyId == "k1",
           TrustChainManager.currentKeyRotationPolicy() != nil {
            effectiveKeyId = TrustChainManager.currentKeyId(baseKeyId: keyId)
        } else {
            effectiveKeyId = keyId
        }

        let trustLevel = TrustChainManager.evaluateTrustLevel(
            deviceID: report.deviceID,
            hardwareMachine: report.device.hardwareMachine ?? "",
            kernelVersion: Sysctl.string("kern.version") ?? ""
        )

        let armorSnapshot = ensureArmorRuntimeStarted(trigger: "build_envelope")
        let signatureVersion: String
        let signatureProvider: ((Data) throws -> String)?
        let bindingMode: String

        if armorSnapshot.status == .active {
            let authentic = cprisk_is_integrity_poisoned() == 0
            if authentic {
                signatureProvider = { signatureInput in
                    guard let signature = Self.signWithArmorDerivedKey(
                        baseKey: signingKey,
                        signatureInput: signatureInput
                    ) else {
                        throw ReportEnvelope.ReportEnvelopeError.signingFailed
                    }
                    return signature
                }
                #if DEBUG
                signatureVersion = hardening.enableEnvelopeSignatureV2 ? "v2a" : "v1"
                #else
                signatureVersion = "v2a"
                #endif
                bindingMode = "armor_request_binding_sha256_v1"
            } else if requireArmor {
                Logger.log("buildSecureReportEnvelope: armor material marked poisoned by runtime state")
                throw SecureUploadError.armorRuntimeUnavailable(reason: "material_poisoned")
            } else {
                Logger.log("buildSecureReportEnvelope: armor material marked poisoned, degrading to v2d signature")
                signatureProvider = nil
                signatureVersion = "v2d"
                bindingMode = "plain_hmac_fallback_v1"
            }
        } else if requireArmor {
            Logger.log("buildSecureReportEnvelope: armor unavailable status=\(armorSnapshot.status.rawValue) reason=\(armorSnapshot.reason)")
            throw SecureUploadError.armorRuntimeUnavailable(reason: armorSnapshot.reason)
        } else {
            Logger.log("buildSecureReportEnvelope: armor unavailable, degrading to v2d signature (status=\(armorSnapshot.status.rawValue))")
            signatureProvider = nil
            signatureVersion = "v2d"
            bindingMode = "plain_hmac_fallback_v1"
        }

        let envelopeConfig = ReportEnvelope.Config(signatureVersion: signatureVersion)

        return try ReportEnvelope.create(
            payloadData: payloadData,
            reportId: report.reportID,
            sessionToken: sessionToken,
            signingKey: signingKey,
            keyId: effectiveKeyId,
            fieldMapping: mapping,
            attestationKeyId: attestationKeyId,
            trustLevel: trustLevel,
            config: envelopeConfig,
            signatureProvider: signatureProvider,
            bindingMode: bindingMode
        )
    }

    // MARK: - Armor Signing

    internal static func clearCStringBuffer(_ buffer: inout [CChar]) {
        for index in buffer.indices {
            buffer[index] = 0
        }
    }

    internal static func requestBindingDigest(for signatureInput: Data) -> Data {
        Data(SHA256.hash(data: signatureInput))
    }

    internal static func signWithArmorDerivedKey(baseKey: String, signatureInput: Data) -> String? {
        guard var keyData = baseKey.data(using: .utf8) else {
            Logger.log("armor_sign: UTF-8 encoding failed for baseKey")
            return nil
        }
        defer { secureZeroData(&keyData) }
        var bindingDigest = requestBindingDigest(for: signatureInput)
        defer { secureZeroData(&bindingDigest) }

        var signatureBuffer = [CChar](
            repeating: 0,
            count: Int(CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE) + 1
        )
        defer { clearCStringBuffer(&signatureBuffer) }

        let rc = signatureBuffer.withUnsafeMutableBufferPointer { signaturePtr in
            keyData.withUnsafeBytes { keyRaw in
                bindingDigest.withUnsafeBytes { digestRaw in
                    signatureInput.withUnsafeBytes { inputRaw in
                        guard let keyPtr = keyRaw.bindMemory(to: UInt8.self).baseAddress,
                              let digestPtr = digestRaw.bindMemory(to: UInt8.self).baseAddress,
                              let inputPtr = inputRaw.bindMemory(to: UInt8.self).baseAddress,
                              let sigPtr = signaturePtr.baseAddress else {
                            return Int32(-1)
                        }
                        return cprisk_sign_with_derived_key_and_request_binding_digest(
                            keyPtr,
                            keyData.count,
                            inputPtr,
                            signatureInput.count,
                            digestPtr,
                            sigPtr
                        )
                    }
                }
            }
        }
        guard rc == 0 else {
            Logger.log("armor_sign: bound cprisk_sign_with_derived_key failed rc=\(rc)")
            return nil
        }
        return String(cString: signatureBuffer)
    }

    internal static func verifyWithArmorDerivedKey(
        baseKey: String,
        signatureInput: Data,
        expectedSignature: String
    ) -> Bool {
        guard var keyData = baseKey.data(using: .utf8) else {
            Logger.log("armor_verify: UTF-8 encoding failed for baseKey")
            return false
        }
        defer { secureZeroData(&keyData) }
        var bindingDigest = requestBindingDigest(for: signatureInput)
        defer { secureZeroData(&bindingDigest) }

        var expectedCString = Array(expectedSignature.utf8CString)
        defer { clearCStringBuffer(&expectedCString) }

        let rc = expectedCString.withUnsafeBufferPointer { signaturePtr in
            keyData.withUnsafeBytes { keyRaw in
                bindingDigest.withUnsafeBytes { digestRaw in
                    signatureInput.withUnsafeBytes { inputRaw in
                        guard let keyPtr = keyRaw.bindMemory(to: UInt8.self).baseAddress,
                              let digestPtr = digestRaw.bindMemory(to: UInt8.self).baseAddress,
                              let inputPtr = inputRaw.bindMemory(to: UInt8.self).baseAddress,
                              let sigPtr = signaturePtr.baseAddress else {
                            return Int32(-1)
                        }
                        return cprisk_verify_with_derived_key_and_request_binding_digest(
                            keyPtr,
                            keyData.count,
                            inputPtr,
                            signatureInput.count,
                            digestPtr,
                            sigPtr
                        )
                    }
                }
            }
        }
        return rc == 0
    }

    // MARK: - Remote Config Management

    internal func currentRemoteConfigProvider() -> RemoteConfigProvider? {
        let (provider, endpoint) = stateLock.withLock { (remoteConfigProvider, remoteConfigEndpoint) }

        if let provider {
            return provider
        }

        if let endpoint {
            _ = configureRemoteConfigProvider(urlString: endpoint.absoluteString)
        } else if let persisted = UserDefaults.standard.string(forKey: Self.remoteConfigEndpointKey) {
            _ = configureRemoteConfigProvider(urlString: persisted)
        }

        return stateLock.withLock { remoteConfigProvider }
    }

    internal func currentRemoteConfig() -> RemoteConfig? {
        let (cached, provider) = stateLock.withLock { (latestRemoteConfig, remoteConfigProvider) }

        if let cached {
            return cached
        }

        return provider?.currentConfig
    }

    internal func resolveTextSegmentReference(for sdkVersion: String) -> TextSegmentReference? {
        let (resolver, cached, provider) = stateLock.withLock { (textSegmentReferenceResolver, latestRemoteConfig, remoteConfigProvider) }

        if let resolved = resolver?.resolveTextSegmentReference(for: sdkVersion) {
            return resolved
        }

        let config = cached ?? provider?.currentConfig
        guard let config,
              let expectedHash = config.textSegmentHashReference?[sdkVersion] else {
            return nil
        }

        return TextSegmentReference(
            expectedHash: expectedHash,
            source: "remote_config",
            version: String(config.version)
        )
    }

    @discardableResult
    internal func configureRemoteConfigProvider(urlString: String?) -> Bool {
        guard let rawURL = urlString?.trimmingCharacters(in: .whitespacesAndNewlines), !rawURL.isEmpty else {
            return false
        }
        guard
            let url = URL(string: rawURL),
            let scheme = url.scheme?.lowercased(),
            scheme == "https" || scheme == "http"
        else {
            Logger.log("remote_config.endpoint invalid: \(urlString ?? "nil")")
            return false
        }

#if !DEBUG
        if scheme == "http" {
            Logger.log("remote_config.endpoint rejected: http not allowed in release build, use https")
            return false
        }
#endif

        let (sameEndpoint, existingProvider, hasCachedConfig) = stateLock.withLock {
            (remoteConfigEndpoint == url, remoteConfigProvider, latestRemoteConfig != nil)
        }

        if sameEndpoint, let existingProvider {
            existingProvider.configurePinning(pinMaterial: Self.currentPinnedPinMaterial())
            existingProvider.reloadCachedConfigTrustState()
            if !hasCachedConfig {
                _ = applyRemoteConfigIfAccepted(existingProvider.currentConfig, source: "provider_reuse")
            }
            return true
        }

        let provider = RemoteConfigProvider(
            configURL: url,
            pinnedPinMaterial: Self.currentPinnedPinMaterial()
        )
        stateLock.withLock {
            remoteConfigEndpoint = url
            remoteConfigProvider = provider
        }

        _ = applyRemoteConfigIfAccepted(provider.currentConfig, source: "provider_init")
        UserDefaults.standard.set(rawURL, forKey: Self.remoteConfigEndpointKey)

        Logger.log("remote_config.endpoint set: \(url.absoluteString)")
        return true
    }

    @discardableResult
    internal func applyRemoteConfigIfAccepted(
        _ config: RemoteConfig,
        source: String,
        validateStrictly: Bool = true
    ) -> Bool {
        let effectiveConfig = Self.releaseHardenedRemoteConfig(config)
        let validation = effectiveConfig.validate()
        if !validation.isValid, validateStrictly {
            let detail = validation.errors.joined(separator: " | ")
            Logger.log("remote_config.\(source) rejected: invalid config, errors=\(detail)")
            return false
        }
        if !validation.isValid {
            let detail = validation.errors.joined(separator: " | ")
            Logger.log("remote_config.\(source) warning: invalid config accepted for local testing, errors=\(detail)")
        }
        if !validation.warnings.isEmpty {
            let warning = validation.warnings.joined(separator: " | ")
            Logger.log("remote_config.\(source) warning: \(warning)")
        }

        let remoteSafe = effectiveConfig.securityHardening?.enableAppStoreSafeProfile ?? false

        let accepted = stateLock.withLock { () -> Bool in
            if let currentVersion = latestRemoteConfig?.version {
                if effectiveConfig.version < currentVersion, !Self.localRemoteConfigRollbackAllowed {
                    Logger.log(
                        "remote_config.\(source) rejected: rollback detected " +
                        "incoming=\(effectiveConfig.version) < current=\(currentVersion)"
                    )
                    return false
                }
                if effectiveConfig.version == currentVersion {
                    let currentHash = latestRemoteConfig.flatMap(Self.stableConfigHash)
                    let newHash = Self.stableConfigHash(effectiveConfig)
                    if let currentHash, currentHash == newHash {
                        return true
                    }
                    Logger.log("remote_config.\(source) rejected: same version but different content hash")
                    return false
                }
            }

            latestRemoteConfig = effectiveConfig

            DynamicFeatureList.shared.applyRemoteConfig(
                additionalSuspiciousLibraries: effectiveConfig.additionalSuspiciousLibraries,
                additionalSuspiciousPaths: effectiveConfig.additionalSuspiciousPaths,
                additionalSuspiciousPorts: effectiveConfig.additionalSuspiciousPorts
            )

            return true
        }

        if accepted {
            stateLock.withLock { lastRemoteAppStoreSafeProfileFlag = remoteSafe }
            reapplyAntiDebugRuntimeModeAfterRemoteConfigChange()
        }

        return accepted
    }

    // MARK: - Certificate Pinning & Trust

    internal func applyPinnedCertificateHashes(_ material: PinnedCertificatePinMaterial) {
        currentRemoteConfigProvider()?.configurePinning(pinMaterial: material)
    }

    internal func refreshRemoteTrustState() {
        if let provider = currentRemoteConfigProvider() {
            provider.reloadCachedConfigTrustState()
            _ = applyRemoteConfigIfAccepted(provider.currentConfig, source: "trust_refresh", validateStrictly: false)
        } else {
            stateLock.withLock {
                latestRemoteConfig = nil
                lastRemoteAppStoreSafeProfileFlag = false
            }
            reapplyAntiDebugRuntimeModeAfterRemoteConfigChange()
        }
        PolicyManager.shared.reloadTrustedCacheState()
    }

    // MARK: - Attestation Envelope

    @available(iOS 14.0, macOS 11.0, *)
    internal func buildSecureReportEnvelopeWithAttestationImpl(
        report: CPRiskReport, sessionToken: String, signingKey: String,
        keyId: String = "k1", requireAttestation: Bool = true
    ) async throws -> ReportEnvelope {
        let effectiveKeyId = (keyId == "k1" && TrustChainManager.currentKeyRotationPolicy() != nil)
            ? TrustChainManager.currentKeyId(baseKeyId: keyId) : keyId
        guard AppAttestSigner.isSupported else {
            if requireAttestation { throw AppAttestSigner.AppAttestError.hardwareTrustUnsupported }
            return try buildSecureReportEnvelopeImpl(report: report, sessionToken: sessionToken, signingKey: signingKey, keyId: effectiveKeyId, requireArmor: false)
        }
        do {
            let attestKeyId = try await AppAttestSigner.resolveKeyId()
            var envelope = try buildSecureReportEnvelopeImpl(report: report, sessionToken: sessionToken, signingKey: signingKey, keyId: effectiveKeyId, attestationKeyId: attestKeyId)
            guard let payloadData = (try envelope.canonicalPayloadString()).data(using: .utf8) else {
                if requireAttestation { throw SecureUploadError.invalidPayloadShape }
                return envelope
            }
            let (_, assertion) = try await AppAttestSigner.generateAssertion(for: payloadData)
            envelope = envelope.withAttestation(attestationKeyId: attestKeyId, assertion: assertion)
            if TrustChainManager.shouldRefreshAttestation(),
               let ch = PolicyManager.shared.activePolicy?.reAttestationChallenge, !ch.isEmpty {
                do {
                    let (_, ra) = try await AppAttestSigner.generateAssertion(for: ch)
                    envelope = envelope.withReAttestationAssertion(ra)
                    TrustChainManager.markAttestationChecked()
                } catch { envelope = envelope.withTrustLevel(TrustChainManager.degradedTrustLevel()) }
            } else { TrustChainManager.markAttestationChecked() }
            return envelope
        } catch {
            if requireAttestation { throw error }
            let fallback = try buildSecureReportEnvelopeImpl(report: report, sessionToken: sessionToken, signingKey: signingKey, keyId: effectiveKeyId, requireArmor: false)
            return fallback.withTrustLevel(TrustChainManager.degradedTrustLevel())
        }
    }

    // MARK: - Static Helpers

    internal static func normalizedPinnedCertificateHashes(from hashes: [String]) -> Set<String> {
        Set(
            hashes
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }
        )
    }

    internal static func currentPinnedPinMaterial() -> PinnedCertificatePinMaterial {
        remoteTrustLock.withLock { pinnedCertificatePinMaterial }
    }

    internal static func releaseHardenedRemoteConfig(_ config: RemoteConfig) -> RemoteConfig {
#if DEBUG
        return config
#else
        return config.enforcingReleaseSecurityFloor()
#endif
    }

    internal static func stableConfigHash(_ config: RemoteConfig) -> String? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(config) else { return nil }
        return SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
    }

    internal static func integrityRecheckPoisonedSignal() -> RiskSignal {
        RiskSignal(
            id: ObfuscatedConstants.signalIntegrityRuntimeTampered,
            category: "integrity",
            score: 85,
            evidence: ["reason": "integrity_poison_flag_set"],
            state: .tampered,
            layer: 2,
            weightHint: 85
        )
    }

    private static func mprotectTamperedSignal() -> RiskSignal {
        RiskSignal(
            id: ObfuscatedConstants.signalMemoryProtectionTampered,
            category: ObfuscatedConstants.categoryAntiTamper,
            score: 85,
            evidence: ["detail": "mprotect_syscall_blocked"],
            state: .tampered,
            layer: 1,
            weightHint: 90
        )
    }
}
