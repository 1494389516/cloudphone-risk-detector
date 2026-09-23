import Foundation

/// Authenticated HTTP client for the paired Collector service.
///
/// The client owns transport mechanics only. App Attest enrollment/report
/// serialization stays in `AppAttestSigner`, so challenge acquisition through
/// Collector acknowledgement is one serialized transaction.
@available(iOS 14.0, macOS 11.0, *)
public actor CollectorClient {
    public struct Configuration: Sendable {
        public let baseURL: URL
        public let bearerToken: String
        public let timeout: TimeInterval
        public let context: GrpcReportContext

        public init(
            baseURL: URL,
            bearerToken: String,
            timeout: TimeInterval = 10,
            context: GrpcReportContext
        ) {
            self.baseURL = baseURL
            self.bearerToken = bearerToken
            self.timeout = timeout
            self.context = context
        }
    }

    public struct Receipt: Sendable {
        public let evidenceID: String
        public let reportID: String
        public let idempotentReplay: Bool
    }

    public enum Error: Swift.Error, LocalizedError {
        case invalidConfiguration
        case invalidResponse
        case rejected(status: Int)
        case invalidChallenge
        case invalidReceipt

        public var errorDescription: String? {
            switch self {
            case .invalidConfiguration: return "Collector requires HTTPS and a non-empty bearer token"
            case .invalidResponse: return "Collector returned a non-HTTP response"
            case .rejected(let status): return "Collector rejected request (HTTP \(status))"
            case .invalidChallenge: return "Collector challenge response is invalid"
            case .invalidReceipt: return "Collector receipt is invalid"
            }
        }
    }

    private let configuration: Configuration
    private let session: URLSession

    public init(configuration: Configuration, session: URLSession? = nil) throws {
        guard configuration.baseURL.scheme?.lowercased() == "https",
              !configuration.bearerToken.isEmpty else {
            throw Error.invalidConfiguration
        }
        self.configuration = configuration
        if let session {
            self.session = session
        } else {
            let cfg = URLSessionConfiguration.ephemeral
            cfg.timeoutIntervalForRequest = configuration.timeout
            cfg.timeoutIntervalForResource = configuration.timeout
            self.session = URLSession(configuration: cfg)
        }
    }

    public func configureAppAttestEnrollment() {
        AppAttestSigner.configureEnrollment(
            challenge: { [self] in try await challenge(purpose: "enrollment") },
            submit: { [self] keyID, attestation, challengeID in
                try await enroll(keyID: keyID, attestation: attestation, challengeID: challengeID)
            }
        )
    }

    @discardableResult
    public func submit(
        payloadData: Data,
        reportID: String,
        sessionToken: String,
        signingKey: String,
        keyID: String
    ) async throws -> Receipt {
        var receipt: Receipt?
        try await AppAttestSigner.submitCollectorReport(
            payloadData: payloadData,
            reportId: reportID,
            sessionToken: sessionToken,
            signingKey: signingKey,
            keyId: keyID,
            challenge: { [self] in try await challenge(purpose: "assertion") },
            submit: { [self] envelope in
                receipt = try await upload(envelope)
            }
        )
        guard let receipt else { throw Error.invalidReceipt }
        return receipt
    }

    private func challenge(purpose: String) async throws -> AppAttestSigner.EnrollmentChallenge {
        let body = try JSONSerialization.data(withJSONObject: ["purpose": purpose], options: [.sortedKeys])
        let data = try await request(path: "/attestation/challenge", body: body)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let identifier = object["challenge_id"] as? String,
              let encoded = object["challenge"] as? String,
              let bytes = Data(base64Encoded: encoded),
              !identifier.isEmpty, bytes.count >= 32 else {
            throw Error.invalidChallenge
        }
        return .init(id: identifier, bytes: bytes)
    }

    private func enroll(keyID: String, attestation: Data, challengeID: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: [
            "key_id": keyID,
            "attestation": attestation.base64EncodedString(),
            "challenge_id": challengeID,
        ], options: [.sortedKeys])
        _ = try await request(path: "/attestation/enroll", body: body)
    }

    private func upload(_ envelope: ReportEnvelope) async throws -> Receipt {
        let body = try envelope.toGrpcRequestBytes(context: configuration.context)
        let data = try await request(path: "/reports", body: body)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let evidenceID = object["evidence_id"] as? String,
              let reportID = object["report_id"] as? String,
              !evidenceID.isEmpty, !reportID.isEmpty else {
            throw Error.invalidReceipt
        }
        return Receipt(
            evidenceID: evidenceID,
            reportID: reportID,
            idempotentReplay: object["idempotent_replay"] as? Bool ?? false
        )
    }

    private func request(path: String, body: Data) async throws -> Data {
        guard let url = URL(string: path, relativeTo: configuration.baseURL)?.absoluteURL else {
            throw Error.invalidConfiguration
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = configuration.timeout
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer " + configuration.bearerToken, forHTTPHeaderField: "Authorization")
        request.httpBody = body
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw Error.invalidResponse }
        guard (200..<300).contains(http.statusCode) else { throw Error.rejected(status: http.statusCode) }
        return data
    }
}
