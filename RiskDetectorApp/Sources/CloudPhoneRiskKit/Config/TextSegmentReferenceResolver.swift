import Foundation

/// __TEXT.__text 服务端参考哈希的本地解析结果。
///
/// `expectedHash` 应来自服务端预计算结果或其签名缓存，不应来自设备本地基线。
public struct TextSegmentReference: Codable, Sendable {
    public let expectedHash: String
    public let source: String
    public let version: String?

    private enum CodingKeys: String, CodingKey {
        case expectedHash = "eh"
        case source = "s"
        case version = "v"
    }

    public init(expectedHash: String, source: String = "custom", version: String? = nil) {
        self.expectedHash = expectedHash
        self.source = source
        self.version = version
    }
}

/// 可选的参考哈希解析扩展点。
///
/// 默认情况下 SDK 会使用 `RemoteConfig.textSegmentHashReference`。
/// 若业务方已有独立的签名配置中心，可注入该解析器覆盖默认来源。
public protocol TextSegmentReferenceResolving: Sendable {
    /// 返回指定 SDK 版本的可信参考哈希；返回 `nil` 时 SDK 会回退到默认 RemoteConfig 解析。
    ///
    /// 该方法应只访问本地已验证缓存或内存快照，不建议在检测链路中发起网络请求。
    func resolveTextSegmentReference(for sdkVersion: String) -> TextSegmentReference?
}
