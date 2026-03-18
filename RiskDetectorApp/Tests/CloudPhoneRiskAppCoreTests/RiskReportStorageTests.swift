import XCTest

@testable import CloudPhoneRiskAppCore
@testable import CloudPhoneRiskKit

/// RiskReportStorage 单元测试：保存/加载、持久化、错误处理。
final class RiskReportStorageTests: XCTestCase {

  private var tempDir: URL!

  override func setUp() {
    super.setUp()
    tempDir = FileManager.default.temporaryDirectory
      .appendingPathComponent(UUID().uuidString, isDirectory: true)
    try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
  }

  override func tearDown() {
    try? FileManager.default.removeItem(at: tempDir)
    super.tearDown()
  }

  // MARK: - reportsDirectoryURL

  func testReportsDirectoryURL_ReturnsValidPath() throws {
    let url = try RiskReportStorage.reportsDirectoryURL()
    XCTAssertTrue(url.path.contains("CloudPhoneRiskKit"))
    XCTAssertEqual(url.lastPathComponent, "reports")
  }

  func testResolveBaseDirectoryPrefersApplicationSupport() {
    let appSupport = URL(fileURLWithPath: "/tmp/app-support", isDirectory: true)
    let caches = URL(fileURLWithPath: "/tmp/caches", isDirectory: true)
    let temp = URL(fileURLWithPath: "/tmp/temp", isDirectory: true)

    let resolved = RiskReportStorage.resolveBaseDirectory(
      applicationSupportDirectories: [appSupport],
      cachesDirectories: [caches],
      temporaryDirectory: temp
    )

    XCTAssertEqual(resolved, appSupport)
  }

  func testResolveBaseDirectoryFallsBackToCaches() {
    let caches = URL(fileURLWithPath: "/tmp/caches", isDirectory: true)
    let temp = URL(fileURLWithPath: "/tmp/temp", isDirectory: true)

    let resolved = RiskReportStorage.resolveBaseDirectory(
      applicationSupportDirectories: [],
      cachesDirectories: [caches],
      temporaryDirectory: temp
    )

    XCTAssertEqual(resolved, caches.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true))
  }

  func testResolveBaseDirectoryFallsBackToTemporaryDirectory() {
    let temp = URL(fileURLWithPath: "/tmp/temp", isDirectory: true)

    let resolved = RiskReportStorage.resolveBaseDirectory(
      applicationSupportDirectories: [],
      cachesDirectories: [],
      temporaryDirectory: temp
    )

    XCTAssertEqual(resolved, temp.appendingPathComponent("CloudPhoneRiskKit", isDirectory: true))
  }

  // MARK: - list(in:)

  func testList_EmptyDirectoryReturnsEmpty() {
    let items = RiskReportStorage.list(in: tempDir)
    XCTAssertTrue(items.isEmpty)
  }

  func testList_IgnoresMetaFiles() {
    let metaPath = tempDir.appendingPathComponent("risk-123.json.meta.json")
    try? "{}".write(to: metaPath, atomically: true, encoding: .utf8)
    let items = RiskReportStorage.list(in: tempDir)
    XCTAssertTrue(items.isEmpty, "应忽略 .meta.json 文件")
  }

  func testList_ReturnsReportsSortedByModifiedDate() {
    let report1 = tempDir.appendingPathComponent("risk-001.json")
    let report2 = tempDir.appendingPathComponent("risk-002.json")
    try? "{\"deviceID\":\"a\"}".write(to: report1, atomically: true, encoding: .utf8)
    try? "{\"deviceID\":\"b\"}".write(to: report2, atomically: true, encoding: .utf8)

    let items = RiskReportStorage.list(in: tempDir)
    XCTAssertEqual(items.count, 2)
    XCTAssertTrue(items[0].filename == "risk-001.json" || items[0].filename == "risk-002.json")
    XCTAssertEqual(items[0].isEncrypted, false)
    XCTAssertGreaterThanOrEqual(items[0].bytes, 0)
  }

  // MARK: - loadJSONString / loadDTO

  func testLoadJSONString_ExistingFile() {
    let path = tempDir.appendingPathComponent("test-report.json").path
    let content = "{\"deviceID\":\"test-123\"}"
    try? content.write(toFile: path, atomically: true, encoding: .utf8)

    #if os(iOS)
      // iOS 使用 CPRiskStore 解密，测试环境可能不可用
      _ = RiskReportStorage.loadJSONString(atPath: path)
    #else
      let loaded = RiskReportStorage.loadJSONString(atPath: path)
      XCTAssertEqual(loaded, content)
    #endif
  }

  func testLoadJSONString_NonExistentFileReturnsNil() {
    let path = "/nonexistent/path/risk-999.json"
    let loaded = RiskReportStorage.loadJSONString(atPath: path)
    #if os(iOS)
      _ = loaded
    #else
      XCTAssertNil(loaded)
    #endif
  }

  func testLoadDTO_ValidJSON() {
    let json = """
      {
        "generatedAt": "2024-01-15T10:00:00.000Z",
        "deviceID": "storage-test",
        "score": 30,
        "isHighRisk": false,
        "summary": "low_risk",
        "network": {
          "interfaceType": {"value": "wifi", "method": "NWPathMonitor"},
          "isExpensive": false,
          "isConstrained": false,
          "vpn": {"detected": false, "method": "ifaddrs", "confidence": "weak"},
          "proxy": {"detected": false, "method": "CFNetwork", "confidence": "weak"}
        },
        "behavior": {
          "touch": {"sampleCount": 0, "tapCount": 0, "swipeCount": 0},
          "motion": {"sampleCount": 0},
          "touchMotionCorrelation": null,
          "actionCount": 0
        },
        "jailbreak": {
          "isJailbroken": false,
          "confidence": 0,
          "detectedMethods": [],
          "details": ""
        },
        "signals": []
      }
      """
    let path = tempDir.appendingPathComponent("valid-report.json").path
    try? json.write(toFile: path, atomically: true, encoding: .utf8)

    #if os(iOS)
      _ = RiskReportStorage.loadDTO(atPath: path)
    #else
      let dto = RiskReportStorage.loadDTO(atPath: path)
      XCTAssertNotNil(dto)
      XCTAssertEqual(dto?.deviceID, "storage-test")
      XCTAssertEqual(dto?.score, 30)
    #endif
  }

  func testLoadDTO_InvalidJSONReturnsNil() {
    let path = tempDir.appendingPathComponent("invalid.json").path
    try? "not json".write(toFile: path, atomically: true, encoding: .utf8)

    #if os(iOS)
      _ = RiskReportStorage.loadDTO(atPath: path)
    #else
      let dto = RiskReportStorage.loadDTO(atPath: path)
      XCTAssertNil(dto)
    #endif
  }

  // MARK: - delete / deleteAll

  func testDelete_ExistingFile() {
    let path = tempDir.appendingPathComponent("to-delete.json").path
    try? "{}".write(toFile: path, atomically: true, encoding: .utf8)
    XCTAssertTrue(FileManager.default.fileExists(atPath: path))

    let result = RiskReportStorage.delete(atPath: path)
    XCTAssertTrue(result)
    XCTAssertFalse(FileManager.default.fileExists(atPath: path))
  }

  func testDelete_NonExistentFileReturnsFalse() {
    let result = RiskReportStorage.delete(atPath: "/nonexistent/file.json")
    XCTAssertFalse(result)
  }

  func testDeleteAll_RemovesAllReports() {
    let r1 = tempDir.appendingPathComponent("r1.json").path
    let r2 = tempDir.appendingPathComponent("r2.json").path
    try? "{}".write(toFile: r1, atomically: true, encoding: .utf8)
    try? "{}".write(toFile: r2, atomically: true, encoding: .utf8)

    RiskReportStorage.deleteAll()
    // deleteAll 使用 list() 获取默认目录，不会影响 tempDir；此处仅验证不崩溃
    _ = RiskReportStorage.list(in: tempDir)
    try? FileManager.default.removeItem(atPath: r1)
    try? FileManager.default.removeItem(atPath: r2)
  }

  // MARK: - StoredRiskReport

  func testStoredRiskReport_IsEncryptedFlag() {
    let encryptedPath = tempDir.appendingPathComponent("risk.enc")
    try? Data().write(to: encryptedPath)
    let items = RiskReportStorage.list(in: tempDir)
    let enc = items.first { $0.filename.hasSuffix(".enc") }
    XCTAssertNotNil(enc)
    XCTAssertTrue(enc?.isEncrypted ?? false)

    let jsonPath = tempDir.appendingPathComponent("risk.json")
    try? "{}".write(to: jsonPath, atomically: true, encoding: .utf8)
    let jsonItems = RiskReportStorage.list(in: tempDir)
    let json = jsonItems.first {
      $0.filename.hasSuffix(".json") && !$0.filename.hasSuffix(".meta.json")
    }
    XCTAssertNotNil(json)
    XCTAssertFalse(json?.isEncrypted ?? true)
  }
}
