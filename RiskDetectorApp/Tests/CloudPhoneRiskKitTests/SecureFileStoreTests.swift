import XCTest
@testable import CloudPhoneRiskKit

final class SecureFileStoreTests: XCTestCase {

    private var store: SecureFileStore!
    private let testSubdir = "test_secure_store_\(UUID().uuidString)"

    override func setUp() {
        super.setUp()
        store = SecureFileStore(subdirectory: testSubdir)
    }

    override func tearDown() {
        // Clean up test files
        if let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first {
            let testDir = appSupport.appendingPathComponent(testSubdir)
            try? FileManager.default.removeItem(at: testDir)
        }
        store = nil
        super.tearDown()
    }

    // MARK: - Basic Read/Write

    func testWriteAndRead() {
        let data = Data("hello secure store".utf8)
        XCTAssertTrue(store.write(key: "test_key", data: data))

        let readBack = store.read(key: "test_key")
        XCTAssertEqual(readBack, data)
    }

    func testReadNonExistentKey() {
        let data = store.read(key: "nonexistent_key")
        XCTAssertNil(data)
    }

    func testOverwrite() {
        let data1 = Data("first".utf8)
        let data2 = Data("second".utf8)

        store.write(key: "overwrite_key", data: data1)
        store.write(key: "overwrite_key", data: data2)

        let readBack = store.read(key: "overwrite_key")
        XCTAssertEqual(readBack, data2)
    }

    // MARK: - Remove

    func testRemove() {
        let data = Data("to be removed".utf8)
        store.write(key: "remove_key", data: data)

        store.remove(key: "remove_key")
        XCTAssertNil(store.read(key: "remove_key"))
    }

    func testRemoveNonExistent() {
        // Should not crash
        store.remove(key: "nonexistent")
    }

    // MARK: - Exists

    func testExists() {
        XCTAssertFalse(store.exists(key: "exists_key"))

        store.write(key: "exists_key", data: Data("data".utf8))
        XCTAssertTrue(store.exists(key: "exists_key"))

        store.remove(key: "exists_key")
        XCTAssertFalse(store.exists(key: "exists_key"))
    }

    // MARK: - Size

    func testSize() {
        let data = Data("12345678".utf8)
        store.write(key: "size_key", data: data)

        let size = store.size(key: "size_key")
        XCTAssertEqual(size, 8)
    }

    func testSizeNonExistent() {
        XCTAssertEqual(store.size(key: "nonexistent"), 0)
    }

    // MARK: - Key Sanitization

    func testKeySanitizationSlash() {
        let data = Data("sanitized".utf8)
        store.write(key: "path/with/slashes", data: data)

        let readBack = store.read(key: "path/with/slashes")
        XCTAssertEqual(readBack, data)
    }

    func testKeySanitizationDotDot() {
        let data = Data("sanitized".utf8)
        store.write(key: "../escape_attempt", data: data)

        let readBack = store.read(key: "../escape_attempt")
        XCTAssertEqual(readBack, data)
    }

    // MARK: - Empty Data

    func testWriteEmptyData() {
        let emptyData = Data()
        XCTAssertTrue(store.write(key: "empty_key", data: emptyData))

        let readBack = store.read(key: "empty_key")
        XCTAssertEqual(readBack, emptyData)
    }

    // MARK: - Thread Safety

    func testConcurrentReadWrite() {
        let iterations = 100
        let group = DispatchGroup()

        for i in 0..<iterations {
            group.enter()
            DispatchQueue.global().async {
                let key = "concurrent_\(i % 10)"
                let data = Data("value_\(i)".utf8)
                self.store.write(key: key, data: data)
                _ = self.store.read(key: key)
                _ = self.store.exists(key: key)
                _ = self.store.size(key: key)
                group.leave()
            }
        }

        let result = group.wait(timeout: .now() + 10)
        XCTAssertEqual(result, .success)
    }
}
