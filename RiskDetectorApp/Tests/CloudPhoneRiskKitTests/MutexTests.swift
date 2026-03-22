import XCTest
@testable import CloudPhoneRiskKit

final class MutexTests: XCTestCase {

    // MARK: - Basic Mutex<Value> Tests

    func testMutexInitialValue() {
        let mutex = Mutex(42)
        let value = mutex.withLock { $0 }
        XCTAssertEqual(value, 42)
    }

    func testMutexMutation() {
        let mutex = Mutex(0)
        mutex.withLock { $0 = 99 }
        let value = mutex.withLock { $0 }
        XCTAssertEqual(value, 99)
    }

    func testMutexReturnValue() {
        let mutex = Mutex([1, 2, 3])
        let count = mutex.withLock { $0.count }
        XCTAssertEqual(count, 3)
    }

    func testMutexWithStructState() {
        struct State {
            var counter: Int = 0
            var name: String = ""
        }

        let mutex = Mutex(State())
        mutex.withLock {
            $0.counter = 10
            $0.name = "test"
        }

        let snapshot = mutex.withLock { ($0.counter, $0.name) }
        XCTAssertEqual(snapshot.0, 10)
        XCTAssertEqual(snapshot.1, "test")
    }

    func testMutexThrowingClosure() {
        struct TestError: Error {}
        let mutex = Mutex(0)

        XCTAssertThrowsError(try mutex.withLock { _ -> Int in
            throw TestError()
        })

        // Value should be unchanged after thrown error
        let value = mutex.withLock { $0 }
        XCTAssertEqual(value, 0)
    }

    func testMutexConcurrentAccess() {
        let mutex = Mutex(0)
        let iterations = 1000
        let expectation = XCTestExpectation(description: "concurrent")
        expectation.expectedFulfillmentCount = iterations

        for _ in 0..<iterations {
            DispatchQueue.global().async {
                mutex.withLock { $0 += 1 }
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 10.0)
        let finalValue = mutex.withLock { $0 }
        XCTAssertEqual(finalValue, iterations)
    }

    func testMutexConcurrentReadWrite() {
        struct State {
            var items: [Int] = []
        }

        let mutex = Mutex(State())
        let writeCount = 500
        let readCount = 500
        let group = DispatchGroup()

        // Concurrent writes
        for i in 0..<writeCount {
            group.enter()
            DispatchQueue.global().async {
                mutex.withLock { $0.items.append(i) }
                group.leave()
            }
        }

        // Concurrent reads
        for _ in 0..<readCount {
            group.enter()
            DispatchQueue.global().async {
                _ = mutex.withLock { $0.items.count }
                group.leave()
            }
        }

        let result = group.wait(timeout: .now() + 10)
        XCTAssertEqual(result, .success)

        let finalCount = mutex.withLock { $0.items.count }
        XCTAssertEqual(finalCount, writeCount)
    }

    // MARK: - UnfairLock Tests

    func testUnfairLockBasic() {
        let lock = UnfairLock()
        var counter = 0

        lock.withLock { counter += 1 }
        XCTAssertEqual(counter, 1)
    }

    func testUnfairLockReturnValue() {
        let lock = UnfairLock()
        let result = lock.withLock { 42 }
        XCTAssertEqual(result, 42)
    }

    func testUnfairLockConcurrent() {
        let lock = UnfairLock()
        var counter = 0
        let iterations = 1000
        let expectation = XCTestExpectation(description: "concurrent lock")
        expectation.expectedFulfillmentCount = iterations

        for _ in 0..<iterations {
            DispatchQueue.global().async {
                lock.withLock { counter += 1 }
                expectation.fulfill()
            }
        }

        wait(for: [expectation], timeout: 10.0)
        XCTAssertEqual(counter, iterations)
    }

    func testUnfairLockThrowingClosure() {
        struct TestError: Error {}
        let lock = UnfairLock()

        XCTAssertThrowsError(try lock.withLock { () -> Int in
            throw TestError()
        })
    }
}
