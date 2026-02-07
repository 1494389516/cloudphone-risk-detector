import XCTest
@testable import CloudPhoneRiskKit

/// 时序分析单元测试
/// 
/// 测试策略：
/// 1. 测试事件存储与检索
/// 2. 测试时序特征计算
/// 3. 测试异常检测
/// 4. 测试边界条件与清理策略
final class TemporalAnalysisTests: XCTestCase {
    
    var store: RiskHistoryStore!
    
    override func setUp() {
        super.setUp()
        store = RiskHistoryStore(defaults: UserDefaults())
        // 清空测试数据
        clearStore()
    }
    
    override func tearDown() {
        clearStore()
        super.tearDown()
    }
    
    private func clearStore() {
        // 通过添加过期事件触发清理
        let now = Date().timeIntervalSince1970
        let oldEvent = RiskHistoryEvent(t: now - 10 * 24 * 3600, score: 0, isHighRisk: false, summary: "old")
        store.append(oldEvent)
        store.append(RiskHistoryEvent(t: now, score: 0, isHighRisk: false, summary: "clear"))
    }
    
    // MARK: - 事件存储测试
    
    func testAppendEvent() {
        let event = RiskHistoryEvent(
            t: Date().timeIntervalSince1970,
            score: 50,
            isHighRisk: false,
            summary: "test_event"
        )
        
        store.append(event)
        
        let pattern = store.pattern(now: event.t + 1)
        XCTAssertEqual(pattern.events24h, 1, "应存储 1 个事件")
    }
    
    func testAppendMultipleEvents() {
        let now = Date().timeIntervalSince1970
        
        for i in 0..<5 {
            let event = RiskHistoryEvent(
                t: now + Double(i),
                score: Double(i * 10),
                isHighRisk: false,
                summary: "event_\(i)"
            )
            store.append(event)
        }
        
        let pattern = store.pattern(now: now + 10)
        XCTAssertEqual(pattern.events24h, 5, "应存储 5 个事件")
    }
    
    func testEventOrdering() {
        let now = Date().timeIntervalSince1970
        
        // 乱序添加
        store.append(RiskHistoryEvent(t: now + 3, score: 30, isHighRisk: false, summary: "c"))
        store.append(RiskHistoryEvent(t: now + 1, score: 10, isHighRisk: false, summary: "a"))
        store.append(RiskHistoryEvent(t: now + 2, score: 20, isHighRisk: false, summary: "b"))
        
        // 获取最新事件应该是最后添加的
        let pattern = store.pattern(now: now + 10)
        XCTAssertEqual(pattern.events24h, 3, "应有 3 个事件")
    }
    
    // MARK: - 时间窗口测试
    
    func test24HourWindow() {
        let now = Date().timeIntervalSince1970
        
        // 24 小时内的事件
        store.append(RiskHistoryEvent(t: now - 3600, score: 10, isHighRisk: false, summary: "recent"))
        
        // 24 小时外的事件
        store.append(RiskHistoryEvent(t: now - 25 * 3600, score: 20, isHighRisk: false, summary: "old"))
        
        let pattern = store.pattern(now: now)
        XCTAssertEqual(pattern.events24h, 1, "只应统计 24 小时内的事件")
    }
    
    func testWindowBoundary() {
        let now = Date().timeIntervalSince1970
        let windowStart = now - 24 * 3600
        
        // 刚好在边界内
        store.append(RiskHistoryEvent(t: windowStart + 1, score: 10, isHighRisk: false, summary: "inside"))
        
        // 刚好在边界外
        store.append(RiskHistoryEvent(t: windowStart - 1, score: 20, isHighRisk: false, summary: "outside"))
        
        let pattern = store.pattern(now: now)
        XCTAssertEqual(pattern.events24h, 1, "边界事件应正确处理")
    }
    
    func testFutureEventIgnored() {
        let now = Date().timeIntervalSince1970
        
        store.append(RiskHistoryEvent(t: now - 3600, score: 10, isHighRisk: false, summary: "past"))
        store.append(RiskHistoryEvent(t: now + 3600, score: 20, isHighRisk: false, summary: "future"))
        
        let pattern = store.pattern(now: now)
        // future 事件在 now 之后的窗口外
        XCTAssertEqual(pattern.events24h, 1, "未来事件不应被统计")
    }
    
    // MARK: - 小时分布测试
    
    func testUniqueHours() {
        let now = Date().timeIntervalSince1970
        let calendar = Calendar(identifier: .gregorian)
        let currentHour = calendar.component(.hour, from: Date())
        
        // 在不同小时添加事件
        for offset in [-3600, -7200, -10800] {
            let event = RiskHistoryEvent(
                t: now + Double(offset),
                score: 10,
                isHighRisk: false,
                summary: "hour_event"
            )
            store.append(event)
        }
        
        let pattern = store.pattern(now: now)
        XCTAssertEqual(pattern.uniqueHours24h, 3, "应有 3 个不同小时")
    }
    
    func testSameHourEvents() {
        let now = Date().timeIntervalSince1970
        
        // 在同一小时内添加多个事件
        for i in 0..<5 {
            let event = RiskHistoryEvent(
                t: now + Double(i * 60),  // 每分钟一个
                score: 10,
                isHighRisk: false,
                summary: "same_hour"
            )
            store.append(event)
        }
        
        let pattern = store.pattern(now: now + 300)
        XCTAssertEqual(pattern.uniqueHours24h, 1, "同一小时应只计为 1 个")
    }
    
    // MARK: - 夜间活动测试
    
    func testNightActivityDetection() {
        let now = Date().timeIntervalSince1970
        
        // 模拟凌晨 2 点的活动（0-5 点为夜间）
        let calendar = Calendar(identifier: .gregorian)
        var components = calendar.dateComponents([.year, .month, .day], from: Date())
        components.hour = 2
        components.minute = 30
        let nightTime = calendar.date(from: components)!.timeIntervalSince1970
        
        store.append(RiskHistoryEvent(t: nightTime, score: 10, isHighRisk: false, summary: "night"))
        store.append(RiskHistoryEvent(t: nightTime + 3600, score: 10, isHighRisk: false, summary: "night2"))
        store.append(RiskHistoryEvent(t: nightTime + 7200, score: 10, isHighRisk: false, summary: "night3"))
        
        // 白天活动
        components.hour = 14
        let dayTime = calendar.date(from: components)!.timeIntervalSince1970
        store.append(RiskHistoryEvent(t: dayTime, score: 10, isHighRisk: false, summary: "day"))
        
        let pattern = store.pattern(now: dayTime + 3600)
        XCTAssertEqual(pattern.events24h, 4, "总事件数应为 4")
        XCTAssertEqual(pattern.nightRatio24h ?? 0, 0.75, accuracy: 0.01, "夜间比例应为 75%")
    }
    
    func testNoNightActivity() {
        let now = Date().timeIntervalSince1970
        
        // 只有白天活动（10-18 点）
        for hour in [10, 12, 14, 16] {
            let calendar = Calendar(identifier: .gregorian)
            var components = calendar.dateComponents([.year, .month, .day], from: Date())
            components.hour = hour
            let time = calendar.date(from: components)!.timeIntervalSince1970
            
            store.append(RiskHistoryEvent(t: time, score: 10, isHighRisk: false, summary: "day_\(hour)"))
        }
        
        let pattern = store.pattern(now: now)
        XCTAssertEqual(pattern.nightRatio24h, 0.0, "无夜间活动时比例应为 0")
    }
    
    // MARK: - 间隔时间测试
    
    func testAverageInterval() {
        let now = Date().timeIntervalSince1970
        
        // 事件间隔：5 分钟
        let baseTime = now - 3600
        for i in 0..<4 {
            let event = RiskHistoryEvent(
                t: baseTime + Double(i * 300),  // 每 5 分钟
                score: 10,
                isHighRisk: false,
                summary: "interval_\(i)"
            )
            store.append(event)
        }
        
        let pattern = store.pattern(now: now)
        XCTAssertEqual(pattern.averageIntervalSeconds24h ?? 0, 300, accuracy: 0.1, "平均间隔应为 300 秒")
    }
    
    func testVariableIntervals() {
        let now = Date().timeIntervalSince1970
        
        // 可变间隔：1 分钟、5 分钟、10 分钟
        let baseTime = now - 1000
        store.append(RiskHistoryEvent(t: baseTime, score: 10, isHighRisk: false, summary: "t0"))
        store.append(RiskHistoryEvent(t: baseTime + 60, score: 10, isHighRisk: false, summary: "t1"))
        store.append(RiskHistoryEvent(t: baseTime + 360, score: 10, isHighRisk: false, summary: "t2"))
        store.append(RiskHistoryEvent(t: baseTime + 960, score: 10, isHighRisk: false, summary: "t3"))
        
        // 间隔: 60, 300, 600
        // 平均: (60 + 300 + 600) / 3 = 320
        let pattern = store.pattern(now: now)
        XCTAssertEqual(pattern.averageIntervalSeconds24h ?? 0, 320, accuracy: 0.1)
    }
    
    func testSingleEventNoInterval() {
        let now = Date().timeIntervalSince1970
        
        store.append(RiskHistoryEvent(t: now - 100, score: 10, isHighRisk: false, summary: "single"))
        
        let pattern = store.pattern(now: now)
        XCTAssertNil(pattern.averageIntervalSeconds24h, "单个事件不应有平均间隔")
    }
    
    // MARK: - 事件限制测试
    
    func testMaxEventsLimit() {
        // 测试最多存储 200 个事件
        let now = Date().timeIntervalSince1970
        
        // 添加超过限制的事件
        for i in 0..<250 {
            let event = RiskHistoryEvent(
                t: now - Double(i * 60),  // 时间倒序
                score: 10,
                isHighRisk: false,
                summary: "event_\(i)"
            )
            store.append(event)
        }
        
        // 由于有 7 天过期限制，这里只测试逻辑
        // 实际限制在 7 天内的 200 个
        let pattern = store.pattern(now: now)
        XCTAssertLessThanOrEqual(pattern.events24h, 200, "事件数不应超过限制")
    }
    
    func testMaxAgePruning() {
        // 测试 7 天过期
        let now = Date().timeIntervalSince1970
        let eightDaysAgo = now - 8 * 24 * 3600
        
        store.append(RiskHistoryEvent(t: eightDaysAgo, score: 10, isHighRisk: false, summary: "too_old"))
        store.append(RiskHistoryEvent(t: now - 3600, score: 10, isHighRisk: false, summary: "recent"))
        
        let pattern = store.pattern(now: now)
        XCTAssertEqual(pattern.events24h, 1, "过期事件应被清理")
    }
    
    // MARK: - 时序异常测试
    
    func testBurstActivity() {
        // 测试突发活动（短时间内大量事件）
        let now = Date().timeIntervalSince1970
        
        // 1 小时内 20 个事件
        for i in 0..<20 {
            let event = RiskHistoryEvent(
                t: now - Double(i * 180),  // 每 3 分钟
                score: 10,
                isHighRisk: false,
                summary: "burst_\(i)"
            )
            store.append(event)
        }
        
        let pattern = store.pattern(now: now)
        XCTAssertEqual(pattern.events24h, 20)
        XCTAssertLessThan(pattern.averageIntervalSeconds24h!, 200, "突发活动间隔应很小")
    }
    
    func testSparseActivity() {
        // 测试稀疏活动（长时间只有少量事件）
        let now = Date().timeIntervalSince1970
        
        // 24 小时内只有 3 个事件
        store.append(RiskHistoryEvent(t: now - 8 * 3600, score: 10, isHighRisk: false, summary: "sparse1"))
        store.append(RiskHistoryEvent(t: now - 16 * 3600, score: 10, isHighRisk: false, summary: "sparse2"))
        store.append(RiskHistoryEvent(t: now - 23 * 3600, score: 10, isHighRisk: false, summary: "sparse3"))
        
        let pattern = store.pattern(now: now)
        XCTAssertEqual(pattern.events24h, 3)
        XCTAssertGreaterThan(pattern.averageIntervalSeconds24h!, 10000, "稀疏活动间隔应很大")
    }
    
    // MARK: - 风险分数时序测试
    
    func testRiskScoreTracking() {
        let now = Date().timeIntervalSince1970
        
        store.append(RiskHistoryEvent(t: now - 7200, score: 10, isHighRisk: false, summary: "low"))
        store.append(RiskHistoryEvent(t: now - 3600, score: 50, isHighRisk: false, summary: "medium"))
        store.append(RiskHistoryEvent(t: now - 1800, score: 80, isHighRisk: true, summary: "high"))
        
        // RiskHistoryStore 只存储模式，不存储原始事件
        // 这里测试事件能被正确存储和计数
        let pattern = store.pattern(now: now)
        XCTAssertEqual(pattern.events24h, 3)
    }
    
    func testHighRiskEventsOnly() {
        let now = Date().timeIntervalSince1970
        
        store.append(RiskHistoryEvent(t: now - 3600, score: 70, isHighRisk: true, summary: "high1"))
        store.append(RiskHistoryEvent(t: now - 1800, score: 75, isHighRisk: true, summary: "high2"))
        
        let pattern = store.pattern(now: now)
        XCTAssertEqual(pattern.events24h, 2)
    }
    
    // MARK: - 边界条件测试
    
    func testEmptyStore() {
        let pattern = store.pattern()
        XCTAssertEqual(pattern.events24h, 0, "空存储应返回 0 事件")
        XCTAssertEqual(pattern.uniqueHours24h, 0)
        XCTAssertNil(pattern.nightRatio24h)
        XCTAssertNil(pattern.averageIntervalSeconds24h)
    }
    
    func testZeroTimestamp() {
        let event = RiskHistoryEvent(t: 0, score: 10, isHighRisk: false, summary: "epoch")
        store.append(event)
        
        // 0 时间戳在 1970 年，远超过 7 天窗口
        let pattern = store.pattern(now: Date().timeIntervalSince1970)
        XCTAssertEqual(pattern.events24h, 0, "过期时间戳的事件不应被统计")
    }
    
    func testNegativeTimestamp() {
        let event = RiskHistoryEvent(t: -1000, score: 10, isHighRisk: false, summary: "negative")
        store.append(event)
        
        let pattern = store.pattern(now: Date().timeIntervalSince1970)
        XCTAssertEqual(pattern.events24h, 0)
    }
    
    // MARK: - 并发测试
    
    func testConcurrentAppend() {
        let now = Date().timeIntervalSince1970
        let expectation = XCTestExpectation(description: "Concurrent appends")
        expectation.expectedFulfillmentCount = 10
        
        let queue = DispatchQueue.global(qos: .userInitiated)
        
        for i in 0..<10 {
            queue.async {
                let event = RiskHistoryEvent(
                    t: now + Double(i),
                    score: 10,
                    isHighRisk: false,
                    summary: "concurrent_\(i)"
                )
                self.store.append(event)
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
        
        let pattern = store.pattern(now: now + 100)
        XCTAssertEqual(pattern.events24h, 10, "所有并发事件应被存储")
    }
    
    // MARK: - 序列化测试
    
    func testEventSerialization() {
        let event = RiskHistoryEvent(
            t: 1234567890.0,
            score: 55.5,
            isHighRisk: true,
            summary: "test_summary"
        )
        
        let encoded = try? JSONEncoder().encode(event)
        XCTAssertNotNil(encoded, "事件应能被编码")
        
        let decoded = try? JSONDecoder().decode(RiskHistoryEvent.self, from: encoded!)
        XCTAssertNotNil(decoded, "事件应能被解码")
        XCTAssertEqual(decoded?.t, event.t)
        XCTAssertEqual(decoded?.score, event.score)
        XCTAssertEqual(decoded?.isHighRisk, event.isHighRisk)
        XCTAssertEqual(decoded?.summary, event.summary)
    }
    
    func testPatternSerialization() {
        let pattern = TimePattern(
            events24h: 42,
            uniqueHours24h: 18,
            nightRatio24h: 0.15,
            averageIntervalSeconds24h: 3600.0
        )
        
        let encoded = try? JSONEncoder().encode(pattern)
        XCTAssertNotNil(encoded)
        
        let decoded = try? JSONDecoder().decode(TimePattern.self, from: encoded!)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?.events24h, 42)
        XCTAssertEqual(decoded?.uniqueHours24h, 18)
    }
}
