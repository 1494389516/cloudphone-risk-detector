import Foundation
import XCTest

/// 测试模拟器工具集
/// 
/// 提供各种测试场��的模拟环境：
/// 1. 越狱环境模拟器
/// 2. 网络信号模拟器
/// 3. 行为数据模拟器
/// 4. 性能测试工具
enum TestSimulators {
    
    // MARK: - 越狱环境模拟器
    
    /// 越狱环境模拟器
    enum JailbreakSimulator {
        /// 越狱类型
        enum JailbreakType {
            case none              // 正常设备
            case checkra1n         // checkra1n 越狱
            case unc0ver           // unc0ver 越狱
            case palera1n          // palera1n（rootless）
            case dopamine          // Dopamine（rootless）
            case chimera           // Chimera 越狱
        }
        
        /// 生成模拟的越狱检测结果
        static func simulate(type: JailbreakType) -> MockJailbreakResult {
            switch type {
            case .none:
                return MockJailbreakResult(
                    isJailbroken: false,
                    confidence: 0,
                    detectedMethods: [],
                    details: "normal_device"
                )
                
            case .checkra1n:
                return MockJailbreakResult(
                    isJailbroken: true,
                    confidence: 85,
                    detectedMethods: [
                        "file:/Applications/checkra1n.app",
                        "dyld:cydia",
                        "dyld:substitute",
                        "file:/bin/bash"
                    ],
                    details: "checkra1n_jailbreak_detected"
                )
                
            case .unc0ver:
                return MockJailbreakResult(
                    isJailbroken: true,
                    confidence: 90,
                    detectedMethods: [
                        "file:/Applications/unc0ver.app",
                        "dyld:substrate",
                        "file:/Library/MobileSubstrate/DynamicLibraries",
                        "file:/etc/apt"
                    ],
                    details: "unc0ver_jailbreak_detected"
                )
                
            case .palera1n:
                return MockJailbreakResult(
                    isJailbroken: true,
                    confidence: 75,
                    detectedMethods: [
                        "file:/var/jb",
                        "file:/var/jb/Applications/Sileo.app",
                        "file:/var/jb/usr/lib/ElleKit.dylib"
                    ],
                    details: "palera1n_rootless_jailbreak"
                )
                
            case .dopamine:
                return MockJailbreakResult(
                    isJailbroken: true,
                    confidence: 80,
                    detectedMethods: [
                        "file:/var/jb",
                        "dyld:ellekit",
                        "objc_class:DopamineManager",
                        "file:/private/preboot/*/jb"
                    ],
                    details: "dopamine_rootless_jailbreak"
                )
                
            case .chimera:
                return MockJailbreakResult(
                    isJailbroken: true,
                    confidence: 88,
                    detectedMethods: [
                        "file:/Applications/chimera.app",
                        "dyld:substitute",
                        "file:/usr/lib/substitute",
                        "env:DYLD_INSERT_LIBRARIES"
                    ],
                    details: "chimera_jailbreak_detected"
                )
            }
        }
        
        /// 生成部分 Hook 的场景（使用修改工具）
        static func partialHook() -> MockJailbreakResult {
            MockJailbreakResult(
                isJailbroken: false,
                confidence: 35,
                detectedMethods: [
                    "objc_class:FridaGadget"
                ],
                details: "partial_hook_detected"
            )
        }
    }
    
    // MARK: - 网络信号模拟器
    
    /// 网络信号模拟器
    enum NetworkSimulator {
        /// 网络场景类型
        enum NetworkScenario {
            case normal            // 正常 Wi-Fi
            case vpnOnly           // 仅 VPN
            case proxyOnly         // 仅代理
            case vpnAndProxy       // VPN + 代理
            case cellular          // 蜂窝网络
            case datacenter        // 数据中心 IP
        }
        
        /// 生成模拟的网络信号
        static func simulate(scenario: NetworkScenario) -> MockNetworkSignals {
            switch scenario {
            case .normal:
                return MockNetworkSignals(
                    interfaceType: "wifi",
                    isExpensive: false,
                    isConstrained: false,
                    vpn: MockDetectionSignal(detected: false, method: "ifaddrs_prefix", evidence: nil, confidence: .weak),
                    proxy: MockDetectionSignal(detected: false, method: "CFNetworkCopySystemProxySettings", evidence: nil, confidence: .weak)
                )
                
            case .vpnOnly:
                return MockNetworkSignals(
                    interfaceType: "wifi",
                    isExpensive: false,
                    isConstrained: false,
                    vpn: MockDetectionSignal(
                        detected: true,
                        method: "ifaddrs_prefix",
                        evidence: ["utun0", "utun1"],
                        confidence: .weak
                    ),
                    proxy: MockDetectionSignal(detected: false, method: "CFNetworkCopySystemProxySettings", evidence: nil, confidence: .weak)
                )
                
            case .proxyOnly:
                return MockNetworkSignals(
                    interfaceType: "wifi",
                    isExpensive: false,
                    isConstrained: false,
                    vpn: MockDetectionSignal(detected: false, method: "ifaddrs_prefix", evidence: nil, confidence: .weak),
                    proxy: MockDetectionSignal(
                        detected: true,
                        method: "CFNetworkCopySystemProxySettings",
                        evidence: ["http_proxy": "127.0.0.1:8888", "pac_url": "http://proxy.pac"],
                        confidence: .weak
                    )
                )
                
            case .vpnAndProxy:
                return MockNetworkSignals(
                    interfaceType: "wifi",
                    isExpensive: false,
                    isConstrained: false,
                    vpn: MockDetectionSignal(
                        detected: true,
                        method: "ifaddrs_prefix",
                        evidence: ["utun0"],
                        confidence: .weak
                    ),
                    proxy: MockDetectionSignal(
                        detected: true,
                        method: "CFNetworkCopySystemProxySettings",
                        evidence: ["http_proxy": "192.168.1.1:8080"],
                        confidence: .weak
                    )
                )
                
            case .cellular:
                return MockNetworkSignals(
                    interfaceType: "cellular",
                    isExpensive: true,
                    isConstrained: false,
                    vpn: MockDetectionSignal(detected: false, method: "ifaddrs_prefix", evidence: nil, confidence: .weak),
                    proxy: MockDetectionSignal(detected: false, method: "CFNetworkCopySystemProxySettings", evidence: nil, confidence: .weak)
                )
                
            case .datacenter:
                return MockNetworkSignals(
                    interfaceType: "wired",
                    isExpensive: false,
                    isConstrained: false,
                    vpn: MockDetectionSignal(detected: false, method: "ifaddrs_prefix", evidence: nil, confidence: .weak),
                    proxy: MockDetectionSignal(detected: false, method: "CFNetworkCopySystemProxySettings", evidence: nil, confidence: .weak)
                )
            }
        }
    }
    
    // MARK: - 行为数据模拟器
    
    /// 行为数据模拟器
    enum BehaviorSimulator {
        /// 行为场景类型
        enum BehaviorScenario {
            case normal            // 正常用户行为
            case bot               // 机器人行为
            case emulator          // 模拟器操作
            case remoteControl     // 远程控制
        }
        
        /// 生成模拟的行为信号
        static func simulate(scenario: BehaviorScenario) -> MockBehaviorSignals {
            switch scenario {
            case .normal:
                return MockBehaviorSignals(
                    touch: MockTouchMetrics(
                        sampleCount: 50,
                        tapCount: 30,
                        swipeCount: 20,
                        coordinateSpread: 5.2,
                        intervalCV: 0.45,
                        averageLinearity: 0.85,
                        forceVariance: 0.35,
                        majorRadiusVariance: 0.28
                    ),
                    motion: MockMotionMetrics(
                        sampleCount: 100,
                        stillnessRatio: 0.65,
                        motionEnergy: 0.45
                    ),
                    touchMotionCorrelation: 0.72,
                    actionCount: 50
                )
                
            case .bot:
                return MockBehaviorSignals(
                    touch: MockTouchMetrics(
                        sampleCount: 30,
                        tapCount: 30,
                        swipeCount: 0,
                        coordinateSpread: 0.8,     // 点过于集中
                        intervalCV: 0.05,           // 间隔过于规律
                        averageLinearity: nil,
                        forceVariance: 0.02,        // 力度几乎一致
                        majorRadiusVariance: 0.01
                    ),
                    motion: MockMotionMetrics(
                        sampleCount: 50,
                        stillnessRatio: 0.99,       // 设备几乎静止
                        motionEnergy: 0.001
                    ),
                    touchMotionCorrelation: 0.02,  // 触摸与运动不相关
                    actionCount: 30
                )
                
            case .emulator:
                return MockBehaviorSignals(
                    touch: MockTouchMetrics(
                        sampleCount: 20,
                        tapCount: 18,
                        swipeCount: 2,
                        coordinateSpread: 12.5,    // 点过于分散
                        intervalCV: 0.65,          // 间隔混乱
                        averageLinearity: 0.98,    // 滑动过于直线
                        forceVariance: 0.15,
                        majorRadiusVariance: 0.05
                    ),
                    motion: MockMotionMetrics(
                        sampleCount: 0,            // 模拟器可能没有运动传感器
                        stillnessRatio: nil,
                        motionEnergy: nil
                    ),
                    touchMotionCorrelation: nil,
                    actionCount: 20
                )
                
            case .remoteControl:
                return MockBehaviorSignals(
                    touch: MockTouchMetrics(
                        sampleCount: 25,
                        tapCount: 25,
                        swipeCount: 0,
                        coordinateSpread: 1.2,
                        intervalCV: 0.08,
                        averageLinearity: nil,
                        forceVariance: 0.05,
                        majorRadiusVariance: 0.03
                    ),
                    motion: MockMotionMetrics(
                        sampleCount: 80,
                        stillnessRatio: 0.98,
                        motionEnergy: 0.005
                    ),
                    touchMotionCorrelation: 0.05,
                    actionCount: 25
                )
            }
        }
    }
    
    // MARK: - 性能测试工具
    
    /// 性能测试工具
    enum PerformanceTest {
        /// 测量执行时间
        static func measure<T>(_ label: String, operation: () throws -> T) rethrows -> T {
            let start = CFAbsoluteTimeGetCurrent()
            let result = try operation()
            let end = CFAbsoluteTimeGetCurrent()
            let duration = (end - start) * 1000 // 转换为毫秒
            print("[Performance] \(label): \(String(format: "%.2f", duration))ms")
            return result
        }
        
        /// 执行多次并计算平均时间
        static func measureAverage<T>(
            _ label: String,
            iterations: Int = 100,
            operation: () throws -> T
        ) rethrows -> (result: T, averageTime: Double, minTime: Double, maxTime: Double) {
            var times: [Double] = []
            times.reserveCapacity(iterations)
            
            var lastResult: T?
            
            for _ in 0..<iterations {
                let start = CFAbsoluteTimeGetCurrent()
                let r = try operation()
                let end = CFAbsoluteTimeGetCurrent()
                times.append((end - start) * 1000)
                lastResult = r
            }
            
            let average = times.reduce(0, +) / Double(times.count)
            let minTime = times.min() ?? 0
            let maxTime = times.max() ?? 0
            
            print("[Performance] \(label) - Avg: \(String(format: "%.2f", average))ms, Min: \(String(format: "%.2f", minTime))ms, Max: \(String(format: "%.2f", maxTime))ms")
            
            return (lastResult!, average, minTime, maxTime)
        }
        
        /// 测量内存使用
        static func measureMemory<T>(_ label: String, operation: () throws -> T) rethrows -> T {
            // 注意：这需要在真实设备上才能准确测量
            let startMemory = getMemoryUsage()
            let result = try operation()
            let endMemory = getMemoryUsage()
            let delta = endMemory - startMemory
            print("[Memory] \(label): +\(String(format: "%.2f", delta / 1024 / 1024))MB")
            return result
        }
        
        private static func getMemoryUsage() -> UInt64 {
            var info = mach_task_basic_info()
            var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size) / 4
            
            let result = withUnsafeMutablePointer(to: &info) {
                $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                    task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
                }
            }
            
            return result == KERN_SUCCESS ? info.resident_size : 0
        }
    }
}

// MARK: - Mock 数据类型


enum MockDetectionConfidence: String {
    case weak
    case medium
    case strong
}

struct MockJailbreakResult {
    let isJailbroken: Bool
    let confidence: Double
    let detectedMethods: [String]
    let details: String
}

struct MockDetectionSignal<Evidence> {
    let detected: Bool
    let method: String
    let evidence: Evidence?
    let confidence: MockDetectionConfidence
}

struct MockNetworkSignals {
    let interfaceType: String
    let isExpensive: Bool
    let isConstrained: Bool
    let vpn: MockDetectionSignal<[String]>
    let proxy: MockDetectionSignal<[String: String]>
}

struct MockTouchMetrics {
    let sampleCount: Int
    let tapCount: Int
    let swipeCount: Int
    let coordinateSpread: Double?
    let intervalCV: Double?
    let averageLinearity: Double?
    let forceVariance: Double?
    let majorRadiusVariance: Double?
}

struct MockMotionMetrics {
    let sampleCount: Int
    let stillnessRatio: Double?
    let motionEnergy: Double?
}

struct MockBehaviorSignals {
    let touch: MockTouchMetrics
    let motion: MockMotionMetrics
    let touchMotionCorrelation: Double?
    let actionCount: Int
}

// MARK: - 测试辅助扩展

extension XCTestCase {
    /// 断言检测结果是否匹配预期
    func assertDetectionResult(
        _ result: MockJailbreakResult,
        isJailbroken: Bool,
        minConfidence: Double = 0,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        XCTAssertEqual(result.isJailbroken, isJailbroken, "越狱状态不匹配", file: file, line: line)
        XCTAssertGreaterThanOrEqual(result.confidence, minConfidence, "置信度低于预期", file: file, line: line)
    }
    
    /// 断言分数在范围内
    func assertScoreInRange(
        _ score: Double,
        min: Double,
        max: Double,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        XCTAssertGreaterThanOrEqual(score, min, "分数 \(score) 低于最小值 \(min)", file: file, line: line)
        XCTAssertLessThanOrEqual(score, max, "分数 \(score) 高于最大值 \(max)", file: file, line: line)
    }
}
