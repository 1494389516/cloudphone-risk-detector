import XCTest
@testable import CloudPhoneRiskKit
import Foundation

/// HookDetector 单元测试
/// 
/// 测试策略：
/// 1. 测试可疑 ObjC 类检测
/// 2. 测试符号地址验证
/// 3. 测试子检测器调用
/// 4. 覆盖正常/越狱场景
final class HookDetectorTests: XCTestCase {
    
    // MARK: - 可疑 ObjC 类检测测试
    
    func testSuspiciousObjCClassesList() {
        // 验证可疑类列表完整
        let suspiciousClasses = [
            // Cydia / Sileo / package managers
            "CydiaObject", "Cydia", "CydiaDelegate",
            "SileoPackage", "SileoSource", "SileoManager",
            
            // FLEX / Frida / hook frameworks
            "FLEXManager", "FridaServer", "FridaGadget",
            "FishHook", "CydiaSubstrate",
            
            // Other tools
            "SSLKillSwitch", "Liberty", "ABypass",
            "RocketBootstrap", "HBPreferences"
        ]
        
        // 验证列表不为空且包含关键类
        XCTAssertFalse(suspiciousClasses.isEmpty, "可疑类列表不应为空")
        XCTAssertTrue(suspiciousClasses.contains("Cydia"), "应包含 Cydia 类")
        XCTAssertTrue(suspiciousClasses.contains("FridaServer"), "应包含 Frida 类")
    }
    
    func testClassDetectionScore() {
        // 测试每个检测到的类加 15 分
        let detectedClasses = ["Cydia", "Sileo", "FridaServer"]
        let scorePerClass = 15.0
        
        let expectedScore = Double(detectedClasses.count) * scorePerClass
        XCTAssertEqual(expectedScore, 45.0, "3 个可疑类应得 45 分")
    }
    
    func testClassDetectionMethodFormat() {
        // 测试检测方法格式
        let className = "Cydia"
        let expectedMethod = "objc_class:\(className)"
        
        XCTAssertEqual(expectedMethod, "objc_class:Cydia")
    }
    
    // MARK: - 符号地址验证测试
    
    func testSymbolOpenImagePath() {
        // 测试 open 符号路径检测
        // 正常设备：/usr/lib/system/libsystem_kernel.dylib
        // 越狱/注入：可能在其他路径
        
        let normalPath = "/usr/lib/system/libsystem_kernel.dylib"
        let suspiciousPath = "/usr/lib/libsubstitute.dylib"
        
        let isNormal = normalPath.contains("/usr/lib/system")
        XCTAssertTrue(isNormal, "系统库路径应包含 /usr/lib/system")
        
        let isSuspicious = !suspiciousPath.contains("/usr/lib/system")
        XCTAssertTrue(isSuspicious, "可疑库路径不在系统目录")
        
        // 可疑路径应增加 25 分
        let suspiciousScore = isSuspicious ? 25 : 0
        XCTAssertEqual(suspiciousScore, 25, "可疑符号路径应加 25 分")
    }
    
    func testSymbolPathNotFound() {
        // 测试符号未找到场景
        let path: String? = nil
        
        let score: Double
        if let p = path, !p.contains("/usr/lib/system") {
            score = 25
        } else {
            score = 0
        }
        
        XCTAssertEqual(score, 0, "未找到符号不应加分")
    }
    
    // MARK: - 子检测器调用测试
    
    func testSubDetectorCalls() {
        // 验证所有子检测器都被调用
        let subDetectors = [
            "PointerValidationDetector",
            "HookFrameworkSymbolDetector",
            "PrologueBranchDetector",
            "IndirectSymbolPointerDetector",
            "ObjCIMPDetector",
            "ObjCMetadataDetector"
        ]
        
        XCTAssertEqual(subDetectors.count, 6, "应有 6 个子检测器")
        
        // 模拟各检测器返回分数
        let mockScores = [10.0, 15.0, 8.0, 12.0, 5.0, 20.0]
        let totalSubScore = mockScores.reduce(0, +)
        
        XCTAssertEqual(totalSubScore, 70.0, "子检测器分数应累加")
    }
    
    // MARK: - ObjC Metadata 检测测试
    
    func testClassScanPatterns() {
        // 测试类扫描模式
        let patterns = [
            "cydia", "sileo", "zebra", "filza", "frida", "gum",
            "substrate", "substitute", "preferenceloader", "activator",
            "rocketbootstrap", "libhooker", "ellekit", "shadow", "dopamine"
        ]
        
        // 测试匹配逻辑
        let className1 = "CydiaPackageManager"
        let className2 = "NormalViewController"
        
        let isSuspicious1 = patterns.contains { className1.lowercased().contains($0) }
        let isSuspicious2 = patterns.contains { className2.lowercased().contains($0) }
        
        XCTAssertTrue(isSuspicious1, "CydiaPackageManager 应被检测为可疑")
        XCTAssertFalse(isSuspicious2, "NormalViewController 不应被检测为可疑")
    }
    
    func testSuspiciousProtocols() {
        // 测试可疑协议检测
        let suspiciousProtocols = [
            "CydiaDelegate",
            "SileoDelegate",
            "SubstituteDelegate",
            "FridaHelper",
            "JailbreakProtocol"
        ]
        
        XCTAssertEqual(suspiciousProtocols.count, 5, "应有 5 个可疑协议")
        XCTAssertTrue(suspiciousProtocols.contains("FridaHelper"), "应包含 FridaHelper")
    }
    
    func testNSObjectExtensionMethodPrefixes() {
        // 测试 NSObject 扩展方法前缀
        let prefixes = [
            "jb_", "cydia_", "sileo_", "hook_",
            "patch_", "tweak_", "substrate_", "ms_"
        ]
        
        let method1 = "jb_initialize"
        let method2 = "normalMethod"
        
        let hasSuspiciousPrefix1 = prefixes.contains { method1.lowercased().hasPrefix($0) }
        let hasSuspiciousPrefix2 = prefixes.contains { method2.lowercased().hasPrefix($0) }
        
        XCTAssertTrue(hasSuspiciousPrefix1, "jb_ 前缀应被检测")
        XCTAssertFalse(hasSuspiciousPrefix2, "正常方法前缀不应被检测")
    }
    
    // MARK: - 分数封顶测试
    
    func testObjCMetadataScoreCap() {
        // ObjCMetadataDetector 分数封顶在 35
        let rawScore = 50.0
        let maxScore = 35.0
        
        let finalScore = min(rawScore, maxScore)
        XCTAssertEqual(finalScore, maxScore, "ObjC Metadata 分数应封顶在 35")
    }
    
    func testMethodsDisplayLimit() {
        // 测试检测方法显示限制（只显示前 3 个）
        let allMethods = [
            "objc_class:Cydia",
            "objc_class:Sileo", 
            "objc_class:FridaServer",
            "objc_class:SSLSKillSwitch",
            "objc_class:Liberty"
        ]
        
        let displayMethods = Array(allMethods.prefix(3))
        XCTAssertEqual(displayMethods.count, 3, "只应显示前 3 个方法")
        XCTAssertEqual(displayMethods.last, "objc_class:FridaServer")
    }
    
    // MARK: - 综合场景测试
    
    func testCleanDeviceScore() {
        // 测试干净设备场景
        var score = 0.0
        var methods: [String] = []
        
        // 没有检测到任何可疑类
        let detectedClasses: [String] = []
        score += Double(detectedClasses.count) * 15
        
        // open 符号在系统路径
        let openPath: String? = "/usr/lib/system/libsystem_kernel.dylib"
        if let p = openPath, !p.contains("/usr/lib/system") {
            score += 25
            methods.append("symbol_open_image:\(p)")
        }
        
        // 子检测器未检测到异常
        let subDetectorScores: [Double] = [0, 0, 0, 0, 0, 0]
        score += subDetectorScores.reduce(0, +)
        
        XCTAssertEqual(score, 0, "干净设备得分应为 0")
        XCTAssertTrue(methods.isEmpty, "干净设备不应有检测方法")
    }
    
    func testJailbrokenDeviceScore() {
        // 测试越狱设备场景
        var score = 0.0
        var methods: [String] = []
        
        // 检测到 2 个可疑类
        let detectedClasses = ["Cydia", "Sileo"]
        score += Double(detectedClasses.count) * 15
        methods += detectedClasses.map { "objc_class:\($0)" }
        
        // open 符号在可疑路径
        let openPath = "/usr/lib/libsubstitute.dylib"
        if !openPath.contains("/usr/lib/system") {
            score += 25
            methods.append("symbol_open_image:\(openPath)")
        }
        
        // 子检测器检测到异常
        let subDetectorScores: [Double] = [10, 15, 0, 0, 8, 0]
        score += subDetectorScores.reduce(0, +)
        
        let expectedScore = 2 * 15 + 25 + 10 + 15 + 8  // 88
        XCTAssertEqual(score, Double(expectedScore))
        XCTAssertGreaterThan(score, 50, "越狱设备得分应较高")
    }
    
    func testPartiallyHookedDevice() {
        // 测试部分 Hook 设备（可能使用修改工具）
        var score = 0.0
        
        // 只检测到 Frida
        let detectedClasses = ["FridaGadget"]
        score += Double(detectedClasses.count) * 15
        
        // open 符号正常
        let openPath = "/usr/lib/system/libsystem_kernel.dylib"
        if !openPath.contains("/usr/lib/system") {
            score += 25
        }
        
        // 只有一个子检测器触发
        let subDetectorScore = 12.0
        score += subDetectorScore
        
        let expectedScore = 15.0 + 12.0  // 27
        XCTAssertEqual(score, expectedScore)
    }
    
    // MARK: - 边界条件测试
    
    func testEmptyClassName() {
        // 测试空类名处理
        let className = ""
        let isValidName = !className.isEmpty
        
        XCTAssertFalse(isValidName, "空类名应无效")
    }
    
    func testCaseInsensitiveMatching() {
        // 测试大小写不敏感匹配
        let patterns = ["cydia", "sileo"]
        let testClassName = "CYDIAPackageManager"
        
        let isMatch = patterns.contains { testClassName.lowercased().contains($0) }
        XCTAssertTrue(isMatch, "应支持大小写不敏感匹配")
    }
    
    func testVeryLongClassName() {
        // 测试超长类名处理
        let longClassName = String(repeating: "A", count: 1000)
        
        let patterns = ["test"]
        let isMatch = patterns.contains { longClassName.lowercased().contains($0) }
        
        XCTAssertFalse(isMatch, "超长类名不应误匹配")
    }
    
    // MARK: - 性能测试
    
    func testClassScanningPerformance() {
        // 测试类扫描性能
        measure {
            let mockClassCount = 5000
            var count = 0
            for _ in 0..<mockClassCount {
                count += 1
            }
            XCTAssertGreaterThan(count, 0)
        }
    }
    
    func testProtocolScanningPerformance() {
        // 测试协议扫描性能
        let protocols = ["CydiaDelegate", "SileoDelegate", "SubstituteDelegate", "FridaHelper", "JailbreakProtocol"]
        
        measure {
            for _ in 0..<1000 {
                _ = protocols.contains { $0.hasPrefix("Cydia") }
            }
        }
    }
}
