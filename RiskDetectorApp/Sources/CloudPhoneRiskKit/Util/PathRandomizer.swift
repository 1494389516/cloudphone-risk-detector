import Foundation

// MARK: - 路径运行时随机化 [4.4.x]
//
// ⚠️ DEPRECATED / 死代码：自 FileDetector 改为确定性全量检查后，仓库内
// 已无调用方。未物理删除：Xcode 工程（project.pbxproj，不在本任务可改
// 目录内）显式引用了它；如需清理，请由工程维护方同时移除 pbxproj 中的
// 引用后再删除本文件。
@available(*, deprecated, message: "无调用方；FileDetector 已改为确定性全量检查")
enum PathRandomizer {

    /// 带种子的随机数生成器，用于可复现的测试
    private struct SeededRNG: RandomNumberGenerator {
        private var state: UInt64

        init(seed: UInt64) {
            self.state = seed == 0 ? 1 : seed
        }

        mutating func next() -> UInt64 {
            state ^= state >> 12
            state ^= state << 25
            state ^= state >> 27
            return state &* 2_685_821_657_736_338_717
        }
    }

    /// 从数组中随机选取指定数量的元素，并打乱顺序。
    /// - Parameters:
    ///   - array: 源数组
    ///   - count: 目标数量（若大于 array.count 则返回全部）
    ///   - seed: 可选种子；nil 时使用当前时间戳与 UUID 混合，保证每次调用结果不同
    /// - Returns: 随机子集，顺序已打乱
    static func randomSubset<T>(from array: [T], count: Int, seed: UInt64? = nil) -> [T] {
        guard !array.isEmpty else { return [] }
        let takeCount = min(max(0, count), array.count)

        let shuffled: [T]
        if let s = seed {
            var rng = SeededRNG(seed: s)
            shuffled = array.shuffled(using: &rng)
        } else {
            shuffled = array.shuffled()
        }

        return Array(shuffled.prefix(takeCount))
    }
}
