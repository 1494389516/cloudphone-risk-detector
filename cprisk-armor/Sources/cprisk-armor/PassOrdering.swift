import Foundation
import MachOKit

/// Stable topological ordering for pass dependencies.
func resolvePassOrder(_ registered: [(Int, ArmorPass)]) throws -> [(Int, ArmorPass)] {
    let dependencyIDs: [Int: Set<Int>] = [
        4: [3],         // runtime data expects pass3 outputs pre-anchor
        5: [4],         // structure obfuscation after anchor sections are created
        12: [4],        // text encryption depends on anchor metadata
    ]

    let n = registered.count
    var indegree = Array(repeating: 0, count: n)
    var outgoing = Array(repeating: Set<Int>(), count: n)

    for i in 0..<n {
        let id = registered[i].0
        let deps = dependencyIDs[id] ?? []
        guard !deps.contains(id) else { continue }
        if deps.isEmpty { continue }
        for j in 0..<n where i != j {
            if deps.contains(registered[j].0), outgoing[j].insert(i).inserted {
                indegree[i] += 1
            }
        }
    }

    var queue = Array(0..<n).filter { indegree[$0] == 0 }
    var sortedIndices = [Int]()
    while let idx = queue.first {
        queue.removeFirst()
        sortedIndices.append(idx)
        for nxt in outgoing[idx] {
            indegree[nxt] -= 1
            if indegree[nxt] == 0 {
                queue.append(nxt)
                queue.sort()
            }
        }
    }
    guard sortedIndices.count == n else {
        throw NSError(
            domain: "cprisk-armor",
            code: 2001,
            userInfo: [NSLocalizedDescriptionKey: "pass dependency graph contains a cycle"]
        )
    }
    return sortedIndices.map { registered[$0] }
}
