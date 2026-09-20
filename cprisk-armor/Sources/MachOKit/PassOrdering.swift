import Foundation

/// Stable topological ordering for the armor pipeline.
///
/// The ordering is part of the producer/runtime contract: code transforms must
/// finish before the text anchor is computed, consumers of that anchor run
/// afterwards, symbol-dependent passes run before stripping, and the header
/// snapshot is taken only after every load-command mutation is complete.
public func resolveArmorPassOrder(
    _ registered: [(Int, ArmorPass)]
) throws -> [(Int, ArmorPass)] {
    let dependencyIDs: [Int: Set<Int>] = [
        9: [8],                    // CFF observes the post-substitution text.
        13: [8, 9],                // VMP is the final plaintext code transform.
        4: [8, 9, 13],             // Anchor the final plaintext __text image.
        3: [4],                    // Data KDF consumes the split anchor lanes.
        5: [4],
        12: [4, 13],               // Text encryption consumes the final anchor.
        6: [1, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13],
        11: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13],
    ]

    let count = registered.count
    var indegree = Array(repeating: 0, count: count)
    var outgoing = Array(repeating: Set<Int>(), count: count)

    for index in 0..<count {
        let passID = registered[index].0
        let dependencies = dependencyIDs[passID] ?? []
        guard !dependencies.contains(passID) else {
            throw MachOError.invalidData("pass \(passID) depends on itself")
        }
        for candidate in 0..<count where candidate != index {
            if dependencies.contains(registered[candidate].0),
               outgoing[candidate].insert(index).inserted {
                indegree[index] += 1
            }
        }
    }

    var queue = Array(0..<count).filter { indegree[$0] == 0 }
    var sortedIndices = [Int]()
    while let index = queue.first {
        queue.removeFirst()
        sortedIndices.append(index)
        for next in outgoing[index] {
            indegree[next] -= 1
            if indegree[next] == 0 {
                queue.append(next)
                queue.sort()
            }
        }
    }

    guard sortedIndices.count == count else {
        throw MachOError.invalidData("armor pass dependency graph contains a cycle")
    }
    return sortedIndices.map { registered[$0] }
}
