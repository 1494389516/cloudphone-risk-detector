import Foundation

internal struct CFFRuntimeSaltInputs: Sendable, Equatable {
    var deviceWord: UInt64?
    var integrityWord: UInt64?
    var challengeWord: UInt64?
    var trustWord: UInt64?
    var extraWords: [UInt64]
    var strings: [String]
    var flags: [Bool]

    init(
        deviceWord: UInt64? = nil,
        integrityWord: UInt64? = nil,
        challengeWord: UInt64? = nil,
        trustWord: UInt64? = nil,
        extraWords: [UInt64] = [],
        strings: [String] = [],
        flags: [Bool] = []
    ) {
        self.deviceWord = deviceWord
        self.integrityWord = integrityWord
        self.challengeWord = challengeWord
        self.trustWord = trustWord
        self.extraWords = extraWords
        self.strings = strings
        self.flags = flags
    }

    var words: [UInt64] {
        [deviceWord, integrityWord, challengeWord, trustWord].compactMap { $0 } + extraWords
    }
}

internal enum CFFRuntimeSalt {
    static func derive(
        functionSeed: UInt64,
        inputs: CFFRuntimeSaltInputs = .init(),
        includeProcessContext: Bool = true
    ) -> UInt32 {
        var words = inputs.words
        words.append(functionSeed)

        if includeProcessContext {
            words.append(contentsOf: processContextWords())
        }

        return combine(words: words, strings: inputs.strings, flags: inputs.flags)
    }

    static func combine(words: [UInt64] = [], strings: [String] = [], flags: [Bool] = []) -> UInt32 {
        var hash: UInt64 = 0xCBF29CE484222325
        let prime: UInt64 = 0x100000001B3

        for word in words {
            var value = word
            for _ in 0..<8 {
                hash ^= value & 0xFF
                hash = hash &* prime
                value >>= 8
            }
        }

        for flag in flags {
            hash ^= flag ? 1 : 0
            hash = hash &* prime
        }

        for string in strings {
            for byte in string.utf8 {
                hash ^= UInt64(byte)
                hash = hash &* prime
            }
            hash ^= 0xFF
            hash = hash &* prime
        }

        return UInt32(truncatingIfNeeded: hash ^ (hash >> 32))
    }

    private static func processContextWords() -> [UInt64] {
        let processInfo = ProcessInfo.processInfo
        let uptimeMillis = UInt64((processInfo.systemUptime * 1_000.0).rounded(.down))
        let pid = UInt64(processInfo.processIdentifier)
        let debugMarker: UInt64

        #if DEBUG
        debugMarker = 0xD38B_D38B_D38B_D38B
        #else
        debugMarker = 0xA11C_E551_A11C_E551
        #endif

        return [pid, uptimeMillis, debugMarker]
    }
}
