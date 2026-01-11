import Foundation

enum JSON {
    static func encode<T: Encodable>(_ value: T, prettyPrinted: Bool) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = prettyPrinted ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
        return try encoder.encode(value)
    }

    static func stringify<T: Encodable>(_ value: T) throws -> String {
        let data = try encode(value, prettyPrinted: false)
        return String(decoding: data, as: UTF8.self)
    }
}

