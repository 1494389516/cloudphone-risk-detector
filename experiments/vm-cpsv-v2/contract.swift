import Foundation
// Standalone codec test only; production uses the real MachOKit error type.
enum MachOError: Error { case invalidData(String) }
@main struct Contract {
    static func main() throws {
        let input = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))) as! [[String: Any]]
        var count = 0
        for row in input {
            let p = Data(base64Encoded: row["payload"] as! String)!
            let uuid = Data(base64Encoded: row["uuid"] as! String)!
            let rvas = (row["rvas"] as! [String]).map { UInt64($0)! }
            var accepted = true
            do { try CPSV2Manifest.validate(p, uuid: uuid, expectedRVAs: rvas,
                  textRVA: UInt64(row["textRVA"] as! String)!, textSize: UInt64(row["textSize"] as! String)!) }
            catch { accepted = false }
            precondition(accepted == (row["accepted"] as! Bool), "C/Swift mismatch: \(row["name"]!)")
            count += 1
        }
        print("Swift/C parser parity: \(count) cases")
    }
}
