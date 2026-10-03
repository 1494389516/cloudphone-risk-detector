import Foundation

public struct VMPolicyValidationError: Error, CustomStringConvertible {
    public let code: String
    public let line: Int
    public let detail: String
    public var description: String { "VMP policy \(code) at line \(line): \(detail)" }
}

/// Deliberately limited YAML grammar shared with the legacy parser. This is
/// not a general YAML parser: aliases, quoted scalars and inline collections
/// are rejected rather than interpreted differently by the two entry points.
enum VMPolicyStrictValidator {
    static func validate(_ text: String) throws {
        let sections: Set<String> = ["functions", "anti_analysis", "opaque_vpc_encoding", "hardening"]
        let booleans: Set<String> = [
            "protect_vm_interpreter_with_cff", "enable_dead_handler_injection",
            "opaque_vpc_predicate_chain", "interpreter_self_integrity_check",
            "dispatch_table_keystream", "bytecode_immediate_keystream",
            "bytecode_segment_runtime_sha256", "anti_symbolic_heavy", "fuse_add_rol_acc"
        ]
        let integers: Set<String> = ["synthetic_branch_ind_budget", "synthetic_branch_ind_max_per_function", "synthetic_branch_ind_forward_span"]
        var section = ""
        var list: String?
        var keys = Set<String>()
        var symbols = Set<String>()
        func fail(_ code: String, _ line: Int, _ detail: String) throws -> Never {
            throw VMPolicyValidationError(code: code, line: line, detail: detail)
        }
        for (index, raw) in text.components(separatedBy: .newlines).enumerated() {
            let line = index + 1
            let content = String(raw.prefix { $0 != "#" })
            let value = content.trimmingCharacters(in: .whitespaces)
            if value.isEmpty { continue }
            if content.contains("\t") { try fail("syntax", line, "tabs are not supported") }
            let indent = content.prefix { $0 == " " }.count
            if indent == 4 {
                guard section == "functions", list != nil, value.hasPrefix("- ") else {
                    try fail("syntax", line, "expected a function list item")
                }
                let symbol = String(value.dropFirst(2)).trimmingCharacters(in: .whitespaces)
                guard symbol.range(of: "^[A-Za-z_$][A-Za-z0-9_.$]*$", options: .regularExpression) != nil else {
                    try fail("value", line, "expected an unquoted function symbol")
                }
                guard symbols.insert(symbol).inserted else {
                    try fail("duplicate_target", line, symbol)
                }
                continue
            }
            guard indent == 0 || indent == 2, let colon = value.firstIndex(of: ":") else {
                try fail("syntax", line, "unsupported indentation or missing colon")
            }
            let key = String(value[..<colon])
            let scalar = String(value[value.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            let identity = indent == 0 ? key : section + "." + key
            guard keys.insert(identity).inserted else { try fail("duplicate_key", line, identity) }
            if indent == 0 {
                section = ""
                list = nil
                if key == "version" {
                    guard scalar == "1" else { try fail("version", line, "only integer version 1 is supported") }
                } else {
                    guard sections.contains(key) else { try fail("unknown_key", line, key) }
                    guard scalar.isEmpty else { try fail("type", line, "expected block mapping") }
                    section = key
                }
                continue
            }
            guard !section.isEmpty else { try fail("syntax", line, "key outside a section") }
            if section == "functions" {
                guard ["full", "partial", "never"].contains(key) else { try fail("unknown_key", line, identity) }
                guard scalar.isEmpty else { try fail("type", line, "expected block list") }
                list = key
                continue
            }
            let isBool = (section == "anti_analysis" && key == "handler_duplication") ||
                (section == "opaque_vpc_encoding" && key == "enabled") ||
                (section == "hardening" && booleans.contains(key))
            if isBool {
                guard scalar == "true" || scalar == "false" else { try fail("type", line, "expected true or false") }
            } else if section == "hardening" && integers.contains(key) {
                guard scalar.range(of: "^[0-9]+$", options: .regularExpression) != nil,
                      let number = Int(scalar), number >= 0 else { try fail("value", line, "expected nonnegative integer") }
                if key == "synthetic_branch_ind_forward_span" && number > 16 {
                    try fail("value", line, "forward span must be 0...16")
                }
            } else if section == "hardening" && key == "synthetic_branch_ind_rate" {
                guard let number = Double(scalar), number.isFinite, (0...1).contains(number) else {
                    try fail("value", line, "rate must be finite and in 0...1")
                }
            } else if section == "hardening" && key == "interpreter_cff_tier" {
                guard ["light", "medium", "heavy"].contains(scalar) else { try fail("value", line, identity) }
            } else if section == "hardening" && key == "synthetic_branch_ind_mode" {
                guard ["unreachable_skip", "semi_identity", "semi_semantic"].contains(scalar) else {
                    try fail("value", line, identity)
                }
            } else {
                try fail("unknown_key", line, identity)
            }
        }
        guard keys.contains("version"), keys.contains("functions") else {
            try fail("missing_key", 0, "version and functions are required")
        }
    }
}
