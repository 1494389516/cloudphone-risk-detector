import Foundation

/// Canonical UInt64 for Feistel SPN byte substitution — must stay aligned with:
/// - `CPRISK_CFF_SPN_CANONICAL_SEED_U64` in `cprisk_cff.h`
/// - `cprisk_cff_spn_sbox_install_from_seed` / `CFFSBoxPermutation256.generate(seed:)`
///
/// Derivation: `fnv1a64("cprisk-armor/CFFSBoxPermutation256/v1") ^ 0xA37C19E45B62D08F`
/// (registry root mix); zero maps to 1 in the PRNG.
internal enum CFFSBoxMaterial {
    static let canonicalSeed: UInt64 = 0x6AFD56260D3F7F05
}
