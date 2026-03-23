import CRiskCore
import XCTest

/// Validates C-layer spawn iface probe wiring; on a clean OS image all addresses should agree.
final class SpawnIfaceProbeTests: XCTestCase {
    func testCProbeCompletesAndAddressesNonZero() {
        var raw = cprisk_spawn_iface_probe_result_t()
        XCTAssertEqual(cprisk_spawn_iface_probe(&raw), 0)
        XCTAssertGreaterThan(raw.addr_rtld_default_spawn, 0)
        XCTAssertTrue(
            raw.addr_dlopen_libc_spawn > 0 || raw.addr_export_trie_spawn > 0,
            "spawn secondary resolution should expose at least one non-zero path"
        )
        XCTAssertGreaterThan(raw.addr_rtld_default_spawnp, 0)
        XCTAssertTrue(
            raw.addr_dlopen_libc_spawnp > 0 || raw.addr_export_trie_spawnp > 0,
            "spawnp secondary resolution should expose at least one non-zero path"
        )
    }

}
