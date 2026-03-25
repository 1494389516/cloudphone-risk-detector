import XCTest
@testable import CloudPhoneRiskKit

/// Ensures obfuscated `SignalID` sources still decode to protocol-stable wire values.
final class SignalIDRuntimeContractTests: XCTestCase {

    func testSensitiveSignalIDsMatchLegacyWireStrings() {
        XCTAssertEqual(SignalID.antiDebugWatchdogDyldInjection, "anti_debug_watchdog_dyld_injection")
        XCTAssertEqual(SignalID.antiDebugWatchdogDenyAttachVerify, "anti_debug_watchdog_deny_attach_verify")
        XCTAssertEqual(SignalID.antiDebugWatchdogAMFICsFlags, "anti_debug_watchdog_amfi_cs_flags")
        XCTAssertEqual(SignalID.antiDebugWatchdogGetTaskAllow, "anti_debug_watchdog_get_task_allow")
        XCTAssertEqual(SignalID.antiDebugWatchdogPacThreadEntry, "anti_debug_watchdog_pac_thread_entry")
        XCTAssertEqual(SignalID.antiDebugWatchdogVmImageLayoutDrift, "anti_debug_watchdog_vm_image_layout_drift")
        XCTAssertEqual(SignalID.whiteboxPrfProbeDegraded, "whitebox_prf_probe_degraded")
        XCTAssertEqual(SignalID.softwareBreakpointDetected, "software_breakpoint_detected")
        XCTAssertEqual(SignalID.exceptionDeliveryTimeout, "exception_delivery_timeout")
        XCTAssertEqual(SignalID.libcDirectSyscallFallback, "libc_direct_syscall_fallback")
        XCTAssertEqual(SignalID.stalkerJitRWX, "stalker_jit_rwx")
        XCTAssertEqual(SignalID.rwxJitCoexistence, "rwx_jit_coexistence")
        XCTAssertEqual(SignalID.multiPathCrossInconsistency, "multipath_cross_inconsistency")
        XCTAssertEqual(SignalID.pacDisabled, "pac_disabled")
        XCTAssertEqual(SignalID.pacPointerInvalid, "pac_pointer_invalid")
        XCTAssertEqual(SignalID.dtraceKdebugActivity, "dtrace_kdebug_activity")
        XCTAssertEqual(SignalID.lldbJitSmallRWX, "lldb_jit_small_rwx")
        XCTAssertEqual(SignalID.dyldSharedCacheIntegrity, "dyld_shared_cache_integrity")
        XCTAssertEqual(SignalID.dyldSharedCacheUUIDMismatch, "dyld_shared_cache_uuid_mismatch")
        XCTAssertEqual(SignalID.dyldSharedCacheSlideMismatch, "dyld_shared_cache_slide_mismatch")
        XCTAssertEqual(SignalID.dyldSharedCacheSymbolMismatch, "dyld_shared_cache_symbol_mismatch")
        XCTAssertEqual(SignalID.dylibInjectImageCountLow, "dylib_inject_image_count_low")
        XCTAssertEqual(SignalID.ifaceSpawnPathDivergence, "iface_spawn_path_divergence")
        XCTAssertEqual(SignalID.certificatePinningAnomaly, "certificate_pinning_anomaly")
    }

    func testPreviouslyObfuscatedSignalIDsStillStable() {
        XCTAssertEqual(SignalID.vmRemapSharedAnonymous, "vm_remap_shared_anonymous_exec")
        XCTAssertEqual(SignalID.vmRemapImageAlias, "vm_remap_image_alias")
        XCTAssertEqual(SignalID.taskPortExceptionHijack, "task_port_exception_hijack")
        XCTAssertEqual(SignalID.taskPortRightsAnomaly, "task_port_rights_anomaly")
        XCTAssertEqual(SignalID.fridaModuleDetected, "frida_module_detected")
    }
}
