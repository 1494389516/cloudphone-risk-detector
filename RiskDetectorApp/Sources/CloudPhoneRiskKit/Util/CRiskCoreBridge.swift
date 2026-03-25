import CRiskCore
import Foundation

enum CRiskCoreBridge {
    private static let lock = NSLock()
    private static var cache: [UInt32: UnsafeMutableRawPointer] = [:]

    static func resolve<T>(_ index: UInt32, as type: T.Type) -> T {
        lock.lock()
        if let cached = cache[index] {
            lock.unlock()
            return unsafeBitCast(cached, to: type)
        }
        lock.unlock()

        var addr: UnsafeMutableRawPointer?
        let rc = cprisk_resolve_import(index, &addr)
        guard rc == 0, let resolved = addr else {
            fatalError("CRiskCore bridge resolve failed for index \(index)")
        }

        lock.lock()
        cache[index] = resolved
        lock.unlock()
        return unsafeBitCast(resolved, to: type)
    }
}

typealias _CRiskVoidFn0 = @convention(c) () -> Void
typealias _CRiskIntFn0 = @convention(c) () -> CInt
typealias _CRiskUInt32Fn0 = @convention(c) () -> UInt32
typealias _CRiskUInt64Fn0 = @convention(c) () -> UInt64
typealias _CRiskPidFn0 = @convention(c) () -> pid_t
typealias _CRiskUidFn0 = @convention(c) () -> uid_t
typealias _CRiskIntFnRawPtr = @convention(c) (UnsafeRawPointer?) -> CInt
typealias _CRiskIntFnCStringIntErr = @convention(c) (UnsafePointer<CChar>?, CInt, UnsafeMutablePointer<CInt>?) -> CInt
typealias _CRiskIntFnCStringStatErr = @convention(c) (UnsafePointer<CChar>?, UnsafeMutablePointer<stat>?, UnsafeMutablePointer<CInt>?) -> CInt
typealias _CRiskIntFnConnect = @convention(c) (CInt, UnsafePointer<sockaddr>?, socklen_t, UnsafeMutablePointer<CInt>?) -> CInt
typealias _CRiskIntFnSysctlByName = @convention(c) (UnsafePointer<CChar>?, UnsafeMutableRawPointer?, UnsafeMutablePointer<Int>?, UnsafeRawPointer?, Int, UnsafeMutablePointer<CInt>?) -> CInt
typealias _CRiskIntFnSysctl = @convention(c) (UnsafeMutablePointer<CInt>?, CUnsignedInt, UnsafeMutableRawPointer?, UnsafeMutablePointer<Int>?, UnsafeRawPointer?, Int, UnsafeMutablePointer<CInt>?) -> CInt
typealias _CRiskPACFn = @convention(c) (UnsafeRawPointer?, UInt) -> UnsafeMutableRawPointer?
typealias _CRiskIntFnPathProbe = @convention(c) (UnsafePointer<CChar>?, UnsafeMutablePointer<cprisk_path_probe_snapshot_t>?) -> CInt
typealias _CRiskIntFnSpawnProbe = @convention(c) (UnsafeMutablePointer<cprisk_spawn_iface_probe_result_t>?) -> CInt
typealias _CRiskIntFnWatchdogSnapshot = @convention(c) (UnsafeMutablePointer<cprisk_anti_debug_watchdog_snapshot_t>?) -> CInt
typealias _CRiskIntFnPlanSnapshot = @convention(c) (UnsafeMutablePointer<cprisk_antidebug_plan_snapshot_t>?) -> CInt
typealias _CRiskIntFnFridaSnapshot = @convention(c) (UnsafeMutablePointer<cprisk_frida_runtime_snapshot_t>?) -> CInt
typealias _CRiskIntFnMteSnapshot = @convention(c) (UnsafeMutablePointer<cprisk_mte_guard_snapshot_t>?) -> CInt
typealias _CRiskIntFnInitProtection = @convention(c) (UnsafePointer<UInt8>?, Int) -> CInt
typealias _CRiskVoidFnHardeningMode = @convention(c) (cprisk_runtime_hardening_mode_t) -> Void
typealias _CRiskHardeningModeFn0 = @convention(c) () -> cprisk_runtime_hardening_mode_t
typealias _CRiskIntFnU8Out32 = @convention(c) (UnsafeMutablePointer<UInt8>?) -> CInt
typealias _CRiskVoidFnInt = @convention(c) (CInt) -> Void
typealias _CRiskIntFnScanBP = @convention(c) (UnsafeRawPointer?, Int) -> CInt
typealias _CRiskIntFnAdvanceUContext = @convention(c) (UnsafeMutableRawPointer?, UInt) -> CInt
typealias _CRiskIntFnReadAnchor = @convention(c) (UnsafeMutablePointer<UInt8>?) -> CInt
typealias _CRiskIntFnPinsetContainsDigest = @convention(c) (UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int) -> CInt
typealias _CRiskIntFnSign = @convention(c) (UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, UnsafeMutablePointer<CChar>?) -> CInt
typealias _CRiskIntFnVerify = @convention(c) (UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, UnsafePointer<CChar>?) -> CInt

let cprisk_access_direct: _CRiskIntFnCStringIntErr =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_ACCESS_DIRECT), as: _CRiskIntFnCStringIntErr.self)
let cprisk_addr_in_any_image: _CRiskIntFnRawPtr =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_ADDR_IN_ANY_IMAGE), as: _CRiskIntFnRawPtr.self)
let cprisk_advance_ucontext_pc: _CRiskIntFnAdvanceUContext =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_ADVANCE_UCONTEXT_PC), as: _CRiskIntFnAdvanceUContext.self)
let cprisk_cleanup_protection: _CRiskVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_CLEANUP_PROTECTION), as: _CRiskVoidFn0.self)
let cprisk_close_direct: @convention(c) (CInt, UnsafeMutablePointer<CInt>?) -> CInt =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_CLOSE_DIRECT), as: (@convention(c) (CInt, UnsafeMutablePointer<CInt>?) -> CInt).self)
let cprisk_connect_direct: _CRiskIntFnConnect =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_CONNECT_DIRECT), as: _CRiskIntFnConnect.self)
let cprisk_crypto_trace_last_ns_i: _CRiskUInt64Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_CRYPTO_TRACE_LAST_NS_I), as: _CRiskUInt64Fn0.self)
let cprisk_crypto_trace_peek_flags_i: _CRiskUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_CRYPTO_TRACE_PEEK_FLAGS_I), as: _CRiskUInt32Fn0.self)
let cprisk_crypto_trace_primitive_enter_i: _CRiskVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_CRYPTO_TRACE_PRIMITIVE_ENTER_I), as: _CRiskVoidFn0.self)
let cprisk_csops_debug_check: _CRiskIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_CSOPS_DEBUG_CHECK), as: _CRiskIntFn0.self)
let cprisk_deny_attach: _CRiskVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_DENY_ATTACH), as: _CRiskVoidFn0.self)
let cprisk_deny_attach_status: @convention(c) (UnsafeMutablePointer<CInt>?) -> CInt =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_DENY_ATTACH_STATUS), as: (@convention(c) (UnsafeMutablePointer<CInt>?) -> CInt).self)
let cprisk_detect_developer_disk: _CRiskIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_DETECT_DEVELOPER_DISK), as: _CRiskIntFn0.self)
let cprisk_detect_hardware_breakpoints: _CRiskIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_DETECT_HARDWARE_BREAKPOINTS), as: _CRiskIntFn0.self)
let cprisk_detect_suspicious_threads: _CRiskIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_DETECT_SUSPICIOUS_THREADS), as: _CRiskIntFn0.self)
let cprisk_detect_tty_debug: _CRiskIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_DETECT_TTY_DEBUG), as: _CRiskIntFn0.self)
let cprisk_erase_macho_header: _CRiskVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_ERASE_MACHO_HEADER), as: _CRiskVoidFn0.self)
let cprisk_frida_runtime_snapshot: _CRiskIntFnFridaSnapshot =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_FRIDA_RUNTIME_SNAPSHOT), as: _CRiskIntFnFridaSnapshot.self)
let cprisk_get_anti_debug_watchdog_snapshot: _CRiskIntFnWatchdogSnapshot =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_ANTI_DEBUG_WATCHDOG_SNAPSHOT), as: _CRiskIntFnWatchdogSnapshot.self)
let cprisk_get_antidebug_plan_snapshot: _CRiskIntFnPlanSnapshot =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_ANTIDEBUG_PLAN_SNAPSHOT), as: _CRiskIntFnPlanSnapshot.self)
let cprisk_get_mprotect_direct_failure_count: _CRiskUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_MPROTECT_DIRECT_FAILURE_COUNT), as: _CRiskUInt32Fn0.self)
let cprisk_get_mprotect_fallback_success_count: _CRiskUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_MPROTECT_FALLBACK_SUCCESS_COUNT), as: _CRiskUInt32Fn0.self)
let cprisk_getpid_direct: _CRiskPidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GETPID_DIRECT), as: _CRiskPidFn0.self)
let cprisk_getppid_direct: _CRiskPidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GETPPID_DIRECT), as: _CRiskPidFn0.self)
let cprisk_getuid_direct: _CRiskUidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GETUID_DIRECT), as: _CRiskUidFn0.self)
let cprisk_init_protection: _CRiskIntFnInitProtection =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_INIT_PROTECTION), as: _CRiskIntFnInitProtection.self)
let cprisk_integrity_poison_code_signing_lane: _CRiskVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_INTEGRITY_POISON_CODE_SIGNING_LANE), as: _CRiskVoidFn0.self)
let cprisk_integrity_poison_svc_iface_lane: _CRiskVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_INTEGRITY_POISON_SVC_IFACE_LANE), as: _CRiskVoidFn0.self)
let cprisk_is_being_traced: _CRiskIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_IS_BEING_TRACED), as: _CRiskIntFn0.self)
let cprisk_is_cntpct_clock_available: _CRiskIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_IS_CNTPCT_CLOCK_AVAILABLE), as: _CRiskIntFn0.self)
let cprisk_is_integrity_poisoned: _CRiskIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_IS_INTEGRITY_POISONED), as: _CRiskIntFn0.self)
let cprisk_is_mprotect_tampered: _CRiskIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_IS_MPROTECT_TAMPERED), as: _CRiskIntFn0.self)
let cprisk_lstat_direct: _CRiskIntFnCStringStatErr =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_LSTAT_DIRECT), as: _CRiskIntFnCStringStatErr.self)
let cprisk_mte_guard_snapshot: _CRiskIntFnMteSnapshot =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_MTE_GUARD_SNAPSHOT), as: _CRiskIntFnMteSnapshot.self)
let cprisk_pac_auth_function_pointer: _CRiskPACFn =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_PAC_AUTH_FUNCTION_POINTER), as: _CRiskPACFn.self)
let cprisk_pac_sign_function_pointer: _CRiskPACFn =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_PAC_SIGN_FUNCTION_POINTER), as: _CRiskPACFn.self)
let cprisk_pinset_contains_sha256_digest: _CRiskIntFnPinsetContainsDigest =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_PINSET_CONTAINS_SHA256_DIGEST), as: _CRiskIntFnPinsetContainsDigest.self)
let cprisk_probe_debugger_via_signal: _CRiskIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_PROBE_DEBUGGER_VIA_SIGNAL), as: _CRiskIntFn0.self)
let cprisk_probe_path_snapshot: _CRiskIntFnPathProbe =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_PROBE_PATH_SNAPSHOT), as: _CRiskIntFnPathProbe.self)
let cprisk_read_full_anchor_hash: _CRiskIntFnReadAnchor =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_READ_FULL_ANCHOR_HASH), as: _CRiskIntFnReadAnchor.self)
let cprisk_recheck_integrity: _CRiskIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_RECHECK_INTEGRITY), as: _CRiskIntFn0.self)
let cprisk_verify_svc_stub_integrity: _CRiskUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_VERIFY_SVC_STUB_INTEGRITY), as: _CRiskUInt32Fn0.self)
let cprisk_register_exception_handler: _CRiskVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_REGISTER_EXCEPTION_HANDLER), as: _CRiskVoidFn0.self)
let cprisk_scan_software_breakpoints: _CRiskIntFnScanBP =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_SCAN_SOFTWARE_BREAKPOINTS), as: _CRiskIntFnScanBP.self)
let cprisk_set_runtime_hardening_mode: _CRiskVoidFnHardeningMode =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_SET_RUNTIME_HARDENING_MODE), as: _CRiskVoidFnHardeningMode.self)
let cprisk_sign_with_derived_key_and_request_binding_digest: _CRiskIntFnSign =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_SIGN_WITH_DERIVED_KEY_AND_REQUEST_BINDING_DIGEST), as: _CRiskIntFnSign.self)
let cprisk_socket_direct: @convention(c) (CInt, CInt, CInt, UnsafeMutablePointer<CInt>?) -> CInt =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_SOCKET_DIRECT), as: (@convention(c) (CInt, CInt, CInt, UnsafeMutablePointer<CInt>?) -> CInt).self)
let cprisk_spawn_iface_probe: _CRiskIntFnSpawnProbe =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_SPAWN_IFACE_PROBE), as: _CRiskIntFnSpawnProbe.self)
let cprisk_start_anti_debug_watchdog: _CRiskIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_START_ANTI_DEBUG_WATCHDOG), as: _CRiskIntFn0.self)
let cprisk_start_anti_dump_probe: @convention(c) (CInt) -> CInt =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_START_ANTI_DUMP_PROBE), as: (@convention(c) (CInt) -> CInt).self)
let cprisk_stat_direct: _CRiskIntFnCStringStatErr =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_STAT_DIRECT), as: _CRiskIntFnCStringStatErr.self)
let cprisk_stop_anti_debug_watchdog: _CRiskVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_STOP_ANTI_DEBUG_WATCHDOG), as: _CRiskVoidFn0.self)
let cprisk_stop_anti_dump_probe: _CRiskVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_STOP_ANTI_DUMP_PROBE), as: _CRiskVoidFn0.self)
let cprisk_sysctl_direct: _CRiskIntFnSysctl =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_SYSCTL_DIRECT), as: _CRiskIntFnSysctl.self)
let cprisk_sysctlbyname_direct: _CRiskIntFnSysctlByName =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_SYSCTLBYNAME_DIRECT), as: _CRiskIntFnSysctlByName.self)
let cprisk_verify_exception_handler: _CRiskVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_VERIFY_EXCEPTION_HANDLER), as: _CRiskVoidFn0.self)
let cprisk_verify_with_derived_key_and_request_binding_digest: _CRiskIntFnVerify =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_VERIFY_WITH_DERIVED_KEY_AND_REQUEST_BINDING_DIGEST), as: _CRiskIntFnVerify.self)
