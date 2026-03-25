import CRiskCore
import Foundation
@testable import CloudPhoneRiskKit

typealias _CRiskTestVoidFn0 = @convention(c) () -> Void
typealias _CRiskTestVoidFnInt = @convention(c) (CInt) -> Void
typealias _CRiskTestVoidFnUInt32 = @convention(c) (UInt32) -> Void
typealias _CRiskTestVoidFnHardeningMode = @convention(c) (cprisk_runtime_hardening_mode_t) -> Void
typealias _CRiskTestVoidFnBufLen = @convention(c) (UnsafeMutableRawPointer?, Int) -> Void
typealias _CRiskTestIntFn0 = @convention(c) () -> CInt
typealias _CRiskTestUInt32Fn0 = @convention(c) () -> UInt32
typealias _CRiskTestUInt64Fn0 = @convention(c) () -> UInt64
typealias _CRiskTestHardeningModeFn0 = @convention(c) () -> cprisk_runtime_hardening_mode_t
typealias _CRiskTestPACFn = @convention(c) (UnsafeRawPointer?, UInt) -> UnsafeMutableRawPointer?
typealias _CRiskTestIntFnMaterial = @convention(c) (UnsafeMutablePointer<UInt8>?) -> CInt
typealias _CRiskTestIntFnInitProtection = @convention(c) (UnsafePointer<UInt8>?, Int) -> CInt
typealias _CRiskTestIntFnInitHybrid = @convention(c) (UnsafePointer<UInt8>?) -> CInt
typealias _CRiskTestUInt64FnMachineMode = @convention(c) (UnsafePointer<CChar>?, cprisk_runtime_hardening_mode_t) -> UInt64
typealias _CRiskTestIntFnSecureRegion = @convention(c) (UnsafeMutableRawPointer?, Int) -> CInt
typealias _CRiskTestIntFnPlanSnapshot = @convention(c) (UnsafeMutablePointer<cprisk_antidebug_plan_snapshot_t>?) -> CInt
typealias _CRiskTestIntFnFridaSnapshot = @convention(c) (UnsafeMutablePointer<cprisk_frida_runtime_snapshot_t>?) -> CInt
typealias _CRiskTestIntFnSpawnProbe = @convention(c) (UnsafeMutablePointer<cprisk_spawn_iface_probe_result_t>?) -> CInt
typealias _CRiskTestIntFnFlagsErr = @convention(c) (UnsafeMutablePointer<UInt32>?, UnsafeMutablePointer<CInt>?) -> CInt
typealias _CRiskTestIntFnReadAnchor = @convention(c) (UnsafeMutablePointer<UInt8>?) -> CInt
typealias _CRiskTestIntFnHMACHex = @convention(c) (UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<CChar>?) -> CInt
typealias _CRiskTestIntFnSign = @convention(c) (UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, UnsafeMutablePointer<CChar>?) -> CInt
typealias _CRiskTestIntFnVerify = @convention(c) (UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, UnsafePointer<CChar>?) -> CInt
typealias _CRiskTestIntFnDecode = @convention(c) (UInt32, UInt32, UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<CChar>?, Int) -> CInt
typealias _CRiskTestIntFnDeriveDevice = @convention(c) (UnsafePointer<UInt8>?, UnsafeMutablePointer<UInt8>?) -> CInt
typealias _CRiskTestIntFnScanPrefix = @convention(c) (UnsafeRawPointer?, Int) -> CInt
typealias _CRiskTestIntFnDomainInput = @convention(c) (UInt32, UnsafePointer<UInt8>?, UnsafeMutablePointer<UInt8>?) -> CInt
typealias _CRiskTestIntFnWhiteboxBundle = @convention(c) (UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int, UnsafePointer<UInt8>?, Int) -> CInt
typealias _CRiskTestUInt32FnDecryptPath = @convention(c) (UInt32, UnsafePointer<UInt8>?, UInt64) -> UInt32
typealias _CRiskTestIntFnSetPlan = @convention(c) (UnsafePointer<UInt8>?, Int) -> CInt
typealias _CRiskTestIntFnWhiteboxEval = @convention(c) (UInt32, UnsafePointer<UInt8>?, UnsafeMutablePointer<UInt8>?) -> CInt
typealias _CRiskTestIntFnWhiteboxProbe = @convention(c) (UnsafeMutablePointer<cprisk_whitebox_probe_result>?) -> CInt
typealias _CRiskTestIntFnTrustHookMask = @convention(c) (UnsafeMutablePointer<UInt32>?) -> CInt

let cprisk_armor_vm_protect: @convention(c) (UnsafeMutableRawPointer?, Int, CInt) -> CInt =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_ARMOR_VM_PROTECT), as: (@convention(c) (UnsafeMutableRawPointer?, Int, CInt) -> CInt).self)
let cprisk_check_init_timing: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_CHECK_INIT_TIMING), as: _CRiskTestIntFn0.self)
let cprisk_cleanup_protection: _CRiskTestVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_CLEANUP_PROTECTION), as: _CRiskTestVoidFn0.self)
let cprisk_crypto_trace_consume_flags_i: _CRiskTestUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_CRYPTO_TRACE_CONSUME_FLAGS_I), as: _CRiskTestUInt32Fn0.self)
let cprisk_crypto_trace_peek_flags_i: _CRiskTestUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_CRYPTO_TRACE_PEEK_FLAGS_I), as: _CRiskTestUInt32Fn0.self)
let cprisk_crypto_trace_primitive_enter_i: _CRiskTestVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_CRYPTO_TRACE_PRIMITIVE_ENTER_I), as: _CRiskTestVoidFn0.self)
let cprisk_csops_status_flags: _CRiskTestIntFnFlagsErr =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_CSOPS_STATUS_FLAGS), as: _CRiskTestIntFnFlagsErr.self)
let cprisk_derive_device_key: _CRiskTestIntFnDeriveDevice =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_DERIVE_DEVICE_KEY), as: _CRiskTestIntFnDeriveDevice.self)
let cprisk_detect_dbi_markers: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_DETECT_DBI_MARKERS), as: _CRiskTestIntFn0.self)
let cprisk_detect_hardware_breakpoints: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_DETECT_HARDWARE_BREAKPOINTS), as: _CRiskTestIntFn0.self)
let cprisk_detect_single_stepping: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_DETECT_SINGLE_STEPPING), as: _CRiskTestIntFn0.self)
let cprisk_detect_thread_exception_ports: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_DETECT_THREAD_EXCEPTION_PORTS), as: _CRiskTestIntFn0.self)
let cprisk_frida_runtime_snapshot: _CRiskTestIntFnFridaSnapshot =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_FRIDA_RUNTIME_SNAPSHOT), as: _CRiskTestIntFnFridaSnapshot.self)
let cprisk_get_antidebug_plan_snapshot: _CRiskTestIntFnPlanSnapshot =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_ANTIDEBUG_PLAN_SNAPSHOT), as: _CRiskTestIntFnPlanSnapshot.self)
let cprisk_get_init_elapsed_ns: _CRiskTestUInt64Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_INIT_ELAPSED_NS), as: _CRiskTestUInt64Fn0.self)
let cprisk_get_last_dbi_marker_flags: _CRiskTestUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_LAST_DBI_MARKER_FLAGS), as: _CRiskTestUInt32Fn0.self)
let cprisk_get_last_dbi_marker_hit_count: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_LAST_DBI_MARKER_HIT_COUNT), as: _CRiskTestIntFn0.self)
let cprisk_get_last_pac_cfi_flags: _CRiskTestUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_LAST_PAC_CFI_FLAGS), as: _CRiskTestUInt32Fn0.self)
let cprisk_get_last_timing_anomaly_flags: _CRiskTestUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_LAST_TIMING_ANOMALY_FLAGS), as: _CRiskTestUInt32Fn0.self)
let cprisk_get_last_timing_probe_max_ns: _CRiskTestUInt64Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_LAST_TIMING_PROBE_MAX_NS), as: _CRiskTestUInt64Fn0.self)
let cprisk_get_last_timing_probe_median_ns: _CRiskTestUInt64Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_LAST_TIMING_PROBE_MEDIAN_NS), as: _CRiskTestUInt64Fn0.self)
let cprisk_get_last_timing_probe_threshold_ns: _CRiskTestUInt64Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_LAST_TIMING_PROBE_THRESHOLD_NS), as: _CRiskTestUInt64Fn0.self)
let cprisk_get_mprotect_consecutive_full_fail_streak: _CRiskTestUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_MPROTECT_CONSECUTIVE_FULL_FAIL_STREAK), as: _CRiskTestUInt32Fn0.self)
let cprisk_get_mprotect_direct_failure_count: _CRiskTestUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_MPROTECT_DIRECT_FAILURE_COUNT), as: _CRiskTestUInt32Fn0.self)
let cprisk_get_mprotect_fail_streak_threshold: _CRiskTestUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_MPROTECT_FAIL_STREAK_THRESHOLD), as: _CRiskTestUInt32Fn0.self)
let cprisk_get_mprotect_fallback_success_count: _CRiskTestUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_MPROTECT_FALLBACK_SUCCESS_COUNT), as: _CRiskTestUInt32Fn0.self)
let cprisk_get_runtime_hardening_mode: _CRiskTestHardeningModeFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_RUNTIME_HARDENING_MODE), as: _CRiskTestHardeningModeFn0.self)
let cprisk_get_runtime_material: _CRiskTestIntFnMaterial =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_RUNTIME_MATERIAL), as: _CRiskTestIntFnMaterial.self)
let cprisk_get_vm_mprotect_crosscheck_mismatch_count: _CRiskTestUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_VM_MPROTECT_CROSSCHECK_MISMATCH_COUNT), as: _CRiskTestUInt32Fn0.self)
let cprisk_get_vm_mprotect_mach_trap_mismatch_count: _CRiskTestUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_GET_VM_MPROTECT_MACH_TRAP_MISMATCH_COUNT), as: _CRiskTestUInt32Fn0.self)
let cprisk_hmac_sha256_hex: _CRiskTestIntFnHMACHex =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_HMAC_SHA256_HEX), as: _CRiskTestIntFnHMACHex.self)
let cprisk_init_hybrid_kdf: _CRiskTestIntFnInitHybrid =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_INIT_HYBRID_KDF), as: _CRiskTestIntFnInitHybrid.self)
let cprisk_init_protection: _CRiskTestIntFnInitProtection =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_INIT_PROTECTION), as: _CRiskTestIntFnInitProtection.self)
let cprisk_is_being_traced_redundant: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_IS_BEING_TRACED_REDUNDANT), as: _CRiskTestIntFn0.self)
let cprisk_is_device_bound: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_IS_DEVICE_BOUND), as: _CRiskTestIntFn0.self)
let cprisk_is_integrity_poisoned: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_IS_INTEGRITY_POISONED), as: _CRiskTestIntFn0.self)
let cprisk_is_mprotect_tampered: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_IS_MPROTECT_TAMPERED), as: _CRiskTestIntFn0.self)
let cprisk_obf_decode_sha256_tag: _CRiskTestIntFnDecode =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_OBF_DECODE_SHA256_TAG), as: _CRiskTestIntFnDecode.self)
let cprisk_pac_auth_function_pointer: _CRiskTestPACFn =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_PAC_AUTH_FUNCTION_POINTER), as: _CRiskTestPACFn.self)
let cprisk_pac_is_arm64e_supported: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_PAC_IS_ARM64E_SUPPORTED), as: _CRiskTestIntFn0.self)
let cprisk_pac_self_test: @convention(c) (UInt) -> CInt =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_PAC_SELF_TEST), as: (@convention(c) (UInt) -> CInt).self)
let cprisk_pac_sign_function_pointer: _CRiskTestPACFn =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_PAC_SIGN_FUNCTION_POINTER), as: _CRiskTestPACFn.self)
let cprisk_pac_validate_core_callbacks: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_PAC_VALIDATE_CORE_CALLBACKS), as: _CRiskTestIntFn0.self)
let cprisk_probe_debugger_via_signal: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_PROBE_DEBUGGER_VIA_SIGNAL), as: _CRiskTestIntFn0.self)
let cprisk_protect_decrypted_pages: _CRiskTestIntFnSecureRegion =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_PROTECT_DECRYPTED_PAGES), as: _CRiskTestIntFnSecureRegion.self)
let cprisk_recheck_integrity: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_RECHECK_INTEGRITY), as: _CRiskTestIntFn0.self)
let cprisk_restore_macho_header: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_RESTORE_MACHO_HEADER), as: _CRiskTestIntFn0.self)
let cprisk_run_all_signal_probes: _CRiskTestUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_RUN_ALL_SIGNAL_PROBES), as: _CRiskTestUInt32Fn0.self)
let cprisk_scan_arm64_instant_return_nop_patch_prefix: _CRiskTestIntFnScanPrefix =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_SCAN_ARM64_INSTANT_RETURN_NOP_PATCH_PREFIX), as: _CRiskTestIntFnScanPrefix.self)
let cprisk_scan_instant_return_key_symbols_prefix: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_SCAN_INSTANT_RETURN_KEY_SYMBOLS_PREFIX), as: _CRiskTestIntFn0.self)
let cprisk_set_runtime_hardening_mode: _CRiskTestVoidFnHardeningMode =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_SET_RUNTIME_HARDENING_MODE), as: _CRiskTestVoidFnHardeningMode.self)
let cprisk_sign_with_derived_key_and_request_binding_digest: _CRiskTestIntFnSign =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_SIGN_WITH_DERIVED_KEY_AND_REQUEST_BINDING_DIGEST), as: _CRiskTestIntFnSign.self)
let cprisk_spawn_iface_probe: _CRiskTestIntFnSpawnProbe =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_SPAWN_IFACE_PROBE), as: _CRiskTestIntFnSpawnProbe.self)
let cprisk_test_clear_whitebox_bundle: _CRiskTestVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_TEST_CLEAR_WHITEBOX_BUNDLE), as: _CRiskTestVoidFn0.self)
let cprisk_test_init_timing_threshold_ns_for_machine: _CRiskTestUInt64FnMachineMode =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_TEST_INIT_TIMING_THRESHOLD_NS_FOR_MACHINE), as: _CRiskTestUInt64FnMachineMode.self)
let cprisk_test_mprotect_reset_tamper_state: _CRiskTestVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_TEST_MPROTECT_RESET_TAMPER_STATE), as: _CRiskTestVoidFn0.self)
let cprisk_test_mprotect_set_fail_streak_threshold: _CRiskTestVoidFnUInt32 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_TEST_MPROTECT_SET_FAIL_STREAK_THRESHOLD), as: _CRiskTestVoidFnUInt32.self)
let cprisk_test_mprotect_set_force_direct_fail: _CRiskTestVoidFnInt =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_TEST_MPROTECT_SET_FORCE_DIRECT_FAIL), as: _CRiskTestVoidFnInt.self)
let cprisk_test_mprotect_set_force_fallback_fail: _CRiskTestVoidFnInt =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_TEST_MPROTECT_SET_FORCE_FALLBACK_FAIL), as: _CRiskTestVoidFnInt.self)
let cprisk_test_secure_zero: _CRiskTestVoidFnBufLen =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_TEST_SECURE_ZERO), as: _CRiskTestVoidFnBufLen.self)
let cprisk_test_select_string_decrypt_path: _CRiskTestUInt32FnDecryptPath =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_TEST_SELECT_STRING_DECRYPT_PATH), as: _CRiskTestUInt32FnDecryptPath.self)
let cprisk_test_set_antidebug_plan: _CRiskTestIntFnSetPlan =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_TEST_SET_ANTIDEBUG_PLAN), as: _CRiskTestIntFnSetPlan.self)
let cprisk_test_set_whitebox_bundle: _CRiskTestIntFnWhiteboxBundle =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_TEST_SET_WHITEBOX_BUNDLE), as: _CRiskTestIntFnWhiteboxBundle.self)
let cprisk_test_set_whitebox_recompute_mismatch: _CRiskTestVoidFnInt =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_TEST_SET_WHITEBOX_RECOMPUTE_MISMATCH), as: _CRiskTestVoidFnInt.self)
let cprisk_test_whitebox_prepare_domain_input: _CRiskTestIntFnDomainInput =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_TEST_WHITEBOX_PREPARE_DOMAIN_INPUT), as: _CRiskTestIntFnDomainInput.self)
let cprisk_unprotect_pages: _CRiskTestIntFnSecureRegion =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_UNPROTECT_PAGES), as: _CRiskTestIntFnSecureRegion.self)
let cprisk_verify_dlsym_prologue: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_VERIFY_DLSYM_PROLOGUE), as: _CRiskTestIntFn0.self)
let cprisk_verify_runtime_hook_surface_prologues: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_VERIFY_RUNTIME_HOOK_SURFACE_PROLOGUES), as: _CRiskTestIntFn0.self)
let cprisk_integrity_poison_watchdog_lane: _CRiskTestVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_INTEGRITY_POISON_WATCHDOG_LANE), as: _CRiskTestVoidFn0.self)
let cprisk_test_reset_staged_poison_for_tests: _CRiskTestVoidFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_TEST_RESET_STAGED_POISON_FOR_TESTS), as: _CRiskTestVoidFn0.self)
let cprisk_verify_mprotect_dlsym_matches_export_trie: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_VERIFY_MPROTECT_DLSYM_MATCHES_EXPORT_TRIE), as: _CRiskTestIntFn0.self)
let cprisk_verify_page_protection: _CRiskTestIntFnSecureRegion =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_VERIFY_PAGE_PROTECTION), as: _CRiskTestIntFnSecureRegion.self)
let cprisk_verify_svc_stub_integrity: _CRiskTestUInt32Fn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_VERIFY_SVC_STUB_INTEGRITY), as: _CRiskTestUInt32Fn0.self)
let cprisk_verify_trust_hook_surface_integrity: _CRiskTestIntFnTrustHookMask =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_VERIFY_TRUST_HOOK_SURFACE_INTEGRITY), as: _CRiskTestIntFnTrustHookMask.self)
let cprisk_verify_with_derived_key_and_request_binding_digest: _CRiskTestIntFnVerify =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_VERIFY_WITH_DERIVED_KEY_AND_REQUEST_BINDING_DIGEST), as: _CRiskTestIntFnVerify.self)
let cprisk_whitebox_available: _CRiskTestIntFn0 =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_WHITEBOX_AVAILABLE), as: _CRiskTestIntFn0.self)
let cprisk_whitebox_evaluate_domain: _CRiskTestIntFnWhiteboxEval =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_WHITEBOX_EVALUATE_DOMAIN), as: _CRiskTestIntFnWhiteboxEval.self)
let cprisk_whitebox_probe: _CRiskTestIntFnWhiteboxProbe =
    CRiskCoreBridge.resolve(UInt32(CPRISK_SWIFT_BRIDGE_IMPORT_WHITEBOX_PROBE), as: _CRiskTestIntFnWhiteboxProbe.self)
