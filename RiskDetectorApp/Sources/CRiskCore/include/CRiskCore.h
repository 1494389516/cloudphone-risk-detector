#ifndef CRiskCore_h
#define CRiskCore_h

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cprisk_armor_abi.h"
#include "cprisk_secure_zero.h"
#include "cprisk_memory_guard.h"
#include "cprisk_mte_guard.h"
#include "cprisk_swift_bridge.h"
#include "cprisk_vm_interpreter.h"
#include "cprisk_crypto_trace.h"

#ifdef __cplusplus
extern "C" {
#endif

/// Issue a direct deny-attach syscall to block debugger attachment.
/// Safe to call multiple times.
void cprisk_deny_attach(void);

/// Issue deny-attach via direct syscall and surface raw errno.
/// Returns 0 on success, -1 on syscall error. When error_out is non-null,
/// it receives the raw BSD errno produced by the syscall path.
int cprisk_deny_attach_status(int *error_out);

/// Check if the current process is being traced (debugger attached).
/// Uses sysctl KERN_PROC_PID to read P_TRACED from kinfo_proc.
/// Returns 1 if traced, 0 if not traced or on query failure/simulator.
int cprisk_is_being_traced(void);

/// Alternate entry point with identical semantics to `cprisk_is_being_traced` (shared
/// implementation) to reduce single-export hook leverage across call sites.
int cprisk_is_being_traced_alt(void);

/// sysctl + Mach pre-check, then aggregate trace evaluation.
int cprisk_is_being_traced_redundant(void);

/// Independent sysctl-only P_TRACED probe (duplicate path from `cprisk_is_being_traced`).
/// Use alongside `cprisk_mach_trace_suspicious` to reduce single-function hook surface.
int cprisk_is_being_traced_sysctl_only(void);

/// Mach-path trace suspicion helper used to cross-check sysctl/unix results.
/// Returns 1 when Mach state indicates suspicious trace/hijack characteristics.
int cprisk_mach_trace_suspicious(void);

/// Returns non-zero when unix/sysctl path and Mach path disagree.
int cprisk_trace_crosscheck_inconsistent(void);

enum {
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_NONE = 0u,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED = 1u << 0,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH = 1u << 1,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_PORT = 1u << 2,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_QUERY = 1u << 3,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SIGNAL_PROBE     = 1u << 4,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_HARDWARE_BP      = 1u << 5,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_CSOPS_DEBUGGED   = 1u << 6,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SUSPICIOUS_THREAD = 1u << 7,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SINGLE_STEP      = 1u << 8,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TTY              = 1u << 9,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DEVELOPER_DISK   = 1u << 10,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SOFTWARE_BP      = 1u << 11,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_EXCEPTION_DELIVERY_TIMEOUT = 1u << 12,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_WATCHDOG_PEER_STALL = 1u << 13,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SHADOW_STACK = 1u << 14,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DBI_MARKER = 1u << 15,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TIMING_SIDECHANNEL = 1u << 16,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACE_CROSSCHECK = 1u << 17,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_TRACED_PROBE_DIVERGENCE = 1u << 18,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_FUNCTION_PROLOGUE = 1u << 19,
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DYLD_INJECTION = 1u << 20,
    /** deny_attach syscall returned success but post-hoc sysctl/Mach consistency failed. */
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_DENY_ATTACH_VERIFY = 1u << 21,
    /** csops code-signing flags snapshot indicates unexpected CS_VALID / CS_HARD / CS_KILL / CS_DEBUGGED mix. */
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_AMFI_CS_FLAGS = 1u << 22,
    /** task_for_pid(self) unexpectedly succeeded (get-task-allow-class capability). */
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GET_TASK_ALLOW = 1u << 23,
    /** Guard page (PROT_NONE honeypot) fault — anti-dump / scan attempt. */
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_GUARD_PAGE = 1u << 24,
    /** ARM64 function-entry NOP/RET instant-return patch (e.g. mov x0,x0; ret) on monitored symbols. */
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_INSTANT_RETURN_PATCH = 1u << 25,
    /** Direct syscall SVC stub snapshot mismatch (syscall template or deny-attach body). */
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_SVC_STUB_INTEGRITY = 1u << 26,
    /** vm_region/vm_protect cross-check saw POSIX mprotect success diverge from Mach VM state. */
    CPRISK_ANTI_DEBUG_WATCHDOG_ANOMALY_VM_MPROTECT_MACH_DIVERGENCE = 1u << 27,
};

enum {
    CPRISK_AMFI_PROBE_CS_DEBUGGED = 1u << 0,
    CPRISK_AMFI_PROBE_CS_VALID_ABSENT = 1u << 1,
    CPRISK_AMFI_PROBE_CS_HARD_ABSENT = 1u << 2,
    CPRISK_AMFI_PROBE_CS_KILL_ABSENT = 1u << 3,
};

typedef struct cprisk_exception_handler_snapshot {
    uint32_t supported;
    uint32_t registered;
    uint32_t port_matches;
    uint32_t last_query_succeeded;
    uint32_t last_reclaim_attempted;
    uint32_t last_hijack_detected;
    uint32_t early_phase_captured;
    uint32_t last_race_detected;
    int32_t last_query_kern_return;
    int32_t last_register_kern_return;
    uint64_t verify_count;
    uint64_t reclaim_count;
} cprisk_exception_handler_snapshot_t;

typedef struct cprisk_anti_debug_watchdog_snapshot {
    uint32_t supported;
    uint32_t running;
    uint32_t thread_active;
    uint32_t stop_requested;
    uint32_t interval_seconds;
    uint32_t anomaly_flags;
    uint32_t last_traced;
    uint32_t last_exception_port_healthy;
    uint32_t last_exception_query_succeeded;
    uint32_t last_exception_reclaim_attempted;
    uint32_t last_exception_hijack_detected;
    int32_t last_deny_attach_result;
    int32_t last_deny_attach_errno;
    int32_t last_exception_query_kern_return;
    int32_t last_exception_register_kern_return;
    uint64_t iteration_count;
    uint64_t traced_event_count;
    uint64_t deny_attach_error_count;
    uint64_t exception_anomaly_count;
    uint64_t last_check_monotonic_ns;
    uint32_t last_signal_probe_result;
    uint32_t last_hardware_bp_detected;
    uint32_t last_software_bp_detected;
    uint32_t last_csops_debugged;
    uint32_t last_suspicious_thread_count;
    uint32_t last_single_step_detected;
    uint32_t last_tty_detected;
    uint32_t last_developer_disk_detected;
    uint32_t last_exception_delivery_timeout_detected;
    uint32_t last_exception_delivery_probe_handled;
    uint64_t last_exception_delivery_probe_ns;
    uint64_t signal_probe_anomaly_count;
    uint64_t hardware_bp_anomaly_count;
    uint64_t software_bp_anomaly_count;
    uint64_t csops_anomaly_count;
    uint64_t suspicious_thread_anomaly_count;
    uint64_t exception_delivery_timeout_anomaly_count;
    uint64_t peer_watchdog_anomaly_count;
    uint64_t shadow_stack_anomaly_count;
    uint32_t last_peer_watchdog_stalled;
    uint32_t last_shadow_stack_mismatch;
    uint32_t last_dbi_detected;
    uint32_t last_dbi_marker_flags;
    uint32_t last_timing_anomaly_flags;
    uint64_t last_timing_probe_median_ns;
    uint64_t last_timing_probe_max_ns;
    uint64_t last_timing_probe_threshold_ns;
    uint64_t dbi_anomaly_count;
    uint64_t timing_anomaly_count;
    uint64_t prologue_integrity_anomaly_count;
    uint64_t dyld_injection_anomaly_count;
    uint32_t last_prologue_fail_mask;
    uint32_t last_dyld_injection_flags;
    uint32_t last_csops_status_flags;
    uint32_t last_amfi_probe_bits;
    uint32_t last_get_task_allow_suspect;
    uint32_t last_deny_attach_verify_bits;
    uint64_t deny_attach_verify_anomaly_count;
    uint64_t amfi_cs_flags_anomaly_count;
    uint64_t get_task_allow_anomaly_count;
    /** Cumulative Mach vs POSIX mprotect cross-check mismatches (see cprisk_data_loader.c). */
    uint64_t vm_mprotect_crosscheck_mismatch_total;
    /** Cumulative vm_protect trap failures after a \"successful\" mprotect (hook surface). */
    uint64_t vm_mprotect_mach_trap_mismatch_total;
    /** Bitset: libc / arc4random paths used because direct syscall was unavailable (see CPRISK_LIBC_FALLBACK_USED_*). */
    uint32_t libc_fallback_used_mask;
    /** Count of fallback notifications since last mask reset; may exceed popcount(mask). */
    uint32_t libc_fallback_event_total;
} cprisk_anti_debug_watchdog_snapshot_t;

typedef struct cprisk_antidebug_plan_snapshot {
    uint32_t section_present;
    uint32_t section_valid;
    uint32_t parse_error;
    uint32_t entry_count;
    uint32_t policy_union_bits;
    uint32_t last_applied_policy_bits;
    uint32_t last_probe_bits;
    uint32_t last_gate_closed;
    uint32_t last_soft_fail_mode;
    uint64_t last_delay_ns;
    uint64_t consume_count;
    uint64_t escalation_count;
    uint64_t trap_event_count;
    uint64_t inline_patch_count;
    uint64_t inline_patch_failure_count;
    uint32_t inline_patch_armed;
    uint32_t last_inline_patch_tamper;
} cprisk_antidebug_plan_snapshot_t;

/// Invoke sysctlbyname via direct BSD syscall on arm64 Apple targets.
/// Returns 0 on success, -1 on error. When error_out is non-null, it receives
/// the raw BSD errno from the direct syscall path (or errno on fallback builds).
int cprisk_sysctlbyname_direct(
    const char *name,
    void *oldp,
    size_t *oldlenp,
    const void *newp,
    size_t newlen,
    int *error_out
);

/// Invoke sysctl via direct BSD syscall on arm64 Apple targets.
/// Returns 0 on success, -1 on error. When error_out is non-null, it receives
/// the raw BSD errno from the direct syscall path (or errno on fallback builds).
int cprisk_sysctl_direct(
    int *name,
    unsigned int namelen,
    void *oldp,
    size_t *oldlenp,
    const void *newp,
    size_t newlen,
    int *error_out
);

/// Invoke stat/lstat/access via direct BSD syscall on arm64 Apple targets.
/// Returns 0 on success, -1 on error. When error_out is non-null, it receives
/// the raw BSD errno from the direct syscall path (or errno on fallback builds).
int cprisk_stat_direct(const char *path, struct stat *sb, int *error_out);
int cprisk_lstat_direct(const char *path, struct stat *sb, int *error_out);
int cprisk_access_direct(const char *path, int amode, int *error_out);

enum {
    CPRISK_PATH_PROBE_ACCESS = 1u << 0,
    CPRISK_PATH_PROBE_STAT = 1u << 1,
    CPRISK_PATH_PROBE_FOPEN = 1u << 2,
};

typedef struct cprisk_path_probe_snapshot {
    uint32_t available_mask;
    uint32_t exists_mask;
} cprisk_path_probe_snapshot_t;

/// Probe path existence in C layer using access/stat/fopen.
/// Returns 0 on success, -1 on invalid input.
int cprisk_probe_path_snapshot(const char *path, cprisk_path_probe_snapshot_t *out_snapshot);

/// Result of libc spawn-entry multi-path address comparison (RTLD_DEFAULT vs dlopen+dlsym vs export trie).
typedef struct cprisk_spawn_iface_probe_result {
    uint64_t addr_rtld_default_spawn;
    uint64_t addr_dlopen_libc_spawn;
    uint64_t addr_export_trie_spawn;
    uint64_t addr_rtld_default_spawnp;
    uint64_t addr_dlopen_libc_spawnp;
    uint64_t addr_export_trie_spawnp;
    uint32_t flags;
    uint32_t reserved;
} cprisk_spawn_iface_probe_result_t;

/// Populate \p out with resolved addresses and inconsistency flags. Returns 0 on success, -1 if \p out is NULL.
int cprisk_spawn_iface_probe(cprisk_spawn_iface_probe_result_t *out);

/// Return the current process ID via direct syscall (SYS_getpid).
/// Never fails; uses cprisk_direct_syscall0 for minimal overhead.
pid_t cprisk_getpid_direct(void);

/// Return the parent process ID via direct syscall (SYS_getppid).
/// Never fails; uses cprisk_direct_syscall0 for minimal overhead.
pid_t cprisk_getppid_direct(void);

/// Return the real user ID via direct syscall (SYS_getuid).
/// Never fails; uses cprisk_direct_syscall0 for minimal overhead.
uid_t cprisk_getuid_direct(void);

/// Open a file via direct syscall (SYS_open).
/// Returns a file descriptor on success, -1 on error.
int cprisk_open_direct(const char *path, int flags, int *error_out);

/// Close a file descriptor via direct syscall (SYS_close).
/// Returns 0 on success, -1 on error.
int cprisk_close_direct(int fd, int *error_out);

/// Read from a file descriptor via direct syscall (SYS_read).
/// Returns bytes read on success, -1 on error.
ssize_t cprisk_read_direct(int fd, void *buf, size_t nbyte, int *error_out);

/// Create a socket via direct syscall (SYS_socket).
/// Returns a file descriptor on success, -1 on error.
int cprisk_socket_direct(int domain, int type, int protocol, int *error_out);

/// Connect a socket via direct syscall (SYS_connect).
/// Returns 0 on success, -1 on error.
int cprisk_connect_direct(int sockfd, const struct sockaddr *addr, socklen_t addrlen, int *error_out);

/// Sign an unauthenticated function pointer for later indirect calls.
/// On arm64e this applies pointer authentication; on other architectures it is
/// a no-op pass-through and simply returns ptr.
void *cprisk_pac_sign_function_pointer(const void *ptr, uintptr_t discriminator);

/// Authenticate a previously signed function pointer before invocation.
/// Returns NULL when authentication fails (arm64e), otherwise returns an
/// authenticated callable pointer.
void *cprisk_pac_auth_function_pointer(const void *ptr, uintptr_t discriminator);

/// Returns 1 when arm64e PAC runtime support is compiled in, 0 otherwise.
int cprisk_pac_is_arm64e_supported(void);

enum {
    CPRISK_PAC_CFI_FLAG_NONE = 0u,
    CPRISK_PAC_CFI_FLAG_UNAVAILABLE = 1u << 0,
    CPRISK_PAC_CFI_FLAG_SIGN_FAILED = 1u << 1,
    CPRISK_PAC_CFI_FLAG_AUTH_FAILED = 1u << 2,
    CPRISK_PAC_CFI_FLAG_WEAK_BINDING = 1u << 3,
    CPRISK_PAC_CFI_FLAG_SELFTEST_FAILED = 1u << 4,
    CPRISK_PAC_CFI_FLAG_CALLBACK_VALIDATION_FAILED = 1u << 5,
};

/// Validate PAC/CFI binding by signing + authenticating a function pointer with
/// the supplied discriminator.
/// Returns 0 when validation succeeds (or PAC is unavailable), 1 on validation
/// failure, -1 on invalid input.
int cprisk_pac_validate_indirect_call_target(const void *func_ptr, uintptr_t discriminator);

/// Run a PAC self-test on an internal function pointer + call path.
/// Returns 0 on success (or PAC unavailable), 1 when validation fails.
int cprisk_pac_self_test(uintptr_t discriminator);

/// Validate a built-in core callback target used by the integrity pipeline.
/// Returns 0 when callback binding is valid (or PAC unavailable), 1 otherwise.
int cprisk_pac_validate_core_callbacks(void);

/// Return last PAC/CFI status flags (CPRISK_PAC_CFI_FLAG_*).
uint32_t cprisk_get_last_pac_cfi_flags(void);

/// Fill a buffer with random bytes via direct syscall (SYS_getentropy).
/// Returns 0 on success, -1 on error. buflen must be <= 256.
int cprisk_getentropy_direct(void *buf, size_t buflen, int *error_out);

/// Code signing ops via direct syscall (SYS_csops).
/// Returns 0 on success, -1 on error. On failure, `error_out` receives errno when available.
int cprisk_csops_direct(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, int *error_out);

/// Change virtual-memory protection via direct syscall (SYS_mprotect).
/// Returns 0 on success, -1 on error.
int cprisk_mprotect_direct(void *addr, size_t len, int prot, int *error_out);

/// Bits for \c cprisk_note_libc_fallback_used / \c cprisk_get_libc_fallback_used_mask:
/// record when CRiskCore took a libc (or arc4random) path because direct syscall
/// implementations were unavailable for this build or platform.
enum {
    CPRISK_LIBC_FALLBACK_USED_DIRECT_MPROTECT = 1u << 0,
    CPRISK_LIBC_FALLBACK_USED_DIRECT_GETENTROPY = 1u << 1,
    CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCTL = 1u << 2,
    CPRISK_LIBC_FALLBACK_USED_DIRECT_STAT_PATH = 1u << 3,
    CPRISK_LIBC_FALLBACK_USED_DIRECT_FD_IO = 1u << 4,
    CPRISK_LIBC_FALLBACK_USED_DIRECT_IDS = 1u << 5,
    CPRISK_LIBC_FALLBACK_USED_ARMOR_MPROTECT = 1u << 6,
    /** Build has no in-process SVC stubs (simulator, non-arm64 Apple, etc.); libc substitutes are expected. */
    CPRISK_LIBC_FALLBACK_USED_UNSUPPORTED_PLATFORM = 1u << 7,
    /** csops direct path unavailable in this build; callers receive ENOTSUP without libc substitute. */
    CPRISK_LIBC_FALLBACK_USED_DIRECT_CSOPS_UNAVAILABLE = 1u << 8,
    /**
     * Internal direct-syscall stub returned ENOTSUP (should not happen when wrappers are used;
     * recorded defensively so the event is never fully silent).
     */
    CPRISK_LIBC_FALLBACK_USED_DIRECT_SYSCALL_STUB_FALLBACK = 1u << 9,
};

void cprisk_note_libc_fallback_used(uint32_t bits);
uint32_t cprisk_get_libc_fallback_used_mask(void);
void cprisk_reset_libc_fallback_used_mask(void);
uint32_t cprisk_get_libc_fallback_event_total(void);

#ifndef CPRISK_MPROTECT_FULL_FAIL_STREAK_THRESHOLD
/// Consecutive "full" mprotect failures (direct + libc fallback both fail, or no libc)
/// required before cprisk_is_mprotect_tampered() latches. Override at compile time if needed.
#define CPRISK_MPROTECT_FULL_FAIL_STREAK_THRESHOLD 3u
#endif

/// Data-loader VM protection entry (direct syscall + libc fallback + tamper streak policy).
int cprisk_armor_vm_protect(void *addr, size_t len, int prot);

/// Register EXC_BREAKPOINT handler to preempt Frida/debugger from hijacking exception ports.
/// Call from CPRiskKit.start() after cprisk_deny_attach.
void cprisk_register_exception_handler(void);

/// Capture early-phase exception port ownership fingerprint.
/// Intended for __DATA,__thread_init callback after first registration.
void cprisk_capture_early_exception_ports(void);

/// Verify current EXC_BREAKPOINT handler is still ours; re-register if hijacked.
/// Call periodically (e.g. in evaluate() or a background check).
void cprisk_verify_exception_handler(void);

/// Copy the latest exception-handler state snapshot into out_snapshot.
/// Returns 0 on success, -1 when out_snapshot is NULL.
int cprisk_get_exception_handler_snapshot(cprisk_exception_handler_snapshot_t *out_snapshot);

/// Start the anti-debug watchdog thread. The watchdog is idempotent:
/// repeated calls while running do not create additional threads.
/// Returns 0 on success/already-running/no-op platforms, -1 on thread creation failure.
int cprisk_start_anti_debug_watchdog(void);

/// Request the anti-debug watchdog to stop and wait for the thread to exit.
/// Safe to call multiple times.
void cprisk_stop_anti_debug_watchdog(void);

/// Copy the latest anti-debug watchdog state into out_snapshot.
/// Returns 0 on success, -1 when out_snapshot is NULL.
int cprisk_get_anti_debug_watchdog_snapshot(
    cprisk_anti_debug_watchdog_snapshot_t *out_snapshot
);

/// Verify `dlsym` function prologue against an early baseline snapshot (stack shadow memcpy + memcmp).
/// Used on the encrypted import resolve path and by the anti-debug watchdog. Returns 1 if intact,
/// 0 on mismatch (integrity poison). On simulator / unsupported builds this is a no-op success.
int cprisk_verify_dlsym_prologue(void);

/// Copy the latest anti-debug plan parser/policy snapshot into out_snapshot.
/// Returns 0 on success, -1 when out_snapshot is NULL.
int cprisk_get_antidebug_plan_snapshot(
    cprisk_antidebug_plan_snapshot_t *out_snapshot
);

/// Finds the current image's Mach-O header in memory, makes it writable,
/// and zeroes out the magic number and key load commands to thwart memory dumping.
void cprisk_erase_macho_header(void);

/// Restore encrypted mach_header_64 fields from the __DATA.__swift5_mhsav
/// backup section.  Supports both legacy fixed marker and per-binary
/// camouflaged reserved values.
/// Returns 0 on success, 1 if no restoration needed/already restored, -1 on error.
/// Safe to call repeatedly; runtime uses constructor + once + retry semantics.
int cprisk_restore_macho_header(void);

/* ── cprisk-armor Runtime Support (ABI v1) ─────────────────────────── */

/// Initialize the string decryptor with a 32-byte key.
/// Returns 0 on success, -1 on failure.
int cprisk_init_string_decryptor(const uint8_t *key, size_t key_len);

/// Decrypt the string identified by string_id from
/// the packed string table section into buffer.
/// Returns decrypted byte count, -1 on failure.
/// Side-effect: updates the string integrity accumulator.
int cprisk_decrypt_string(uint32_t string_id, char *buffer, size_t buffer_size);

/// Single-slot lazy decrypt cache (first-touch semantics); copies into `buffer` when possible.
int cprisk_decrypt_string_lazy(uint32_t string_id, char *buffer, size_t buffer_size);

/// Clears resident lazy plaintext (best-effort overwrite).
void cprisk_string_lazy_scrub_all(void);

/// Return the current string integrity accumulator value.
uint64_t cprisk_get_string_integrity_accumulator(void);

/// Securely wipe decryption key and accumulator state.
void cprisk_cleanup_string_decryptor(void);

/// Test-only helper: select the distributed decrypt micro-path using
/// the same deterministic selector as runtime dispatch.
/// Returns a value in [0, 3].
uint32_t cprisk_test_select_string_decrypt_path(
    uint32_t string_id,
    const uint8_t nonce[CPRISK_ARMOR_NONCE_SIZE],
    uint64_t seed
);

/// Initialize the data segment loader with a 32-byte key.
/// Returns 0 on success, -1 on failure.
int cprisk_init_data_loader(const uint8_t *key, size_t key_len);

/// Decrypt all protected __DATA sections described by the ABI-v1 loader
/// descriptor. The runtime validates descriptor bounds, target section
/// ownership, and basic writable permissions before mutating any bytes.
/// On failure it rolls back previously decrypted entries and returns -1.
/// Returns the number of sections decrypted, -1 on failure.
int cprisk_load_protected_data(void);

/// Decrypts a specific page on-demand when a bad access exception occurs.
/// Returns 1 on success (page decrypted), 0 on failure or if not a protected page.
int cprisk_jit_decrypt_page(void *fault_addr);

/// __TEXT encryption (Pass12): decrypt protected page containing `addr` without taking a fault (use-and-reencrypt timer unchanged).
int cprisk_text_on_demand_decrypt(void *addr);

/// __TEXT.__text idle re-encrypt: call from a periodic context (e.g. anti-debug watchdog)
/// so decrypted execute pages are re-wrapped after a short bounded dwell time without
/// waiting for another fault. No-op on simulator / when Pass12 metadata is absent.
void cprisk_text_encrypt_service_idle(void);

/// Return the current data integrity accumulator value.
uint64_t cprisk_get_data_integrity_accumulator(void);

/// Securely wipe decrypted data sections and loader state.
void cprisk_unload_protected_data(void);

/// Compute a three-path integrity hash of __TEXT.__text.
/// Path C reconstructs the 32-byte anchor digest from the four split anchor
/// sections. Writes 32 bytes to out_hash. Returns 0 on success, -1 on failure.
int cprisk_compute_integrity_hash(uint8_t *out_hash);

/// Read the full anchor hash by reconstructing it from split anchor lanes.
/// ABI v2: the full-hash section now stores only an HMAC tag; the actual
/// hash is reassembled from the four 8-byte split lanes.
/// Writes 32 bytes to out_hash. Returns 0 on success, -1 on failure.
int cprisk_read_full_anchor_hash(uint8_t *out_hash);

/// Verify the HMAC anchor tag stored in the full-hash section against
/// the provided full_hash using root_material as the HMAC key.
/// Returns 0 on success (HMAC matches), -1 on failure.
int cprisk_verify_anchor_hmac(const uint8_t root_material[32],
                              const uint8_t full_hash[32]);

/// Anti-debug / init policy tier for SDK integration (development vs production).
/// Set via \c cprisk_set_runtime_hardening_mode() before \c cprisk_init_protection()
/// (or any time — affects subsequent policy application and init-timing checks).
enum {
    CPRISK_RUNTIME_HARDENING_PRODUCTION = 0,
    /** Dev/QA: weak probes (TTY, Developer Disk, timing) do not inflate debugger scoring; init-timing bar is higher. */
    CPRISK_RUNTIME_HARDENING_RELAXED_DEV_QA = 1,
};

typedef int cprisk_runtime_hardening_mode_t;

void cprisk_set_runtime_hardening_mode(cprisk_runtime_hardening_mode_t mode);
cprisk_runtime_hardening_mode_t cprisk_get_runtime_hardening_mode(void);

/// Master initialization: root material + full anchor hash + integrity hash
/// feed an anchor-bound accumulator, which is then consumed by loader-key
/// and runtime-material derivation before decrypting protected data.
/// root_key must be non-NULL and non-zero (all-zero keys are rejected with -1
/// to prevent a predictable key chain); values longer than 32 bytes are
/// truncated. Returns 0 on success, negative on failure.
int cprisk_init_protection(const uint8_t *root_key, size_t root_key_len);

/// Cleanup all armor runtime state (keys, accumulators, decrypted data).
void cprisk_cleanup_protection(void);

/// Retrieve the 32-byte runtime material consumed by Swift signing/validation.
/// On the authentic path, out_material contains the real derived material.
/// On poison/deception paths, out_material still receives 32 bytes, but they may
/// be deterministic decoy bytes chosen to mislead local hooks or return-code
/// oracles.
/// Always writes exactly 32 bytes to out_material.
/// Returns 0 for all non-NULL calls; the return value is NOT a reliable oracle
/// for authenticity. Callers that need an explicit fail-closed signal must rely
/// on other runtime state (for example, visible poison flags or init status).
int cprisk_get_runtime_material(uint8_t out_material[32]);

/// Returns 1 when authentic runtime material was successfully derived during
/// init and is currently available to helper pipelines, 0 otherwise.
/// Unlike cprisk_get_runtime_material(), this does not expose any bytes.
int cprisk_runtime_material_ready(void);

/* ── Import Table Encryption Resolver ──────────────────────────────── */

/// Resolve a symbol from the encrypted import table by index.
/// Reads __DATA.__swift5_dyrel, verifies HMAC-SHA256 integrity, decrypts
/// the symbol name via SHA256-based keystream, and resolves it via dlsym.
///
/// symbol_index: zero-based index into the encrypted import table.
/// High-range values beginning at CPRISK_SWIFT_BRIDGE_IMPORT_BASE are reserved
/// for Swift bridge aliases and resolve against opaque self-image exports.
/// out_addr: receives the resolved symbol address on success.
///
/// Returns 0 on success (symbol resolved), -1 on failure
/// (not found, tampered HMAC, bounds error, or dlsym failure).
int cprisk_resolve_import(uint32_t symbol_index, void **out_addr);

/// Sanity check: `dlsym(RTLD_DEFAULT,"mprotect")` must match export-trie resolution
/// for libsystem_kernel (see cprisk_dlsym). For tests / diagnostics only.
/// Returns 0 on match, 1 on mismatch, -1 if either lookup failed.
int cprisk_verify_mprotect_dlsym_matches_export_trie(void);

/* ── White-box Frontend / Signing Helpers ─────────────────────────── */

/// Returns a compile-time/runtime capability bitmask for the current armor
/// runtime. The bitset advertises helper availability and whether reserved
/// white-box metadata sections are present in the current image.
uint32_t cprisk_get_armor_capabilities(void);

/// Populate a minimal white-box probe snapshot.
/// abi_version describes the reserved white-box metadata ABI, capabilities is a
/// bitmask of helper/support flags, flags carries probe state such as
/// COMPILED / METADATA_PRESENT / ENGINE_READY, and metadata_version surfaces
/// the embedded metadata header version when present.
/// Returns 0 on success, -1 when out_probe is NULL.
int cprisk_whitebox_probe(struct cprisk_whitebox_probe_result *out_probe);

/// Returns 1 only when a valid white-box metadata section is embedded and marks
/// the future engine as ready; current placeholder builds typically return 0.
int cprisk_whitebox_available(void);

/// Evaluate one white-box PRF domain against a 32-byte input state.
/// Returns 0 on success, -1 on validation failure, unknown domain, or null out.
///
/// When embedded metadata sets \c CPRISK_ARMOR_WHITEBOX_FLAG_ASLR_TABLE_BIND (v2 header,
/// 56-byte \c __swift5_mdext), table bytes in \c __swift5_mdbdy are XOR-masked vs Mach
/// slide; runtime decodes using \c aslr_table_anchor_slide before PRF evaluation.
/// Disable at runtime: \c CPRISK_WB_ASLR_TABLE_DISABLE=1. Strip decode path at compile
/// time: \c CPRISK_DISABLE_WHITEBOX_ASLR_TABLE.
/// Domains 6-9: when \c cprisk_get_effective_root() succeeds (after hybrid KDF), the PRF
/// input is SHA256(label||domain_id_le||input||effective_root); if not, input is identity
/// (early boot before KDF).
int cprisk_whitebox_evaluate_domain(
    uint32_t domain_id,
    const uint8_t input[32],
    uint8_t out[32]
);

/// Derive a 32-byte effective signing key from the current runtime material and
/// the caller-provided base key. This is the C-side equivalent of the former
/// Swift HMAC(runtime_material, base_key_utf8) step.
/// ASLR bind (iOS device): release builds XOR slide-derived entropy into the first
/// 8 bytes of runtime material before HMAC by default. Override with
/// `CPRISK_SIGNING_KEY_ASLR_BIND=1` to force enable or `=0` to force disable.
/// Returns 0 on success, -1 on failure.
int cprisk_derive_effective_signing_key(
    const uint8_t *base_key,
    size_t base_key_len,
    uint8_t out_key[32]
);

/// Variant of cprisk_derive_effective_signing_key() that performs request-level
/// direct re-key with the full 32-byte request-binding digest:
///   derived = HMAC(runtime_material, base_key)
///   rebound = HMAC(derived, request_binding_digest)
/// Returns 0 on success, -1 on failure.
int cprisk_derive_effective_signing_key_with_request_binding_digest(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t request_binding_digest[32],
    uint8_t out_key[32]
);

/// Same derivation as cprisk_derive_effective_signing_key(), but hex-encodes
/// the resulting 32-byte key into out_hex (64 chars + trailing NUL).
/// Returns 0 on success, -1 on failure.
int cprisk_derive_effective_signing_key_hex(
    const uint8_t *base_key,
    size_t base_key_len,
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
);

/// Generic HMAC-SHA256 helper that writes lower-case hex into out_hex
/// (64 chars + trailing NUL). Returns 0 on success, -1 on failure.
int cprisk_hmac_sha256_hex(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *msg,
    size_t msg_len,
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
);

/// Derive the effective signing key from runtime material inside C, then HMAC
/// the supplied message and return the lower-case hex digest in out_hex.
/// This is the preferred bridge for v2a-style envelope signing because Swift
/// no longer needs to hold runtime_material or perform the derivation itself.
/// Returns 0 on success, -1 on failure.
int cprisk_sign_with_derived_key(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
);

/// Same helper pipeline as cprisk_sign_with_derived_key(), but first direct
/// re-keys the effective key with a full 32-byte request-binding digest.
/// Returns 0 on success, -1 on failure.
int cprisk_sign_with_derived_key_and_request_binding_digest(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t request_binding_digest[32],
    char out_hex[CPRISK_ARMOR_HEX_ENCODED_HASH_SIZE + 1]
);

/// Same helper pipeline as cprisk_sign_with_derived_key(), but compares the
/// computed hex digest with expected_hex in constant time.
/// Returns 0 on success (match), -1 on mismatch or failure.
int cprisk_verify_with_derived_key(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    const char *expected_hex
);

/// Same helper pipeline as
/// cprisk_sign_with_derived_key_and_request_binding_digest(), but compares the
/// computed hex digest with expected_hex in constant time.
/// Returns 0 on success (match), -1 on mismatch or failure.
int cprisk_verify_with_derived_key_and_request_binding_digest(
    const uint8_t *base_key,
    size_t base_key_len,
    const uint8_t *msg,
    size_t msg_len,
    const uint8_t request_binding_digest[32],
    const char *expected_hex
);

/* ── Hybrid Key Derivation (Three-Layer KDF) ───────────────────────── */

/* Initialize the three-layer Hybrid KDF from the root key.
 * Layer 2: deviceKey     = HMAC(rootKey, deviceSalt)
 * Layer 3: effectiveRoot  = HMAC(deviceKey, sessionToken)
 * Populates internal state consumed by white-box domains 6-9.
 * Call after cprisk_init_protection() or as part of its flow.
 * Returns 0 on success, -1 on invalid input. */
int cprisk_init_hybrid_kdf(const uint8_t *root_key);

/* Derive the Layer-2 device key from the root key.
 * deviceKey = HMAC(rootKey, deviceSalt)
 * Salt is sourced from IOKit/Keychain when available; static fallback otherwise.
 * Returns 0 on success, -1 on invalid input. */
int cprisk_derive_device_key(const uint8_t *root_key,
                             uint8_t out_device_key[CPRISK_ARMOR_KEY_SIZE]);

/* Retrieve the stored device key (Layer-2).
 * Returns 0 on success (key copied to out_key), -1 if not ready. */
int cprisk_get_device_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]);

/* Retrieve the effective root key (Layer-3 effectiveRoot).
 * This is the key used for white-box domains 6-9 derivations.
 * Returns 0 on success (key copied to out_key), -1 if not ready. */
int cprisk_get_effective_root(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]);

/* Returns 1 when a real (non-fallback) hardware salt is in use, 0 otherwise. */
int cprisk_is_device_bound(void);

/* ── Session Token Management ─────────────────────────────────────── */

/* Install a session token for Layer-3 key derivation.
 * Accepted formats:
 *   - legacy: 32-byte raw token
 *   - signed: [32-byte token_data][32-byte HMAC(token_data)]
 * Returns 0 on success, -1 on invalid token or HMAC mismatch. */
int cprisk_set_session_token(const uint8_t *token, size_t token_len);

/* Retrieve the session key (Layer-3) for composing effectiveRoot.
 * Returns 0 on success (session key copied to out_key), -1 if no
 * valid session token is active. */
int cprisk_get_session_key(uint8_t out_key[CPRISK_ARMOR_KEY_SIZE]);

/* Returns 1 if a valid, non-expired session token is installed, 0 otherwise. */
int cprisk_has_session_token(void);

/* Wipe the installed session token from memory. */
void cprisk_clear_session_token(void);

/* ── Anti-Dump Memory Protection ───────────────────────────────────── */

/* Start the anti-dump active defense probe thread.
 * Polls every `interval_seconds` (minimum 1; 0 uses the default of 5).
 * Scans VM regions for shared/RWX mappings and checks dylibs for injection
 * frameworks (Frida, Cycript, etc.). On detection, activates deception mode.
 * Thread runs detached; safe to call multiple times (idempotent).
 * Returns 0 on success, -1 on thread creation failure. */
int cprisk_start_anti_dump_probe(int interval_seconds);

/* Request the anti-dump probe thread to stop.
 * Safe to call even if the thread was never started. */
void cprisk_stop_anti_dump_probe(void);

/* ── Runtime Integrity Re-check ────────────────────────────────────── */

/// Re-compute __TEXT.__text hash and compare with the value saved at init.
/// Returns 0 if integrity is intact, 1 if tampered (poison flag set),
/// -1 if no saved hash, -2 on computation error.
/// Does NOT crash; sets an internal poison flag readable via
/// cprisk_is_integrity_poisoned().
int cprisk_recheck_integrity(void);

/// Returns 1 if integrity re-check detected tampering, 0 otherwise.
/// When deception mode is active, this may intentionally return 0 to avoid
/// surfacing a direct local oracle to higher layers.
int cprisk_is_integrity_poisoned(void);

/// Per-lane integrity poison entry points: same high-level outcome (runtime material poisoned)
/// but distinct bookkeeping, lane-specific deception XOR windows, and epoch/cause-mix state;
/// decoy \c cprisk_get_runtime_material bytes are further XOR-mixed from that state.
/// `evt_a` / `evt_b` remain for compatibility, but new internal call sites should prefer
/// domain-specific lanes below so semantics do not collapse into two generic buckets.
void cprisk_integrity_poison_evt_a(void);
void cprisk_integrity_poison_evt_b(void);
/// Domain-specific lanes (preferred over \c cprisk_force_integrity_poison for new call sites).
void cprisk_integrity_poison_watchdog_lane(void);
void cprisk_integrity_poison_code_signing_lane(void);
void cprisk_integrity_poison_svc_iface_lane(void);
void cprisk_integrity_poison_antidebug_lane(void);
void cprisk_integrity_poison_exception_lane(void);
void cprisk_integrity_poison_anti_dump_lane(void);
void cprisk_integrity_poison_data_loader_lane(void);
void cprisk_integrity_poison_text_encrypt_lane(void);
void cprisk_integrity_poison_whitebox_lane(void);
void cprisk_integrity_poison_cff_lane(void);

/// XOR-folded bookkeeping fingerprint for integrity poison lanes (diagnostics / future policy).
/// Returns 0 while deception mode is active, matching \c cprisk_is_integrity_poisoned().
uint32_t cprisk_get_integrity_poison_semantic_breadcrumb(void);

enum {
    CPRISK_POISON_LANE_EVT_A = 0,
    CPRISK_POISON_LANE_EVT_B = 1,
    CPRISK_POISON_LANE_FORCE = 2,
    CPRISK_POISON_LANE_GUARD = 3,
    /** Internal integrity re-check failures (PAC/MTE/hash) — distinct from evt_a/evt_b call sites. */
    CPRISK_POISON_LANE_RECHECK = 4,
    /** Anti-debug watchdog and related C-layer enforcement. */
    CPRISK_POISON_LANE_WATCHDOG = 5,
    /** App signing / Team ID / identity checks (Swift or policy-driven). */
    CPRISK_POISON_LANE_CODE_SIGNING = 6,
    /** PAC / SVC / signed indirect call interface failures. */
    CPRISK_POISON_LANE_SVC_IFACE = 7,
    /** Anti-debug plan, trace cross-checks, runtime gate, and anti-debug policy escalation. */
    CPRISK_POISON_LANE_ANTIDEBUG = 8,
    /** Exception-port fingerprint drift / hijack races distinct from generic anti-debug probes. */
    CPRISK_POISON_LANE_EXCEPTION = 9,
    /** Anti-dump VM scan / dylib injection / task-for-pid escalation probes. */
    CPRISK_POISON_LANE_ANTI_DUMP = 10,
    /** Data-segment loader and JIT-decrypt protection path failures. */
    CPRISK_POISON_LANE_DATA_LOADER = 11,
    /** Text-segment page encryption / re-encrypt / poison transitions. */
    CPRISK_POISON_LANE_TEXT_ENCRYPT = 12,
    /** White-box PRF evaluation / verification failures. */
    CPRISK_POISON_LANE_WHITEBOX = 13,
    /** Control-flow flattening default poison path. */
    CPRISK_POISON_LANE_CFF = 14,
    CPRISK_POISON_LANE_COUNT = 15,
};

/// Event count for the given lane (see \c CPRISK_POISON_LANE_*).
/// Returns 0 while deception mode is active to avoid exposing a local oracle.
uint32_t cprisk_get_integrity_poison_lane_event_count(unsigned lane);

/// Monotonic poison-wave counter (incremented on every poison side-effect batch).
/// Returns 0 while deception mode is active to avoid exposing a local oracle.
uint32_t cprisk_get_integrity_poison_epoch(void);

/// Fingerprint of which lanes fired and in what order (not only evt_a vs evt_b).
/// Returns 0 while deception mode is active to avoid exposing a local oracle.
uint64_t cprisk_get_integrity_poison_cause_mix(void);

/// Aggregate integrity poison: applies EVT_A + EVT_B + FORCE lane bookkeeping in one call.
/// Prefer domain lanes (\c cprisk_integrity_poison_watchdog_lane, etc.) so semantics are not
/// routed through a single externally-visible symbol.
void cprisk_force_integrity_poison(void);

/// Guard-page (memory trap) access: deception + integrity poison + watchdog anomaly bit.
void cprisk_guard_page_fault_notify(void);

/// Returns 1 if any security-critical mprotect call failed (kernel-level
/// interference or syscall hook), 0 otherwise. Checked by Swift layer
/// during evaluate() to surface the tamper signal.
int cprisk_is_mprotect_tampered(void);

/// Returns how many direct mprotect syscall attempts failed.
uint32_t cprisk_get_mprotect_direct_failure_count(void);

/// Returns how many times libc mprotect fallback succeeded after direct failure.
uint32_t cprisk_get_mprotect_fallback_success_count(void);

/// Current consecutive "full failure" streak (direct failed and libc failed or absent).
uint32_t cprisk_get_mprotect_consecutive_full_fail_streak(void);

/// Effective fail-streak threshold (see CPRISK_MPROTECT_FULL_FAIL_STREAK_THRESHOLD).
uint32_t cprisk_get_mprotect_fail_streak_threshold(void);

/// Test-only: force the direct syscall path to report failure without calling it.
void cprisk_test_mprotect_set_force_direct_fail(int enabled);

/// Test-only: force the libc mprotect fallback to report failure without calling it.
void cprisk_test_mprotect_set_force_fallback_fail(int enabled);

/// Test-only: set consecutive full-failure threshold (0 restores compile default).
void cprisk_test_mprotect_set_fail_streak_threshold(uint32_t threshold);

/// Test-only: reset tamper flag, counters, streak, threshold override, and injection flags.
void cprisk_test_mprotect_reset_tamper_state(void);

/* ── Per-Section Chained Key Derivation ─────────────────────────── */

/// Returns 1 if chained per-section keys are active (v3 entries were processed),
/// 0 if running in legacy v2 mode with the global loader key.
int cprisk_get_chain_status(void);

/// Return wall-clock nanoseconds spent in cprisk_init_protection().
uint64_t cprisk_get_init_elapsed_ns(void);

/// Current suspicious-init threshold (nanoseconds), after device-tier slack and mode.
/// Use for diagnostics/tests; compares against \c cprisk_get_init_elapsed_ns().
uint64_t cprisk_get_init_timing_threshold_ns(void);

/// Check if cprisk_init_protection() took suspiciously long (device-tiered; not a fixed 5s).
/// A DBI tool (e.g. Frida Stalker) slows execution 10-100x, pushing init
/// well beyond the normal sub-second range.
/// Returns 1 if suspicious, 0 otherwise.
int cprisk_check_init_timing(void);

/// Test-only: override init-timing threshold (0 = disable, use live computation).
void cprisk_test_set_init_timing_threshold_ns_override(uint64_t threshold_ns);

/// Test-only: compute threshold from a synthetic hw.machine string (no sysctl).
uint64_t cprisk_test_init_timing_threshold_ns_for_machine(
    const char *machine,
    cprisk_runtime_hardening_mode_t mode
);

/// Thin wrapper around cprisk_secure_zero() exposed for testing.
void cprisk_test_secure_zero(void *buf, size_t len);

/// Inject a test-only white-box bundle so runtime probe/available/evaluate
/// paths can exercise the real validator without requiring the current test
/// process image to be linked with reserved white-box sections.
/// The function copies all four buffers and owns them until
/// cprisk_test_clear_whitebox_bundle() is called.
/// Returns 0 on success, -1 on invalid input or allocation failure.
int cprisk_test_set_whitebox_bundle(
    const uint8_t *meta,
    size_t meta_len,
    const uint8_t *code,
    size_t code_len,
    const uint8_t *data,
    size_t data_len,
    const uint8_t *tag,
    size_t tag_len
);

/// Clear the injected test-only white-box bundle and restore normal runtime
/// behavior that reads white-box sections from the current image.
void cprisk_test_clear_whitebox_bundle(void);

/// Test-only switch to force white-box recompute mismatch in
/// cprisk_whitebox_evaluate_domain(), used to verify poison/fail-closed behavior.
void cprisk_test_set_whitebox_recompute_mismatch(int enabled);

/// Test-only: mirror PRF input preparation for domain 6-9 effectiveRoot binding
/// (SHA256 when hybrid KDF has run; else identity). Domains 1-5 copy input.
/// Returns 0 on success, -1 on invalid out pointer.
int cprisk_test_whitebox_prepare_domain_input(
    uint32_t domain_id,
    const uint8_t input[32],
    uint8_t out[32]
);

/// Test-only: inject an anti-debug plan payload for parser/policy verification.
/// The runtime copies and owns the plan bytes until cprisk_test_clear_antidebug_plan().
/// Returns 0 on success, -1 on invalid input or allocation failure.
int cprisk_test_set_antidebug_plan(
    const uint8_t *plan,
    size_t plan_len
);

/// Test-only: clear the injected anti-debug plan payload.
void cprisk_test_clear_antidebug_plan(void);

/* ── Image address check (dladdr-free) ───────────────────────────────── */

/// Returns 1 if addr is within any loaded image's segment, 0 otherwise.
/// Uses task_info + dyld_all_image_infos; does not call dladdr or _dyld_*.
/// Resistant to dladdr hook used to hide anonymous memory (e.g. Frida Stalker JIT).
int cprisk_addr_in_any_image(const void *addr);

/* ── Frida / Gum runtime hints (dyld image paths, dlsym, proc table) ─ */

enum {
    CPRISK_FRIDA_RT_IMAGE = 1u << 0,
    CPRISK_FRIDA_RT_DLSYM = 1u << 1,
    CPRISK_FRIDA_RT_PROC = 1u << 2,
};

typedef struct cprisk_frida_runtime_snapshot {
    uint32_t supported;
    uint32_t flags;
    uint32_t image_hit_count;
    uint32_t dlsym_hit_count;
    uint32_t proc_hit_count;
} cprisk_frida_runtime_snapshot_t;

/// Populate runtime Frida/Gum hints. On simulator, `supported` is 0.
/// Returns 0 on success, -1 when `out` is NULL.
int cprisk_frida_runtime_snapshot(cprisk_frida_runtime_snapshot_t *out);
#define CPRISK_FRIDA_RUNTIME_SNAPSHOT_DECLARED 1

/// Decode a short literal using SHA256(label) as a repeating XOR mask (v1).
/// Sensitive keywords are not stored as contiguous ASCII in the binary.
/// Returns 0 on success, -1 on invalid input.
int cprisk_obf_decode_sha256_label(
    const char *label,
    size_t label_len,
    const uint8_t *enc,
    size_t enc_len,
    char *out,
    size_t out_sz
);

/** v2: mask = SHA256(le32(domain) || le32(key_id)) — no searchable ASCII label constant. */
int cprisk_obf_decode_sha256_tag(
    uint32_t domain,
    uint32_t key_id,
    const uint8_t *enc,
    size_t enc_len,
    char *out,
    size_t out_sz
);

#define CPRISK_OBF_TAG_DOMAIN_FRIDA_RT 0xC0A11901u
#define CPRISK_OBF_TAG_DOMAIN_WD_DYLD 0xC0A11902u
#define CPRISK_OBF_TAG_DOMAIN_ANTI_DUMP 0xC0A11903u
#define CPRISK_OBF_TAG_DOMAIN_SIGNAL_DBI 0xC0A11904u

/// Mach VM cross-check counters after `cprisk_armor_vm_protect` / hidden mprotect.
uint32_t cprisk_get_vm_mprotect_crosscheck_mismatch_count(void);
uint32_t cprisk_get_vm_mprotect_mach_trap_mismatch_count(void);

/// Snapshot + periodic verify for critical `svc #0x80` syscall templates.
/// Returns a bitmask: bit0 = syscall6, bit1 = deny-attach, bit2 = syscall0 (each 1 = failure).
uint32_t cprisk_verify_svc_stub_integrity(void);

/// Constant-time compare of one raw SHA-256 digest against a packed pinset buffer.
/// `packed_pins` must contain `pin_count * 32` bytes.
/// Returns 1 on match, 0 on no match, -1 on invalid input.
int cprisk_pinset_contains_sha256_digest(
    const uint8_t *candidate_digest,
    size_t candidate_len,
    const uint8_t *packed_pins,
    size_t pin_count
);

/// arm64: returns 1 if [fn, fn+len) contains at least one A64 `svc` opcode (Darwin syscall ABI).
int cprisk_stub_contains_svc_opcode(const void *fn, size_t len);

/* ── Signal Probe Bitmask ──────────────────────────────────────────── */

enum {
    CPRISK_PROBE_SIGNAL_TRAP       = 1u << 0,
    CPRISK_PROBE_HARDWARE_BP       = 1u << 1,
    CPRISK_PROBE_SOFTWARE_BP       = 1u << 2,
    CPRISK_PROBE_TTY               = 1u << 3,
    CPRISK_PROBE_CSOPS             = 1u << 4,
    CPRISK_PROBE_SINGLE_STEP       = 1u << 5,
    CPRISK_PROBE_SUSPICIOUS_THREAD = 1u << 6,
    CPRISK_PROBE_DEVELOPER_DISK    = 1u << 7,
    CPRISK_PROBE_EXCEPTION_DELIVERY_TIMEOUT = 1u << 8,
    CPRISK_PROBE_DBI_MARKER        = 1u << 9,
    CPRISK_PROBE_TIMING_ANOMALY    = 1u << 10,
    CPRISK_PROBE_THREAD_EXCEPTION_PORT = 1u << 11,
    CPRISK_PROBE_TRACE_CROSSCHECK  = 1u << 12,
    /** mov x0,x0; ret / nop; ret style patches at function prefix (key symbols only). */
    CPRISK_PROBE_INSTANT_RETURN_PATCH = 1u << 13,
};

enum {
    CPRISK_BRK_IMM_SIGNAL_PROBE = 0xC0DEu,
    CPRISK_BRK_IMM_EXCEPTION_DELIVERY_PROBE = 0xC0DFu,
    CPRISK_BRK_IMM_RUNTIME_GATE = 0xC0E0u,
};

enum {
    CPRISK_DBI_MARKER_ENV = 1u << 0,
    CPRISK_DBI_MARKER_IMAGE = 1u << 1,
    CPRISK_DBI_MARKER_THREAD = 1u << 2,
    /** Full-process environ scan matched a DBI/QBDI substring (supplements named-key checks). */
    CPRISK_DBI_MARKER_ENVIRON_SCAN = 1u << 3,
    /** Current task exposes writable+executable code regions typical of DBI/JIT code caches. */
    CPRISK_DBI_MARKER_EXEC_WRITE = 1u << 4,
};

enum {
    CPRISK_TIMING_ANOMALY_MEDIAN = 1u << 0,
    CPRISK_TIMING_ANOMALY_SPIKE = 1u << 1,
    CPRISK_TIMING_ANOMALY_JITTER = 1u << 2,
    CPRISK_TIMING_ANOMALY_CLOCK_SKEW = 1u << 3,
    /** CNTPCT_EL0 delta vs mach_absolute_time delta around the same workload disagree (DBI / time virtualization). */
    CPRISK_TIMING_ANOMALY_DUAL_CLOCK_DRIFT = 1u << 4,
    /** Internal SHA-256/HMAC sentinel observed gross slowdown consistent with DBI / Stalker / QBDI trace amplification. */
    CPRISK_TIMING_ANOMALY_CRYPTO_TRACE = 1u << 5,
    /** Crypto-trace CNTPCT vs Mach skew on the same workload (see cprisk_crypto_trace). */
    CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_SKEW = 1u << 6,
    /** Deterministic crypto-trace workload digest mismatch. */
    CPRISK_TIMING_ANOMALY_CRYPTO_TRACE_INVARIANT = 1u << 7,
};

/// Probe debugger presence via SIGTRAP signal delivery after BRK #0xC0DE.
/// Returns 1 if a debugger intercepted the exception, 0 otherwise.
int cprisk_probe_debugger_via_signal(void);

/// Detect active hardware breakpoints/watchpoints via ARM debug registers.
/// Returns the number of enabled HW breakpoint/watchpoint slots found.
int cprisk_detect_hardware_breakpoints(void);

/// Detect threads that have per-thread EXC_BREAKPOINT/EXC_BAD_ACCESS ports
/// different from the task-level handler (indicative of debugger hijack).
/// Returns the number of mismatched threads found.
int cprisk_detect_thread_exception_ports(void);

/// Scan a memory region for software BRK instructions (excluding our own).
/// Returns the number of foreign BRK instructions found.
int cprisk_scan_software_breakpoints(const void *func_ptr, size_t size);

/// Scan only the first \p prefix_bytes (min 8) of \p func_ptr for ARM64
/// instant-return patches: two-word sequences such as `mov x0, x0; ret`,
/// `nop; ret`, or `mov w0, w0; ret` at offset 0. Returns 1 if a match is found, else 0.
int cprisk_scan_arm64_instant_return_nop_patch_prefix(const void *func_ptr, size_t prefix_bytes);

/// Prefix-only scan of the same high-value symbols as the anti-debug watchdog
/// (deny-attach, signal probes, exception-handler helpers). Returns the number
/// of symbols whose entry matches an instant-return patch pattern.
int cprisk_scan_instant_return_key_symbols_prefix(void);

/// Randomly sample executable __TEXT sections for software BRK instructions.
/// Returns the number of foreign BRK instructions found.
int cprisk_scan_software_breakpoints_randomized_text(
    size_t sample_windows,
    size_t window_size
);

/// Trigger a reserved breakpoint handled by our Mach exception port and flag
/// suspicious delivery latency or fallback signal delivery.
int cprisk_probe_exception_delivery_timeout(void);

/// Detect if stdout is connected to a debug TTY (/dev/ttys* or /dev/pts*).
/// Returns 1 if a debug terminal is detected, 0 otherwise.
int cprisk_detect_tty_debug(void);

/// Check the CS_DEBUGGED codesign flag via direct csops syscall.
/// Returns 1 if the process is marked as debugged, 0 otherwise.
int cprisk_csops_debug_check(void);

/// Read full csops CS_OPS_STATUS flags (0 on simulator / failure). Returns 0 on success.
int cprisk_csops_status_flags(uint32_t *flags_out, int *error_out);

enum {
    CPRISK_DENY_ATTACH_VERIFY_FLAG_MISMATCH = 1u << 0,
    CPRISK_DENY_ATTACH_VERIFY_SELF_PID_MISMATCH = 1u << 1,
    CPRISK_DENY_ATTACH_VERIFY_LIBC_DIRECT_DIVERGENCE = 1u << 2,
    CPRISK_DENY_ATTACH_VERIFY_PID_MISMATCH = 1u << 3,
    CPRISK_DENY_ATTACH_VERIFY_SIZE_MISMATCH = 1u << 4,
    CPRISK_DENY_ATTACH_VERIFY_TRACE_FLAG_SET = 1u << 5,
};

/// After a successful deny_attach syscall, re-validate sysctl proc state consistency.
/// Returns non-zero if the post-check looks suspicious (hooks / unstable state).
int cprisk_deny_attach_effective_verify(int deny_attach_rc, int deny_attach_errno, uint32_t *detail_bits_out);

/// Aggregate AMFI / entitlement-oriented probes for the watchdog snapshot.
/// Writes cs flags, get-task-allow suspicion (0/1), and anomaly category bits.
void cprisk_amfi_entitlement_watchdog_probe(
    uint32_t *cs_flags_out,
    uint32_t *get_task_allow_suspect_out,
    uint32_t *amfi_anomaly_bits_out
);

/// Detect single-stepping by timing ~100 arithmetic instructions.
/// Returns 1 if execution took suspiciously long (>50ms), 0 otherwise.
int cprisk_detect_single_stepping(void);

/// Enumerate Mach threads and check if any PC falls outside known images.
/// Returns the count of suspicious threads (0 = normal).
int cprisk_detect_suspicious_threads(void);

/// Check for Developer Disk Image paths (debugserver, libMainThreadChecker).
/// Returns 1 if any developer tool path is accessible, 0 otherwise.
int cprisk_detect_developer_disk(void);

/// Detect DBI footprints (Pin/DynamoRIO/Valgrind/QBDI) via env/image/thread markers
/// plus a bounded full-environ substring scan.
/// Returns the number of matched markers in the current process view.
int cprisk_detect_dbi_markers(void);

/// Return DBI marker category bits (CPRISK_DBI_MARKER_*).
uint32_t cprisk_get_last_dbi_marker_flags(void);

/// Return the last DBI marker hit count.
int cprisk_get_last_dbi_marker_hit_count(void);

/// Return timing anomaly category bits (CPRISK_TIMING_ANOMALY_*).
uint32_t cprisk_get_last_timing_anomaly_flags(void);

/// Return the latest timing probe median/max/threshold in nanoseconds.
uint64_t cprisk_get_last_timing_probe_median_ns(void);
uint64_t cprisk_get_last_timing_probe_max_ns(void);
uint64_t cprisk_get_last_timing_probe_threshold_ns(void);

/// Run all signal probes and return a bitmask of CPRISK_PROBE_* flags.
uint32_t cprisk_run_all_signal_probes(void);

/// Returns 1 when CNTPCT_EL0 hardware monotonic clock path is available.
int cprisk_is_cntpct_clock_available(void);

#ifdef __cplusplus
}
#endif

#endif /* CRiskCore_h */
