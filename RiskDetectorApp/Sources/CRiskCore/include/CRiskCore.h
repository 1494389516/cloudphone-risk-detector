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

#ifdef __cplusplus
extern "C" {
#endif

/// Call ptrace(PT_DENY_ATTACH) to deny debugger attachment.
/// Safe to call multiple times.
void cprisk_deny_attach(void);

/// Call ptrace(PT_DENY_ATTACH) via direct syscall and surface raw errno.
/// Returns 0 on success, -1 on syscall error. When error_out is non-null,
/// it receives the raw BSD errno produced by the syscall path.
int cprisk_deny_attach_status(int *error_out);

/// Check if the current process is being traced (debugger attached).
/// Uses sysctl KERN_PROC_PID to read P_TRACED from kinfo_proc.
/// Returns 1 if traced, 0 if not traced or on query failure/simulator.
int cprisk_is_being_traced(void);

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

/// Fill a buffer with random bytes via direct syscall (SYS_getentropy).
/// Returns 0 on success, -1 on error. buflen must be <= 256.
int cprisk_getentropy_direct(void *buf, size_t buflen, int *error_out);

/// Register EXC_BREAKPOINT handler to preempt Frida/debugger from hijacking exception ports.
/// Call from CPRiskKit.start() after cprisk_deny_attach.
void cprisk_register_exception_handler(void);

/// Verify current EXC_BREAKPOINT handler is still ours; re-register if hijacked.
/// Call periodically (e.g. in evaluate() or a background check).
void cprisk_verify_exception_handler(void);

/// Finds the current image's Mach-O header in memory, makes it writable,
/// and zeroes out the magic number and key load commands to thwart memory dumping.
void cprisk_erase_macho_header(void);

/* ── cprisk-armor Runtime Support (ABI v1) ─────────────────────────── */

/// Initialize the string decryptor with a 32-byte key.
/// Returns 0 on success, -1 on failure.
int cprisk_init_string_decryptor(const uint8_t *key, size_t key_len);

/// Decrypt the string identified by string_id from
/// the packed string table section into buffer.
/// Returns decrypted byte count, -1 on failure.
/// Side-effect: updates the string integrity accumulator.
int cprisk_decrypt_string(uint32_t string_id, char *buffer, size_t buffer_size);

/// Return the current string integrity accumulator value.
uint64_t cprisk_get_string_integrity_accumulator(void);

/// Securely wipe decryption key and accumulator state.
void cprisk_cleanup_string_decryptor(void);

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
int cprisk_whitebox_evaluate_domain(
    uint32_t domain_id,
    const uint8_t input[32],
    uint8_t out[32]
);

/// Derive a 32-byte effective signing key from the current runtime material and
/// the caller-provided base key. This is the C-side equivalent of the former
/// Swift HMAC(runtime_material, base_key_utf8) step.
/// Returns 0 on success, -1 on failure.
int cprisk_derive_effective_signing_key(
    const uint8_t *base_key,
    size_t base_key_len,
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

/* ── Anti-Dump Memory Protection ───────────────────────────────────── */

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

/// Force-set the integrity poison flag from external modules
/// (e.g. when a security-critical mprotect fails).
void cprisk_force_integrity_poison(void);

/// Returns 1 if any security-critical mprotect call failed (kernel-level
/// interference or syscall hook), 0 otherwise. Checked by Swift layer
/// during evaluate() to surface the tamper signal.
int cprisk_is_mprotect_tampered(void);

/// Return wall-clock nanoseconds spent in cprisk_init_protection().
uint64_t cprisk_get_init_elapsed_ns(void);

/// Check if cprisk_init_protection() took suspiciously long (>5s).
/// A DBI tool (e.g. Frida Stalker) slows execution 10-100x, pushing init
/// well beyond the normal sub-second range.
/// Returns 1 if suspicious, 0 otherwise.
int cprisk_check_init_timing(void);

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

/* ── Image address check (dladdr-free) ───────────────────────────────── */

/// Returns 1 if addr is within any loaded image's segment, 0 otherwise.
/// Uses task_info + dyld_all_image_infos; does not call dladdr or _dyld_*.
/// Resistant to dladdr hook used to hide anonymous memory (e.g. Frida Stalker JIT).
int cprisk_addr_in_any_image(const void *addr);

#ifdef __cplusplus
}
#endif

#endif /* CRiskCore_h */
