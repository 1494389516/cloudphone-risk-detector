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

/// Return the current data integrity accumulator value.
uint64_t cprisk_get_data_integrity_accumulator(void);

/// Securely wipe decrypted data sections and loader state.
void cprisk_unload_protected_data(void);

/// Compute a three-path integrity hash of __TEXT.__text.
/// Path C reconstructs the 32-byte anchor digest from the four split anchor
/// sections. Writes 32 bytes to out_hash. Returns 0 on success, -1 on failure.
int cprisk_compute_integrity_hash(uint8_t *out_hash);

/// Read the full obfuscated anchor hash from the masked full-hash section.
/// Section layout is `{ mask[32], masked_hash[32] }` where
/// `masked_hash[i] = full_hash[i] ^ mask[i]`.
/// Writes 32 bytes to out_hash. Returns 0 on success, -1 on failure.
int cprisk_read_full_anchor_hash(uint8_t *out_hash);

/// Master initialization: pass1 bootstrap string → pass4 integrity/anchor
/// material → pass3 loader key derivation → decrypt protected data.
/// root_key must be non-NULL and non-zero (all-zero keys are rejected with -1
/// to prevent a predictable key chain); values longer than 32 bytes are
/// truncated. Returns 0 on success, negative on failure.
int cprisk_init_protection(const uint8_t *root_key, size_t root_key_len);

/// Cleanup all armor runtime state (keys, accumulators, decrypted data).
void cprisk_cleanup_protection(void);

/// Retrieve the 32-byte runtime material derived from the full armor init chain.
/// If armor runtime is not initialized or was tampered, out_material will be
/// filled with a per-execution random poison value (generated via arc4random_buf
/// on first use; never a public constant).
/// Always writes exactly 32 bytes to out_material. Returns 0 if material is
/// authentic (init succeeded), -1 if poisoned (init failed/skipped).
int cprisk_get_runtime_material(uint8_t out_material[32]);

/* ── Anti-Dump Memory Protection ───────────────────────────────────── */

/// Verify that the specified memory region is read-only protected.
/// Uses vm_region_64() to inspect page protection attributes.
/// Returns 1 if the region is read-only (protection valid),
/// 0 if writable or query failed (potentially tampered).
int cprisk_verify_page_protection(void *region, size_t len);

/* ── Runtime Integrity Re-check ────────────────────────────────────── */

/// Re-compute __TEXT.__text hash and compare with the value saved at init.
/// Returns 0 if integrity is intact, 1 if tampered (poison flag set),
/// -1 if no saved hash, -2 on computation error.
/// Does NOT crash; sets an internal poison flag readable via
/// cprisk_is_integrity_poisoned().
int cprisk_recheck_integrity(void);

/// Returns 1 if integrity re-check detected tampering, 0 otherwise.
int cprisk_is_integrity_poisoned(void);

/// Return wall-clock nanoseconds spent in cprisk_init_protection().
uint64_t cprisk_get_init_elapsed_ns(void);

/// Thin wrapper around cprisk_secure_zero() exposed for testing.
void cprisk_test_secure_zero(void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CRiskCore_h */
