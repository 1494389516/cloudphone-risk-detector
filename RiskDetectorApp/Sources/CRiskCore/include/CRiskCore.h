#ifndef CRiskCore_h
#define CRiskCore_h

#include <stddef.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

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

#ifdef __cplusplus
}
#endif

#endif /* CRiskCore_h */
