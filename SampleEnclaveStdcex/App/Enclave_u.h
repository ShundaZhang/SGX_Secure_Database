#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "dirent.h"
#include "stdio.h"
#include "time.h"
#include "fcntl.h"
#include "pwd.h"
#include "grp.h"
#include "netdb.h"
#include "sys/time.h"
#include "sys/stat.h"
#include "sys/select.h"
#include "sys/socket.h"
#include "sys/poll.h"
#include "sys/utsname.h"
#include "sys/epoll.h"
#include "sys/types.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __iovec_t
#define __iovec_t
typedef struct _iovec_t {
	void* iov_base;
	size_t iov_len;
} _iovec_t;
#endif

#ifndef U_OPENDIR_DEFINED__
#define U_OPENDIR_DEFINED__
DIR* SGX_UBRIDGE(SGX_NOCONVENTION, u_opendir, (const char* name));
#endif
#ifndef U_READDIR_DEFINED__
#define U_READDIR_DEFINED__
struct dirent* SGX_UBRIDGE(SGX_NOCONVENTION, u_readdir, (DIR* dirp));
#endif
#ifndef U_REWINDDIR_DEFINED__
#define U_REWINDDIR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_rewinddir, (DIR* dirp));
#endif
#ifndef U_CLOSEDIR_DEFINED__
#define U_CLOSEDIR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_closedir, (DIR* dirp));
#endif
#ifndef U_TELLDIR_DEFINED__
#define U_TELLDIR_DEFINED__
long int SGX_UBRIDGE(SGX_NOCONVENTION, u_telldir, (DIR* dirp));
#endif
#ifndef U_SEEKDIR_DEFINED__
#define U_SEEKDIR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_seekdir, (DIR* dirp, long int loc));
#endif
#ifndef U_GETDENTS64_DEFINED__
#define U_GETDENTS64_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_getdents64, (unsigned int fd, struct dirent* dirp, unsigned int count));
#endif
#ifndef U_FCNTL_DEFINED__
#define U_FCNTL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fcntl, (int fd, int cmd, int arg, uint64_t argsize, void* argout));
#endif
#ifndef U_OPEN_DEFINED__
#define U_OPEN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_open, (const char* pathname, int flags, mode_t mode));
#endif
#ifndef U_OPENAT_DEFINED__
#define U_OPENAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_openat, (int dirfd, const char* pathname, int flags, mode_t mode));
#endif
#ifndef U_STAT_DEFINED__
#define U_STAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_stat, (const char* pathname, struct stat* buf));
#endif
#ifndef U_LSTAT_DEFINED__
#define U_LSTAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_lstat, (const char* pathname, struct stat* buf));
#endif
#ifndef U_FSTAT_DEFINED__
#define U_FSTAT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fstat, (int fd, struct stat* buf));
#endif
#ifndef U_MKDIR_DEFINED__
#define U_MKDIR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_mkdir, (const char* pathname, mode_t mode));
#endif
#ifndef U_FCHMOD_DEFINED__
#define U_FCHMOD_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fchmod, (int fd, mode_t mode));
#endif
#ifndef U_SOCKET_DEFINED__
#define U_SOCKET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_socket, (int domain, int type, int protocol));
#endif
#ifndef U_BIND_DEFINED__
#define U_BIND_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_bind, (int fd, const struct sockaddr* addr, socklen_t len));
#endif
#ifndef U_LISTEN_DEFINED__
#define U_LISTEN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_listen, (int fd, int n));
#endif
#ifndef U_ACCEPT_DEFINED__
#define U_ACCEPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_accept, (int fd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out));
#endif
#ifndef U_CONNECT_DEFINED__
#define U_CONNECT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_connect, (int fd, const struct sockaddr* addr, socklen_t len));
#endif
#ifndef U_SEND_DEFINED__
#define U_SEND_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_send, (int fd, const void* buf, size_t n, int flags));
#endif
#ifndef U_SENDTO_DEFINED__
#define U_SENDTO_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sendto, (int fd, const void* buf, size_t n, int flags, const struct sockaddr* addr, socklen_t addr_len));
#endif
#ifndef U_SENDMSG_DEFINED__
#define U_SENDMSG_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_sendmsg, (int sockfd, const struct msghdr* msg, int flags));
#endif
#ifndef U_RECV_DEFINED__
#define U_RECV_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_recv, (int fd, void* buf, size_t n, int flags));
#endif
#ifndef U_RECVFROM_DEFINED__
#define U_RECVFROM_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_recvfrom, (int fd, void* buf, size_t n, int flags, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out));
#endif
#ifndef U_RECVMSG_DEFINED__
#define U_RECVMSG_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_recvmsg, (int sockfd, struct msghdr* msg, int flags));
#endif
#ifndef U_GETSOCKOPT_DEFINED__
#define U_GETSOCKOPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_getsockopt, (int fd, int level, int optname, void* optval, socklen_t optlen_in, socklen_t* optlen_out));
#endif
#ifndef U_SETSOCKOPT_DEFINED__
#define U_SETSOCKOPT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_setsockopt, (int fd, int level, int optname, const void* optval, socklen_t optlen));
#endif
#ifndef U_POLL_DEFINED__
#define U_POLL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_poll, (struct pollfd* fds, nfds_t nfds, int timeout));
#endif
#ifndef U_SELECT_DEFINED__
#define U_SELECT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_select, (int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout));
#endif
#ifndef U_GETSOCKNAME_DEFINED__
#define U_GETSOCKNAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_getsockname, (int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out));
#endif
#ifndef U_GETPEERNAME_DEFINED__
#define U_GETPEERNAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_getpeername, (int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out));
#endif
#ifndef U_SOCKETPAIR_DEFINED__
#define U_SOCKETPAIR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_socketpair, (int domain, int type, int protocol, int retfd[2]));
#endif
#ifndef U_SHUTDOWN_DEFINED__
#define U_SHUTDOWN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_shutdown, (int sockfd, int how));
#endif
#ifndef U_REALPATH_DEFINED__
#define U_REALPATH_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, u_realpath, (const char* path));
#endif
#ifndef U_FPRINTF_DEFINED__
#define U_FPRINTF_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_fprintf, (FILE* stream, const char* str, size_t maxlen));
#endif
#ifndef U_FGETS_DEFINED__
#define U_FGETS_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, u_fgets, (char* s, int size, FILE* stream));
#endif
#ifndef U_FOPEN_DEFINED__
#define U_FOPEN_DEFINED__
FILE* SGX_UBRIDGE(SGX_NOCONVENTION, u_fopen, (const char* pathname, const char* mode));
#endif
#ifndef U_FDOPEN_DEFINED__
#define U_FDOPEN_DEFINED__
FILE* SGX_UBRIDGE(SGX_NOCONVENTION, u_fdopen, (int fd, const char* mode));
#endif
#ifndef U_FCLOSE_DEFINED__
#define U_FCLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fclose, (FILE* stream));
#endif
#ifndef U_FREAD_DEFINED__
#define U_FREAD_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fread, (void* ptr, size_t size, size_t nmemb, FILE* stream));
#endif
#ifndef U_FWRITE_DEFINED__
#define U_FWRITE_DEFINED__
size_t SGX_UBRIDGE(SGX_NOCONVENTION, u_fwrite, (const void* ptr, size_t size, size_t nmemb, FILE* stream));
#endif
#ifndef U_REWIND_DEFINED__
#define U_REWIND_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_rewind, (FILE* stream));
#endif
#ifndef U_FFLUSH_DEFINED__
#define U_FFLUSH_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fflush, (FILE* stream));
#endif
#ifndef U_CLEARERR_DEFINED__
#define U_CLEARERR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_clearerr, (FILE* stream));
#endif
#ifndef U_FEOF_DEFINED__
#define U_FEOF_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_feof, (FILE* stream));
#endif
#ifndef U_FERROR_DEFINED__
#define U_FERROR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_ferror, (FILE* stream));
#endif
#ifndef U_FILENO_DEFINED__
#define U_FILENO_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fileno, (FILE* stream));
#endif
#ifndef U_GETLINE_DEFINED__
#define U_GETLINE_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_getline, (char** lineptr, size_t* n, FILE* stream));
#endif
#ifndef U_GETDELIM_DEFINED__
#define U_GETDELIM_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_getdelim, (char** lineptr, size_t* n, int delim, FILE* stream));
#endif
#ifndef U_MALLOC_DEFINED__
#define U_MALLOC_DEFINED__
void* SGX_UBRIDGE(SGX_NOCONVENTION, u_malloc, (size_t size));
#endif
#ifndef U_FREE_DEFINED__
#define U_FREE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_free, (void* ptr));
#endif
#ifndef U_UNAME_DEFINED__
#define U_UNAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_uname, (struct utsname* buf));
#endif
#ifndef U_EPOLL_CREATE1_DEFINED__
#define U_EPOLL_CREATE1_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_epoll_create1, (int flags));
#endif
#ifndef U_EPOLL_WAIT_DEFINED__
#define U_EPOLL_WAIT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_epoll_wait, (int epfd, struct epoll_event* events, unsigned int maxevents, int timeout));
#endif
#ifndef U_EPOLL_CTL_DEFINED__
#define U_EPOLL_CTL_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_epoll_ctl, (int epfd, int op, int fd, struct epoll_event* event));
#endif
#ifndef U_MOUNT_DEFINED__
#define U_MOUNT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_mount, (const char* source, const char* target, const char* filesystemtype, unsigned long int mountflags));
#endif
#ifndef U_UMOUNT2_DEFINED__
#define U_UMOUNT2_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_umount2, (const char* target, int flags));
#endif
#ifndef U_GETHOSTNAME_DEFINED__
#define U_GETHOSTNAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_gethostname, (char* name, size_t len));
#endif
#ifndef U_GETDOMAINNAME_DEFINED__
#define U_GETDOMAINNAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_getdomainname, (char* name, size_t len));
#endif
#ifndef U_GETCWD_DEFINED__
#define U_GETCWD_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, u_getcwd, (char* buf, size_t size));
#endif
#ifndef U_CHDIR_DEFINED__
#define U_CHDIR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_chdir, (const char* path));
#endif
#ifndef U_NANOSLEEP_DEFINED__
#define U_NANOSLEEP_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_nanosleep, (struct timespec* req, struct timespec* rem));
#endif
#ifndef U_CLOCK_NANOSLEEP_DEFINED__
#define U_CLOCK_NANOSLEEP_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_clock_nanosleep, (clockid_t clockid, int flag, struct timespec* req, struct timespec* rem));
#endif
#ifndef U_GETPID_DEFINED__
#define U_GETPID_DEFINED__
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, u_getpid, (void));
#endif
#ifndef U_GETPPID_DEFINED__
#define U_GETPPID_DEFINED__
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, u_getppid, (void));
#endif
#ifndef U_GETPGRP_DEFINED__
#define U_GETPGRP_DEFINED__
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, u_getpgrp, (void));
#endif
#ifndef U_GETUID_DEFINED__
#define U_GETUID_DEFINED__
uid_t SGX_UBRIDGE(SGX_NOCONVENTION, u_getuid, (void));
#endif
#ifndef U_GETEUID_DEFINED__
#define U_GETEUID_DEFINED__
uid_t SGX_UBRIDGE(SGX_NOCONVENTION, u_geteuid, (void));
#endif
#ifndef U_GETGID_DEFINED__
#define U_GETGID_DEFINED__
gid_t SGX_UBRIDGE(SGX_NOCONVENTION, u_getgid, (void));
#endif
#ifndef U_GETEGID_DEFINED__
#define U_GETEGID_DEFINED__
gid_t SGX_UBRIDGE(SGX_NOCONVENTION, u_getegid, (void));
#endif
#ifndef U_GETPGID_DEFINED__
#define U_GETPGID_DEFINED__
pid_t SGX_UBRIDGE(SGX_NOCONVENTION, u_getpgid, (int pid));
#endif
#ifndef U_GETGROUPS_DEFINED__
#define U_GETGROUPS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_getgroups, (size_t size, unsigned int* list));
#endif
#ifndef U_READ_DEFINED__
#define U_READ_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_read, (int fd, void* buf, size_t count));
#endif
#ifndef U_WRITE_DEFINED__
#define U_WRITE_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_write, (int fd, const void* buf, size_t count));
#endif
#ifndef U_CLOSE_DEFINED__
#define U_CLOSE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_close, (int fd));
#endif
#ifndef U_FLOCK_DEFINED__
#define U_FLOCK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_flock, (int fd, int operation));
#endif
#ifndef U_FSYNC_DEFINED__
#define U_FSYNC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fsync, (int fd));
#endif
#ifndef U_FDATASYNC_DEFINED__
#define U_FDATASYNC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fdatasync, (int fd));
#endif
#ifndef U_FCHOWN_DEFINED__
#define U_FCHOWN_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_fchown, (int fd, unsigned int uid, unsigned int gid));
#endif
#ifndef U_DUP_DEFINED__
#define U_DUP_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_dup, (int oldfd));
#endif
#ifndef U_DUP2_DEFINED__
#define U_DUP2_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_dup2, (int oldfd, int newfd));
#endif
#ifndef U_RMDIR_DEFINED__
#define U_RMDIR_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_rmdir, (const char* pathname));
#endif
#ifndef U_LINK_DEFINED__
#define U_LINK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_link, (const char* oldpath, const char* newpath));
#endif
#ifndef U_UNLINK_DEFINED__
#define U_UNLINK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_unlink, (const char* pathname));
#endif
#ifndef U_TRUNCATE_DEFINED__
#define U_TRUNCATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_truncate, (const char* path, off_t length));
#endif
#ifndef U_FTRUNCATE_DEFINED__
#define U_FTRUNCATE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_ftruncate, (int fd, off_t length));
#endif
#ifndef U_LSEEK_DEFINED__
#define U_LSEEK_DEFINED__
off_t SGX_UBRIDGE(SGX_NOCONVENTION, u_lseek, (int fd, off_t offset, int whence));
#endif
#ifndef U_PREAD_DEFINED__
#define U_PREAD_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_pread, (int fd, void* buf, size_t count, off_t offset));
#endif
#ifndef U_PWRITE_DEFINED__
#define U_PWRITE_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_pwrite, (int fd, const void* buf, size_t count, off_t offset));
#endif
#ifndef U_READV_DEFINED__
#define U_READV_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_readv, (int fd, struct _iovec_t* iov, int iovcnt));
#endif
#ifndef U_WRITEV_DEFINED__
#define U_WRITEV_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_writev, (int fd, struct _iovec_t* iov, int iovcnt));
#endif
#ifndef U_ACCESS_DEFINED__
#define U_ACCESS_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_access, (const char* pathname, int mode));
#endif
#ifndef U_READLINK_DEFINED__
#define U_READLINK_DEFINED__
ssize_t SGX_UBRIDGE(SGX_NOCONVENTION, u_readlink, (const char* pathname, char* buf, size_t bufsize));
#endif
#ifndef U_SYSCONF_DEFINED__
#define U_SYSCONF_DEFINED__
long int SGX_UBRIDGE(SGX_NOCONVENTION, u_sysconf, (int name));
#endif
#ifndef U_RENAME_DEFINED__
#define U_RENAME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_rename, (const char* oldpath, const char* newpath));
#endif
#ifndef U_REMOVE_DEFINED__
#define U_REMOVE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_remove, (const char* pathname));
#endif
#ifndef U_GETENV_DEFINED__
#define U_GETENV_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, u_getenv, (const char* name));
#endif
#ifndef U_GETGRGID_R_DEFINED__
#define U_GETGRGID_R_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_getgrgid_r, (gid_t gid, struct group* grp, char* buf, size_t buflen, struct group** result));
#endif
#ifndef U_GETPWUID_DEFINED__
#define U_GETPWUID_DEFINED__
struct passwd* SGX_UBRIDGE(SGX_NOCONVENTION, u_getpwuid, (uid_t uid));
#endif
#ifndef U_GETPWUID_R_DEFINED__
#define U_GETPWUID_R_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_getpwuid_r, (uid_t uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result));
#endif
#ifndef U_FPATHCONF_DEFINED__
#define U_FPATHCONF_DEFINED__
long int SGX_UBRIDGE(SGX_NOCONVENTION, u_fpathconf, (int fd, int name));
#endif
#ifndef U_PATHCONF_DEFINED__
#define U_PATHCONF_DEFINED__
long int SGX_UBRIDGE(SGX_NOCONVENTION, u_pathconf, (const char* path, int name));
#endif
#ifndef U_TIME_DEFINED__
#define U_TIME_DEFINED__
time_t SGX_UBRIDGE(SGX_NOCONVENTION, u_time, (time_t* tloc));
#endif
#ifndef U_UTIMES_DEFINED__
#define U_UTIMES_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_utimes, (const char* filename, const struct timeval* times));
#endif
#ifndef U_LOCALTIME_DEFINED__
#define U_LOCALTIME_DEFINED__
struct tm* SGX_UBRIDGE(SGX_NOCONVENTION, u_localtime, (const time_t* t));
#endif
#ifndef U_GETTIMEOFDAY_DEFINED__
#define U_GETTIMEOFDAY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_gettimeofday, (struct timeval* tv));
#endif
#ifndef U_CLOCK_GETTIME_DEFINED__
#define U_CLOCK_GETTIME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_clock_gettime, (clockid_t clk_id, struct timespec* tp));
#endif
#ifndef U_GETADDRINFO_DEFINED__
#define U_GETADDRINFO_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_getaddrinfo, (const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res));
#endif
#ifndef U_FREEADDRINFO_DEFINED__
#define U_FREEADDRINFO_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_freeaddrinfo, (struct addrinfo* res));
#endif
#ifndef U_GETNAMEINFO_DEFINED__
#define U_GETNAMEINFO_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_getnameinfo, (const struct sockaddr* sa, socklen_t salen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags));
#endif
#ifndef U_GAI_STRERROR_DEFINED__
#define U_GAI_STRERROR_DEFINED__
char* SGX_UBRIDGE(SGX_NOCONVENTION, u_gai_strerror, (int errcode));
#endif
#ifndef U_SCHED_YIELD_DEFINED__
#define U_SCHED_YIELD_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, u_sched_yield, (void));
#endif

sgx_status_t ecall_printf(sgx_enclave_id_t eid);
sgx_status_t ecall_memset_s(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_fchmod(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_socket_receiver(sgx_enclave_id_t eid);
sgx_status_t ecall_socket_sender(sgx_enclave_id_t eid);
sgx_status_t ecall_time(sgx_enclave_id_t eid, int* retval);
sgx_status_t ecall_mmap(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
