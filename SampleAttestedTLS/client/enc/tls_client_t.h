#ifndef TLS_CLIENT_T_H__
#define TLS_CLIENT_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

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
#include "unistd.h"

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

int launch_tls_client(char* server_name, char* server_port, const char* input_file, const char* output_file);

sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len);
sgx_status_t SGX_CDECL u_sgxssl_write(ssize_t* retval, int fd, const void* buf, size_t n);
sgx_status_t SGX_CDECL u_sgxssl_read(ssize_t* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL u_sgxssl_close(int* retval, int fd);
sgx_status_t SGX_CDECL u_sgxssl_open(int* retval, const char* fname, int flags);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);
sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout);
sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self);
sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter);
sgx_status_t SGX_CDECL u_opendir(DIR** retval, const char* name);
sgx_status_t SGX_CDECL u_readdir(struct dirent** retval, DIR* dirp);
sgx_status_t SGX_CDECL u_rewinddir(DIR* dirp);
sgx_status_t SGX_CDECL u_closedir(int* retval, DIR* dirp);
sgx_status_t SGX_CDECL u_telldir(long int* retval, DIR* dirp);
sgx_status_t SGX_CDECL u_seekdir(DIR* dirp, long int loc);
sgx_status_t SGX_CDECL u_getdents64(int* retval, unsigned int fd, struct dirent* dirp, unsigned int count);
sgx_status_t SGX_CDECL u_fcntl(int* retval, int fd, int cmd, int arg, uint64_t argsize, void* argout);
sgx_status_t SGX_CDECL u_open(int* retval, const char* pathname, int flags, mode_t mode);
sgx_status_t SGX_CDECL u_openat(int* retval, int dirfd, const char* pathname, int flags, mode_t mode);
sgx_status_t SGX_CDECL u_stat(int* retval, const char* pathname, struct stat* buf);
sgx_status_t SGX_CDECL u_lstat(int* retval, const char* pathname, struct stat* buf);
sgx_status_t SGX_CDECL u_fstat(int* retval, int fd, struct stat* buf);
sgx_status_t SGX_CDECL u_mkdir(int* retval, const char* pathname, mode_t mode);
sgx_status_t SGX_CDECL u_fchmod(int* retval, int fd, mode_t mode);
sgx_status_t SGX_CDECL u_socket(int* retval, int domain, int type, int protocol);
sgx_status_t SGX_CDECL u_bind(int* retval, int fd, const struct sockaddr* addr, socklen_t len);
sgx_status_t SGX_CDECL u_listen(int* retval, int fd, int n);
sgx_status_t SGX_CDECL u_accept(int* retval, int fd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out);
sgx_status_t SGX_CDECL u_connect(int* retval, int fd, const struct sockaddr* addr, socklen_t len);
sgx_status_t SGX_CDECL u_send(ssize_t* retval, int fd, const void* buf, size_t n, int flags);
sgx_status_t SGX_CDECL u_sendto(ssize_t* retval, int fd, const void* buf, size_t n, int flags, const struct sockaddr* addr, socklen_t addr_len);
sgx_status_t SGX_CDECL u_sendmsg(ssize_t* retval, int sockfd, const struct msghdr* msg, int flags);
sgx_status_t SGX_CDECL u_recv(ssize_t* retval, int fd, void* buf, size_t n, int flags);
sgx_status_t SGX_CDECL u_recvfrom(ssize_t* retval, int fd, void* buf, size_t n, int flags, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out);
sgx_status_t SGX_CDECL u_recvmsg(ssize_t* retval, int sockfd, struct msghdr* msg, int flags);
sgx_status_t SGX_CDECL u_getsockopt(int* retval, int fd, int level, int optname, void* optval, socklen_t optlen_in, socklen_t* optlen_out);
sgx_status_t SGX_CDECL u_setsockopt(int* retval, int fd, int level, int optname, const void* optval, socklen_t optlen);
sgx_status_t SGX_CDECL u_poll(int* retval, struct pollfd* fds, nfds_t nfds, int timeout);
sgx_status_t SGX_CDECL u_select(int* retval, int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout);
sgx_status_t SGX_CDECL u_getsockname(int* retval, int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out);
sgx_status_t SGX_CDECL u_getpeername(int* retval, int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out);
sgx_status_t SGX_CDECL u_socketpair(int* retval, int domain, int type, int protocol, int retfd[2]);
sgx_status_t SGX_CDECL u_shutdown(int* retval, int sockfd, int how);
sgx_status_t SGX_CDECL u_realpath(char** retval, const char* path);
sgx_status_t SGX_CDECL u_fprintf(FILE* stream, const char* str, size_t maxlen);
sgx_status_t SGX_CDECL u_fgets(char** retval, char* s, int size, FILE* stream);
sgx_status_t SGX_CDECL u_fopen(FILE** retval, const char* pathname, const char* mode);
sgx_status_t SGX_CDECL u_fdopen(FILE** retval, int fd, const char* mode);
sgx_status_t SGX_CDECL u_fclose(int* retval, FILE* stream);
sgx_status_t SGX_CDECL u_fread(size_t* retval, void* ptr, size_t size, size_t nmemb, FILE* stream);
sgx_status_t SGX_CDECL u_fwrite(size_t* retval, const void* ptr, size_t size, size_t nmemb, FILE* stream);
sgx_status_t SGX_CDECL u_rewind(FILE* stream);
sgx_status_t SGX_CDECL u_fflush(int* retval, FILE* stream);
sgx_status_t SGX_CDECL u_clearerr(FILE* stream);
sgx_status_t SGX_CDECL u_feof(int* retval, FILE* stream);
sgx_status_t SGX_CDECL u_ferror(int* retval, FILE* stream);
sgx_status_t SGX_CDECL u_fileno(int* retval, FILE* stream);
sgx_status_t SGX_CDECL u_getline(ssize_t* retval, char** lineptr, size_t* n, FILE* stream);
sgx_status_t SGX_CDECL u_getdelim(ssize_t* retval, char** lineptr, size_t* n, int delim, FILE* stream);
sgx_status_t SGX_CDECL u_malloc(void** retval, size_t size);
sgx_status_t SGX_CDECL u_free(void* ptr);
sgx_status_t SGX_CDECL u_uname(int* retval, struct utsname* buf);
sgx_status_t SGX_CDECL u_epoll_create1(int* retval, int flags);
sgx_status_t SGX_CDECL u_epoll_wait(int* retval, int epfd, struct epoll_event* events, unsigned int maxevents, int timeout);
sgx_status_t SGX_CDECL u_epoll_ctl(int* retval, int epfd, int op, int fd, struct epoll_event* event);
sgx_status_t SGX_CDECL u_mount(int* retval, const char* source, const char* target, const char* filesystemtype, unsigned long int mountflags);
sgx_status_t SGX_CDECL u_umount2(int* retval, const char* target, int flags);
sgx_status_t SGX_CDECL u_gethostname(int* retval, char* name, size_t len);
sgx_status_t SGX_CDECL u_getdomainname(int* retval, char* name, size_t len);
sgx_status_t SGX_CDECL u_getcwd(char** retval, char* buf, size_t size);
sgx_status_t SGX_CDECL u_chdir(int* retval, const char* path);
sgx_status_t SGX_CDECL u_nanosleep(int* retval, struct timespec* req, struct timespec* rem);
sgx_status_t SGX_CDECL u_clock_nanosleep(int* retval, clockid_t clockid, int flag, struct timespec* req, struct timespec* rem);
sgx_status_t SGX_CDECL u_getpid(pid_t* retval);
sgx_status_t SGX_CDECL u_getppid(pid_t* retval);
sgx_status_t SGX_CDECL u_getpgrp(pid_t* retval);
sgx_status_t SGX_CDECL u_getuid(uid_t* retval);
sgx_status_t SGX_CDECL u_geteuid(uid_t* retval);
sgx_status_t SGX_CDECL u_getgid(gid_t* retval);
sgx_status_t SGX_CDECL u_getegid(gid_t* retval);
sgx_status_t SGX_CDECL u_getpgid(pid_t* retval, int pid);
sgx_status_t SGX_CDECL u_getgroups(int* retval, size_t size, unsigned int* list);
sgx_status_t SGX_CDECL u_read(ssize_t* retval, int fd, void* buf, size_t count);
sgx_status_t SGX_CDECL u_write(ssize_t* retval, int fd, const void* buf, size_t count);
sgx_status_t SGX_CDECL u_close(int* retval, int fd);
sgx_status_t SGX_CDECL u_flock(int* retval, int fd, int operation);
sgx_status_t SGX_CDECL u_fsync(int* retval, int fd);
sgx_status_t SGX_CDECL u_fdatasync(int* retval, int fd);
sgx_status_t SGX_CDECL u_fchown(int* retval, int fd, unsigned int uid, unsigned int gid);
sgx_status_t SGX_CDECL u_dup(int* retval, int oldfd);
sgx_status_t SGX_CDECL u_dup2(int* retval, int oldfd, int newfd);
sgx_status_t SGX_CDECL u_rmdir(int* retval, const char* pathname);
sgx_status_t SGX_CDECL u_link(int* retval, const char* oldpath, const char* newpath);
sgx_status_t SGX_CDECL u_unlink(int* retval, const char* pathname);
sgx_status_t SGX_CDECL u_truncate(int* retval, const char* path, off_t length);
sgx_status_t SGX_CDECL u_ftruncate(int* retval, int fd, off_t length);
sgx_status_t SGX_CDECL u_lseek(off_t* retval, int fd, off_t offset, int whence);
sgx_status_t SGX_CDECL u_pread(ssize_t* retval, int fd, void* buf, size_t count, off_t offset);
sgx_status_t SGX_CDECL u_pwrite(ssize_t* retval, int fd, const void* buf, size_t count, off_t offset);
sgx_status_t SGX_CDECL u_readv(ssize_t* retval, int fd, struct _iovec_t* iov, int iovcnt);
sgx_status_t SGX_CDECL u_writev(ssize_t* retval, int fd, struct _iovec_t* iov, int iovcnt);
sgx_status_t SGX_CDECL u_access(int* retval, const char* pathname, int mode);
sgx_status_t SGX_CDECL u_readlink(ssize_t* retval, const char* pathname, char* buf, size_t bufsize);
sgx_status_t SGX_CDECL u_sysconf(long int* retval, int name);
sgx_status_t SGX_CDECL u_rename(int* retval, const char* oldpath, const char* newpath);
sgx_status_t SGX_CDECL u_remove(int* retval, const char* pathname);
sgx_status_t SGX_CDECL u_getenv(char** retval, const char* name);
sgx_status_t SGX_CDECL u_getgrgid_r(int* retval, gid_t gid, struct group* grp, char* buf, size_t buflen, struct group** result);
sgx_status_t SGX_CDECL u_getpwuid(struct passwd** retval, uid_t uid);
sgx_status_t SGX_CDECL u_getpwuid_r(int* retval, uid_t uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result);
sgx_status_t SGX_CDECL u_fpathconf(long int* retval, int fd, int name);
sgx_status_t SGX_CDECL u_pathconf(long int* retval, const char* path, int name);
sgx_status_t SGX_CDECL u_time(time_t* retval, time_t* tloc);
sgx_status_t SGX_CDECL u_utimes(int* retval, const char* filename, const struct timeval* times);
sgx_status_t SGX_CDECL u_localtime(struct tm** retval, const time_t* t);
sgx_status_t SGX_CDECL u_gettimeofday(int* retval, struct timeval* tv);
sgx_status_t SGX_CDECL u_clock_gettime(int* retval, clockid_t clk_id, struct timespec* tp);
sgx_status_t SGX_CDECL u_getaddrinfo(int* retval, const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res);
sgx_status_t SGX_CDECL u_freeaddrinfo(struct addrinfo* res);
sgx_status_t SGX_CDECL u_getnameinfo(int* retval, const struct sockaddr* sa, socklen_t salen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags);
sgx_status_t SGX_CDECL u_gai_strerror(char** retval, int errcode);
sgx_status_t SGX_CDECL u_sched_yield(int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
