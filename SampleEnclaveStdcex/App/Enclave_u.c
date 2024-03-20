#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_memset_s_t {
	int ms_retval;
} ms_ecall_memset_s_t;

typedef struct ms_ecall_fchmod_t {
	int ms_retval;
} ms_ecall_fchmod_t;

typedef struct ms_ecall_time_t {
	int ms_retval;
} ms_ecall_time_t;

typedef struct ms_ecall_mmap_t {
	int ms_retval;
} ms_ecall_mmap_t;

typedef struct ms_u_opendir_t {
	DIR* ms_retval;
	int ocall_errno;
	const char* ms_name;
} ms_u_opendir_t;

typedef struct ms_u_readdir_t {
	struct dirent* ms_retval;
	int ocall_errno;
	DIR* ms_dirp;
} ms_u_readdir_t;

typedef struct ms_u_rewinddir_t {
	DIR* ms_dirp;
} ms_u_rewinddir_t;

typedef struct ms_u_closedir_t {
	int ms_retval;
	int ocall_errno;
	DIR* ms_dirp;
} ms_u_closedir_t;

typedef struct ms_u_telldir_t {
	long int ms_retval;
	int ocall_errno;
	DIR* ms_dirp;
} ms_u_telldir_t;

typedef struct ms_u_seekdir_t {
	DIR* ms_dirp;
	long int ms_loc;
} ms_u_seekdir_t;

typedef struct ms_u_getdents64_t {
	int ms_retval;
	int ocall_errno;
	unsigned int ms_fd;
	struct dirent* ms_dirp;
	unsigned int ms_count;
} ms_u_getdents64_t;

typedef struct ms_u_fcntl_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	int ms_cmd;
	int ms_arg;
	uint64_t ms_argsize;
	void* ms_argout;
} ms_u_fcntl_t;

typedef struct ms_u_open_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_pathname;
	int ms_flags;
	mode_t ms_mode;
} ms_u_open_t;

typedef struct ms_u_openat_t {
	int ms_retval;
	int ocall_errno;
	int ms_dirfd;
	const char* ms_pathname;
	int ms_flags;
	mode_t ms_mode;
} ms_u_openat_t;

typedef struct ms_u_stat_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_pathname;
	struct stat* ms_buf;
} ms_u_stat_t;

typedef struct ms_u_lstat_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_pathname;
	struct stat* ms_buf;
} ms_u_lstat_t;

typedef struct ms_u_fstat_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	struct stat* ms_buf;
} ms_u_fstat_t;

typedef struct ms_u_mkdir_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_pathname;
	mode_t ms_mode;
} ms_u_mkdir_t;

typedef struct ms_u_fchmod_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	mode_t ms_mode;
} ms_u_fchmod_t;

typedef struct ms_u_socket_t {
	int ms_retval;
	int ocall_errno;
	int ms_domain;
	int ms_type;
	int ms_protocol;
} ms_u_socket_t;

typedef struct ms_u_bind_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	const struct sockaddr* ms_addr;
	socklen_t ms_len;
} ms_u_bind_t;

typedef struct ms_u_listen_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	int ms_n;
} ms_u_listen_t;

typedef struct ms_u_accept_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	struct sockaddr* ms_addr;
	socklen_t ms_addrlen_in;
	socklen_t* ms_addrlen_out;
} ms_u_accept_t;

typedef struct ms_u_connect_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	const struct sockaddr* ms_addr;
	socklen_t ms_len;
} ms_u_connect_t;

typedef struct ms_u_send_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	const void* ms_buf;
	size_t ms_n;
	int ms_flags;
} ms_u_send_t;

typedef struct ms_u_sendto_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	const void* ms_buf;
	size_t ms_n;
	int ms_flags;
	const struct sockaddr* ms_addr;
	socklen_t ms_addr_len;
} ms_u_sendto_t;

typedef struct ms_u_sendmsg_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	const struct msghdr* ms_msg;
	int ms_flags;
} ms_u_sendmsg_t;

typedef struct ms_u_recv_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	void* ms_buf;
	size_t ms_n;
	int ms_flags;
} ms_u_recv_t;

typedef struct ms_u_recvfrom_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	void* ms_buf;
	size_t ms_n;
	int ms_flags;
	struct sockaddr* ms_addr;
	socklen_t ms_addrlen_in;
	socklen_t* ms_addrlen_out;
} ms_u_recvfrom_t;

typedef struct ms_u_recvmsg_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_sockfd;
	struct msghdr* ms_msg;
	int ms_flags;
} ms_u_recvmsg_t;

typedef struct ms_u_getsockopt_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	int ms_level;
	int ms_optname;
	void* ms_optval;
	socklen_t ms_optlen_in;
	socklen_t* ms_optlen_out;
} ms_u_getsockopt_t;

typedef struct ms_u_setsockopt_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	int ms_level;
	int ms_optname;
	const void* ms_optval;
	socklen_t ms_optlen;
} ms_u_setsockopt_t;

typedef struct ms_u_poll_t {
	int ms_retval;
	int ocall_errno;
	struct pollfd* ms_fds;
	nfds_t ms_nfds;
	int ms_timeout;
} ms_u_poll_t;

typedef struct ms_u_select_t {
	int ms_retval;
	int ocall_errno;
	int ms_nfds;
	fd_set* ms_readfds;
	fd_set* ms_writefds;
	fd_set* ms_exceptfds;
	struct timeval* ms_timeout;
} ms_u_select_t;

typedef struct ms_u_getsockname_t {
	int ms_retval;
	int ocall_errno;
	int ms_sockfd;
	struct sockaddr* ms_addr;
	socklen_t ms_addrlen_in;
	socklen_t* ms_addrlen_out;
} ms_u_getsockname_t;

typedef struct ms_u_getpeername_t {
	int ms_retval;
	int ocall_errno;
	int ms_sockfd;
	struct sockaddr* ms_addr;
	socklen_t ms_addrlen_in;
	socklen_t* ms_addrlen_out;
} ms_u_getpeername_t;

typedef struct ms_u_socketpair_t {
	int ms_retval;
	int ocall_errno;
	int ms_domain;
	int ms_type;
	int ms_protocol;
	int* ms_retfd;
} ms_u_socketpair_t;

typedef struct ms_u_shutdown_t {
	int ms_retval;
	int ocall_errno;
	int ms_sockfd;
	int ms_how;
} ms_u_shutdown_t;

typedef struct ms_u_realpath_t {
	char* ms_retval;
	int ocall_errno;
	const char* ms_path;
} ms_u_realpath_t;

typedef struct ms_u_fprintf_t {
	FILE* ms_stream;
	const char* ms_str;
	size_t ms_maxlen;
} ms_u_fprintf_t;

typedef struct ms_u_fgets_t {
	char* ms_retval;
	char* ms_s;
	int ms_size;
	FILE* ms_stream;
} ms_u_fgets_t;

typedef struct ms_u_fopen_t {
	FILE* ms_retval;
	int ocall_errno;
	const char* ms_pathname;
	const char* ms_mode;
} ms_u_fopen_t;

typedef struct ms_u_fdopen_t {
	FILE* ms_retval;
	int ocall_errno;
	int ms_fd;
	const char* ms_mode;
} ms_u_fdopen_t;

typedef struct ms_u_fclose_t {
	int ms_retval;
	int ocall_errno;
	FILE* ms_stream;
} ms_u_fclose_t;

typedef struct ms_u_fread_t {
	size_t ms_retval;
	void* ms_ptr;
	size_t ms_size;
	size_t ms_nmemb;
	FILE* ms_stream;
} ms_u_fread_t;

typedef struct ms_u_fwrite_t {
	size_t ms_retval;
	const void* ms_ptr;
	size_t ms_size;
	size_t ms_nmemb;
	FILE* ms_stream;
} ms_u_fwrite_t;

typedef struct ms_u_rewind_t {
	FILE* ms_stream;
} ms_u_rewind_t;

typedef struct ms_u_fflush_t {
	int ms_retval;
	int ocall_errno;
	FILE* ms_stream;
} ms_u_fflush_t;

typedef struct ms_u_clearerr_t {
	FILE* ms_stream;
} ms_u_clearerr_t;

typedef struct ms_u_feof_t {
	int ms_retval;
	FILE* ms_stream;
} ms_u_feof_t;

typedef struct ms_u_ferror_t {
	int ms_retval;
	FILE* ms_stream;
} ms_u_ferror_t;

typedef struct ms_u_fileno_t {
	int ms_retval;
	int ocall_errno;
	FILE* ms_stream;
} ms_u_fileno_t;

typedef struct ms_u_getline_t {
	ssize_t ms_retval;
	int ocall_errno;
	char** ms_lineptr;
	size_t* ms_n;
	FILE* ms_stream;
} ms_u_getline_t;

typedef struct ms_u_getdelim_t {
	ssize_t ms_retval;
	int ocall_errno;
	char** ms_lineptr;
	size_t* ms_n;
	int ms_delim;
	FILE* ms_stream;
} ms_u_getdelim_t;

typedef struct ms_u_malloc_t {
	void* ms_retval;
	int ocall_errno;
	size_t ms_size;
} ms_u_malloc_t;

typedef struct ms_u_free_t {
	void* ms_ptr;
} ms_u_free_t;

typedef struct ms_u_uname_t {
	int ms_retval;
	int ocall_errno;
	struct utsname* ms_buf;
} ms_u_uname_t;

typedef struct ms_u_epoll_create1_t {
	int ms_retval;
	int ocall_errno;
	int ms_flags;
} ms_u_epoll_create1_t;

typedef struct ms_u_epoll_wait_t {
	int ms_retval;
	int ocall_errno;
	int ms_epfd;
	struct epoll_event* ms_events;
	unsigned int ms_maxevents;
	int ms_timeout;
} ms_u_epoll_wait_t;

typedef struct ms_u_epoll_ctl_t {
	int ms_retval;
	int ocall_errno;
	int ms_epfd;
	int ms_op;
	int ms_fd;
	struct epoll_event* ms_event;
} ms_u_epoll_ctl_t;

typedef struct ms_u_mount_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_source;
	const char* ms_target;
	const char* ms_filesystemtype;
	unsigned long int ms_mountflags;
} ms_u_mount_t;

typedef struct ms_u_umount2_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_target;
	int ms_flags;
} ms_u_umount2_t;

typedef struct ms_u_gethostname_t {
	int ms_retval;
	int ocall_errno;
	char* ms_name;
	size_t ms_len;
} ms_u_gethostname_t;

typedef struct ms_u_getdomainname_t {
	int ms_retval;
	int ocall_errno;
	char* ms_name;
	size_t ms_len;
} ms_u_getdomainname_t;

typedef struct ms_u_getcwd_t {
	char* ms_retval;
	int ocall_errno;
	char* ms_buf;
	size_t ms_size;
} ms_u_getcwd_t;

typedef struct ms_u_chdir_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_path;
} ms_u_chdir_t;

typedef struct ms_u_nanosleep_t {
	int ms_retval;
	int ocall_errno;
	struct timespec* ms_req;
	struct timespec* ms_rem;
} ms_u_nanosleep_t;

typedef struct ms_u_clock_nanosleep_t {
	int ms_retval;
	clockid_t ms_clockid;
	int ms_flag;
	struct timespec* ms_req;
	struct timespec* ms_rem;
} ms_u_clock_nanosleep_t;

typedef struct ms_u_getpid_t {
	pid_t ms_retval;
} ms_u_getpid_t;

typedef struct ms_u_getppid_t {
	pid_t ms_retval;
} ms_u_getppid_t;

typedef struct ms_u_getpgrp_t {
	pid_t ms_retval;
	int ocall_errno;
} ms_u_getpgrp_t;

typedef struct ms_u_getuid_t {
	uid_t ms_retval;
} ms_u_getuid_t;

typedef struct ms_u_geteuid_t {
	uid_t ms_retval;
} ms_u_geteuid_t;

typedef struct ms_u_getgid_t {
	gid_t ms_retval;
} ms_u_getgid_t;

typedef struct ms_u_getegid_t {
	gid_t ms_retval;
} ms_u_getegid_t;

typedef struct ms_u_getpgid_t {
	pid_t ms_retval;
	int ocall_errno;
	int ms_pid;
} ms_u_getpgid_t;

typedef struct ms_u_getgroups_t {
	int ms_retval;
	int ocall_errno;
	size_t ms_size;
	unsigned int* ms_list;
} ms_u_getgroups_t;

typedef struct ms_u_read_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_u_read_t;

typedef struct ms_u_write_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	const void* ms_buf;
	size_t ms_count;
} ms_u_write_t;

typedef struct ms_u_close_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
} ms_u_close_t;

typedef struct ms_u_flock_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	int ms_operation;
} ms_u_flock_t;

typedef struct ms_u_fsync_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
} ms_u_fsync_t;

typedef struct ms_u_fdatasync_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
} ms_u_fdatasync_t;

typedef struct ms_u_fchown_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	unsigned int ms_uid;
	unsigned int ms_gid;
} ms_u_fchown_t;

typedef struct ms_u_dup_t {
	int ms_retval;
	int ocall_errno;
	int ms_oldfd;
} ms_u_dup_t;

typedef struct ms_u_dup2_t {
	int ms_retval;
	int ocall_errno;
	int ms_oldfd;
	int ms_newfd;
} ms_u_dup2_t;

typedef struct ms_u_rmdir_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_pathname;
} ms_u_rmdir_t;

typedef struct ms_u_link_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_oldpath;
	const char* ms_newpath;
} ms_u_link_t;

typedef struct ms_u_unlink_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_pathname;
} ms_u_unlink_t;

typedef struct ms_u_truncate_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_path;
	off_t ms_length;
} ms_u_truncate_t;

typedef struct ms_u_ftruncate_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
	off_t ms_length;
} ms_u_ftruncate_t;

typedef struct ms_u_lseek_t {
	off_t ms_retval;
	int ocall_errno;
	int ms_fd;
	off_t ms_offset;
	int ms_whence;
} ms_u_lseek_t;

typedef struct ms_u_pread_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
	off_t ms_offset;
} ms_u_pread_t;

typedef struct ms_u_pwrite_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	const void* ms_buf;
	size_t ms_count;
	off_t ms_offset;
} ms_u_pwrite_t;

typedef struct ms_u_readv_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	struct _iovec_t* ms_iov;
	int ms_iovcnt;
} ms_u_readv_t;

typedef struct ms_u_writev_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	struct _iovec_t* ms_iov;
	int ms_iovcnt;
} ms_u_writev_t;

typedef struct ms_u_access_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_pathname;
	int ms_mode;
} ms_u_access_t;

typedef struct ms_u_readlink_t {
	ssize_t ms_retval;
	int ocall_errno;
	const char* ms_pathname;
	char* ms_buf;
	size_t ms_bufsize;
} ms_u_readlink_t;

typedef struct ms_u_sysconf_t {
	long int ms_retval;
	int ocall_errno;
	int ms_name;
} ms_u_sysconf_t;

typedef struct ms_u_rename_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_oldpath;
	const char* ms_newpath;
} ms_u_rename_t;

typedef struct ms_u_remove_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_pathname;
} ms_u_remove_t;

typedef struct ms_u_getenv_t {
	char* ms_retval;
	const char* ms_name;
} ms_u_getenv_t;

typedef struct ms_u_getgrgid_r_t {
	int ms_retval;
	int ocall_errno;
	gid_t ms_gid;
	struct group* ms_grp;
	char* ms_buf;
	size_t ms_buflen;
	struct group** ms_result;
} ms_u_getgrgid_r_t;

typedef struct ms_u_getpwuid_t {
	struct passwd* ms_retval;
	int ocall_errno;
	uid_t ms_uid;
} ms_u_getpwuid_t;

typedef struct ms_u_getpwuid_r_t {
	int ms_retval;
	int ocall_errno;
	uid_t ms_uid;
	struct passwd* ms_pwd;
	char* ms_buf;
	size_t ms_buflen;
	struct passwd** ms_result;
} ms_u_getpwuid_r_t;

typedef struct ms_u_fpathconf_t {
	long int ms_retval;
	int ocall_errno;
	int ms_fd;
	int ms_name;
} ms_u_fpathconf_t;

typedef struct ms_u_pathconf_t {
	long int ms_retval;
	int ocall_errno;
	const char* ms_path;
	int ms_name;
} ms_u_pathconf_t;

typedef struct ms_u_time_t {
	time_t ms_retval;
	int ocall_errno;
	time_t* ms_tloc;
} ms_u_time_t;

typedef struct ms_u_utimes_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_filename;
	const struct timeval* ms_times;
} ms_u_utimes_t;

typedef struct ms_u_localtime_t {
	struct tm* ms_retval;
	int ocall_errno;
	const time_t* ms_t;
} ms_u_localtime_t;

typedef struct ms_u_gettimeofday_t {
	int ms_retval;
	int ocall_errno;
	struct timeval* ms_tv;
} ms_u_gettimeofday_t;

typedef struct ms_u_clock_gettime_t {
	int ms_retval;
	int ocall_errno;
	clockid_t ms_clk_id;
	struct timespec* ms_tp;
} ms_u_clock_gettime_t;

typedef struct ms_u_getaddrinfo_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_node;
	const char* ms_service;
	const struct addrinfo* ms_hints;
	struct addrinfo** ms_res;
} ms_u_getaddrinfo_t;

typedef struct ms_u_freeaddrinfo_t {
	struct addrinfo* ms_res;
} ms_u_freeaddrinfo_t;

typedef struct ms_u_getnameinfo_t {
	int ms_retval;
	int ocall_errno;
	const struct sockaddr* ms_sa;
	socklen_t ms_salen;
	char* ms_host;
	socklen_t ms_hostlen;
	char* ms_serv;
	socklen_t ms_servlen;
	int ms_flags;
} ms_u_getnameinfo_t;

typedef struct ms_u_gai_strerror_t {
	char* ms_retval;
	int ms_errcode;
} ms_u_gai_strerror_t;

typedef struct ms_u_sched_yield_t {
	int ms_retval;
	int ocall_errno;
} ms_u_sched_yield_t;

static sgx_status_t SGX_CDECL Enclave_u_opendir(void* pms)
{
	ms_u_opendir_t* ms = SGX_CAST(ms_u_opendir_t*, pms);
	ms->ms_retval = u_opendir(ms->ms_name);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_readdir(void* pms)
{
	ms_u_readdir_t* ms = SGX_CAST(ms_u_readdir_t*, pms);
	ms->ms_retval = u_readdir(ms->ms_dirp);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_rewinddir(void* pms)
{
	ms_u_rewinddir_t* ms = SGX_CAST(ms_u_rewinddir_t*, pms);
	u_rewinddir(ms->ms_dirp);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_closedir(void* pms)
{
	ms_u_closedir_t* ms = SGX_CAST(ms_u_closedir_t*, pms);
	ms->ms_retval = u_closedir(ms->ms_dirp);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_telldir(void* pms)
{
	ms_u_telldir_t* ms = SGX_CAST(ms_u_telldir_t*, pms);
	ms->ms_retval = u_telldir(ms->ms_dirp);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_seekdir(void* pms)
{
	ms_u_seekdir_t* ms = SGX_CAST(ms_u_seekdir_t*, pms);
	u_seekdir(ms->ms_dirp, ms->ms_loc);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getdents64(void* pms)
{
	ms_u_getdents64_t* ms = SGX_CAST(ms_u_getdents64_t*, pms);
	ms->ms_retval = u_getdents64(ms->ms_fd, ms->ms_dirp, ms->ms_count);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fcntl(void* pms)
{
	ms_u_fcntl_t* ms = SGX_CAST(ms_u_fcntl_t*, pms);
	ms->ms_retval = u_fcntl(ms->ms_fd, ms->ms_cmd, ms->ms_arg, ms->ms_argsize, ms->ms_argout);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_open(void* pms)
{
	ms_u_open_t* ms = SGX_CAST(ms_u_open_t*, pms);
	ms->ms_retval = u_open(ms->ms_pathname, ms->ms_flags, ms->ms_mode);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_openat(void* pms)
{
	ms_u_openat_t* ms = SGX_CAST(ms_u_openat_t*, pms);
	ms->ms_retval = u_openat(ms->ms_dirfd, ms->ms_pathname, ms->ms_flags, ms->ms_mode);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_stat(void* pms)
{
	ms_u_stat_t* ms = SGX_CAST(ms_u_stat_t*, pms);
	ms->ms_retval = u_stat(ms->ms_pathname, ms->ms_buf);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_lstat(void* pms)
{
	ms_u_lstat_t* ms = SGX_CAST(ms_u_lstat_t*, pms);
	ms->ms_retval = u_lstat(ms->ms_pathname, ms->ms_buf);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fstat(void* pms)
{
	ms_u_fstat_t* ms = SGX_CAST(ms_u_fstat_t*, pms);
	ms->ms_retval = u_fstat(ms->ms_fd, ms->ms_buf);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_mkdir(void* pms)
{
	ms_u_mkdir_t* ms = SGX_CAST(ms_u_mkdir_t*, pms);
	ms->ms_retval = u_mkdir(ms->ms_pathname, ms->ms_mode);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fchmod(void* pms)
{
	ms_u_fchmod_t* ms = SGX_CAST(ms_u_fchmod_t*, pms);
	ms->ms_retval = u_fchmod(ms->ms_fd, ms->ms_mode);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_socket(void* pms)
{
	ms_u_socket_t* ms = SGX_CAST(ms_u_socket_t*, pms);
	ms->ms_retval = u_socket(ms->ms_domain, ms->ms_type, ms->ms_protocol);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_bind(void* pms)
{
	ms_u_bind_t* ms = SGX_CAST(ms_u_bind_t*, pms);
	ms->ms_retval = u_bind(ms->ms_fd, ms->ms_addr, ms->ms_len);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_listen(void* pms)
{
	ms_u_listen_t* ms = SGX_CAST(ms_u_listen_t*, pms);
	ms->ms_retval = u_listen(ms->ms_fd, ms->ms_n);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_accept(void* pms)
{
	ms_u_accept_t* ms = SGX_CAST(ms_u_accept_t*, pms);
	ms->ms_retval = u_accept(ms->ms_fd, ms->ms_addr, ms->ms_addrlen_in, ms->ms_addrlen_out);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_connect(void* pms)
{
	ms_u_connect_t* ms = SGX_CAST(ms_u_connect_t*, pms);
	ms->ms_retval = u_connect(ms->ms_fd, ms->ms_addr, ms->ms_len);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_send(void* pms)
{
	ms_u_send_t* ms = SGX_CAST(ms_u_send_t*, pms);
	ms->ms_retval = u_send(ms->ms_fd, ms->ms_buf, ms->ms_n, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sendto(void* pms)
{
	ms_u_sendto_t* ms = SGX_CAST(ms_u_sendto_t*, pms);
	ms->ms_retval = u_sendto(ms->ms_fd, ms->ms_buf, ms->ms_n, ms->ms_flags, ms->ms_addr, ms->ms_addr_len);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sendmsg(void* pms)
{
	ms_u_sendmsg_t* ms = SGX_CAST(ms_u_sendmsg_t*, pms);
	ms->ms_retval = u_sendmsg(ms->ms_sockfd, ms->ms_msg, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_recv(void* pms)
{
	ms_u_recv_t* ms = SGX_CAST(ms_u_recv_t*, pms);
	ms->ms_retval = u_recv(ms->ms_fd, ms->ms_buf, ms->ms_n, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_recvfrom(void* pms)
{
	ms_u_recvfrom_t* ms = SGX_CAST(ms_u_recvfrom_t*, pms);
	ms->ms_retval = u_recvfrom(ms->ms_fd, ms->ms_buf, ms->ms_n, ms->ms_flags, ms->ms_addr, ms->ms_addrlen_in, ms->ms_addrlen_out);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_recvmsg(void* pms)
{
	ms_u_recvmsg_t* ms = SGX_CAST(ms_u_recvmsg_t*, pms);
	ms->ms_retval = u_recvmsg(ms->ms_sockfd, ms->ms_msg, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getsockopt(void* pms)
{
	ms_u_getsockopt_t* ms = SGX_CAST(ms_u_getsockopt_t*, pms);
	ms->ms_retval = u_getsockopt(ms->ms_fd, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms_optlen_in, ms->ms_optlen_out);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_setsockopt(void* pms)
{
	ms_u_setsockopt_t* ms = SGX_CAST(ms_u_setsockopt_t*, pms);
	ms->ms_retval = u_setsockopt(ms->ms_fd, ms->ms_level, ms->ms_optname, ms->ms_optval, ms->ms_optlen);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_poll(void* pms)
{
	ms_u_poll_t* ms = SGX_CAST(ms_u_poll_t*, pms);
	ms->ms_retval = u_poll(ms->ms_fds, ms->ms_nfds, ms->ms_timeout);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_select(void* pms)
{
	ms_u_select_t* ms = SGX_CAST(ms_u_select_t*, pms);
	ms->ms_retval = u_select(ms->ms_nfds, ms->ms_readfds, ms->ms_writefds, ms->ms_exceptfds, ms->ms_timeout);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getsockname(void* pms)
{
	ms_u_getsockname_t* ms = SGX_CAST(ms_u_getsockname_t*, pms);
	ms->ms_retval = u_getsockname(ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen_in, ms->ms_addrlen_out);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getpeername(void* pms)
{
	ms_u_getpeername_t* ms = SGX_CAST(ms_u_getpeername_t*, pms);
	ms->ms_retval = u_getpeername(ms->ms_sockfd, ms->ms_addr, ms->ms_addrlen_in, ms->ms_addrlen_out);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_socketpair(void* pms)
{
	ms_u_socketpair_t* ms = SGX_CAST(ms_u_socketpair_t*, pms);
	ms->ms_retval = u_socketpair(ms->ms_domain, ms->ms_type, ms->ms_protocol, ms->ms_retfd);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_shutdown(void* pms)
{
	ms_u_shutdown_t* ms = SGX_CAST(ms_u_shutdown_t*, pms);
	ms->ms_retval = u_shutdown(ms->ms_sockfd, ms->ms_how);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_realpath(void* pms)
{
	ms_u_realpath_t* ms = SGX_CAST(ms_u_realpath_t*, pms);
	ms->ms_retval = u_realpath(ms->ms_path);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fprintf(void* pms)
{
	ms_u_fprintf_t* ms = SGX_CAST(ms_u_fprintf_t*, pms);
	u_fprintf(ms->ms_stream, ms->ms_str, ms->ms_maxlen);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fgets(void* pms)
{
	ms_u_fgets_t* ms = SGX_CAST(ms_u_fgets_t*, pms);
	ms->ms_retval = u_fgets(ms->ms_s, ms->ms_size, ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fopen(void* pms)
{
	ms_u_fopen_t* ms = SGX_CAST(ms_u_fopen_t*, pms);
	ms->ms_retval = u_fopen(ms->ms_pathname, ms->ms_mode);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fdopen(void* pms)
{
	ms_u_fdopen_t* ms = SGX_CAST(ms_u_fdopen_t*, pms);
	ms->ms_retval = u_fdopen(ms->ms_fd, ms->ms_mode);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fclose(void* pms)
{
	ms_u_fclose_t* ms = SGX_CAST(ms_u_fclose_t*, pms);
	ms->ms_retval = u_fclose(ms->ms_stream);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fread(void* pms)
{
	ms_u_fread_t* ms = SGX_CAST(ms_u_fread_t*, pms);
	ms->ms_retval = u_fread(ms->ms_ptr, ms->ms_size, ms->ms_nmemb, ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fwrite(void* pms)
{
	ms_u_fwrite_t* ms = SGX_CAST(ms_u_fwrite_t*, pms);
	ms->ms_retval = u_fwrite(ms->ms_ptr, ms->ms_size, ms->ms_nmemb, ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_rewind(void* pms)
{
	ms_u_rewind_t* ms = SGX_CAST(ms_u_rewind_t*, pms);
	u_rewind(ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fflush(void* pms)
{
	ms_u_fflush_t* ms = SGX_CAST(ms_u_fflush_t*, pms);
	ms->ms_retval = u_fflush(ms->ms_stream);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_clearerr(void* pms)
{
	ms_u_clearerr_t* ms = SGX_CAST(ms_u_clearerr_t*, pms);
	u_clearerr(ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_feof(void* pms)
{
	ms_u_feof_t* ms = SGX_CAST(ms_u_feof_t*, pms);
	ms->ms_retval = u_feof(ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_ferror(void* pms)
{
	ms_u_ferror_t* ms = SGX_CAST(ms_u_ferror_t*, pms);
	ms->ms_retval = u_ferror(ms->ms_stream);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fileno(void* pms)
{
	ms_u_fileno_t* ms = SGX_CAST(ms_u_fileno_t*, pms);
	ms->ms_retval = u_fileno(ms->ms_stream);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getline(void* pms)
{
	ms_u_getline_t* ms = SGX_CAST(ms_u_getline_t*, pms);
	ms->ms_retval = u_getline(ms->ms_lineptr, ms->ms_n, ms->ms_stream);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getdelim(void* pms)
{
	ms_u_getdelim_t* ms = SGX_CAST(ms_u_getdelim_t*, pms);
	ms->ms_retval = u_getdelim(ms->ms_lineptr, ms->ms_n, ms->ms_delim, ms->ms_stream);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_malloc(void* pms)
{
	ms_u_malloc_t* ms = SGX_CAST(ms_u_malloc_t*, pms);
	ms->ms_retval = u_malloc(ms->ms_size);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_free(void* pms)
{
	ms_u_free_t* ms = SGX_CAST(ms_u_free_t*, pms);
	u_free(ms->ms_ptr);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_uname(void* pms)
{
	ms_u_uname_t* ms = SGX_CAST(ms_u_uname_t*, pms);
	ms->ms_retval = u_uname(ms->ms_buf);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_epoll_create1(void* pms)
{
	ms_u_epoll_create1_t* ms = SGX_CAST(ms_u_epoll_create1_t*, pms);
	ms->ms_retval = u_epoll_create1(ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_epoll_wait(void* pms)
{
	ms_u_epoll_wait_t* ms = SGX_CAST(ms_u_epoll_wait_t*, pms);
	ms->ms_retval = u_epoll_wait(ms->ms_epfd, ms->ms_events, ms->ms_maxevents, ms->ms_timeout);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_epoll_ctl(void* pms)
{
	ms_u_epoll_ctl_t* ms = SGX_CAST(ms_u_epoll_ctl_t*, pms);
	ms->ms_retval = u_epoll_ctl(ms->ms_epfd, ms->ms_op, ms->ms_fd, ms->ms_event);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_mount(void* pms)
{
	ms_u_mount_t* ms = SGX_CAST(ms_u_mount_t*, pms);
	ms->ms_retval = u_mount(ms->ms_source, ms->ms_target, ms->ms_filesystemtype, ms->ms_mountflags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_umount2(void* pms)
{
	ms_u_umount2_t* ms = SGX_CAST(ms_u_umount2_t*, pms);
	ms->ms_retval = u_umount2(ms->ms_target, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_gethostname(void* pms)
{
	ms_u_gethostname_t* ms = SGX_CAST(ms_u_gethostname_t*, pms);
	ms->ms_retval = u_gethostname(ms->ms_name, ms->ms_len);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getdomainname(void* pms)
{
	ms_u_getdomainname_t* ms = SGX_CAST(ms_u_getdomainname_t*, pms);
	ms->ms_retval = u_getdomainname(ms->ms_name, ms->ms_len);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getcwd(void* pms)
{
	ms_u_getcwd_t* ms = SGX_CAST(ms_u_getcwd_t*, pms);
	ms->ms_retval = u_getcwd(ms->ms_buf, ms->ms_size);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_chdir(void* pms)
{
	ms_u_chdir_t* ms = SGX_CAST(ms_u_chdir_t*, pms);
	ms->ms_retval = u_chdir(ms->ms_path);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_nanosleep(void* pms)
{
	ms_u_nanosleep_t* ms = SGX_CAST(ms_u_nanosleep_t*, pms);
	ms->ms_retval = u_nanosleep(ms->ms_req, ms->ms_rem);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_clock_nanosleep(void* pms)
{
	ms_u_clock_nanosleep_t* ms = SGX_CAST(ms_u_clock_nanosleep_t*, pms);
	ms->ms_retval = u_clock_nanosleep(ms->ms_clockid, ms->ms_flag, ms->ms_req, ms->ms_rem);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getpid(void* pms)
{
	ms_u_getpid_t* ms = SGX_CAST(ms_u_getpid_t*, pms);
	ms->ms_retval = u_getpid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getppid(void* pms)
{
	ms_u_getppid_t* ms = SGX_CAST(ms_u_getppid_t*, pms);
	ms->ms_retval = u_getppid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getpgrp(void* pms)
{
	ms_u_getpgrp_t* ms = SGX_CAST(ms_u_getpgrp_t*, pms);
	ms->ms_retval = u_getpgrp();
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getuid(void* pms)
{
	ms_u_getuid_t* ms = SGX_CAST(ms_u_getuid_t*, pms);
	ms->ms_retval = u_getuid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_geteuid(void* pms)
{
	ms_u_geteuid_t* ms = SGX_CAST(ms_u_geteuid_t*, pms);
	ms->ms_retval = u_geteuid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getgid(void* pms)
{
	ms_u_getgid_t* ms = SGX_CAST(ms_u_getgid_t*, pms);
	ms->ms_retval = u_getgid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getegid(void* pms)
{
	ms_u_getegid_t* ms = SGX_CAST(ms_u_getegid_t*, pms);
	ms->ms_retval = u_getegid();

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getpgid(void* pms)
{
	ms_u_getpgid_t* ms = SGX_CAST(ms_u_getpgid_t*, pms);
	ms->ms_retval = u_getpgid(ms->ms_pid);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getgroups(void* pms)
{
	ms_u_getgroups_t* ms = SGX_CAST(ms_u_getgroups_t*, pms);
	ms->ms_retval = u_getgroups(ms->ms_size, ms->ms_list);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_read(void* pms)
{
	ms_u_read_t* ms = SGX_CAST(ms_u_read_t*, pms);
	ms->ms_retval = u_read(ms->ms_fd, ms->ms_buf, ms->ms_count);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_write(void* pms)
{
	ms_u_write_t* ms = SGX_CAST(ms_u_write_t*, pms);
	ms->ms_retval = u_write(ms->ms_fd, ms->ms_buf, ms->ms_count);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_close(void* pms)
{
	ms_u_close_t* ms = SGX_CAST(ms_u_close_t*, pms);
	ms->ms_retval = u_close(ms->ms_fd);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_flock(void* pms)
{
	ms_u_flock_t* ms = SGX_CAST(ms_u_flock_t*, pms);
	ms->ms_retval = u_flock(ms->ms_fd, ms->ms_operation);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fsync(void* pms)
{
	ms_u_fsync_t* ms = SGX_CAST(ms_u_fsync_t*, pms);
	ms->ms_retval = u_fsync(ms->ms_fd);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fdatasync(void* pms)
{
	ms_u_fdatasync_t* ms = SGX_CAST(ms_u_fdatasync_t*, pms);
	ms->ms_retval = u_fdatasync(ms->ms_fd);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fchown(void* pms)
{
	ms_u_fchown_t* ms = SGX_CAST(ms_u_fchown_t*, pms);
	ms->ms_retval = u_fchown(ms->ms_fd, ms->ms_uid, ms->ms_gid);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_dup(void* pms)
{
	ms_u_dup_t* ms = SGX_CAST(ms_u_dup_t*, pms);
	ms->ms_retval = u_dup(ms->ms_oldfd);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_dup2(void* pms)
{
	ms_u_dup2_t* ms = SGX_CAST(ms_u_dup2_t*, pms);
	ms->ms_retval = u_dup2(ms->ms_oldfd, ms->ms_newfd);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_rmdir(void* pms)
{
	ms_u_rmdir_t* ms = SGX_CAST(ms_u_rmdir_t*, pms);
	ms->ms_retval = u_rmdir(ms->ms_pathname);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_link(void* pms)
{
	ms_u_link_t* ms = SGX_CAST(ms_u_link_t*, pms);
	ms->ms_retval = u_link(ms->ms_oldpath, ms->ms_newpath);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_unlink(void* pms)
{
	ms_u_unlink_t* ms = SGX_CAST(ms_u_unlink_t*, pms);
	ms->ms_retval = u_unlink(ms->ms_pathname);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_truncate(void* pms)
{
	ms_u_truncate_t* ms = SGX_CAST(ms_u_truncate_t*, pms);
	ms->ms_retval = u_truncate(ms->ms_path, ms->ms_length);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_ftruncate(void* pms)
{
	ms_u_ftruncate_t* ms = SGX_CAST(ms_u_ftruncate_t*, pms);
	ms->ms_retval = u_ftruncate(ms->ms_fd, ms->ms_length);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_lseek(void* pms)
{
	ms_u_lseek_t* ms = SGX_CAST(ms_u_lseek_t*, pms);
	ms->ms_retval = u_lseek(ms->ms_fd, ms->ms_offset, ms->ms_whence);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_pread(void* pms)
{
	ms_u_pread_t* ms = SGX_CAST(ms_u_pread_t*, pms);
	ms->ms_retval = u_pread(ms->ms_fd, ms->ms_buf, ms->ms_count, ms->ms_offset);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_pwrite(void* pms)
{
	ms_u_pwrite_t* ms = SGX_CAST(ms_u_pwrite_t*, pms);
	ms->ms_retval = u_pwrite(ms->ms_fd, ms->ms_buf, ms->ms_count, ms->ms_offset);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_readv(void* pms)
{
	ms_u_readv_t* ms = SGX_CAST(ms_u_readv_t*, pms);
	ms->ms_retval = u_readv(ms->ms_fd, ms->ms_iov, ms->ms_iovcnt);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_writev(void* pms)
{
	ms_u_writev_t* ms = SGX_CAST(ms_u_writev_t*, pms);
	ms->ms_retval = u_writev(ms->ms_fd, ms->ms_iov, ms->ms_iovcnt);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_access(void* pms)
{
	ms_u_access_t* ms = SGX_CAST(ms_u_access_t*, pms);
	ms->ms_retval = u_access(ms->ms_pathname, ms->ms_mode);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_readlink(void* pms)
{
	ms_u_readlink_t* ms = SGX_CAST(ms_u_readlink_t*, pms);
	ms->ms_retval = u_readlink(ms->ms_pathname, ms->ms_buf, ms->ms_bufsize);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sysconf(void* pms)
{
	ms_u_sysconf_t* ms = SGX_CAST(ms_u_sysconf_t*, pms);
	ms->ms_retval = u_sysconf(ms->ms_name);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_rename(void* pms)
{
	ms_u_rename_t* ms = SGX_CAST(ms_u_rename_t*, pms);
	ms->ms_retval = u_rename(ms->ms_oldpath, ms->ms_newpath);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_remove(void* pms)
{
	ms_u_remove_t* ms = SGX_CAST(ms_u_remove_t*, pms);
	ms->ms_retval = u_remove(ms->ms_pathname);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getenv(void* pms)
{
	ms_u_getenv_t* ms = SGX_CAST(ms_u_getenv_t*, pms);
	ms->ms_retval = u_getenv(ms->ms_name);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getgrgid_r(void* pms)
{
	ms_u_getgrgid_r_t* ms = SGX_CAST(ms_u_getgrgid_r_t*, pms);
	ms->ms_retval = u_getgrgid_r(ms->ms_gid, ms->ms_grp, ms->ms_buf, ms->ms_buflen, ms->ms_result);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getpwuid(void* pms)
{
	ms_u_getpwuid_t* ms = SGX_CAST(ms_u_getpwuid_t*, pms);
	ms->ms_retval = u_getpwuid(ms->ms_uid);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getpwuid_r(void* pms)
{
	ms_u_getpwuid_r_t* ms = SGX_CAST(ms_u_getpwuid_r_t*, pms);
	ms->ms_retval = u_getpwuid_r(ms->ms_uid, ms->ms_pwd, ms->ms_buf, ms->ms_buflen, ms->ms_result);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_fpathconf(void* pms)
{
	ms_u_fpathconf_t* ms = SGX_CAST(ms_u_fpathconf_t*, pms);
	ms->ms_retval = u_fpathconf(ms->ms_fd, ms->ms_name);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_pathconf(void* pms)
{
	ms_u_pathconf_t* ms = SGX_CAST(ms_u_pathconf_t*, pms);
	ms->ms_retval = u_pathconf(ms->ms_path, ms->ms_name);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_time(void* pms)
{
	ms_u_time_t* ms = SGX_CAST(ms_u_time_t*, pms);
	ms->ms_retval = u_time(ms->ms_tloc);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_utimes(void* pms)
{
	ms_u_utimes_t* ms = SGX_CAST(ms_u_utimes_t*, pms);
	ms->ms_retval = u_utimes(ms->ms_filename, ms->ms_times);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_localtime(void* pms)
{
	ms_u_localtime_t* ms = SGX_CAST(ms_u_localtime_t*, pms);
	ms->ms_retval = u_localtime(ms->ms_t);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_gettimeofday(void* pms)
{
	ms_u_gettimeofday_t* ms = SGX_CAST(ms_u_gettimeofday_t*, pms);
	ms->ms_retval = u_gettimeofday(ms->ms_tv);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_clock_gettime(void* pms)
{
	ms_u_clock_gettime_t* ms = SGX_CAST(ms_u_clock_gettime_t*, pms);
	ms->ms_retval = u_clock_gettime(ms->ms_clk_id, ms->ms_tp);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getaddrinfo(void* pms)
{
	ms_u_getaddrinfo_t* ms = SGX_CAST(ms_u_getaddrinfo_t*, pms);
	ms->ms_retval = u_getaddrinfo(ms->ms_node, ms->ms_service, ms->ms_hints, ms->ms_res);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_freeaddrinfo(void* pms)
{
	ms_u_freeaddrinfo_t* ms = SGX_CAST(ms_u_freeaddrinfo_t*, pms);
	u_freeaddrinfo(ms->ms_res);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_getnameinfo(void* pms)
{
	ms_u_getnameinfo_t* ms = SGX_CAST(ms_u_getnameinfo_t*, pms);
	ms->ms_retval = u_getnameinfo(ms->ms_sa, ms->ms_salen, ms->ms_host, ms->ms_hostlen, ms->ms_serv, ms->ms_servlen, ms->ms_flags);
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_gai_strerror(void* pms)
{
	ms_u_gai_strerror_t* ms = SGX_CAST(ms_u_gai_strerror_t*, pms);
	ms->ms_retval = u_gai_strerror(ms->ms_errcode);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_u_sched_yield(void* pms)
{
	ms_u_sched_yield_t* ms = SGX_CAST(ms_u_sched_yield_t*, pms);
	ms->ms_retval = u_sched_yield();
	ms->ocall_errno = errno;
	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[113];
} ocall_table_Enclave = {
	113,
	{
		(void*)Enclave_u_opendir,
		(void*)Enclave_u_readdir,
		(void*)Enclave_u_rewinddir,
		(void*)Enclave_u_closedir,
		(void*)Enclave_u_telldir,
		(void*)Enclave_u_seekdir,
		(void*)Enclave_u_getdents64,
		(void*)Enclave_u_fcntl,
		(void*)Enclave_u_open,
		(void*)Enclave_u_openat,
		(void*)Enclave_u_stat,
		(void*)Enclave_u_lstat,
		(void*)Enclave_u_fstat,
		(void*)Enclave_u_mkdir,
		(void*)Enclave_u_fchmod,
		(void*)Enclave_u_socket,
		(void*)Enclave_u_bind,
		(void*)Enclave_u_listen,
		(void*)Enclave_u_accept,
		(void*)Enclave_u_connect,
		(void*)Enclave_u_send,
		(void*)Enclave_u_sendto,
		(void*)Enclave_u_sendmsg,
		(void*)Enclave_u_recv,
		(void*)Enclave_u_recvfrom,
		(void*)Enclave_u_recvmsg,
		(void*)Enclave_u_getsockopt,
		(void*)Enclave_u_setsockopt,
		(void*)Enclave_u_poll,
		(void*)Enclave_u_select,
		(void*)Enclave_u_getsockname,
		(void*)Enclave_u_getpeername,
		(void*)Enclave_u_socketpair,
		(void*)Enclave_u_shutdown,
		(void*)Enclave_u_realpath,
		(void*)Enclave_u_fprintf,
		(void*)Enclave_u_fgets,
		(void*)Enclave_u_fopen,
		(void*)Enclave_u_fdopen,
		(void*)Enclave_u_fclose,
		(void*)Enclave_u_fread,
		(void*)Enclave_u_fwrite,
		(void*)Enclave_u_rewind,
		(void*)Enclave_u_fflush,
		(void*)Enclave_u_clearerr,
		(void*)Enclave_u_feof,
		(void*)Enclave_u_ferror,
		(void*)Enclave_u_fileno,
		(void*)Enclave_u_getline,
		(void*)Enclave_u_getdelim,
		(void*)Enclave_u_malloc,
		(void*)Enclave_u_free,
		(void*)Enclave_u_uname,
		(void*)Enclave_u_epoll_create1,
		(void*)Enclave_u_epoll_wait,
		(void*)Enclave_u_epoll_ctl,
		(void*)Enclave_u_mount,
		(void*)Enclave_u_umount2,
		(void*)Enclave_u_gethostname,
		(void*)Enclave_u_getdomainname,
		(void*)Enclave_u_getcwd,
		(void*)Enclave_u_chdir,
		(void*)Enclave_u_nanosleep,
		(void*)Enclave_u_clock_nanosleep,
		(void*)Enclave_u_getpid,
		(void*)Enclave_u_getppid,
		(void*)Enclave_u_getpgrp,
		(void*)Enclave_u_getuid,
		(void*)Enclave_u_geteuid,
		(void*)Enclave_u_getgid,
		(void*)Enclave_u_getegid,
		(void*)Enclave_u_getpgid,
		(void*)Enclave_u_getgroups,
		(void*)Enclave_u_read,
		(void*)Enclave_u_write,
		(void*)Enclave_u_close,
		(void*)Enclave_u_flock,
		(void*)Enclave_u_fsync,
		(void*)Enclave_u_fdatasync,
		(void*)Enclave_u_fchown,
		(void*)Enclave_u_dup,
		(void*)Enclave_u_dup2,
		(void*)Enclave_u_rmdir,
		(void*)Enclave_u_link,
		(void*)Enclave_u_unlink,
		(void*)Enclave_u_truncate,
		(void*)Enclave_u_ftruncate,
		(void*)Enclave_u_lseek,
		(void*)Enclave_u_pread,
		(void*)Enclave_u_pwrite,
		(void*)Enclave_u_readv,
		(void*)Enclave_u_writev,
		(void*)Enclave_u_access,
		(void*)Enclave_u_readlink,
		(void*)Enclave_u_sysconf,
		(void*)Enclave_u_rename,
		(void*)Enclave_u_remove,
		(void*)Enclave_u_getenv,
		(void*)Enclave_u_getgrgid_r,
		(void*)Enclave_u_getpwuid,
		(void*)Enclave_u_getpwuid_r,
		(void*)Enclave_u_fpathconf,
		(void*)Enclave_u_pathconf,
		(void*)Enclave_u_time,
		(void*)Enclave_u_utimes,
		(void*)Enclave_u_localtime,
		(void*)Enclave_u_gettimeofday,
		(void*)Enclave_u_clock_gettime,
		(void*)Enclave_u_getaddrinfo,
		(void*)Enclave_u_freeaddrinfo,
		(void*)Enclave_u_getnameinfo,
		(void*)Enclave_u_gai_strerror,
		(void*)Enclave_u_sched_yield,
	}
};
sgx_status_t ecall_printf(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_memset_s(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_memset_s_t ms;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_fchmod(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_fchmod_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_socket_receiver(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_socket_sender(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_time(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_time_t ms;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_mmap(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_mmap_t ms;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

