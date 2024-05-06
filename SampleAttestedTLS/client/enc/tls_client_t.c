#include "tls_client_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_launch_tls_client_t {
	int ms_retval;
	char* ms_server_name;
	size_t ms_server_name_len;
	char* ms_server_port;
	size_t ms_server_port_len;
	const char* ms_input_file;
	size_t ms_input_file_len;
	const char* ms_output_file;
	size_t ms_output_file_len;
} ms_launch_tls_client_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_u_sgxssl_write_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	const void* ms_buf;
	size_t ms_n;
} ms_u_sgxssl_write_t;

typedef struct ms_u_sgxssl_read_t {
	ssize_t ms_retval;
	int ocall_errno;
	int ms_fd;
	void* ms_buf;
	size_t ms_count;
} ms_u_sgxssl_read_t;

typedef struct ms_u_sgxssl_close_t {
	int ms_retval;
	int ocall_errno;
	int ms_fd;
} ms_u_sgxssl_close_t;

typedef struct ms_u_sgxssl_open_t {
	int ms_retval;
	int ocall_errno;
	const char* ms_fname;
	int ms_flags;
} ms_u_sgxssl_open_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

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

static sgx_status_t SGX_CDECL sgx_launch_tls_client(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_launch_tls_client_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_launch_tls_client_t* ms = SGX_CAST(ms_launch_tls_client_t*, pms);
	ms_launch_tls_client_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_launch_tls_client_t), ms, sizeof(ms_launch_tls_client_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_server_name = __in_ms.ms_server_name;
	size_t _len_server_name = __in_ms.ms_server_name_len ;
	char* _in_server_name = NULL;
	char* _tmp_server_port = __in_ms.ms_server_port;
	size_t _len_server_port = __in_ms.ms_server_port_len ;
	char* _in_server_port = NULL;
	const char* _tmp_input_file = __in_ms.ms_input_file;
	size_t _len_input_file = __in_ms.ms_input_file_len ;
	char* _in_input_file = NULL;
	const char* _tmp_output_file = __in_ms.ms_output_file;
	size_t _len_output_file = __in_ms.ms_output_file_len ;
	char* _in_output_file = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_server_name, _len_server_name);
	CHECK_UNIQUE_POINTER(_tmp_server_port, _len_server_port);
	CHECK_UNIQUE_POINTER(_tmp_input_file, _len_input_file);
	CHECK_UNIQUE_POINTER(_tmp_output_file, _len_output_file);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_server_name != NULL && _len_server_name != 0) {
		_in_server_name = (char*)malloc(_len_server_name);
		if (_in_server_name == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_server_name, _len_server_name, _tmp_server_name, _len_server_name)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_server_name[_len_server_name - 1] = '\0';
		if (_len_server_name != strlen(_in_server_name) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_server_port != NULL && _len_server_port != 0) {
		_in_server_port = (char*)malloc(_len_server_port);
		if (_in_server_port == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_server_port, _len_server_port, _tmp_server_port, _len_server_port)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_server_port[_len_server_port - 1] = '\0';
		if (_len_server_port != strlen(_in_server_port) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_input_file != NULL && _len_input_file != 0) {
		_in_input_file = (char*)malloc(_len_input_file);
		if (_in_input_file == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_input_file, _len_input_file, _tmp_input_file, _len_input_file)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_input_file[_len_input_file - 1] = '\0';
		if (_len_input_file != strlen(_in_input_file) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_output_file != NULL && _len_output_file != 0) {
		_in_output_file = (char*)malloc(_len_output_file);
		if (_in_output_file == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_output_file, _len_output_file, _tmp_output_file, _len_output_file)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_output_file[_len_output_file - 1] = '\0';
		if (_len_output_file != strlen(_in_output_file) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	_in_retval = launch_tls_client(_in_server_name, _in_server_port, (const char*)_in_input_file, (const char*)_in_output_file);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	if (_in_server_name) free(_in_server_name);
	if (_in_server_port) free(_in_server_port);
	if (_in_input_file) free(_in_input_file);
	if (_in_output_file) free(_in_output_file);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[1];
} g_ecall_table = {
	1,
	{
		{(void*)(uintptr_t)sgx_launch_tls_client, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[126][1];
} g_dyn_entry_table = {
	126,
	{
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
		{0, },
	}
};


sgx_status_t SGX_CDECL u_sgxssl_ftime(void* timeptr, uint32_t timeb_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_timeptr = timeb_len;

	ms_u_sgxssl_ftime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_ftime_t);
	void *__tmp = NULL;

	void *__tmp_timeptr = NULL;

	CHECK_ENCLAVE_POINTER(timeptr, _len_timeptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeptr != NULL) ? _len_timeptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_ftime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_ftime_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_ftime_t);

	if (timeptr != NULL) {
		if (memcpy_verw_s(&ms->ms_timeptr, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_timeptr = __tmp;
		memset_verw(__tmp_timeptr, 0, _len_timeptr);
		__tmp = (void *)((size_t)__tmp + _len_timeptr);
		ocalloc_size -= _len_timeptr;
	} else {
		ms->ms_timeptr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_timeb_len, sizeof(ms->ms_timeb_len), &timeb_len, sizeof(timeb_len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (timeptr) {
			if (memcpy_s((void*)timeptr, _len_timeptr, __tmp_timeptr, _len_timeptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_write(ssize_t* retval, int fd, const void* buf, size_t n)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;

	ms_u_sgxssl_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_write_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_write_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_write_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_n, sizeof(ms->ms_n), &n, sizeof(n))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_read(ssize_t* retval, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_u_sgxssl_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_read_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_read_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_read_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_count, sizeof(ms->ms_count), &count, sizeof(count))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_close(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sgxssl_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_close_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_close_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sgxssl_open(int* retval, const char* fname, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sgxssl_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sgxssl_open_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sgxssl_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sgxssl_open_t));
	ocalloc_size -= sizeof(ms_u_sgxssl_open_t);

	if (memcpy_verw_s(&ms->ms_fname, sizeof(ms->ms_fname), &fname, sizeof(fname))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		if (memcpy_verw_s(&ms->ms_cpuinfo, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}

	if (memcpy_verw_s(&ms->ms_leaf, sizeof(ms->ms_leaf), &leaf, sizeof(leaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_subleaf, sizeof(ms->ms_subleaf), &subleaf, sizeof(subleaf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		if (memcpy_verw_s(&ms->ms_waiters, sizeof(const void**), &__tmp, sizeof(const void**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}

	if (memcpy_verw_s(&ms->ms_total, sizeof(ms->ms_total), &total, sizeof(total))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wait_timeout_ocall(int* retval, unsigned long long waiter, unsigned long long timeout)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wait_timeout_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wait_timeout_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wait_timeout_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wait_timeout_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wait_timeout_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_create_ocall(int* retval, unsigned long long self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_create_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_create_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_create_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_create_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_create_ocall_t);

	if (memcpy_verw_s(&ms->ms_self, sizeof(ms->ms_self), &self, sizeof(self))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL pthread_wakeup_ocall(int* retval, unsigned long long waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_pthread_wakeup_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_pthread_wakeup_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_pthread_wakeup_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_pthread_wakeup_ocall_t));
	ocalloc_size -= sizeof(ms_pthread_wakeup_ocall_t);

	if (memcpy_verw_s(&ms->ms_waiter, sizeof(ms->ms_waiter), &waiter, sizeof(waiter))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_opendir(DIR** retval, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_u_opendir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_opendir_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(name, _len_name);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (name != NULL) ? _len_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_opendir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_opendir_t));
	ocalloc_size -= sizeof(ms_u_opendir_t);

	if (name != NULL) {
		if (memcpy_verw_s(&ms->ms_name, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_name % sizeof(*name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, name, _len_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_name);
		ocalloc_size -= _len_name;
	} else {
		ms->ms_name = NULL;
	}

	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_readdir(struct dirent** retval, DIR* dirp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_readdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_readdir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_readdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_readdir_t));
	ocalloc_size -= sizeof(ms_u_readdir_t);

	if (memcpy_verw_s(&ms->ms_dirp, sizeof(ms->ms_dirp), &dirp, sizeof(dirp))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_rewinddir(DIR* dirp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_rewinddir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_rewinddir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_rewinddir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_rewinddir_t));
	ocalloc_size -= sizeof(ms_u_rewinddir_t);

	if (memcpy_verw_s(&ms->ms_dirp, sizeof(ms->ms_dirp), &dirp, sizeof(dirp))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_closedir(int* retval, DIR* dirp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_closedir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_closedir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_closedir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_closedir_t));
	ocalloc_size -= sizeof(ms_u_closedir_t);

	if (memcpy_verw_s(&ms->ms_dirp, sizeof(ms->ms_dirp), &dirp, sizeof(dirp))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_telldir(long int* retval, DIR* dirp)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_telldir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_telldir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_telldir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_telldir_t));
	ocalloc_size -= sizeof(ms_u_telldir_t);

	if (memcpy_verw_s(&ms->ms_dirp, sizeof(ms->ms_dirp), &dirp, sizeof(dirp))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_seekdir(DIR* dirp, long int loc)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_seekdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_seekdir_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_seekdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_seekdir_t));
	ocalloc_size -= sizeof(ms_u_seekdir_t);

	if (memcpy_verw_s(&ms->ms_dirp, sizeof(ms->ms_dirp), &dirp, sizeof(dirp))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_loc, sizeof(ms->ms_loc), &loc, sizeof(loc))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getdents64(int* retval, unsigned int fd, struct dirent* dirp, unsigned int count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dirp = count;

	ms_u_getdents64_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getdents64_t);
	void *__tmp = NULL;

	void *__tmp_dirp = NULL;

	CHECK_ENCLAVE_POINTER(dirp, _len_dirp);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dirp != NULL) ? _len_dirp : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getdents64_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getdents64_t));
	ocalloc_size -= sizeof(ms_u_getdents64_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (dirp != NULL) {
		if (memcpy_verw_s(&ms->ms_dirp, sizeof(struct dirent*), &__tmp, sizeof(struct dirent*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_dirp = __tmp;
		memset_verw(__tmp_dirp, 0, _len_dirp);
		__tmp = (void *)((size_t)__tmp + _len_dirp);
		ocalloc_size -= _len_dirp;
	} else {
		ms->ms_dirp = NULL;
	}

	if (memcpy_verw_s(&ms->ms_count, sizeof(ms->ms_count), &count, sizeof(count))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (dirp) {
			if (memcpy_s((void*)dirp, _len_dirp, __tmp_dirp, _len_dirp)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fcntl(int* retval, int fd, int cmd, int arg, uint64_t argsize, void* argout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_argout = argsize;

	ms_u_fcntl_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fcntl_t);
	void *__tmp = NULL;

	void *__tmp_argout = NULL;

	CHECK_ENCLAVE_POINTER(argout, _len_argout);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (argout != NULL) ? _len_argout : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fcntl_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fcntl_t));
	ocalloc_size -= sizeof(ms_u_fcntl_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_cmd, sizeof(ms->ms_cmd), &cmd, sizeof(cmd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_arg, sizeof(ms->ms_arg), &arg, sizeof(arg))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_argsize, sizeof(ms->ms_argsize), &argsize, sizeof(argsize))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (argout != NULL) {
		if (memcpy_verw_s(&ms->ms_argout, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_argout = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, argout, _len_argout)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_argout);
		ocalloc_size -= _len_argout;
	} else {
		ms->ms_argout = NULL;
	}

	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (argout) {
			if (memcpy_s((void*)argout, _len_argout, __tmp_argout, _len_argout)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_open(int* retval, const char* pathname, int flags, mode_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_open_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_open_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_open_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_open_t));
	ocalloc_size -= sizeof(ms_u_open_t);

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_mode, sizeof(ms->ms_mode), &mode, sizeof(mode))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_openat(int* retval, int dirfd, const char* pathname, int flags, mode_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_openat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_openat_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_openat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_openat_t));
	ocalloc_size -= sizeof(ms_u_openat_t);

	if (memcpy_verw_s(&ms->ms_dirfd, sizeof(ms->ms_dirfd), &dirfd, sizeof(dirfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_mode, sizeof(ms->ms_mode), &mode, sizeof(mode))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(22, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_stat(int* retval, const char* pathname, struct stat* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_buf = sizeof(struct stat);

	ms_u_stat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_stat_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_stat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_stat_t));
	ocalloc_size -= sizeof(ms_u_stat_t);

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(struct stat*), &__tmp, sizeof(struct stat*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	status = sgx_ocall(23, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_lstat(int* retval, const char* pathname, struct stat* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_buf = sizeof(struct stat);

	ms_u_lstat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_lstat_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_lstat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_lstat_t));
	ocalloc_size -= sizeof(ms_u_lstat_t);

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(struct stat*), &__tmp, sizeof(struct stat*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	status = sgx_ocall(24, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fstat(int* retval, int fd, struct stat* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = sizeof(struct stat);

	ms_u_fstat_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fstat_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fstat_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fstat_t));
	ocalloc_size -= sizeof(ms_u_fstat_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(struct stat*), &__tmp, sizeof(struct stat*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	status = sgx_ocall(25, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_mkdir(int* retval, const char* pathname, mode_t mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_mkdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_mkdir_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_mkdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_mkdir_t));
	ocalloc_size -= sizeof(ms_u_mkdir_t);

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	if (memcpy_verw_s(&ms->ms_mode, sizeof(ms->ms_mode), &mode, sizeof(mode))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(26, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fchmod(int* retval, int fd, mode_t mode)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_fchmod_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fchmod_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fchmod_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fchmod_t));
	ocalloc_size -= sizeof(ms_u_fchmod_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_mode, sizeof(ms->ms_mode), &mode, sizeof(mode))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(27, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_socket(int* retval, int domain, int type, int protocol)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_socket_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_socket_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_socket_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_socket_t));
	ocalloc_size -= sizeof(ms_u_socket_t);

	if (memcpy_verw_s(&ms->ms_domain, sizeof(ms->ms_domain), &domain, sizeof(domain))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_type, sizeof(ms->ms_type), &type, sizeof(type))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_protocol, sizeof(ms->ms_protocol), &protocol, sizeof(protocol))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(28, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_bind(int* retval, int fd, const struct sockaddr* addr, socklen_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = len;

	ms_u_bind_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_bind_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(addr, _len_addr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_bind_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_bind_t));
	ocalloc_size -= sizeof(ms_u_bind_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(const struct sockaddr*), &__tmp, sizeof(const struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(29, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_listen(int* retval, int fd, int n)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_listen_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_listen_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_listen_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_listen_t));
	ocalloc_size -= sizeof(ms_u_listen_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_n, sizeof(ms->ms_n), &n, sizeof(n))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(30, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_accept(int* retval, int fd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = addrlen_in;
	size_t _len_addrlen_out = sizeof(socklen_t);

	ms_u_accept_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_accept_t);
	void *__tmp = NULL;

	void *__tmp_addr = NULL;
	void *__tmp_addrlen_out = NULL;

	CHECK_ENCLAVE_POINTER(addr, _len_addr);
	CHECK_ENCLAVE_POINTER(addrlen_out, _len_addrlen_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addrlen_out != NULL) ? _len_addrlen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_accept_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_accept_t));
	ocalloc_size -= sizeof(ms_u_accept_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(struct sockaddr*), &__tmp, sizeof(struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addr = __tmp;
		memset_verw(__tmp_addr, 0, _len_addr);
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addrlen_in, sizeof(ms->ms_addrlen_in), &addrlen_in, sizeof(addrlen_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addrlen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_addrlen_out, sizeof(socklen_t*), &__tmp, sizeof(socklen_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addrlen_out = __tmp;
		memset_verw(__tmp_addrlen_out, 0, _len_addrlen_out);
		__tmp = (void *)((size_t)__tmp + _len_addrlen_out);
		ocalloc_size -= _len_addrlen_out;
	} else {
		ms->ms_addrlen_out = NULL;
	}

	status = sgx_ocall(31, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addr) {
			if (memcpy_s((void*)addr, _len_addr, __tmp_addr, _len_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen_out) {
			if (memcpy_s((void*)addrlen_out, _len_addrlen_out, __tmp_addrlen_out, _len_addrlen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_connect(int* retval, int fd, const struct sockaddr* addr, socklen_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = len;

	ms_u_connect_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_connect_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(addr, _len_addr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_connect_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_connect_t));
	ocalloc_size -= sizeof(ms_u_connect_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(const struct sockaddr*), &__tmp, sizeof(const struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(32, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_send(ssize_t* retval, int fd, const void* buf, size_t n, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;

	ms_u_send_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_send_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_send_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_send_t));
	ocalloc_size -= sizeof(ms_u_send_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_n, sizeof(ms->ms_n), &n, sizeof(n))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(33, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sendto(ssize_t* retval, int fd, const void* buf, size_t n, int flags, const struct sockaddr* addr, socklen_t addr_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;
	size_t _len_addr = addr_len;

	ms_u_sendto_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sendto_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(addr, _len_addr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sendto_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sendto_t));
	ocalloc_size -= sizeof(ms_u_sendto_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_n, sizeof(ms->ms_n), &n, sizeof(n))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(const struct sockaddr*), &__tmp, sizeof(const struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, addr, _len_addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addr_len, sizeof(ms->ms_addr_len), &addr_len, sizeof(addr_len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(34, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sendmsg(ssize_t* retval, int sockfd, const struct msghdr* msg, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sendmsg_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sendmsg_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sendmsg_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sendmsg_t));
	ocalloc_size -= sizeof(ms_u_sendmsg_t);

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_msg, sizeof(ms->ms_msg), &msg, sizeof(msg))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(35, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_recv(ssize_t* retval, int fd, void* buf, size_t n, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;

	ms_u_recv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_recv_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_recv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_recv_t));
	ocalloc_size -= sizeof(ms_u_recv_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_n, sizeof(ms->ms_n), &n, sizeof(n))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(36, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_recvfrom(ssize_t* retval, int fd, void* buf, size_t n, int flags, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = n;
	size_t _len_addr = addrlen_in;
	size_t _len_addrlen_out = sizeof(socklen_t);

	ms_u_recvfrom_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_recvfrom_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;
	void *__tmp_addr = NULL;
	void *__tmp_addrlen_out = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);
	CHECK_ENCLAVE_POINTER(addr, _len_addr);
	CHECK_ENCLAVE_POINTER(addrlen_out, _len_addrlen_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addrlen_out != NULL) ? _len_addrlen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_recvfrom_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_recvfrom_t));
	ocalloc_size -= sizeof(ms_u_recvfrom_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_n, sizeof(ms->ms_n), &n, sizeof(n))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(struct sockaddr*), &__tmp, sizeof(struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addr = __tmp;
		memset_verw(__tmp_addr, 0, _len_addr);
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addrlen_in, sizeof(ms->ms_addrlen_in), &addrlen_in, sizeof(addrlen_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addrlen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_addrlen_out, sizeof(socklen_t*), &__tmp, sizeof(socklen_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addrlen_out = __tmp;
		memset_verw(__tmp_addrlen_out, 0, _len_addrlen_out);
		__tmp = (void *)((size_t)__tmp + _len_addrlen_out);
		ocalloc_size -= _len_addrlen_out;
	} else {
		ms->ms_addrlen_out = NULL;
	}

	status = sgx_ocall(37, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addr) {
			if (memcpy_s((void*)addr, _len_addr, __tmp_addr, _len_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen_out) {
			if (memcpy_s((void*)addrlen_out, _len_addrlen_out, __tmp_addrlen_out, _len_addrlen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_recvmsg(ssize_t* retval, int sockfd, struct msghdr* msg, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_recvmsg_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_recvmsg_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_recvmsg_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_recvmsg_t));
	ocalloc_size -= sizeof(ms_u_recvmsg_t);

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_msg, sizeof(ms->ms_msg), &msg, sizeof(msg))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(38, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getsockopt(int* retval, int fd, int level, int optname, void* optval, socklen_t optlen_in, socklen_t* optlen_out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_optval = optlen_in;
	size_t _len_optlen_out = sizeof(socklen_t);

	ms_u_getsockopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getsockopt_t);
	void *__tmp = NULL;

	void *__tmp_optval = NULL;
	void *__tmp_optlen_out = NULL;

	CHECK_ENCLAVE_POINTER(optval, _len_optval);
	CHECK_ENCLAVE_POINTER(optlen_out, _len_optlen_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (optval != NULL) ? _len_optval : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (optlen_out != NULL) ? _len_optlen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getsockopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getsockopt_t));
	ocalloc_size -= sizeof(ms_u_getsockopt_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_level, sizeof(ms->ms_level), &level, sizeof(level))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_optname, sizeof(ms->ms_optname), &optname, sizeof(optname))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (optval != NULL) {
		if (memcpy_verw_s(&ms->ms_optval, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_optval = __tmp;
		memset_verw(__tmp_optval, 0, _len_optval);
		__tmp = (void *)((size_t)__tmp + _len_optval);
		ocalloc_size -= _len_optval;
	} else {
		ms->ms_optval = NULL;
	}

	if (memcpy_verw_s(&ms->ms_optlen_in, sizeof(ms->ms_optlen_in), &optlen_in, sizeof(optlen_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (optlen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_optlen_out, sizeof(socklen_t*), &__tmp, sizeof(socklen_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_optlen_out = __tmp;
		memset_verw(__tmp_optlen_out, 0, _len_optlen_out);
		__tmp = (void *)((size_t)__tmp + _len_optlen_out);
		ocalloc_size -= _len_optlen_out;
	} else {
		ms->ms_optlen_out = NULL;
	}

	status = sgx_ocall(39, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (optval) {
			if (memcpy_s((void*)optval, _len_optval, __tmp_optval, _len_optval)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (optlen_out) {
			if (memcpy_s((void*)optlen_out, _len_optlen_out, __tmp_optlen_out, _len_optlen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_setsockopt(int* retval, int fd, int level, int optname, const void* optval, socklen_t optlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_optval = optlen;

	ms_u_setsockopt_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_setsockopt_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(optval, _len_optval);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (optval != NULL) ? _len_optval : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_setsockopt_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_setsockopt_t));
	ocalloc_size -= sizeof(ms_u_setsockopt_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_level, sizeof(ms->ms_level), &level, sizeof(level))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_optname, sizeof(ms->ms_optname), &optname, sizeof(optname))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (optval != NULL) {
		if (memcpy_verw_s(&ms->ms_optval, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, optval, _len_optval)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_optval);
		ocalloc_size -= _len_optval;
	} else {
		ms->ms_optval = NULL;
	}

	if (memcpy_verw_s(&ms->ms_optlen, sizeof(ms->ms_optlen), &optlen, sizeof(optlen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(40, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_poll(int* retval, struct pollfd* fds, nfds_t nfds, int timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_fds = nfds * sizeof(struct pollfd);

	ms_u_poll_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_poll_t);
	void *__tmp = NULL;

	void *__tmp_fds = NULL;

	CHECK_ENCLAVE_POINTER(fds, _len_fds);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (fds != NULL) ? _len_fds : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_poll_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_poll_t));
	ocalloc_size -= sizeof(ms_u_poll_t);

	if (fds != NULL) {
		if (memcpy_verw_s(&ms->ms_fds, sizeof(struct pollfd*), &__tmp, sizeof(struct pollfd*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_fds = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, fds, _len_fds)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_fds);
		ocalloc_size -= _len_fds;
	} else {
		ms->ms_fds = NULL;
	}

	if (memcpy_verw_s(&ms->ms_nfds, sizeof(ms->ms_nfds), &nfds, sizeof(nfds))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(41, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (fds) {
			if (memcpy_s((void*)fds, _len_fds, __tmp_fds, _len_fds)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_select(int* retval, int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_readfds = sizeof(fd_set);
	size_t _len_writefds = sizeof(fd_set);
	size_t _len_exceptfds = sizeof(fd_set);
	size_t _len_timeout = sizeof(struct timeval);

	ms_u_select_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_select_t);
	void *__tmp = NULL;

	void *__tmp_readfds = NULL;
	void *__tmp_writefds = NULL;
	void *__tmp_exceptfds = NULL;
	void *__tmp_timeout = NULL;

	CHECK_ENCLAVE_POINTER(readfds, _len_readfds);
	CHECK_ENCLAVE_POINTER(writefds, _len_writefds);
	CHECK_ENCLAVE_POINTER(exceptfds, _len_exceptfds);
	CHECK_ENCLAVE_POINTER(timeout, _len_timeout);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (readfds != NULL) ? _len_readfds : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (writefds != NULL) ? _len_writefds : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (exceptfds != NULL) ? _len_exceptfds : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (timeout != NULL) ? _len_timeout : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_select_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_select_t));
	ocalloc_size -= sizeof(ms_u_select_t);

	if (memcpy_verw_s(&ms->ms_nfds, sizeof(ms->ms_nfds), &nfds, sizeof(nfds))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (readfds != NULL) {
		if (memcpy_verw_s(&ms->ms_readfds, sizeof(fd_set*), &__tmp, sizeof(fd_set*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_readfds = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, readfds, _len_readfds)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_readfds);
		ocalloc_size -= _len_readfds;
	} else {
		ms->ms_readfds = NULL;
	}

	if (writefds != NULL) {
		if (memcpy_verw_s(&ms->ms_writefds, sizeof(fd_set*), &__tmp, sizeof(fd_set*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_writefds = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, writefds, _len_writefds)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_writefds);
		ocalloc_size -= _len_writefds;
	} else {
		ms->ms_writefds = NULL;
	}

	if (exceptfds != NULL) {
		if (memcpy_verw_s(&ms->ms_exceptfds, sizeof(fd_set*), &__tmp, sizeof(fd_set*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_exceptfds = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, exceptfds, _len_exceptfds)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_exceptfds);
		ocalloc_size -= _len_exceptfds;
	} else {
		ms->ms_exceptfds = NULL;
	}

	if (timeout != NULL) {
		if (memcpy_verw_s(&ms->ms_timeout, sizeof(struct timeval*), &__tmp, sizeof(struct timeval*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_timeout = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, timeout, _len_timeout)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_timeout);
		ocalloc_size -= _len_timeout;
	} else {
		ms->ms_timeout = NULL;
	}

	status = sgx_ocall(42, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (readfds) {
			if (memcpy_s((void*)readfds, _len_readfds, __tmp_readfds, _len_readfds)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (writefds) {
			if (memcpy_s((void*)writefds, _len_writefds, __tmp_writefds, _len_writefds)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (exceptfds) {
			if (memcpy_s((void*)exceptfds, _len_exceptfds, __tmp_exceptfds, _len_exceptfds)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (timeout) {
			if (memcpy_s((void*)timeout, _len_timeout, __tmp_timeout, _len_timeout)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getsockname(int* retval, int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = addrlen_in;
	size_t _len_addrlen_out = sizeof(socklen_t);

	ms_u_getsockname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getsockname_t);
	void *__tmp = NULL;

	void *__tmp_addr = NULL;
	void *__tmp_addrlen_out = NULL;

	CHECK_ENCLAVE_POINTER(addr, _len_addr);
	CHECK_ENCLAVE_POINTER(addrlen_out, _len_addrlen_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addrlen_out != NULL) ? _len_addrlen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getsockname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getsockname_t));
	ocalloc_size -= sizeof(ms_u_getsockname_t);

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(struct sockaddr*), &__tmp, sizeof(struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addr = __tmp;
		memset_verw(__tmp_addr, 0, _len_addr);
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addrlen_in, sizeof(ms->ms_addrlen_in), &addrlen_in, sizeof(addrlen_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addrlen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_addrlen_out, sizeof(socklen_t*), &__tmp, sizeof(socklen_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addrlen_out = __tmp;
		memset_verw(__tmp_addrlen_out, 0, _len_addrlen_out);
		__tmp = (void *)((size_t)__tmp + _len_addrlen_out);
		ocalloc_size -= _len_addrlen_out;
	} else {
		ms->ms_addrlen_out = NULL;
	}

	status = sgx_ocall(43, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addr) {
			if (memcpy_s((void*)addr, _len_addr, __tmp_addr, _len_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen_out) {
			if (memcpy_s((void*)addrlen_out, _len_addrlen_out, __tmp_addrlen_out, _len_addrlen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getpeername(int* retval, int sockfd, struct sockaddr* addr, socklen_t addrlen_in, socklen_t* addrlen_out)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_addr = addrlen_in;
	size_t _len_addrlen_out = sizeof(socklen_t);

	ms_u_getpeername_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getpeername_t);
	void *__tmp = NULL;

	void *__tmp_addr = NULL;
	void *__tmp_addrlen_out = NULL;

	CHECK_ENCLAVE_POINTER(addr, _len_addr);
	CHECK_ENCLAVE_POINTER(addrlen_out, _len_addrlen_out);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addr != NULL) ? _len_addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (addrlen_out != NULL) ? _len_addrlen_out : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getpeername_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getpeername_t));
	ocalloc_size -= sizeof(ms_u_getpeername_t);

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addr != NULL) {
		if (memcpy_verw_s(&ms->ms_addr, sizeof(struct sockaddr*), &__tmp, sizeof(struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addr = __tmp;
		memset_verw(__tmp_addr, 0, _len_addr);
		__tmp = (void *)((size_t)__tmp + _len_addr);
		ocalloc_size -= _len_addr;
	} else {
		ms->ms_addr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_addrlen_in, sizeof(ms->ms_addrlen_in), &addrlen_in, sizeof(addrlen_in))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (addrlen_out != NULL) {
		if (memcpy_verw_s(&ms->ms_addrlen_out, sizeof(socklen_t*), &__tmp, sizeof(socklen_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_addrlen_out = __tmp;
		memset_verw(__tmp_addrlen_out, 0, _len_addrlen_out);
		__tmp = (void *)((size_t)__tmp + _len_addrlen_out);
		ocalloc_size -= _len_addrlen_out;
	} else {
		ms->ms_addrlen_out = NULL;
	}

	status = sgx_ocall(44, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addr) {
			if (memcpy_s((void*)addr, _len_addr, __tmp_addr, _len_addr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (addrlen_out) {
			if (memcpy_s((void*)addrlen_out, _len_addrlen_out, __tmp_addrlen_out, _len_addrlen_out)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_socketpair(int* retval, int domain, int type, int protocol, int retfd[2])
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_retfd = 2 * sizeof(int);

	ms_u_socketpair_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_socketpair_t);
	void *__tmp = NULL;

	void *__tmp_retfd = NULL;

	CHECK_ENCLAVE_POINTER(retfd, _len_retfd);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (retfd != NULL) ? _len_retfd : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_socketpair_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_socketpair_t));
	ocalloc_size -= sizeof(ms_u_socketpair_t);

	if (memcpy_verw_s(&ms->ms_domain, sizeof(ms->ms_domain), &domain, sizeof(domain))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_type, sizeof(ms->ms_type), &type, sizeof(type))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_protocol, sizeof(ms->ms_protocol), &protocol, sizeof(protocol))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (retfd != NULL) {
		if (memcpy_verw_s(&ms->ms_retfd, sizeof(int*), &__tmp, sizeof(int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_retfd = __tmp;
		if (_len_retfd % sizeof(*retfd) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_retfd, 0, _len_retfd);
		__tmp = (void *)((size_t)__tmp + _len_retfd);
		ocalloc_size -= _len_retfd;
	} else {
		ms->ms_retfd = NULL;
	}

	status = sgx_ocall(45, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (retfd) {
			if (memcpy_s((void*)retfd, _len_retfd, __tmp_retfd, _len_retfd)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_shutdown(int* retval, int sockfd, int how)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_shutdown_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_shutdown_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_shutdown_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_shutdown_t));
	ocalloc_size -= sizeof(ms_u_shutdown_t);

	if (memcpy_verw_s(&ms->ms_sockfd, sizeof(ms->ms_sockfd), &sockfd, sizeof(sockfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_how, sizeof(ms->ms_how), &how, sizeof(how))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(46, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_realpath(char** retval, const char* path)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_u_realpath_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_realpath_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(path, _len_path);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_realpath_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_realpath_t));
	ocalloc_size -= sizeof(ms_u_realpath_t);

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	status = sgx_ocall(47, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fprintf(FILE* stream, const char* str, size_t maxlen)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_u_fprintf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fprintf_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fprintf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fprintf_t));
	ocalloc_size -= sizeof(ms_u_fprintf_t);

	if (memcpy_verw_s(&ms->ms_stream, sizeof(ms->ms_stream), &stream, sizeof(stream))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (str != NULL) {
		if (memcpy_verw_s(&ms->ms_str, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}

	if (memcpy_verw_s(&ms->ms_maxlen, sizeof(ms->ms_maxlen), &maxlen, sizeof(maxlen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(48, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fgets(char** retval, char* s, int size, FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_s = size;

	ms_u_fgets_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fgets_t);
	void *__tmp = NULL;

	void *__tmp_s = NULL;

	CHECK_ENCLAVE_POINTER(s, _len_s);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (s != NULL) ? _len_s : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fgets_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fgets_t));
	ocalloc_size -= sizeof(ms_u_fgets_t);

	if (s != NULL) {
		if (memcpy_verw_s(&ms->ms_s, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_s = __tmp;
		if (_len_s % sizeof(*s) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_s, 0, _len_s);
		__tmp = (void *)((size_t)__tmp + _len_s);
		ocalloc_size -= _len_s;
	} else {
		ms->ms_s = NULL;
	}

	if (memcpy_verw_s(&ms->ms_size, sizeof(ms->ms_size), &size, sizeof(size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_stream, sizeof(ms->ms_stream), &stream, sizeof(stream))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(49, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (s) {
			if (memcpy_s((void*)s, _len_s, __tmp_s, _len_s)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fopen(FILE** retval, const char* pathname, const char* mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_mode = sizeof(char);

	ms_u_fopen_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fopen_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(mode, _len_mode);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (mode != NULL) ? _len_mode : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fopen_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fopen_t));
	ocalloc_size -= sizeof(ms_u_fopen_t);

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	if (mode != NULL) {
		if (memcpy_verw_s(&ms->ms_mode, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_mode % sizeof(*mode) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, mode, _len_mode)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_mode);
		ocalloc_size -= _len_mode;
	} else {
		ms->ms_mode = NULL;
	}

	status = sgx_ocall(50, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fdopen(FILE** retval, int fd, const char* mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_mode = sizeof(char);

	ms_u_fdopen_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fdopen_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(mode, _len_mode);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (mode != NULL) ? _len_mode : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fdopen_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fdopen_t));
	ocalloc_size -= sizeof(ms_u_fdopen_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (mode != NULL) {
		if (memcpy_verw_s(&ms->ms_mode, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_mode % sizeof(*mode) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, mode, _len_mode)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_mode);
		ocalloc_size -= _len_mode;
	} else {
		ms->ms_mode = NULL;
	}

	status = sgx_ocall(51, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fclose(int* retval, FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_fclose_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fclose_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fclose_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fclose_t));
	ocalloc_size -= sizeof(ms_u_fclose_t);

	if (memcpy_verw_s(&ms->ms_stream, sizeof(ms->ms_stream), &stream, sizeof(stream))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(52, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fread(size_t* retval, void* ptr, size_t size, size_t nmemb, FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ptr = nmemb * size;

	ms_u_fread_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fread_t);
	void *__tmp = NULL;

	void *__tmp_ptr = NULL;

	CHECK_ENCLAVE_POINTER(ptr, _len_ptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ptr != NULL) ? _len_ptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fread_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fread_t));
	ocalloc_size -= sizeof(ms_u_fread_t);

	if (ptr != NULL) {
		if (memcpy_verw_s(&ms->ms_ptr, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_ptr = __tmp;
		memset_verw(__tmp_ptr, 0, _len_ptr);
		__tmp = (void *)((size_t)__tmp + _len_ptr);
		ocalloc_size -= _len_ptr;
	} else {
		ms->ms_ptr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_size, sizeof(ms->ms_size), &size, sizeof(size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_nmemb, sizeof(ms->ms_nmemb), &nmemb, sizeof(nmemb))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_stream, sizeof(ms->ms_stream), &stream, sizeof(stream))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(53, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (ptr) {
			if (memcpy_s((void*)ptr, _len_ptr, __tmp_ptr, _len_ptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fwrite(size_t* retval, const void* ptr, size_t size, size_t nmemb, FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_ptr = nmemb * size;

	ms_u_fwrite_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fwrite_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(ptr, _len_ptr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (ptr != NULL) ? _len_ptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fwrite_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fwrite_t));
	ocalloc_size -= sizeof(ms_u_fwrite_t);

	if (ptr != NULL) {
		if (memcpy_verw_s(&ms->ms_ptr, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, ptr, _len_ptr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_ptr);
		ocalloc_size -= _len_ptr;
	} else {
		ms->ms_ptr = NULL;
	}

	if (memcpy_verw_s(&ms->ms_size, sizeof(ms->ms_size), &size, sizeof(size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_nmemb, sizeof(ms->ms_nmemb), &nmemb, sizeof(nmemb))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_stream, sizeof(ms->ms_stream), &stream, sizeof(stream))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(54, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_rewind(FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_rewind_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_rewind_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_rewind_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_rewind_t));
	ocalloc_size -= sizeof(ms_u_rewind_t);

	if (memcpy_verw_s(&ms->ms_stream, sizeof(ms->ms_stream), &stream, sizeof(stream))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(55, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fflush(int* retval, FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_fflush_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fflush_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fflush_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fflush_t));
	ocalloc_size -= sizeof(ms_u_fflush_t);

	if (memcpy_verw_s(&ms->ms_stream, sizeof(ms->ms_stream), &stream, sizeof(stream))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(56, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_clearerr(FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_clearerr_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_clearerr_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_clearerr_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_clearerr_t));
	ocalloc_size -= sizeof(ms_u_clearerr_t);

	if (memcpy_verw_s(&ms->ms_stream, sizeof(ms->ms_stream), &stream, sizeof(stream))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(57, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_feof(int* retval, FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_feof_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_feof_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_feof_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_feof_t));
	ocalloc_size -= sizeof(ms_u_feof_t);

	if (memcpy_verw_s(&ms->ms_stream, sizeof(ms->ms_stream), &stream, sizeof(stream))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(58, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_ferror(int* retval, FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_ferror_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_ferror_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_ferror_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_ferror_t));
	ocalloc_size -= sizeof(ms_u_ferror_t);

	if (memcpy_verw_s(&ms->ms_stream, sizeof(ms->ms_stream), &stream, sizeof(stream))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(59, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fileno(int* retval, FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_fileno_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fileno_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fileno_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fileno_t));
	ocalloc_size -= sizeof(ms_u_fileno_t);

	if (memcpy_verw_s(&ms->ms_stream, sizeof(ms->ms_stream), &stream, sizeof(stream))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(60, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getline(ssize_t* retval, char** lineptr, size_t* n, FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_lineptr = sizeof(char*);
	size_t _len_n = sizeof(size_t);

	ms_u_getline_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getline_t);
	void *__tmp = NULL;

	void *__tmp_lineptr = NULL;
	void *__tmp_n = NULL;

	CHECK_ENCLAVE_POINTER(lineptr, _len_lineptr);
	CHECK_ENCLAVE_POINTER(n, _len_n);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (lineptr != NULL) ? _len_lineptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (n != NULL) ? _len_n : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getline_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getline_t));
	ocalloc_size -= sizeof(ms_u_getline_t);

	if (lineptr != NULL) {
		if (memcpy_verw_s(&ms->ms_lineptr, sizeof(char**), &__tmp, sizeof(char**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_lineptr = __tmp;
		if (_len_lineptr % sizeof(*lineptr) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, lineptr, _len_lineptr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_lineptr);
		ocalloc_size -= _len_lineptr;
	} else {
		ms->ms_lineptr = NULL;
	}

	if (n != NULL) {
		if (memcpy_verw_s(&ms->ms_n, sizeof(size_t*), &__tmp, sizeof(size_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_n = __tmp;
		if (_len_n % sizeof(*n) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, n, _len_n)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_n);
		ocalloc_size -= _len_n;
	} else {
		ms->ms_n = NULL;
	}

	if (memcpy_verw_s(&ms->ms_stream, sizeof(ms->ms_stream), &stream, sizeof(stream))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(61, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (lineptr) {
			if (memcpy_s((void*)lineptr, _len_lineptr, __tmp_lineptr, _len_lineptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (n) {
			if (memcpy_s((void*)n, _len_n, __tmp_n, _len_n)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getdelim(ssize_t* retval, char** lineptr, size_t* n, int delim, FILE* stream)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_lineptr = sizeof(char*);
	size_t _len_n = sizeof(size_t);

	ms_u_getdelim_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getdelim_t);
	void *__tmp = NULL;

	void *__tmp_lineptr = NULL;
	void *__tmp_n = NULL;

	CHECK_ENCLAVE_POINTER(lineptr, _len_lineptr);
	CHECK_ENCLAVE_POINTER(n, _len_n);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (lineptr != NULL) ? _len_lineptr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (n != NULL) ? _len_n : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getdelim_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getdelim_t));
	ocalloc_size -= sizeof(ms_u_getdelim_t);

	if (lineptr != NULL) {
		if (memcpy_verw_s(&ms->ms_lineptr, sizeof(char**), &__tmp, sizeof(char**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_lineptr = __tmp;
		if (_len_lineptr % sizeof(*lineptr) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, lineptr, _len_lineptr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_lineptr);
		ocalloc_size -= _len_lineptr;
	} else {
		ms->ms_lineptr = NULL;
	}

	if (n != NULL) {
		if (memcpy_verw_s(&ms->ms_n, sizeof(size_t*), &__tmp, sizeof(size_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_n = __tmp;
		if (_len_n % sizeof(*n) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, n, _len_n)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_n);
		ocalloc_size -= _len_n;
	} else {
		ms->ms_n = NULL;
	}

	if (memcpy_verw_s(&ms->ms_delim, sizeof(ms->ms_delim), &delim, sizeof(delim))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_stream, sizeof(ms->ms_stream), &stream, sizeof(stream))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(62, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (lineptr) {
			if (memcpy_s((void*)lineptr, _len_lineptr, __tmp_lineptr, _len_lineptr)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (n) {
			if (memcpy_s((void*)n, _len_n, __tmp_n, _len_n)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_malloc(void** retval, size_t size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_malloc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_malloc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_malloc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_malloc_t));
	ocalloc_size -= sizeof(ms_u_malloc_t);

	if (memcpy_verw_s(&ms->ms_size, sizeof(ms->ms_size), &size, sizeof(size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(63, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_free(void* ptr)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_free_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_free_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_free_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_free_t));
	ocalloc_size -= sizeof(ms_u_free_t);

	if (memcpy_verw_s(&ms->ms_ptr, sizeof(ms->ms_ptr), &ptr, sizeof(ptr))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(64, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_uname(int* retval, struct utsname* buf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = sizeof(struct utsname);

	ms_u_uname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_uname_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_uname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_uname_t));
	ocalloc_size -= sizeof(ms_u_uname_t);

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(struct utsname*), &__tmp, sizeof(struct utsname*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	status = sgx_ocall(65, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_epoll_create1(int* retval, int flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_epoll_create1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_epoll_create1_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_epoll_create1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_epoll_create1_t));
	ocalloc_size -= sizeof(ms_u_epoll_create1_t);

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(66, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_epoll_wait(int* retval, int epfd, struct epoll_event* events, unsigned int maxevents, int timeout)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_events = maxevents * sizeof(struct epoll_event);

	ms_u_epoll_wait_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_epoll_wait_t);
	void *__tmp = NULL;

	void *__tmp_events = NULL;

	CHECK_ENCLAVE_POINTER(events, _len_events);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (events != NULL) ? _len_events : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_epoll_wait_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_epoll_wait_t));
	ocalloc_size -= sizeof(ms_u_epoll_wait_t);

	if (memcpy_verw_s(&ms->ms_epfd, sizeof(ms->ms_epfd), &epfd, sizeof(epfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (events != NULL) {
		if (memcpy_verw_s(&ms->ms_events, sizeof(struct epoll_event*), &__tmp, sizeof(struct epoll_event*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_events = __tmp;
		memset_verw(__tmp_events, 0, _len_events);
		__tmp = (void *)((size_t)__tmp + _len_events);
		ocalloc_size -= _len_events;
	} else {
		ms->ms_events = NULL;
	}

	if (memcpy_verw_s(&ms->ms_maxevents, sizeof(ms->ms_maxevents), &maxevents, sizeof(maxevents))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_timeout, sizeof(ms->ms_timeout), &timeout, sizeof(timeout))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(67, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (events) {
			if (memcpy_s((void*)events, _len_events, __tmp_events, _len_events)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_epoll_ctl(int* retval, int epfd, int op, int fd, struct epoll_event* event)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_event = sizeof(struct epoll_event);

	ms_u_epoll_ctl_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_epoll_ctl_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(event, _len_event);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (event != NULL) ? _len_event : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_epoll_ctl_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_epoll_ctl_t));
	ocalloc_size -= sizeof(ms_u_epoll_ctl_t);

	if (memcpy_verw_s(&ms->ms_epfd, sizeof(ms->ms_epfd), &epfd, sizeof(epfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_op, sizeof(ms->ms_op), &op, sizeof(op))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (event != NULL) {
		if (memcpy_verw_s(&ms->ms_event, sizeof(struct epoll_event*), &__tmp, sizeof(struct epoll_event*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, event, _len_event)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_event);
		ocalloc_size -= _len_event;
	} else {
		ms->ms_event = NULL;
	}

	status = sgx_ocall(68, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_mount(int* retval, const char* source, const char* target, const char* filesystemtype, unsigned long int mountflags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_source = source ? strlen(source) + 1 : 0;
	size_t _len_target = target ? strlen(target) + 1 : 0;
	size_t _len_filesystemtype = filesystemtype ? strlen(filesystemtype) + 1 : 0;

	ms_u_mount_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_mount_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(source, _len_source);
	CHECK_ENCLAVE_POINTER(target, _len_target);
	CHECK_ENCLAVE_POINTER(filesystemtype, _len_filesystemtype);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (source != NULL) ? _len_source : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (target != NULL) ? _len_target : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filesystemtype != NULL) ? _len_filesystemtype : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_mount_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_mount_t));
	ocalloc_size -= sizeof(ms_u_mount_t);

	if (source != NULL) {
		if (memcpy_verw_s(&ms->ms_source, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_source % sizeof(*source) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, source, _len_source)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_source);
		ocalloc_size -= _len_source;
	} else {
		ms->ms_source = NULL;
	}

	if (target != NULL) {
		if (memcpy_verw_s(&ms->ms_target, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_target % sizeof(*target) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, target, _len_target)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_target);
		ocalloc_size -= _len_target;
	} else {
		ms->ms_target = NULL;
	}

	if (filesystemtype != NULL) {
		if (memcpy_verw_s(&ms->ms_filesystemtype, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_filesystemtype % sizeof(*filesystemtype) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, filesystemtype, _len_filesystemtype)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filesystemtype);
		ocalloc_size -= _len_filesystemtype;
	} else {
		ms->ms_filesystemtype = NULL;
	}

	if (memcpy_verw_s(&ms->ms_mountflags, sizeof(ms->ms_mountflags), &mountflags, sizeof(mountflags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(69, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_umount2(int* retval, const char* target, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_target = target ? strlen(target) + 1 : 0;

	ms_u_umount2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_umount2_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(target, _len_target);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (target != NULL) ? _len_target : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_umount2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_umount2_t));
	ocalloc_size -= sizeof(ms_u_umount2_t);

	if (target != NULL) {
		if (memcpy_verw_s(&ms->ms_target, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_target % sizeof(*target) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, target, _len_target)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_target);
		ocalloc_size -= _len_target;
	} else {
		ms->ms_target = NULL;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(70, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_gethostname(int* retval, char* name, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = len;

	ms_u_gethostname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_gethostname_t);
	void *__tmp = NULL;

	void *__tmp_name = NULL;

	CHECK_ENCLAVE_POINTER(name, _len_name);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (name != NULL) ? _len_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_gethostname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_gethostname_t));
	ocalloc_size -= sizeof(ms_u_gethostname_t);

	if (name != NULL) {
		if (memcpy_verw_s(&ms->ms_name, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_name = __tmp;
		if (_len_name % sizeof(*name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_name, 0, _len_name);
		__tmp = (void *)((size_t)__tmp + _len_name);
		ocalloc_size -= _len_name;
	} else {
		ms->ms_name = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(71, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (name) {
			if (memcpy_s((void*)name, _len_name, __tmp_name, _len_name)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getdomainname(int* retval, char* name, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = len;

	ms_u_getdomainname_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getdomainname_t);
	void *__tmp = NULL;

	void *__tmp_name = NULL;

	CHECK_ENCLAVE_POINTER(name, _len_name);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (name != NULL) ? _len_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getdomainname_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getdomainname_t));
	ocalloc_size -= sizeof(ms_u_getdomainname_t);

	if (name != NULL) {
		if (memcpy_verw_s(&ms->ms_name, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_name = __tmp;
		if (_len_name % sizeof(*name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_name, 0, _len_name);
		__tmp = (void *)((size_t)__tmp + _len_name);
		ocalloc_size -= _len_name;
	} else {
		ms->ms_name = NULL;
	}

	if (memcpy_verw_s(&ms->ms_len, sizeof(ms->ms_len), &len, sizeof(len))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(72, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (name) {
			if (memcpy_s((void*)name, _len_name, __tmp_name, _len_name)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getcwd(char** retval, char* buf, size_t size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = size;

	ms_u_getcwd_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getcwd_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getcwd_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getcwd_t));
	ocalloc_size -= sizeof(ms_u_getcwd_t);

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_size, sizeof(ms->ms_size), &size, sizeof(size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(73, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_chdir(int* retval, const char* path)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_u_chdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_chdir_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(path, _len_path);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_chdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_chdir_t));
	ocalloc_size -= sizeof(ms_u_chdir_t);

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	status = sgx_ocall(74, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_nanosleep(int* retval, struct timespec* req, struct timespec* rem)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_req = sizeof(struct timespec);
	size_t _len_rem = sizeof(struct timespec);

	ms_u_nanosleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_nanosleep_t);
	void *__tmp = NULL;

	void *__tmp_rem = NULL;

	CHECK_ENCLAVE_POINTER(req, _len_req);
	CHECK_ENCLAVE_POINTER(rem, _len_rem);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (req != NULL) ? _len_req : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (rem != NULL) ? _len_rem : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_nanosleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_nanosleep_t));
	ocalloc_size -= sizeof(ms_u_nanosleep_t);

	if (req != NULL) {
		if (memcpy_verw_s(&ms->ms_req, sizeof(struct timespec*), &__tmp, sizeof(struct timespec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, req, _len_req)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_req);
		ocalloc_size -= _len_req;
	} else {
		ms->ms_req = NULL;
	}

	if (rem != NULL) {
		if (memcpy_verw_s(&ms->ms_rem, sizeof(struct timespec*), &__tmp, sizeof(struct timespec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_rem = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, rem, _len_rem)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_rem);
		ocalloc_size -= _len_rem;
	} else {
		ms->ms_rem = NULL;
	}

	status = sgx_ocall(75, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (rem) {
			if (memcpy_s((void*)rem, _len_rem, __tmp_rem, _len_rem)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_clock_nanosleep(int* retval, clockid_t clockid, int flag, struct timespec* req, struct timespec* rem)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_req = sizeof(struct timespec);
	size_t _len_rem = sizeof(struct timespec);

	ms_u_clock_nanosleep_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_clock_nanosleep_t);
	void *__tmp = NULL;

	void *__tmp_rem = NULL;

	CHECK_ENCLAVE_POINTER(req, _len_req);
	CHECK_ENCLAVE_POINTER(rem, _len_rem);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (req != NULL) ? _len_req : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (rem != NULL) ? _len_rem : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_clock_nanosleep_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_clock_nanosleep_t));
	ocalloc_size -= sizeof(ms_u_clock_nanosleep_t);

	if (memcpy_verw_s(&ms->ms_clockid, sizeof(ms->ms_clockid), &clockid, sizeof(clockid))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flag, sizeof(ms->ms_flag), &flag, sizeof(flag))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (req != NULL) {
		if (memcpy_verw_s(&ms->ms_req, sizeof(struct timespec*), &__tmp, sizeof(struct timespec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, req, _len_req)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_req);
		ocalloc_size -= _len_req;
	} else {
		ms->ms_req = NULL;
	}

	if (rem != NULL) {
		if (memcpy_verw_s(&ms->ms_rem, sizeof(struct timespec*), &__tmp, sizeof(struct timespec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_rem = __tmp;
		if (memcpy_verw_s(__tmp, ocalloc_size, rem, _len_rem)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_rem);
		ocalloc_size -= _len_rem;
	} else {
		ms->ms_rem = NULL;
	}

	status = sgx_ocall(76, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (rem) {
			if (memcpy_s((void*)rem, _len_rem, __tmp_rem, _len_rem)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getpid(pid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_getpid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getpid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getpid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getpid_t));
	ocalloc_size -= sizeof(ms_u_getpid_t);

	status = sgx_ocall(77, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getppid(pid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_getppid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getppid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getppid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getppid_t));
	ocalloc_size -= sizeof(ms_u_getppid_t);

	status = sgx_ocall(78, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getpgrp(pid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_getpgrp_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getpgrp_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getpgrp_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getpgrp_t));
	ocalloc_size -= sizeof(ms_u_getpgrp_t);

	status = sgx_ocall(79, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getuid(uid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_getuid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getuid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getuid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getuid_t));
	ocalloc_size -= sizeof(ms_u_getuid_t);

	status = sgx_ocall(80, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_geteuid(uid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_geteuid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_geteuid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_geteuid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_geteuid_t));
	ocalloc_size -= sizeof(ms_u_geteuid_t);

	status = sgx_ocall(81, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getgid(gid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_getgid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getgid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getgid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getgid_t));
	ocalloc_size -= sizeof(ms_u_getgid_t);

	status = sgx_ocall(82, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getegid(gid_t* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_getegid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getegid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getegid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getegid_t));
	ocalloc_size -= sizeof(ms_u_getegid_t);

	status = sgx_ocall(83, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getpgid(pid_t* retval, int pid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_getpgid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getpgid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getpgid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getpgid_t));
	ocalloc_size -= sizeof(ms_u_getpgid_t);

	if (memcpy_verw_s(&ms->ms_pid, sizeof(ms->ms_pid), &pid, sizeof(pid))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(84, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getgroups(int* retval, size_t size, unsigned int* list)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_list = size * sizeof(unsigned int);

	ms_u_getgroups_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getgroups_t);
	void *__tmp = NULL;

	void *__tmp_list = NULL;

	CHECK_ENCLAVE_POINTER(list, _len_list);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (list != NULL) ? _len_list : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getgroups_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getgroups_t));
	ocalloc_size -= sizeof(ms_u_getgroups_t);

	if (memcpy_verw_s(&ms->ms_size, sizeof(ms->ms_size), &size, sizeof(size))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (list != NULL) {
		if (memcpy_verw_s(&ms->ms_list, sizeof(unsigned int*), &__tmp, sizeof(unsigned int*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_list = __tmp;
		if (_len_list % sizeof(*list) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_list, 0, _len_list);
		__tmp = (void *)((size_t)__tmp + _len_list);
		ocalloc_size -= _len_list;
	} else {
		ms->ms_list = NULL;
	}

	status = sgx_ocall(85, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (list) {
			if (memcpy_s((void*)list, _len_list, __tmp_list, _len_list)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_read(ssize_t* retval, int fd, void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_u_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_read_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_read_t));
	ocalloc_size -= sizeof(ms_u_read_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_count, sizeof(ms->ms_count), &count, sizeof(count))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(86, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_write(ssize_t* retval, int fd, const void* buf, size_t count)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_u_write_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_write_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_write_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_write_t));
	ocalloc_size -= sizeof(ms_u_write_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_count, sizeof(ms->ms_count), &count, sizeof(count))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(87, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_close(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_close_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_close_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_close_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_close_t));
	ocalloc_size -= sizeof(ms_u_close_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(88, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_flock(int* retval, int fd, int operation)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_flock_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_flock_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_flock_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_flock_t));
	ocalloc_size -= sizeof(ms_u_flock_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_operation, sizeof(ms->ms_operation), &operation, sizeof(operation))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(89, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fsync(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_fsync_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fsync_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fsync_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fsync_t));
	ocalloc_size -= sizeof(ms_u_fsync_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(90, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fdatasync(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_fdatasync_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fdatasync_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fdatasync_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fdatasync_t));
	ocalloc_size -= sizeof(ms_u_fdatasync_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(91, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fchown(int* retval, int fd, unsigned int uid, unsigned int gid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_fchown_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fchown_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fchown_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fchown_t));
	ocalloc_size -= sizeof(ms_u_fchown_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_uid, sizeof(ms->ms_uid), &uid, sizeof(uid))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_gid, sizeof(ms->ms_gid), &gid, sizeof(gid))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(92, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_dup(int* retval, int oldfd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_dup_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_dup_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_dup_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_dup_t));
	ocalloc_size -= sizeof(ms_u_dup_t);

	if (memcpy_verw_s(&ms->ms_oldfd, sizeof(ms->ms_oldfd), &oldfd, sizeof(oldfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(93, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_dup2(int* retval, int oldfd, int newfd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_dup2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_dup2_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_dup2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_dup2_t));
	ocalloc_size -= sizeof(ms_u_dup2_t);

	if (memcpy_verw_s(&ms->ms_oldfd, sizeof(ms->ms_oldfd), &oldfd, sizeof(oldfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_newfd, sizeof(ms->ms_newfd), &newfd, sizeof(newfd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(94, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_rmdir(int* retval, const char* pathname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_rmdir_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_rmdir_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_rmdir_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_rmdir_t));
	ocalloc_size -= sizeof(ms_u_rmdir_t);

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	status = sgx_ocall(95, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_link(int* retval, const char* oldpath, const char* newpath)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_oldpath = oldpath ? strlen(oldpath) + 1 : 0;
	size_t _len_newpath = newpath ? strlen(newpath) + 1 : 0;

	ms_u_link_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_link_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(oldpath, _len_oldpath);
	CHECK_ENCLAVE_POINTER(newpath, _len_newpath);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (oldpath != NULL) ? _len_oldpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (newpath != NULL) ? _len_newpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_link_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_link_t));
	ocalloc_size -= sizeof(ms_u_link_t);

	if (oldpath != NULL) {
		if (memcpy_verw_s(&ms->ms_oldpath, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_oldpath % sizeof(*oldpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, oldpath, _len_oldpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_oldpath);
		ocalloc_size -= _len_oldpath;
	} else {
		ms->ms_oldpath = NULL;
	}

	if (newpath != NULL) {
		if (memcpy_verw_s(&ms->ms_newpath, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_newpath % sizeof(*newpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, newpath, _len_newpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_newpath);
		ocalloc_size -= _len_newpath;
	} else {
		ms->ms_newpath = NULL;
	}

	status = sgx_ocall(96, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_unlink(int* retval, const char* pathname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_unlink_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_unlink_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_unlink_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_unlink_t));
	ocalloc_size -= sizeof(ms_u_unlink_t);

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	status = sgx_ocall(97, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_truncate(int* retval, const char* path, off_t length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_u_truncate_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_truncate_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(path, _len_path);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_truncate_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_truncate_t));
	ocalloc_size -= sizeof(ms_u_truncate_t);

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	if (memcpy_verw_s(&ms->ms_length, sizeof(ms->ms_length), &length, sizeof(length))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(98, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_ftruncate(int* retval, int fd, off_t length)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_ftruncate_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_ftruncate_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_ftruncate_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_ftruncate_t));
	ocalloc_size -= sizeof(ms_u_ftruncate_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_length, sizeof(ms->ms_length), &length, sizeof(length))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(99, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_lseek(off_t* retval, int fd, off_t offset, int whence)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_lseek_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_lseek_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_lseek_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_lseek_t));
	ocalloc_size -= sizeof(ms_u_lseek_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_offset, sizeof(ms->ms_offset), &offset, sizeof(offset))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_whence, sizeof(ms->ms_whence), &whence, sizeof(whence))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(100, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_pread(ssize_t* retval, int fd, void* buf, size_t count, off_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_u_pread_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_pread_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_pread_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_pread_t));
	ocalloc_size -= sizeof(ms_u_pread_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(void*), &__tmp, sizeof(void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_count, sizeof(ms->ms_count), &count, sizeof(count))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_offset, sizeof(ms->ms_offset), &offset, sizeof(offset))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(101, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_pwrite(ssize_t* retval, int fd, const void* buf, size_t count, off_t offset)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = count;

	ms_u_pwrite_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_pwrite_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_pwrite_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_pwrite_t));
	ocalloc_size -= sizeof(ms_u_pwrite_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(const void*), &__tmp, sizeof(const void*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_count, sizeof(ms->ms_count), &count, sizeof(count))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_offset, sizeof(ms->ms_offset), &offset, sizeof(offset))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(102, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_readv(ssize_t* retval, int fd, struct _iovec_t* iov, int iovcnt)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_iov = iovcnt * sizeof(struct _iovec_t);
	struct _iovec_t __local_iov;
	void* __tmp_member_iov = NULL;
	size_t _len_iov_iov_base = 0;
	size_t i = 0;

	ms_u_readv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_readv_t);
	void *__tmp = NULL;

	void *__tmp_iov = NULL;

	CHECK_ENCLAVE_POINTER(iov, _len_iov);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (iov != NULL) ? _len_iov : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_readv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_readv_t));
	ocalloc_size -= sizeof(ms_u_readv_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (iov != NULL) {
		if (memcpy_verw_s(&ms->ms_iov, sizeof(struct _iovec_t*), &__tmp, sizeof(struct _iovec_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_iov = __tmp;
		if (_len_iov % sizeof(*iov) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		for (i = 0; i < _len_iov / sizeof(struct _iovec_t); i++){
			if (memcpy_s(&__local_iov, sizeof(__local_iov), iov + i, sizeof(struct _iovec_t))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
			__local_iov.iov_base = NULL;
			if (memcpy_verw_s((void *)((size_t)__tmp + sizeof(__local_iov) * i), sizeof(__local_iov), &__local_iov, sizeof(__local_iov))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		memset(&__local_iov, 0, sizeof(__local_iov));
		__tmp = (void *)((size_t)__tmp + _len_iov);
		ocalloc_size -= _len_iov;
	} else {
		ms->ms_iov = NULL;
	}

	if (memcpy_verw_s(&ms->ms_iovcnt, sizeof(ms->ms_iovcnt), &iovcnt, sizeof(iovcnt))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (iov != NULL && _len_iov != 0){
		for (i = 0; i < _len_iov / sizeof(struct _iovec_t); i++){
			
			_len_iov_iov_base = (iov + i)->iov_len;
			if ((iov + i)->iov_base && ! sgx_is_within_enclave((iov + i)->iov_base, _len_iov_iov_base)) {
				sgx_ocfree();
				return SGX_ERROR_INVALID_PARAMETER;
			}
				if (ADD_ASSIGN_OVERFLOW(ocalloc_size, ((iov + i)->iov_base != NULL) ? _len_iov_iov_base : 0)) {
				sgx_ocfree();
				return SGX_ERROR_INVALID_PARAMETER;
			}
		}
	}

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (iov != NULL && _len_iov != 0 ) {
		__tmp_member_iov = __tmp;
		for (i = 0; i < _len_iov / sizeof(struct _iovec_t); i++){
			_len_iov_iov_base = (iov + i)->iov_len;
				if ((iov + i)->iov_base != NULL && _len_iov_iov_base != 0) {
					if (memcpy_verw_s(__tmp, _len_iov_iov_base, (iov + i)->iov_base, _len_iov_iov_base) ||
						memcpy_verw_s(&(ms->ms_iov + i)->iov_base, sizeof(void*), &__tmp, sizeof(void*))) {
						sgx_ocfree();
						return SGX_ERROR_UNEXPECTED;
					}
					__tmp = (void *)((size_t)__tmp + _len_iov_iov_base);
					ocalloc_size -= _len_iov_iov_base;
				} else {
					(ms->ms_iov + i)->iov_base = NULL;
				}
		}
	}

	status = sgx_ocall(103, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (iov) {
			for (i = 0; i < _len_iov / sizeof(struct _iovec_t); i++){
				if (memcpy_s(&__local_iov, sizeof(_iovec_t), ((_iovec_t*)__tmp_iov + i), sizeof(_iovec_t))) {
					sgx_ocfree();
					return SGX_ERROR_UNEXPECTED;
				}
				size_t _len_out_iov_iov_base = 0;
				
				_len_iov_iov_base = (iov + i)->iov_len;
				if((iov + i)->iov_base!= NULL &&
						(_len_out_iov_iov_base = __local_iov.iov_len) != 0) {
					if (__local_iov.iov_base != __tmp_member_iov ||
							_len_out_iov_iov_base > _len_iov_iov_base) {
						sgx_ocfree();
						return SGX_ERROR_INVALID_PARAMETER;
					}
					if (memcpy_s((iov + i)->iov_base, _len_iov_iov_base, __tmp_member_iov, _len_out_iov_iov_base)) {
						sgx_ocfree();
						return SGX_ERROR_UNEXPECTED;
					}
				}
				__local_iov.iov_base = (iov + i)->iov_base;
				__tmp_member_iov = (void *)((size_t)__tmp_member_iov + ((iov + i)->iov_base != NULL? _len_iov_iov_base : 0));

				if (memcpy_s((void*)(iov + i), sizeof(__local_iov), &__local_iov, sizeof(__local_iov))) {
					sgx_ocfree();
					return SGX_ERROR_UNEXPECTED;
				}
			}

		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_writev(ssize_t* retval, int fd, struct _iovec_t* iov, int iovcnt)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_iov = iovcnt * sizeof(struct _iovec_t);
	struct _iovec_t __local_iov;
	size_t _len_iov_iov_base = 0;
	size_t i = 0;

	ms_u_writev_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_writev_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(iov, _len_iov);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (iov != NULL) ? _len_iov : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_writev_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_writev_t));
	ocalloc_size -= sizeof(ms_u_writev_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (iov != NULL) {
		if (memcpy_verw_s(&ms->ms_iov, sizeof(struct _iovec_t*), &__tmp, sizeof(struct _iovec_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_iov % sizeof(*iov) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		for (i = 0; i < _len_iov / sizeof(struct _iovec_t); i++){
			if (memcpy_s(&__local_iov, sizeof(__local_iov), iov + i, sizeof(struct _iovec_t))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
			__local_iov.iov_base = NULL;
			if (memcpy_verw_s((void *)((size_t)__tmp + sizeof(__local_iov) * i), sizeof(__local_iov), &__local_iov, sizeof(__local_iov))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		memset(&__local_iov, 0, sizeof(__local_iov));
		__tmp = (void *)((size_t)__tmp + _len_iov);
		ocalloc_size -= _len_iov;
	} else {
		ms->ms_iov = NULL;
	}

	if (memcpy_verw_s(&ms->ms_iovcnt, sizeof(ms->ms_iovcnt), &iovcnt, sizeof(iovcnt))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (iov != NULL && _len_iov != 0){
		for (i = 0; i < _len_iov / sizeof(struct _iovec_t); i++){
			
			_len_iov_iov_base = (iov + i)->iov_len;
			if ((iov + i)->iov_base && ! sgx_is_within_enclave((iov + i)->iov_base, _len_iov_iov_base)) {
				sgx_ocfree();
				return SGX_ERROR_INVALID_PARAMETER;
			}
				if (ADD_ASSIGN_OVERFLOW(ocalloc_size, ((iov + i)->iov_base != NULL) ? _len_iov_iov_base : 0)) {
				sgx_ocfree();
				return SGX_ERROR_INVALID_PARAMETER;
			}
		}
	}

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (iov != NULL && _len_iov != 0 ) {
		for (i = 0; i < _len_iov / sizeof(struct _iovec_t); i++){
			_len_iov_iov_base = (iov + i)->iov_len;
				if ((iov + i)->iov_base != NULL && _len_iov_iov_base != 0) {
					if (memcpy_verw_s(__tmp, _len_iov_iov_base, (iov + i)->iov_base, _len_iov_iov_base) ||
						memcpy_verw_s(&(ms->ms_iov + i)->iov_base, sizeof(void*), &__tmp, sizeof(void*))) {
						sgx_ocfree();
						return SGX_ERROR_UNEXPECTED;
					}
					__tmp = (void *)((size_t)__tmp + _len_iov_iov_base);
					ocalloc_size -= _len_iov_iov_base;
				} else {
					(ms->ms_iov + i)->iov_base = NULL;
				}
		}
	}

	status = sgx_ocall(104, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_access(int* retval, const char* pathname, int mode)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_access_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_access_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_access_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_access_t));
	ocalloc_size -= sizeof(ms_u_access_t);

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	if (memcpy_verw_s(&ms->ms_mode, sizeof(ms->ms_mode), &mode, sizeof(mode))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(105, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_readlink(ssize_t* retval, const char* pathname, char* buf, size_t bufsize)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;
	size_t _len_buf = bufsize;

	ms_u_readlink_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_readlink_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);
	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_readlink_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_readlink_t));
	ocalloc_size -= sizeof(ms_u_readlink_t);

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	if (buf != NULL) {
		if (memcpy_verw_s(&ms->ms_buf, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_buf = __tmp;
		if (_len_buf % sizeof(*buf) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}

	if (memcpy_verw_s(&ms->ms_bufsize, sizeof(ms->ms_bufsize), &bufsize, sizeof(bufsize))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(106, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sysconf(long int* retval, int name)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sysconf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sysconf_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sysconf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sysconf_t));
	ocalloc_size -= sizeof(ms_u_sysconf_t);

	if (memcpy_verw_s(&ms->ms_name, sizeof(ms->ms_name), &name, sizeof(name))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(107, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_rename(int* retval, const char* oldpath, const char* newpath)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_oldpath = oldpath ? strlen(oldpath) + 1 : 0;
	size_t _len_newpath = newpath ? strlen(newpath) + 1 : 0;

	ms_u_rename_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_rename_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(oldpath, _len_oldpath);
	CHECK_ENCLAVE_POINTER(newpath, _len_newpath);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (oldpath != NULL) ? _len_oldpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (newpath != NULL) ? _len_newpath : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_rename_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_rename_t));
	ocalloc_size -= sizeof(ms_u_rename_t);

	if (oldpath != NULL) {
		if (memcpy_verw_s(&ms->ms_oldpath, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_oldpath % sizeof(*oldpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, oldpath, _len_oldpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_oldpath);
		ocalloc_size -= _len_oldpath;
	} else {
		ms->ms_oldpath = NULL;
	}

	if (newpath != NULL) {
		if (memcpy_verw_s(&ms->ms_newpath, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_newpath % sizeof(*newpath) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, newpath, _len_newpath)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_newpath);
		ocalloc_size -= _len_newpath;
	} else {
		ms->ms_newpath = NULL;
	}

	status = sgx_ocall(108, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_remove(int* retval, const char* pathname)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pathname = pathname ? strlen(pathname) + 1 : 0;

	ms_u_remove_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_remove_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(pathname, _len_pathname);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pathname != NULL) ? _len_pathname : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_remove_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_remove_t));
	ocalloc_size -= sizeof(ms_u_remove_t);

	if (pathname != NULL) {
		if (memcpy_verw_s(&ms->ms_pathname, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_pathname % sizeof(*pathname) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, pathname, _len_pathname)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pathname);
		ocalloc_size -= _len_pathname;
	} else {
		ms->ms_pathname = NULL;
	}

	status = sgx_ocall(109, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getenv(char** retval, const char* name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_name = name ? strlen(name) + 1 : 0;

	ms_u_getenv_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getenv_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(name, _len_name);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (name != NULL) ? _len_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getenv_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getenv_t));
	ocalloc_size -= sizeof(ms_u_getenv_t);

	if (name != NULL) {
		if (memcpy_verw_s(&ms->ms_name, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_name % sizeof(*name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, name, _len_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_name);
		ocalloc_size -= _len_name;
	} else {
		ms->ms_name = NULL;
	}

	status = sgx_ocall(110, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getgrgid_r(int* retval, gid_t gid, struct group* grp, char* buf, size_t buflen, struct group** result)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_result = sizeof(struct group*);

	ms_u_getgrgid_r_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getgrgid_r_t);
	void *__tmp = NULL;

	void *__tmp_result = NULL;

	CHECK_ENCLAVE_POINTER(result, _len_result);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (result != NULL) ? _len_result : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getgrgid_r_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getgrgid_r_t));
	ocalloc_size -= sizeof(ms_u_getgrgid_r_t);

	if (memcpy_verw_s(&ms->ms_gid, sizeof(ms->ms_gid), &gid, sizeof(gid))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_grp, sizeof(ms->ms_grp), &grp, sizeof(grp))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_buf, sizeof(ms->ms_buf), &buf, sizeof(buf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_buflen, sizeof(ms->ms_buflen), &buflen, sizeof(buflen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (result != NULL) {
		if (memcpy_verw_s(&ms->ms_result, sizeof(struct group**), &__tmp, sizeof(struct group**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_result = __tmp;
		if (_len_result % sizeof(*result) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_result, 0, _len_result);
		__tmp = (void *)((size_t)__tmp + _len_result);
		ocalloc_size -= _len_result;
	} else {
		ms->ms_result = NULL;
	}

	status = sgx_ocall(111, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (result) {
			if (memcpy_s((void*)result, _len_result, __tmp_result, _len_result)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getpwuid(struct passwd** retval, uid_t uid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_getpwuid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getpwuid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getpwuid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getpwuid_t));
	ocalloc_size -= sizeof(ms_u_getpwuid_t);

	if (memcpy_verw_s(&ms->ms_uid, sizeof(ms->ms_uid), &uid, sizeof(uid))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(112, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getpwuid_r(int* retval, uid_t uid, struct passwd* pwd, char* buf, size_t buflen, struct passwd** result)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_result = sizeof(struct passwd*);

	ms_u_getpwuid_r_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getpwuid_r_t);
	void *__tmp = NULL;

	void *__tmp_result = NULL;

	CHECK_ENCLAVE_POINTER(result, _len_result);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (result != NULL) ? _len_result : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getpwuid_r_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getpwuid_r_t));
	ocalloc_size -= sizeof(ms_u_getpwuid_r_t);

	if (memcpy_verw_s(&ms->ms_uid, sizeof(ms->ms_uid), &uid, sizeof(uid))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_pwd, sizeof(ms->ms_pwd), &pwd, sizeof(pwd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_buf, sizeof(ms->ms_buf), &buf, sizeof(buf))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_buflen, sizeof(ms->ms_buflen), &buflen, sizeof(buflen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (result != NULL) {
		if (memcpy_verw_s(&ms->ms_result, sizeof(struct passwd**), &__tmp, sizeof(struct passwd**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_result = __tmp;
		if (_len_result % sizeof(*result) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_result, 0, _len_result);
		__tmp = (void *)((size_t)__tmp + _len_result);
		ocalloc_size -= _len_result;
	} else {
		ms->ms_result = NULL;
	}

	status = sgx_ocall(113, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (result) {
			if (memcpy_s((void*)result, _len_result, __tmp_result, _len_result)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_fpathconf(long int* retval, int fd, int name)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_fpathconf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_fpathconf_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_fpathconf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_fpathconf_t));
	ocalloc_size -= sizeof(ms_u_fpathconf_t);

	if (memcpy_verw_s(&ms->ms_fd, sizeof(ms->ms_fd), &fd, sizeof(fd))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_name, sizeof(ms->ms_name), &name, sizeof(name))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(114, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_pathconf(long int* retval, const char* path, int name)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_u_pathconf_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_pathconf_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(path, _len_path);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_pathconf_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_pathconf_t));
	ocalloc_size -= sizeof(ms_u_pathconf_t);

	if (path != NULL) {
		if (memcpy_verw_s(&ms->ms_path, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}

	if (memcpy_verw_s(&ms->ms_name, sizeof(ms->ms_name), &name, sizeof(name))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(115, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_time(time_t* retval, time_t* tloc)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tloc = sizeof(time_t);

	ms_u_time_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_time_t);
	void *__tmp = NULL;

	void *__tmp_tloc = NULL;

	CHECK_ENCLAVE_POINTER(tloc, _len_tloc);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tloc != NULL) ? _len_tloc : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_time_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_time_t));
	ocalloc_size -= sizeof(ms_u_time_t);

	if (tloc != NULL) {
		if (memcpy_verw_s(&ms->ms_tloc, sizeof(time_t*), &__tmp, sizeof(time_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_tloc = __tmp;
		memset_verw(__tmp_tloc, 0, _len_tloc);
		__tmp = (void *)((size_t)__tmp + _len_tloc);
		ocalloc_size -= _len_tloc;
	} else {
		ms->ms_tloc = NULL;
	}

	status = sgx_ocall(116, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (tloc) {
			if (memcpy_s((void*)tloc, _len_tloc, __tmp_tloc, _len_tloc)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_utimes(int* retval, const char* filename, const struct timeval* times)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_filename = filename ? strlen(filename) + 1 : 0;
	size_t _len_times = sizeof(struct timeval);

	ms_u_utimes_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_utimes_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(filename, _len_filename);
	CHECK_ENCLAVE_POINTER(times, _len_times);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (filename != NULL) ? _len_filename : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (times != NULL) ? _len_times : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_utimes_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_utimes_t));
	ocalloc_size -= sizeof(ms_u_utimes_t);

	if (filename != NULL) {
		if (memcpy_verw_s(&ms->ms_filename, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_filename % sizeof(*filename) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, filename, _len_filename)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_filename);
		ocalloc_size -= _len_filename;
	} else {
		ms->ms_filename = NULL;
	}

	if (times != NULL) {
		if (memcpy_verw_s(&ms->ms_times, sizeof(const struct timeval*), &__tmp, sizeof(const struct timeval*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, times, _len_times)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_times);
		ocalloc_size -= _len_times;
	} else {
		ms->ms_times = NULL;
	}

	status = sgx_ocall(117, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_localtime(struct tm** retval, const time_t* t)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_t = sizeof(time_t);

	ms_u_localtime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_localtime_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(t, _len_t);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (t != NULL) ? _len_t : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_localtime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_localtime_t));
	ocalloc_size -= sizeof(ms_u_localtime_t);

	if (t != NULL) {
		if (memcpy_verw_s(&ms->ms_t, sizeof(const time_t*), &__tmp, sizeof(const time_t*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, t, _len_t)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_t);
		ocalloc_size -= _len_t;
	} else {
		ms->ms_t = NULL;
	}

	status = sgx_ocall(118, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_gettimeofday(int* retval, struct timeval* tv)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tv = sizeof(struct timeval);

	ms_u_gettimeofday_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_gettimeofday_t);
	void *__tmp = NULL;

	void *__tmp_tv = NULL;

	CHECK_ENCLAVE_POINTER(tv, _len_tv);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tv != NULL) ? _len_tv : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_gettimeofday_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_gettimeofday_t));
	ocalloc_size -= sizeof(ms_u_gettimeofday_t);

	if (tv != NULL) {
		if (memcpy_verw_s(&ms->ms_tv, sizeof(struct timeval*), &__tmp, sizeof(struct timeval*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_tv = __tmp;
		memset_verw(__tmp_tv, 0, _len_tv);
		__tmp = (void *)((size_t)__tmp + _len_tv);
		ocalloc_size -= _len_tv;
	} else {
		ms->ms_tv = NULL;
	}

	status = sgx_ocall(119, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (tv) {
			if (memcpy_s((void*)tv, _len_tv, __tmp_tv, _len_tv)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_clock_gettime(int* retval, clockid_t clk_id, struct timespec* tp)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_tp = sizeof(struct timespec);

	ms_u_clock_gettime_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_clock_gettime_t);
	void *__tmp = NULL;

	void *__tmp_tp = NULL;

	CHECK_ENCLAVE_POINTER(tp, _len_tp);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (tp != NULL) ? _len_tp : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_clock_gettime_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_clock_gettime_t));
	ocalloc_size -= sizeof(ms_u_clock_gettime_t);

	if (memcpy_verw_s(&ms->ms_clk_id, sizeof(ms->ms_clk_id), &clk_id, sizeof(clk_id))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (tp != NULL) {
		if (memcpy_verw_s(&ms->ms_tp, sizeof(struct timespec*), &__tmp, sizeof(struct timespec*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_tp = __tmp;
		memset_verw(__tmp_tp, 0, _len_tp);
		__tmp = (void *)((size_t)__tmp + _len_tp);
		ocalloc_size -= _len_tp;
	} else {
		ms->ms_tp = NULL;
	}

	status = sgx_ocall(120, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (tp) {
			if (memcpy_s((void*)tp, _len_tp, __tmp_tp, _len_tp)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getaddrinfo(int* retval, const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_node = node ? strlen(node) + 1 : 0;
	size_t _len_service = service ? strlen(service) + 1 : 0;
	size_t _len_hints = sizeof(struct addrinfo);
	size_t _len_res = sizeof(struct addrinfo*);

	ms_u_getaddrinfo_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getaddrinfo_t);
	void *__tmp = NULL;

	void *__tmp_res = NULL;

	CHECK_ENCLAVE_POINTER(node, _len_node);
	CHECK_ENCLAVE_POINTER(service, _len_service);
	CHECK_ENCLAVE_POINTER(hints, _len_hints);
	CHECK_ENCLAVE_POINTER(res, _len_res);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (node != NULL) ? _len_node : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (service != NULL) ? _len_service : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (hints != NULL) ? _len_hints : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (res != NULL) ? _len_res : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getaddrinfo_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getaddrinfo_t));
	ocalloc_size -= sizeof(ms_u_getaddrinfo_t);

	if (node != NULL) {
		if (memcpy_verw_s(&ms->ms_node, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_node % sizeof(*node) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, node, _len_node)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_node);
		ocalloc_size -= _len_node;
	} else {
		ms->ms_node = NULL;
	}

	if (service != NULL) {
		if (memcpy_verw_s(&ms->ms_service, sizeof(const char*), &__tmp, sizeof(const char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (_len_service % sizeof(*service) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, service, _len_service)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_service);
		ocalloc_size -= _len_service;
	} else {
		ms->ms_service = NULL;
	}

	if (hints != NULL) {
		if (memcpy_verw_s(&ms->ms_hints, sizeof(const struct addrinfo*), &__tmp, sizeof(const struct addrinfo*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, hints, _len_hints)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_hints);
		ocalloc_size -= _len_hints;
	} else {
		ms->ms_hints = NULL;
	}

	if (res != NULL) {
		if (memcpy_verw_s(&ms->ms_res, sizeof(struct addrinfo**), &__tmp, sizeof(struct addrinfo**))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_res = __tmp;
		if (_len_res % sizeof(*res) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_res, 0, _len_res);
		__tmp = (void *)((size_t)__tmp + _len_res);
		ocalloc_size -= _len_res;
	} else {
		ms->ms_res = NULL;
	}

	status = sgx_ocall(121, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (res) {
			if (memcpy_s((void*)res, _len_res, __tmp_res, _len_res)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_freeaddrinfo(struct addrinfo* res)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_freeaddrinfo_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_freeaddrinfo_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_freeaddrinfo_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_freeaddrinfo_t));
	ocalloc_size -= sizeof(ms_u_freeaddrinfo_t);

	if (memcpy_verw_s(&ms->ms_res, sizeof(ms->ms_res), &res, sizeof(res))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(122, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_getnameinfo(int* retval, const struct sockaddr* sa, socklen_t salen, char* host, socklen_t hostlen, char* serv, socklen_t servlen, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_sa = salen;
	size_t _len_host = hostlen;
	size_t _len_serv = servlen;

	ms_u_getnameinfo_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_getnameinfo_t);
	void *__tmp = NULL;

	void *__tmp_host = NULL;
	void *__tmp_serv = NULL;

	CHECK_ENCLAVE_POINTER(sa, _len_sa);
	CHECK_ENCLAVE_POINTER(host, _len_host);
	CHECK_ENCLAVE_POINTER(serv, _len_serv);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (sa != NULL) ? _len_sa : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (host != NULL) ? _len_host : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (serv != NULL) ? _len_serv : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_getnameinfo_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_getnameinfo_t));
	ocalloc_size -= sizeof(ms_u_getnameinfo_t);

	if (sa != NULL) {
		if (memcpy_verw_s(&ms->ms_sa, sizeof(const struct sockaddr*), &__tmp, sizeof(const struct sockaddr*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		if (memcpy_verw_s(__tmp, ocalloc_size, sa, _len_sa)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_sa);
		ocalloc_size -= _len_sa;
	} else {
		ms->ms_sa = NULL;
	}

	if (memcpy_verw_s(&ms->ms_salen, sizeof(ms->ms_salen), &salen, sizeof(salen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (host != NULL) {
		if (memcpy_verw_s(&ms->ms_host, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_host = __tmp;
		if (_len_host % sizeof(*host) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_host, 0, _len_host);
		__tmp = (void *)((size_t)__tmp + _len_host);
		ocalloc_size -= _len_host;
	} else {
		ms->ms_host = NULL;
	}

	if (memcpy_verw_s(&ms->ms_hostlen, sizeof(ms->ms_hostlen), &hostlen, sizeof(hostlen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (serv != NULL) {
		if (memcpy_verw_s(&ms->ms_serv, sizeof(char*), &__tmp, sizeof(char*))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp_serv = __tmp;
		if (_len_serv % sizeof(*serv) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset_verw(__tmp_serv, 0, _len_serv);
		__tmp = (void *)((size_t)__tmp + _len_serv);
		ocalloc_size -= _len_serv;
	} else {
		ms->ms_serv = NULL;
	}

	if (memcpy_verw_s(&ms->ms_servlen, sizeof(ms->ms_servlen), &servlen, sizeof(servlen))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	if (memcpy_verw_s(&ms->ms_flags, sizeof(ms->ms_flags), &flags, sizeof(flags))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(123, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (host) {
			if (memcpy_s((void*)host, _len_host, __tmp_host, _len_host)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (serv) {
			if (memcpy_s((void*)serv, _len_serv, __tmp_serv, _len_serv)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_gai_strerror(char** retval, int errcode)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_gai_strerror_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_gai_strerror_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_gai_strerror_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_gai_strerror_t));
	ocalloc_size -= sizeof(ms_u_gai_strerror_t);

	if (memcpy_verw_s(&ms->ms_errcode, sizeof(ms->ms_errcode), &errcode, sizeof(errcode))) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}

	status = sgx_ocall(124, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL u_sched_yield(int* retval)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_u_sched_yield_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_u_sched_yield_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_u_sched_yield_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_u_sched_yield_t));
	ocalloc_size -= sizeof(ms_u_sched_yield_t);

	status = sgx_ocall(125, ms);

	if (status == SGX_SUCCESS) {
		if (retval) {
			if (memcpy_s((void*)retval, sizeof(*retval), &ms->ms_retval, sizeof(ms->ms_retval))) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (memcpy_s((void*)&errno, sizeof(errno), &ms->ocall_errno, sizeof(ms->ocall_errno))) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
	}
	sgx_ocfree();
	return status;
}

