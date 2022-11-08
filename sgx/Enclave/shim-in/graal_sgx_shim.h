/*
 * Created on Wed Jul 15 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

#ifndef GRAAL_SGX_SHIM_H
#define GRAAL_SGX_SHIM_H

//#define __USE_LARGEFILE64 //for stat64

//used by some reimplementations. For testing purposes --PYuhala
#define GRAAL_SGX_STACK_SIZE 0x200000
#define GRAAL_SGX_PAGESIZE 4096
#define GRAAL_SGX_GUARDSIZE GRAAL_SGX_PAGESIZE
#define GRAAL_SCHED_POLICY 0
#define COND_NWAITERS_SHIFT 1
#define CLOCK_MONOTONIC 0
#define CLOCK_REALTIME 1
#define NUM_MAPS 100000
#define Pause() __asm__ __volatile__("pause" \
                                     :       \
                                     :       \
                                     : "memory")

#define __USE_LARGEFILE64
//sys
#include <sgx/sys/types.h>
#include <sgx/sys/stat.h>
#include <sgx/pwd.h>
#include <sgx/sys/utsname.h>
#include <sgx/sys/resource.h>
#include <sgx/linux/limits.h>
#include <stdlib.h>
#include <string.h>
#include <sgx/signal.h>
#include <unistd.h>
#include <sgx/netdb.h>
#include <struct/sgx_fcntl_struct.h>
#include <sgx/sys/wait.h>
//#include <sgx/sys/statvfs.h>

//libevent
#include <sgx/event.h>

//io
#include <stdio.h>

#include <sgx/dirent.h>
//#include <struct/sgx_stdio_struct.h>
//#include <struct/sgx_sysstat_struct.h>

//net
#include <sgx/sys/socket.h>
#include <sgx/arpa/inet.h>
#include <sgx/sys/epoll.h>
#include <sgx/sys/uio.h>
#include <sgx/sys/poll.h>
#include <sgx/sys/epoll.h>

//threads
//#include <pthread.h>
#include <struct/sgx_pthread_struct.h>
#include <sgx_thread.h>
//#include <sgx_pthread.h>

#include "graal_sgx_debug.h"

//>>>>> Begin typedefs >>>>>>>>>

typedef unsigned char Byte;
typedef unsigned char Bytef;
typedef long off64_t;
typedef size_t z_size_t;
typedef void DIR;
//typedef int z_streamp;
struct statvfs
{
    int todo;
};

//>>>>>> End typedefs >>>>>>>>

//#define my_printf(...) printf(__VA_ARGS__)

#define PERROR(...) printf("[PERROR]: " __VA_ARGS__ " \n")

//extern char **environ;
// This prevents "name mangling" by g++ ---> PYuhala
#if defined(__cplusplus)
extern "C"
{
#endif

    //custom routines
    void sgx_exit();
    //sys
    void *dlsym(void *handle, const char *symbol);
    void *dlopen(const char *filename, int flag);
    long sysconf(int name);

    ulong crc32(ulong crc, const Byte *buf, uint len);
    uid_t getuid(void);
    uid_t geteuid(void);

    //cpuid: for libchelper.a
    unsigned int get_cpuid_max(unsigned int ext, unsigned int *sig);
    int get_cpuid_count(unsigned int leaf, unsigned int subleaf, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx);
    int get_cpuid(unsigned int leaf, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx);

    //mem management
    int munmap(void *addr, size_t length);
    void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
    int madvise(void *addr, size_t length, int advice);

    //clock
    int clock_gettime(clockid_t clk_id, struct timespec *tp);
    int gettimeofday(struct timeval *tv, void *tz);

    char *getcwd(char *buf, size_t size);
    struct passwd *getpwuid(uid_t uid);
    void exit(int status);
    int getrlimit(int res, struct rlimit *rlim);
    int setrlimit(int resource, const struct rlimit *rlim);
    long syscall(long num, ...);
    int uname(struct utsname *buf);
    unsigned int sleep(unsigned int secs);
    int usleep(useconds_t usec);
    int mprotect(void *addr, size_t len, int prot);
    char *realpath(const char *path, char *resolved_path);
    char *__xpg_strerror_r(int errnum, char *buf, size_t buflen);

    //>>>>>>>>>>>>>>>>>>>>> kyoto >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
    ssize_t getline(char **lineptr, size_t *n, SGX_FILE *stream);

    //>>>>>>>>>>>>>>>>>>>>> start signal shim >>>>>>>>>>>>>>>>>>>>>>>>>>
    int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact); //TODO
    int sigemptyset(sigset_t *set);
    int sigaddset(sigset_t *set, int signum);
    int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
    sighandler_t signal(int signum, sighandler_t handler);
    void sig_handler(int param);
    int raise(int sig);
    int kill(pid_t pid, int sig);
    int nanosleep(const struct timespec *__requested_time, struct timespec *__remaining);
    //>>>>>>>>>>>>>>>>>>>>> end signal shim >>>>>>>>>>>>>>>>>>>>>>>>>>

    ///>>>>>>>>>>>>>>>>>>>>> start io shim >>>>>>>>>>>>>>>>>>>>>>>>>>

    int fstat64(int fd, struct stat *buf);
    int __fxstat64(int ver, int fildes, struct stat *stat_buf);
    int __xstat64(int ver, const char *path, struct stat *stat_buf);

    int __xstat(int ver, const char *path, struct stat *stat_buf);
    int __lxstat(int ver, const char *path, struct stat *stat_buf);
    int __fxstat(int ver, int fildes, struct stat *stat_buf);

    int stat(const char *path, struct stat *buf);
    int fstat(int fd, struct stat *buf);
    int lstat(const char *path, struct stat *buf);
    void empty(int repeats);
    int fsync(int fd);
    void sync(void);
    int syncfs(int fd);

    int dup2(int oldfd, int newfd);
    int open(const char *path, int oflag, ...);
    int open64(const char *path, int oflag, ...);
    int close(int fd);
    SGX_FILE fopen(const char *pathname, const char *mode);
    SGX_FILE fdopen(int fd, const char *mode);
    //SGX_FILE stderr();
    int fclose(SGX_FILE stream);
    int fscanf(SGX_FILE stream, const char *format, ...);
    int fprintf(SGX_FILE stream, const char *fmt, ...);
    int vfprintf(SGX_FILE *stream, const char *format, va_list ap);
    char *fgets(char *str, int n, SGX_FILE stream);
    int puts(const char *str);
    int fputc(int c, SGX_FILE stream);
    int putc(int c, SGX_FILE stream);
    int msync(void *addr, size_t length, int flags);

    //io: added for graphchi
    int mkdir(const char *pathname, mode_t mode);
    int truncate(const char *path, off_t length);
    int ftruncate64(int fd, off_t length);
    int ftruncate(int fd, off_t length);
    void *mmap64(void *addr, size_t len, int prot, int flags, int fildes, off_t off);
    ssize_t pwrite64(int fildes, const void *buf, size_t nbyte, off_t offset);
    int fdatasync(int fd);
    int rename(const char *oldpath, const char *newpath);
    int unlink(const char *pathname);
    int rmdir(const char *pathname);
    clock_t times(struct tms *buf);
    int utimes(const char *filename, const struct timeval times[2]);

    int chown(const char *pathname, uid_t owner, gid_t group);
    int fchown(int fd, uid_t owner, gid_t group);
    int lchown(const char *pathname, uid_t owner, gid_t group);
    int chmod(const char *pathname, mode_t mode);
    int fchmod(int fd, mode_t mode);
    int __lxstat64(int ver, const char *path, struct stat *stat_buf);
    int __xmknod(int vers, const char *path, mode_t mode, dev_t *dev);
    int symlink(const char *target, const char *linkpath);
    

    void *opendir(const char *name);
    //void *fdopendir(int fd);
    int closedir(void *dirp);
    //struct dirent *readdir(void *dirp);
    int readdir64_r(void *dirp, struct dirent *entry, struct dirent **result);
    int remove(const char *pathname);
    ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
    long pathconf(const char *path, int name);
    char *getenv(const char *name);

    size_t fwrite(const void *ptr, size_t size, size_t nmemb, SGX_FILE file);
    size_t fread(void *ptr, size_t size, size_t nmemb, SGX_FILE file);
    int fseeko(SGX_FILE file, off_t offset, int whence);
    off_t ftello(SGX_FILE file);

    ssize_t read(int fd, void *buf, size_t count);
    ssize_t write(int fd, const void *buf, size_t count);
    int sprintf(char *str, const char *format, ...);

    int sscanf(const char *str, const char *format, ...);

    //>>>>>>>>>>>>>>>>>>>>> end io shim >>>>>>>>>>>>>>>>>>>>>>>>>>

    char *strcpy(char *dest, const char *src);
    char *strcat(char *dest, const char *src);

    int getchar(void);

    //net
    int socket(int domain, int type, int protocol);
    int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int inet_pton(int af, const char *src, void *dst);

    uint32_t htonl(uint32_t hostlong);
    uint16_t htons(uint16_t hostshort);
    uint32_t ntohl(uint32_t netlong);
    uint16_t ntohs(uint16_t netshort);

    //>>>>>>>>>>>>>>>>>>>>> start pthread shim >>>>>>>>>>>>>>>>>>>>>>>>>>
    int pthread_create(pthread_t *thread, GRAAL_SGX_PTHREAD_ATTR attr, void *(*start_routine)(void *), void *arg);
    pthread_t pthread_self(void);
    int pthread_join(pthread_t thread, void **retval); //better join outside after pthread_create :-)

    int pthread_attr_getguardsize(GRAAL_SGX_PTHREAD_ATTR attr, size_t *guardsize);
    int pthread_attr_destroy(GRAAL_SGX_PTHREAD_ATTR attr);
    int pthread_attr_getstack(pthread_attr_t *attr, void **stackaddr, size_t *stacksize);
    int pthread_getattr_np(pthread_t thread, GRAAL_SGX_PTHREAD_ATTR attr);
    int pthread_attr_setdetachstate(GRAAL_SGX_PTHREAD_ATTR attr, int detachstate);
    int pthread_attr_init(GRAAL_SGX_PTHREAD_ATTR attr);
    int pthread_setname_np(pthread_t thread, const char *name);
    int pthread_getname_np(pthread_t thread, char *name, size_t len);
    int pthread_attr_setstacksize(GRAAL_SGX_PTHREAD_ATTR attr, size_t stacksize);

    int pthread_condattr_setclock(pthread_condattr_t *attr, clockid_t clock_id);
    int pthread_condattr_init(pthread_condattr_t *attr);
    int pthread_cond_timedwait(pthread_cond_t *__restrict__ cond, pthread_mutex_t *__restrict__ mutex, const struct timespec *__restrict__ abstime);
    int pthread_cond_broadcast(pthread_cond_t *cond);
    int pthread_cond_wait(pthread_cond_t *__restrict__ cond, pthread_mutex_t *__restrict__ mutex);
    int pthread_cond_init(pthread_cond_t *__restrict__ cond, const pthread_condattr_t *__restrict__ attr);

    int pthread_mutex_init(pthread_mutex_t *__restrict__ mutex, const pthread_mutexattr_t *__restrict__ attr);
    int pthread_mutex_lock(pthread_mutex_t *mutex);
    int pthread_mutex_trylock(pthread_mutex_t *mutex);
    int pthread_mutex_unlock(pthread_mutex_t *mutex);

    int pthread_key_create(pthread_key_t *key, void (*destructor)(void *));
    void *pthread_getspecific(pthread_key_t key);
    int pthread_setspecific(pthread_key_t key, const void *value);

    //>>>>>>>>>>>>>>>>>>>>> end pthread shim >>>>>>>>>>>>>>>>>>>>>>>>>>

    int sched_yield(void);

    //job
    bool get_pthreadid_from_sgxtheadid(sgx_thread_t sgx_id, pthread_t *pt);
    void ecall_execute_job(pthread_t pthread_id, unsigned long int job_id);
    void *graal_job(void *arg); //graal_sgx_thread function

    //Added for graal 21.0
    int __libc_current_sigrtmax(void);
    off_t lseek(int fd, off_t offset, int whence);
    struct dirent *readdir(DIR *dirp);
    struct dirent *readdir64(DIR *dirp);
    int ioctl(int fd, unsigned long request, ...);
    off64_t lseek64(int fd, off64_t offset, int whence);
    int fflush(SGX_FILE *stream);

    int getaddrinfo(const char *node, const char *service,
                    const struct addrinfo *hints,
                    struct addrinfo **res);

    void freeaddrinfo(struct addrinfo *res);

    const char *gai_strerror(int ecode);
    ssize_t pread(int fd, void *buf, size_t count, off_t offset);
    ssize_t pread64(int fd, void *buf, size_t count, off64_t offset);
    ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);
    int fcntl(int fd, int cmd, ... /* arg */);
    int fstatvfs64(int fd, struct statvfs *buf);
    int pthread_kill(pthread_t thread, int sig);   
    int dup(int oldfd);
    int access(const char *pathname, int mode);

    //>>>>>>>>>>>>>>>>>>>>>> start network shim >>>>>>>>>>>>>>>>>>>>>>>

    int getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
                    char *host, socklen_t hostlen,
                    char *serv, socklen_t servlen, int flags);
    int gethostname(char *name, size_t len);
    int sethostname(const char *name, size_t len);

    //Added for netty
    pid_t getpid(void);
    int remove(const char *pathname);
    int shutdown(int sockfd, int how);
    int getsockopt(int sockfd, int level, int optname,
                   void *optval, socklen_t *optlen);
    int setsockopt(int sockfd, int level, int optname,
                   const void *optval, socklen_t optlen);

    int socketpair(int domain, int type, int protocol, int sv[2]);
    int bind(int sockfd, const struct sockaddr *addr,
             socklen_t addrlen);

    int epoll_wait(int epfd, struct epoll_event *events,
                   int maxevents, int timeout);

    int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
    ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
    ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
    int pipe(int pipefd[2]);
    int connect(int sockfd, const struct sockaddr *addr,
                socklen_t addrlen);

    int listen(int sockfd, int backlog);
    int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
    int poll(struct pollfd *fds, nfds_t nfds, int timeout);
    int epoll_create(int size);
    const char *inet_ntop(int af, const void *src, char *dst, socklen_t size);

    ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
    ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
    void *transmit_prepare(void);

    ssize_t send(int sockfd, const void *buf, size_t len, int flags);
    ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
    ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);

    int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

    time_t time(time_t *t);

    //>>>>>>>>>>>>>>>>>>>>>>> end network shim >>>>>>>>>>>>>>>>>>>>>>>>>>>>

    //Added for halodb
    int environ(void);
    ssize_t sendfile64(int out_fd, int in_fd, off_t *offset, size_t count);
    ulong adler32(ulong adler, const Bytef *buf, size_t len);

    //Added for palDB
    pid_t waitpid(pid_t pid, int *wstatus, int options); //out
    pid_t vfork(void);
    pid_t fork(void);
    int statvfs64(const char *path, struct statvfs *buf); //out
    int execve(const char *pathname, char *const argv[], char *const envp[]);
    int execvp(const char *file, char *const argv[]);
    int chdir(const char *path);
    void _exit(int status);

    //Added for quickcached
    int fileno(SGX_FILE *stream); //in
    int isatty(int fd);
    mode_t umask(mode_t mask);

    //>>>>>>>>>>>>>>>>>>>>>>> start libevent shim >>>>>>>>>>>>>>>>>>>>>>>>>>>
    //int event_del(struct event *ev);
    //void event_set(struct event *ev, evutil_socket_t socketfd, short flags, void (*handler)(evutil_socket_t, short, void *), void *c);
    //int event_base_set(struct event_base *evb, struct event *ev);
    //int event_add(struct event *ev, const struct timeval *timeout);

    //>>>>>>>>>>>>>>>>>>>>>>> end libevent shim >>>>>>>>>>>>>>>>>>>>>>>>>>>>

    //
    void perror(const char *m);

    // test for zc switchless
    int test_multi(int a, int b);
    void *untrusted_malloc(ssize_t siz);

    // for micro-benchmarking purposes
    void micro_f();
    void micro_g();

#if defined(__cplusplus)
}
#endif

#endif /* GRAAL_SGX_SHIM_H */
