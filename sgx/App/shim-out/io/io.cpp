/*
 * Created on Tue Jul 21 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 * Some ideas were taken from Panoply code
 */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/times.h>
#include <sys/ioctl.h>

#include <map>
#include "ocall_logger.h"
#include "Enclave_u.h"



//#include <libexplain/libexplain.h>
#include "io.h"

using namespace std;
//max num of file descriptors open at once
#define MAX_FILE_DES 50000
#define MAX_DIR 1000
#define MAX_STREAMS 50000

z_streamp *zs_array[MAX_STREAMS];

FILE *fd_array[MAX_FILE_DES];
DIR *dir_array[MAX_DIR];

//std::map<char* name, DIR *> dir_map;

static int num_fd = SGX_STDERR + 1; //(3 files open by default: stdin, stdout, stderr)

FILE *getFile(int fd)
{
    if (fd == SGX_STDIN)
        return stdin;

    if (fd == SGX_STDOUT)
        return stdout;

    if (fd == SGX_STDERR)
        return stderr;

    if (fd < 0)
        return NULL;

    return fd_array[fd];
}

void ocall_empty(int repeats)
{
    log_ocall(__func__);
    int i;

    for (i = 0; i < repeats; i++)
        asm volatile("pause");
}

void copy_stat_buf()
{
    //todo
}

//DIR *getDir(const char*)
int ocall_fsync(int fd)
{
    log_ocall(__func__);
    return fsync(fd);
}

int ocall_msync(void *addr, size_t length, int flags)
{
    log_ocall(__func__);
    return msync(addr, length, flags);
}

void ocall_sync(void)
{
    log_ocall(__func__);
    sync();
}
int ocall_syncfs(int fd)
{
    log_ocall(__func__);
    return syncfs(fd);
}

int ocall_dup2(int oldfd, int newfd)
{
    log_ocall(__func__);
    return dup2(oldfd, newfd);
}
int ocall_open(const char *path, int oflag, int arg)
{
    log_ocall(__func__);
    return open(path, oflag, arg);
}
int ocall_open64(const char *path, int oflag, int arg)
{
    log_ocall(__func__);
    return open64(path, oflag, arg);
}

int ocall_ioctl(int fd, unsigned long request, int arg)
{
    log_ocall(__func__);
    return ioctl(fd, request, arg);
}

void *ocall_stat(const char *path, int *stat_ret)
{
    log_ocall(__func__);
    struct stat *buf = (struct stat *)malloc(sizeof(struct stat));
    *stat_ret = stat(path, buf);
    return (void *)buf;
}

void *ocall_fstat(int fd, int *fstat_ret)
{
    log_ocall(__func__);
    struct stat *buf = (struct stat *)malloc(sizeof(struct stat));
    *fstat_ret = fstat(fd, buf);
    return (void *)buf;
}

void *ocall_lstat(const char *path, int *lstat_ret)
{
    log_ocall(__func__);
    struct stat *buf = (struct stat *)malloc(sizeof(struct stat));
    *lstat_ret = lstat(path, buf);
    return (void *)buf;
}

void *ocall_fstat64(int fd, int *fstat_ret)
{
    log_ocall(__func__);

    struct stat *buf = (struct stat *)malloc(sizeof(struct stat));
    *fstat_ret = fstat64(fd, (struct stat64 *)buf);
    return (void *)buf;
}

int ocall_fxstat64(int ver, int fildes, struct stat *stat_buf)
{
    log_ocall(__func__);
    return __fxstat64(ver, fildes, (struct stat64 *)stat_buf);
}

int ocall_fxstat(int ver, int fd, struct stat *stat_buf)
{
    log_ocall(__func__);
    return __fxstat(ver, fd, stat_buf);
}
int ocall_lxstat(int ver, const char *path, struct stat *stat_buf)
{
    log_ocall(__func__);
    return __lxstat(ver, path, stat_buf);
}
int ocall_xstat(int ver, const char *path, struct stat *stat_buf)
{
    log_ocall(__func__);
    return __xstat(ver, path, stat_buf);
}
long ocall_pathconf(char *path, int name)
{
    log_ocall(__func__);
    return pathconf(path, name);
}
ssize_t ocall_readlink(const char *pathname, char *buf, size_t bufsiz)
{
    log_ocall(__func__);
    return readlink(pathname, buf, bufsiz);
}
int ocall_readdir64_r(void *dirp, void *entry, struct dirent **result)
{
    log_ocall(__func__);
    DIR *dir = (DIR *)dirp;
    return readdir64_r(dir, (struct dirent64 *)entry, (struct dirent64 **)result);
    //TODO
}
void *ocall_opendir(const char *name)
{
    log_ocall(__func__);
    return (void *)opendir(name);
}
int ocall_closedir(void *dirp)
{
    log_ocall(__func__);
    DIR *dir = (DIR *)dirp;
    return closedir(dir);
}

long ocall_pathconf(const char *path, int name)
{
    log_ocall(__func__);
    return pathconf(path, name);
}

//all names with x prefix prevent possible redefinition problems
int ocall_xclose(int fd)
{
    log_ocall(__func__);
    return close(fd);
}

SGX_FILE ocall_fopen(const char *filename, const char *mode)
{
    log_ocall(__func__);
    SGX_FILE fd = num_fd++;
    FILE *f = NULL;
    f = fopen(filename, mode);
    //printf("fopen filename: %s\n",filename);
    fd_array[fd] = f;

    return (f == NULL ? 0 : fd);
}

SGX_FILE ocall_fdopen(int fd, const char *mode)
{
    log_ocall(__func__);
    //FILE *f = fdopen(fd, mode);
    return fd;
}

int ocall_fclose(SGX_FILE stream)
{
    log_ocall(__func__);
    FILE *f = getFile(stream);
    fd_array[stream] = NULL;
    return fclose(f);
}

size_t ocall_fwrite(const void *ptr, size_t size, size_t nmemb, SGX_FILE stream)
{
    log_ocall(__func__);
    FILE *f = getFile(stream);
    ssize_t ret = fwrite(ptr, size, nmemb, f);

    return ret;
}
size_t ocall_fread(void *ptr, size_t size, size_t nmemb, SGX_FILE stream)
{
    log_ocall(__func__);
    FILE *f = getFile(stream);
    ssize_t total_bytes = size * nmemb;
    ssize_t ret = fread(ptr, size, nmemb, f);
    //printf("--------------- fread expected: %d actually read: %d ---------------------\n", total_bytes, ret);
    return ret;
}

int ocall_fseeko(SGX_FILE stream, off_t offset, int whence)
{

    log_ocall(__func__);
    FILE *f = getFile(stream);
    return fseeko(f, offset, whence);
}

off_t ocall_ftello(SGX_FILE stream)
{
    log_ocall(__func__);
    FILE *f = getFile(stream);
    return ftello(f);
}
ssize_t ocall_read(int fd, void *buf, size_t count)
{
    log_ocall(__func__);

    ssize_t ret = read(fd, buf, count);

    //ssize_t debug_ret = read(fd, 0, 0);
    //printf("ocall read return value: %d Error num: %d >>>>>>>>>>>>>>>>>>>>>>\n", debug_ret, errno);
    //printf("Read error: %s\n", explain_read(fd, buf, count));
    //install libexplain-dev: sudo apt install libexplain-dev
    //exit(EXIT_FAILURE);

    return ret;
}

int ocall_getErrno()
{
    return (int)errno;
}

ssize_t ocall_write(int fd, const void *buf, size_t count)
{
    log_ocall(__func__);
    return write(fd, buf, count);
}

int ocall_fscanf(SGX_FILE stream, const char *str)
{
    log_ocall(__func__);
    FILE *f = getFile(stream);
    return fscanf(f, "%s", str);
}
int ocall_fprintf(SGX_FILE stream, const char *str)
{
    log_ocall(__func__);
    FILE *f = getFile(stream);
    return fprintf(f, "%s", str);
}

void ocall_print_string(const char *str)
{
    log_ocall(__func__);
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

void ocall_fgets(char *str, int n, SGX_FILE stream)
{
    log_ocall(__func__);
    FILE *f = getFile(stream);
    char *ret = fgets(str, n, f);
    //printf("Ocall_fgets: %s\n", ret);
}
SGX_FILE ocall_stderr()
{
    log_ocall(__func__);
    return SGX_STDERR;
}

int ocall_puts(const char *str)
{
    log_ocall(__func__);
    return puts(str);
}

//used by graphchi
int ocall_mkdir(const char *pathname, mode_t mode)
{
    log_ocall(__func__);
    return mkdir(pathname, mode);
}
int ocall_truncate(const char *path, off_t length)
{
    log_ocall(__func__);
    return truncate(path, length);
}
int ocall_ftruncate64(int fd, off_t length)
{
    log_ocall(__func__);
    return ftruncate64(fd, length);
}
void *ocall_mmap64(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
    log_ocall(__func__);
    return mmap64(addr, len, prot, flags, fd, off);
}
ssize_t ocall_pwrite64(int fd, const void *buf, size_t nbyte, off_t offset)
{
    log_ocall(__func__);
    return pwrite64(fd, buf, nbyte, offset);
}
int ocall_fdatasync(int fd)
{
    log_ocall(__func__);
    return fdatasync(fd);
}
int ocall_rename(const char *oldpath, const char *newpath)
{
    log_ocall(__func__);
    return rename(oldpath, newpath);
}
int ocall_unlink(const char *pathname)
{
    log_ocall(__func__);
    return unlink(pathname);
}
int ocall_rmdir(const char *pathname)
{
    log_ocall(__func__);
    return rmdir(pathname);
}
clock_t ocall_times()
{
    log_ocall(__func__);
    struct tms *buf = (struct tms *)malloc(sizeof(struct tms));
    return times(buf);
}

int ocall_chown(const char *pathname, uid_t owner, gid_t group)
{
    log_ocall(__func__);
    return chown(pathname, owner, group);
}
int ocall_fchown(int fd, uid_t owner, gid_t group)
{
    log_ocall(__func__);
    return fchown(fd, owner, group);
}
int ocall_lchown(const char *pathname, uid_t owner, gid_t group)
{
    log_ocall(__func__);
    return lchown(pathname, owner, group);
}
int ocall_chmod(const char *pathname, mode_t mode)
{
    log_ocall(__func__);
    return chmod(pathname, mode);
}
int ocall_fchmod(int fd, mode_t mode)
{
    log_ocall(__func__);
    return fchmod(fd, mode);
}
int ocall_lxstat64(int ver, const char *path, struct stat *stat_buf)
{
    log_ocall(__func__);
    return __lxstat64(ver, path, (struct stat64 *)stat_buf);
}
int ocall_xmknod(int vers, const char *path, mode_t mode, dev_t *dev)
{
    log_ocall(__func__);
    return __xmknod(vers, path, mode, dev);
}
int ocall_symlink(const char *target, const char *linkpath)
{
    log_ocall(__func__);
    return symlink(target, linkpath);
}

int ocall_xstat64(int ver, const char *path, struct stat *stat_buf)
{
    log_ocall(__func__);
    return __xstat64(ver, path, (struct stat64 *)stat_buf);
}

/**
 * Different possibilities for fcntl
 */
int ocall_fcntl(int fd, int cmd, int arg)
{
    log_ocall(__func__);
    return fcntl(fd, cmd, arg);
}

int ocall_fcntl1(int fd, int cmd)
{
    log_ocall(__func__);
    return fcntl(fd, cmd);
}

int ocall_fcntl2(int fd, int cmd, long arg)
{

    log_ocall(__func__);
    return fcntl(fd, cmd, arg);
}

int ocall_fcntl3(int fd, int cmd, void *arg_cast, int flock_size)
{
    log_ocall(__func__);
    struct flock *arg = (struct flock *)arg_cast;
    return fcntl(fd, cmd, arg);
}
//--------------------------------zlib-------------------------------

int ocall_deflateEnd(z_streamp stream)
{

    log_ocall(__func__);

    return 0; //TODO: get zlib
}
int ocall_deflateParams(z_streamp stream, int level, int strategy)
{
    log_ocall(__func__);
    return 0; //TODO: get zlib
}
int ocall_deflate(z_streamp stream, int flush)
{
    log_ocall(__func__);
    return 0; //TODO: get zlib
}
int ocall_deflateInit2(z_streamp stream, int level, int method, int windowBits, int memLevel, int strategy)
{
    log_ocall(__func__);
    return 0; //TODO: get zlib
}
int ocall_inflateReset(z_streamp stream)
{
    log_ocall(__func__);
    return 0; //TODO: get zlib
}
ssize_t ocall_sendfile64(int out_fd, int in_fd, off_t *offset, size_t count)
{
    log_ocall(__func__);
    return sendfile64(out_fd, in_fd, (off64_t *)offset, count);
}
ulong ocall_adler32(ulong adler, const Bytef *buf, size_t len)
{
    log_ocall(__func__);
    return 0; //TODO: get zlib
}

off_t ocall_lseek(int fd, off_t offset, int whence)
{
    log_ocall(__func__);
    return lseek(fd, offset, whence);
}
off64_t ocall_lseek64(int fd, off64_t offset, int whence)
{
    log_ocall(__func__);
    return lseek64(fd, offset, whence);
}
int ocall_fflush(SGX_FILE *stream)
{
    log_ocall(__func__);
    FILE *f = getFile(*stream);
    return fflush(f);
}
ssize_t ocall_pread(int fd, void *buf, size_t count, off_t offset)
{
    log_ocall(__func__);
    return pread(fd, buf, count, offset);
}
ssize_t ocall_pread64(int fd, void *buf, size_t count, off64_t offset)
{
    log_ocall(__func__);
    return pread64(fd, buf, count, offset);
}
ssize_t ocall_pwrite(int fd, const void *buf, size_t count, off_t offset)
{
    log_ocall(__func__);
    return pwrite(fd, buf, count, offset);
}
/* int ocall_getenv(const char *env, int envlen, char *ret_str, int ret_len)
{
    log_ocall(__func__);
    const char *env_val = getenv(env);
    if (env_val == NULL)
    {
        return -1;
    }
    memcpy(ret_str, env_val, strlen(env_val) + 1);
    return 0;
} */

char *ocall_getenv(const char *name)
{
    log_ocall(__func__);
    return getenv(name);
}

int ocall_chdir(const char *path)
{
    log_ocall(__func__);
    return chdir(path);
}
int ocall_fileno(SGX_FILE *stream)
{
    log_ocall(__func__);
    int fd = *stream;
    FILE *f = getFile(fd);
    if (fd == SGX_STDIN || fd == SGX_STDOUT || fd == SGX_STDERR)
        return fd;
    else
        return fileno(f);
}
int ocall_isatty(int fd)
{
    log_ocall(__func__);
    return isatty(fd);
}
mode_t ocall_umask(mode_t mask)
{
    log_ocall(__func__);
    return umask(mask);
}

int ocall_getchar()
{
    log_ocall(__func__);
    return getchar();
}

int ocall_fputc(int c, SGX_FILE stream)
{
    log_ocall(__func__);
    FILE *f = getFile(stream);
    return fputc(c, f);
}
int ocall_putc(int c, SGX_FILE stream)
{
    log_ocall(__func__);
    FILE *f = getFile(stream);
    return putc(c, f);
}

//-------------------- test ocalls --------------------
int ocall_test(int a, int b)
{
    log_ocall(__func__);
    return a * b;
}

