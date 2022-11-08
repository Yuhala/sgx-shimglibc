/*
 * Created on Fri Jul 17 2020
 *
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 */

/* Libc headers */
#undef _SIGNAL_H
#define _LARGEFILE_SOURCE 1
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <limits>
#include <string.h>
#include <sys/mman.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include "ocall_logger.h"

/* SGX headers */
#include "sgx_urts.h"
//#include "../../App.h"
#include "../../Enclave_u.h"
#include <stdio.h>

void ocall_dlsym(void *handle, const char *symbol, void *res)
{
    log_ocall(__func__);
    //printf("Dlsym symbol: %s\n", symbol);
    //res = dlsym(handle, symbol);
}

void *ocall_dlopen(const char *filename, int flag)
{
    log_ocall(__func__);
    //return dlopen(filename, flag);
    return nullptr;
}

void *ocall_mmap_file(int hint, size_t length, int prot, int flags, int fd, off_t offset)
{
    log_ocall(__func__);
    return mmap((void *)hint, length, prot, flags, fd, offset);
}

long ocall_sysconf(int name)
{
    log_ocall(__func__);
    return sysconf(name);
}

int ocall_getuid()
{
    log_ocall(__func__);
    uid_t ret = getuid();
    return (int)ret;
}

int ocall_geteuid()
{
    log_ocall(__func__);
    uid_t ret = geteuid();
    return (int)ret;
}

void ocall_getcwd(char *buf, size_t size)
{
    log_ocall(__func__);
    getcwd(buf, size);
}

void ocall_getpwuid(uid_t uid, struct passwd *ret)
{
    log_ocall(__func__);
    ret = getpwuid(uid);
}
void ocall_exit(int status)
{
    log_ocall(__func__);
    exit(status);
}

int ocall_getrlimit(int res, struct rlimit *rlim)
{
    log_ocall(__func__);
    return getrlimit(res, rlim);
}
int ocall_setrlimit(int resource, struct rlimit *rlim)
{
    log_ocall(__func__);
    //if (resource == 7) return 0;
    printf("ocall_setrlimit(resource: %d; rlim->rlim_cur: %lu; rlim->rlim_max: %lu)\n",
           resource, rlim->rlim_cur, rlim->rlim_max);
    return setrlimit(resource, rlim);
}

int ocall_uname(struct utsname *buf)
{
    log_ocall(__func__);
    return uname(buf);
}

unsigned int ocall_sleep(unsigned int secs)
{
    log_ocall(__func__);
    return sleep(secs);
}

int ocall_usleep(useconds_t usec)
{
    log_ocall(__func__);
    return usleep(usec);
}

void ocall_realpath(const char *path, char *res_path)
{
    log_ocall(__func__);
    realpath(path, res_path);
}

void ocall_xpg_strerror_r(int errnum, char *buf, size_t buflen)
{
    log_ocall(__func__);
    char err[8] = "error";
    buf = err;
}
/* Signals */

int ocall_sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    log_ocall(__func__);
    return sigaction(signum, act, oldact);
}

int ocall_sigemptyset(sigset_t *set)
{
    log_ocall(__func__);
    return sigemptyset(set);
}

int ocall_sigaddset(sigset_t *set, int signum)
{
    log_ocall(__func__);
    return sigaddset(set, signum);
}

int ocall_sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
{
    log_ocall(__func__);
    return sigprocmask(how, set, oldset);
}

__sighandler_t ocall_signal(int signum, __sighandler_t handler)
{
    log_ocall(__func__);
    return nullptr; //signal(signum, handler);
}

int ocall_kill(pid_t pid, int sig)
{
    log_ocall(__func__);
    return kill(pid, sig);
}

/* Mem management */
int ocall_munmap(void *addr, size_t len)
{
    log_ocall(__func__);
    return munmap(addr, len);
}

void *ocall_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    log_ocall(__func__);
    return mmap(addr, length, prot, flags, fd, offset);
}
int ocall_mprotect(void *addr, size_t len, int prot)
{
    //int new_prot = prot;
    log_ocall(__func__);
    return mprotect(addr, len, prot);
}

/* cpuid: for libchelper.a */
#include <cpuid.h>
/* Part 1: for trusted side: enclave */
unsigned int ocall_get_cpuid_max(unsigned int ext, unsigned int *sig)
{
    log_ocall(__func__);
    return __get_cpuid_max(ext, sig);
}
int ocall_get_cpuid_count(unsigned int leaf, unsigned int subleaf, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
    log_ocall(__func__);
    int cpuInfo[4];
    asm volatile("cpuid"
                 : "=a"(cpuInfo[0]), "=b"(cpuInfo[1]), "=c"(cpuInfo[2]), "=d"(cpuInfo[3])
                 : "a"(leaf), "c"(0));

    *eax = cpuInfo[0];
    *ebx = cpuInfo[1];
    *ecx = cpuInfo[2];
    *edx = cpuInfo[3];

    return 1;
}
int ocall_get_cpuid(unsigned int leaf, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{
    log_ocall(__func__);
    //return (get_cpuid_count(leaf, 0, eax, ebx, ecx, edx));
}

/* Part 2: for untrusted side: app */
//TODO: put these prototypes in a header file
#if defined(__cplusplus)
extern "C"
{
#endif

    unsigned int get_cpuid_max(unsigned int ext, unsigned int *sig);
    int get_cpuid_count(unsigned int leaf, unsigned int subleaf, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx);
    int get_cpuid(unsigned int leaf, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx);

#if defined(__cplusplus)
}
#endif

unsigned int get_cpuid_max(unsigned int ext, unsigned int *sig)
{

    return __get_cpuid_max(ext, sig);
}

int get_cpuid_count(unsigned int leaf, unsigned int subleaf, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{

    int cpuInfo[4];
    asm volatile("cpuid"
                 : "=a"(cpuInfo[0]), "=b"(cpuInfo[1]), "=c"(cpuInfo[2]), "=d"(cpuInfo[3])
                 : "a"(leaf), "c"(0));

    *eax = cpuInfo[0];
    *ebx = cpuInfo[1];
    *ecx = cpuInfo[2];
    *edx = cpuInfo[3];

    //__cpuid_count(leaf, subleaf, *eax, *ebx, *ecx, *edx);
    return 1;
}

int get_cpuid(unsigned int leaf, unsigned int *eax, unsigned int *ebx, unsigned int *ecx, unsigned int *edx)
{

    return (get_cpuid_count(leaf, 0, eax, ebx, ecx, edx));
}
