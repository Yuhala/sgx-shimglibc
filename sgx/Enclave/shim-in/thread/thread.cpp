/*
 * Created on Fri Jul 24 2020
 *
 * Copyright (c) 2017 Panoply
 * Copyright (c) 2020 Peterson Yuhala, IIUN
 * Some code ideas here is based on code from Panoply source code e.g job map
 * 
 */
#include "../../checks.h" //for pointer checks
#include "../../Enclave.h"
#include <map>
#include <sgx_trts.h>

extern sgx_enclave_id_t global_eid;
extern bool enclave_initiated;

sgx_thread_mutex_t job_map_mutex = SGX_THREAD_MUTEX_INITIALIZER;
sgx_thread_mutex_t pthreadid_map_mutex = SGX_THREAD_MUTEX_INITIALIZER;
std::map<unsigned long int, pthread_job_t> id_to_job_info_map;
std::map<sgx_thread_t, pthread_t> sgx_thread_id_to_pthread_id_info_map;

int pthread_create(pthread_t *thread, GRAAL_SGX_PTHREAD_ATTR attr,
                   void *(*start_routine)(void *), void *arg)
{
    GRAAL_SGX_INFO();
    if (!enclave_initiated)
    {
        fprintf(SGX_STDERR, "The enclave has not been initiated.");
        abort();
    }

    pthread_job_t new_job = {start_routine, arg};
    unsigned long int job_id = put_job(new_job);
    int ret;
    ocall_pthread_create(&ret, thread, job_id, global_eid);
    return ret;
}

pthread_t pthread_self(void)
{
    GRAAL_SGX_INFO();
    pthread_t ret;
    ocall_pthread_self(&ret);
    return ret;
}

int pthread_join(pthread_t thread, void **retval)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_pthread_join(&ret, thread, retval);
    return ret;
}

/*int pthread_attr_getguardsize(GRAAL_SGX_PTHREAD_ATTR attr, size_t *guardsize)
{
    GRAAL_SGX_INFO();
    int ret;
    ocall_pthread_attr_getguardsize(&ret, guardsize);
    return ret;
}*/

int pthread_attr_setdetachstate(GRAAL_SGX_PTHREAD_ATTR attr, int detachstate)
{
    GRAAL_SGX_INFO();
    //TODO
    int ret = 0;
    return ret;
}
int pthread_attr_init(GRAAL_SGX_PTHREAD_ATTR attr)
{
    GRAAL_SGX_INFO();
    //TODO
    int ret = 0;
    return ret;
}
int pthread_setname_np(pthread_t thread, const char *name)
{
    GRAAL_SGX_INFO();
    //TODO
    int ret = 0;
    return ret;
}
int pthread_getname_np(pthread_t thread, char *name, size_t len)
{
    GRAAL_SGX_INFO();
    //TODO
    int ret = 0;
    return ret;
}
int pthread_attr_setstacksize(GRAAL_SGX_PTHREAD_ATTR attr, size_t stacksize)
{
    GRAAL_SGX_INFO();
    //TODO
    int ret = 0;
    return ret;
}

int pthread_attr_getguardsize(GRAAL_SGX_PTHREAD_ATTR attr, size_t *guardsize)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_pthread_attr_getguardsize__bypass(&ret, attr, sizeof(pthread_attr_t), guardsize);
    //ocall_pthread_attr_getguardsize(&ret, guardsize);
    return ret;
}

int pthread_attr_destroy(GRAAL_SGX_PTHREAD_ATTR attr)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_pthread_attr_destroy__bypass(&ret, attr, sizeof(pthread_attr_t));
    //ocall_pthread_attr_destroy(&ret);
    return ret;
}

int pthread_attr_getstack(pthread_attr_t *attr, void **stackaddr, size_t *stacksize)
{
    GRAAL_SGX_INFO();
    //printf("[ENCLAVE] pthread_attr_getstack(..)\n");
    int ret = 0;
    ocall_pthread_attr_getstack__bypass(&ret, attr, sizeof(pthread_attr_t), stackaddr, sizeof(intptr_t), stacksize);
    //ocall_pthread_attr_getstack(&ret, stackaddr, stacksize);
    return ret;
}

/*int pthread_attr_getstack(pthread_attr_t *attr, void **stackaddr, size_t *stacksize)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    intptr_t sp; //stack pointer
    //printf("Dummy stack addr: %p\n", *stackaddr);
    //*stackaddr = nullptr;
    //*stacksize = 0x1000000;
    ocall_pthread_attr_getstack(&ret, stackaddr, sizeof(intptr_t), stacksize);
    //printf("Stack addr ocall: %p\n", *stackaddr);
    *stacksize = 0x1000000;
    asm("movq %%rsp, %0"
        : "=r"(sp));

    *stackaddr = nullptr;
    // *stackaddr = (void *)sp;
    // printf("Stack addr regis: %p\n", (void *)sp);
    return ret;
}*/

int pthread_getattr_np(pthread_t tid, GRAAL_SGX_PTHREAD_ATTR attr)
{
    GRAAL_SGX_INFO();
    printf("[ENCLAVE] pthread_getattr_np(tid: %lu, attr: %p)\n", tid, attr);
    printf(">>>>>>>>>> SGX thread id: %lu\n", sgx_thread_self());
    printf(">>>>>>>>>> POSIX thread id: %lu\n", pthread_self());
    int ret = 0;
    ocall_pthread_getattr_np__bypass(&ret, tid, attr, sizeof(pthread_attr_t));
    //ocall_pthread_getattr_np(&ret, tid);
    return ret;
}

/*int pthread_getattr_np(pthread_t tid, GRAAL_SGX_PTHREAD_ATTR attr)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    ocall_pthread_getattr_np(&ret, tid);
    return ret;
}*/

int pthread_condattr_setclock(pthread_condattr_t *attr, clockid_t clock_id)
{
    GRAAL_SGX_INFO();
    //TODO xxx
    int ret = 0;
    ret = ocall_pthread_condattr_setclock(&ret, attr, clock_id, sizeof(pthread_condattr));

    return ret;
}

int pthread_condattr_init(pthread_condattr_t *attr)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    memset(attr, '\0', sizeof(*attr)); //TODO: allocate attr in map outside with pthread id
    //ocall_pthread_condattr_init(&ret, attr);
    return ret;
}

int pthread_cond_timedwait(pthread_cond_t *__restrict__ cond,
                           pthread_mutex_t *__restrict__ mutex,
                           const struct timespec *__restrict__ abstime)
{
    //GRAAL_SGX_INFO();
    int ret = 0;
    //TODO xxx
    ret = sgx_thread_cond_wait((sgx_thread_cond_t *)cond, (sgx_thread_mutex_t *)mutex);
    return ret;
}

int pthread_mutex_init(pthread_mutex_t *__restrict__ mutex, const pthread_mutexattr_t *__restrict__ attr)
{
    return sgx_thread_mutex_init((sgx_thread_mutex_t *)mutex, (sgx_thread_mutexattr_t *)attr);
}

int pthread_mutex_lock(pthread_mutex_t *mutex)
{

    return sgx_thread_mutex_lock((sgx_thread_mutex_t *)mutex);
}

int pthread_mutex_trylock(pthread_mutex_t *mutex)
{
    return sgx_thread_mutex_trylock((sgx_thread_mutex_t *)mutex);
}

int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    return sgx_thread_mutex_unlock((sgx_thread_mutex_t *)mutex);
}

int pthread_cond_broadcast(pthread_cond_t *cond)
{
    return sgx_thread_cond_broadcast((sgx_thread_cond_t *)cond);
}

int pthread_cond_wait(pthread_cond_t *__restrict__ cond, pthread_mutex_t *__restrict__ mutex)
{
    return sgx_thread_cond_wait((sgx_thread_cond_t *)cond, (sgx_thread_mutex_t *)mutex);
}

int pthread_cond_init(pthread_cond_t *__restrict__ cond, const pthread_condattr_t *__restrict__ attr)
{
    return sgx_thread_cond_init((sgx_thread_cond_t *)cond, (sgx_thread_condattr_t *)attr);
}

int pthread_key_create(pthread_key_t *key, void (*destructor)(void *))
{
    GRAAL_SGX_INFO();
    int ret = 0;
    void *ptr = malloc(sizeof(pthread_key_t));
    key = ptr; //nonsense ?
    printf("TODO: %s\n", __func__);
    return ret;
}

void *pthread_getspecific(pthread_key_t key)
{

    GRAAL_SGX_INFO();
    printf("TODO: %s\n", __func__);
    return NULL;
}
int pthread_setspecific(pthread_key_t key, const void *value)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    printf("TODO: %s\n", __func__);
    return ret;
}

int sched_yield(void)
{
    GRAAL_SGX_INFO();
    int ret = 0;
    Pause();
    return ret;
}

int nanosleep(const struct timespec *__requested_time, struct timespec *__remaining)
{
    //TODO
    return 0;
}

/**
 *  Job related functions
 *  Copyright (c) Panoply 2017
 */

static inline unsigned long int get_random_id()
{
    unsigned long int rand_number = 0;
    sgx_read_rand((unsigned char *)(&rand_number), sizeof(rand_number));
    return rand_number;
}

unsigned long int put_job(pthread_job_t new_job)
{
    unsigned long int new_id = get_random_id();
    sgx_thread_mutex_lock(&job_map_mutex);
    while (id_to_job_info_map.count((new_id)) > 0)
    {
        new_id = get_random_id();
    }
    id_to_job_info_map.insert(std::pair<unsigned long int, pthread_job_t>(new_id, new_job));
    sgx_thread_mutex_unlock(&job_map_mutex);
    return new_id;
}

bool get_job(unsigned long int job_id, pthread_job_t *pt_job)
{
    //Retrieve the job information for the corresponding job id
    // printf("Some one call get_job %d \n", job_id);
    std::map<unsigned long int, pthread_job_t>::iterator it = id_to_job_info_map.find(job_id);
    if (it != id_to_job_info_map.end())
    {
        pthread_job_t *tmp = &it->second;
        *pt_job = *tmp;
        id_to_job_info_map.erase(job_id);
        return true;
    }
    else
    {
        return false;
    }
}

bool get_pthreadid_from_sgxthreadid(sgx_thread_t sgx_id, pthread_t *pt)
{
    std::map<sgx_thread_t, pthread_t>::iterator it = sgx_thread_id_to_pthread_id_info_map.find(sgx_id);
    if (it != sgx_thread_id_to_pthread_id_info_map.end())
    {
        pthread_t *tmp = &it->second;
        *pt = *tmp;
        return true;
    }
    else
    {
        return false;
    }
}

void ecall_execute_job(pthread_t pthread_id, unsigned long int job_id)
{
    GRAAL_SGX_INFO();
    pthread_job_t execute_job = {NULL, NULL};
    sgx_thread_t sgx_id = sgx_thread_self();

    sgx_thread_mutex_lock(&pthreadid_map_mutex);
    sgx_thread_id_to_pthread_id_info_map.insert(std::pair<sgx_thread_t, pthread_t>(sgx_id, pthread_id));
    sgx_thread_mutex_unlock(&pthreadid_map_mutex);

    if (get_job(job_id, &execute_job))
        if (execute_job.start_routine != NULL)
        {
            printf("Executing start_routine %p by the pthread_id: %d \n", execute_job.start_routine, (unsigned long)pthread_id);
            execute_job.start_routine(execute_job.arg);
        }
}
