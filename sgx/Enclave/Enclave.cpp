/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"

#include <sgx_spinlock.h>

#include <inttypes.h>



/* Global variables */
sgx_enclave_id_t global_eid;
bool enclave_initiated;

static __thread pid_t global_tid = -1;

SGX_FILE stdin = SGX_STDIN;
SGX_FILE stdout = SGX_STDOUT;
SGX_FILE stderr = SGX_STDERR;

// pyuhala: should we return 0 or not in the should_be_switchless routine
//  by default do not use zc switchless, ie return_zero = 1
int return_zero = 1;

void ecall_undef_stack_protector()
{
#ifdef __SSP_STRONG__
    printf("__SSP_STRONG__ macro is defined, with value 3, -fstack-protector-strong is in use.\n");
#undef __SSP_STRONG__
#endif
}

pid_t gettid(void)
{
    long tid;
    if (global_tid < 0)
    {
        //ocall_gettid(&tid);
        global_tid = (pid_t)tid;
    }
    return global_tid;
}

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void fill_array()
{
    printf("Filling inside array\n");
    unsigned int size = 1024 * 1024 * 4; // 16mb
    int *array = (int *)malloc(sizeof(int) * size);
    int idx = 0;
    for (int i = 0; i < size; i++)
    {
        array[i] = i;
        idx = i;
    }
    printf("Largest index in: %d\n", idx);
}

/* makes 10 million calls to read or write with a buffer of size 0 <= n <=
 * 65536, switchlessly or not (check what `should_be_switchless` returns before
 * using this)
 */
void rw_benchmark(int n)
{
    int i, fdr, fdw;
    ssize_t ret;
    int buf[65536];

    if ((fdr = open("/dev/zero", O_RDONLY)) == -1)
        printf("\e[1;31mErreur !\e[0m\n");
    for (i = 0; i < 100000; i++)
        ocall_read(&ret, fdr, buf, n);
}

void run_main()
{
    for (int i = 0; i < 4; i++)
    {
        printf("----------------- Hello Petman ----------------\n");
    }
}

void ecall_run_main(int id)
{
    global_eid = id;
    enclave_initiated = true;
    printf("In ecall run main. Global eid: %d \n", id);
    run_main();
}


