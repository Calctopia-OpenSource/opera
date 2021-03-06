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

#include <openssl/sha.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "sgx_tcrypto.h"
#include "sgx_error.h"
#include "cpuid.h"
#include "rdrand.h"
#include "ippcp.h"

#define RDRAND_MASK     0x40000000
#undef memset_s /* in case it was defined as a macro */

#ifdef __cplusplus
extern "C"
#endif
int memset_s(void *s, size_t smax, int c, size_t n);

/*
 * __memset_vp is a volatile pointer to a function.
 * It is initialised to point to memset, and should never be changed.
 */
static void * (* const volatile __memset_vp)(void *, int, size_t)
    = (memset);

static int g_is_rdrand_supported=-1;

sgx_status_t sgx_sha256_msg(const uint8_t *p_src, uint32_t src_len,
        sgx_sha256_hash_t *p_hash)
{
    if ((p_src == NULL) || (p_hash == NULL)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    if (SHA256((const unsigned char *)p_src, src_len,
                (unsigned char *)p_hash) == NULL)
    {
        return SGX_ERROR_UNEXPECTED;
    }
    return SGX_SUCCESS;
}


static int rdrand_cpuid()
{
    int info[4] = {-1, -1, -1, -1};

    /* Are we on an Intel processor? */
    __cpuid(info, 0);
    if (memcmp(&info[1], "Genu", 4) != 0 ||
        memcmp(&info[3], "ineI", 4) != 0 ||
        memcmp(&info[2], "ntel", 4) != 0 ) {
            return 0;
    }

   /* Do we have RDRAND? */
    __cpuid(info, /*feature bits*/1);
    int ecx = info[2];
    if ((ecx & RDRAND_MASK) == RDRAND_MASK) {
        return 1;
    } else {
        return 0;
    }
}


extern "C" sgx_status_t SGXAPI sgx_read_rand(uint8_t *buf, size_t size)
{
    if (buf == NULL || size == 0 || size > UINT32_MAX) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (g_is_rdrand_supported==-1) {
        g_is_rdrand_supported = rdrand_cpuid();
    }
    if (!g_is_rdrand_supported) {
        uint32_t i;
        for (i=0; i < (uint32_t)size; ++i) {
            buf[i] = (uint8_t)rand();
        }
    } else {
        int rd_ret = rdrand_get_bytes((uint32_t)size, buf);
        if (rd_ret != RDRAND_SUCCESS) {
            rd_ret = rdrand_get_bytes((uint32_t)size, buf);
            if (rd_ret != RDRAND_SUCCESS) {
                return SGX_ERROR_UNEXPECTED;
            }
        }
    }
    return SGX_SUCCESS;
}


int memset_s(void *s, size_t smax, int c, size_t n)
{
    int err = 0;

    if (s == NULL) {
        err = EINVAL;
        goto out;
    }
    if (smax > SIZE_MAX) {
        err = E2BIG;
        goto out;
    }
    if (n > SIZE_MAX) {
        err = E2BIG;
        n = smax;
    }
    if (n > smax) {
        err = EOVERFLOW;
        n = smax;
    }

    /* Calling through a volatile pointer should never be optimised away. */
    (*__memset_vp)(s, c, n);

    out:
    if (err == 0) {
        return 0;
    } else {
        errno = err;
        return err;
    }
}

