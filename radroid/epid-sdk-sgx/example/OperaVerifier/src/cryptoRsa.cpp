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

extern "C"{
    #include <stdint.h>
    #include "src/cryptoRsa.h"
    #include "ext/ipp-crypto/sources/ippcp/pcpngrsa.h"
    #include "ext/SGX/sgx_tcrypto.h"
    #include "ext/SGX/se_tcrypto_common.h"
    #include "ext/SGX/ssl_crypto.h"
    #include "ext/SGX/ssl_compat_wrapper.h"
    #include "ext/SGX/assert.h"
    #include "ext/SGX/assert.h"
    #include "ext/SGX/se_memcpy.h"
    #include "ext/SGX/ipp_wrapper.h"
    #include "ext/openssl/include/rsa.h"
    #include "ext/openssl/include/evp.h"
    #include "ext/openssl/include/pem.h"
    #include "ext/openssl/include/sha.h"
    #include "ext/openssl/include/err.h"
}

sgx_status_t sgx_create_rsa_pub1_key(int mod_size, int exp_size, const unsigned char *le_n, const unsigned char *le_e, void **new_pub_key1)
{
    if (new_pub_key1 == NULL || mod_size <= 0 || exp_size <= 0 || le_n == NULL || le_e == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    IppsRSAPublicKeyState *p_pub_key = NULL;
    IppsBigNumState *p_n = NULL, *p_e = NULL;
    int rsa_size = 0;
    sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;
    IppStatus error_code = ippStsNoErr;

    do {

        //generate and assign RSA components BNs
        //
        error_code = sgx_ipp_newBN((const Ipp32u*)le_n, mod_size, &p_n);
        ERROR_BREAK(error_code);
        error_code = sgx_ipp_newBN((const Ipp32u*)le_e, exp_size, &p_e);
        ERROR_BREAK(error_code);

        //allocate and initialize public key
        //
        error_code = ippsRSA_GetSizePublicKey(mod_size * 8, exp_size * 8, &rsa_size);
        ERROR_BREAK(error_code);
        p_pub_key = (IppsRSAPublicKeyState *)malloc(rsa_size);
        if (!p_pub_key)
        {
            error_code = ippStsMemAllocErr;
            break;
        }
        error_code = ippsRSA_InitPublicKey(mod_size * 8, exp_size * 8, p_pub_key, rsa_size);
        ERROR_BREAK(error_code);

        //setup public key with values of input components
        //
        error_code = ippsRSA_SetPublicKey(p_n, p_e, p_pub_key);
        ERROR_BREAK(error_code);

        *new_pub_key1 = (void*)p_pub_key;
        ret_code = SGX_SUCCESS;
    } while (0);

    sgx_ipp_secure_free_BN(p_n, mod_size);
    sgx_ipp_secure_free_BN(p_e, exp_size);

    if (error_code == ippStsMemAllocErr)
        ret_code = SGX_ERROR_OUT_OF_MEMORY;

    if (ret_code != SGX_SUCCESS) {
        secure_free_rsa_pub_key(mod_size, exp_size, p_pub_key);
    }

    return ret_code;
}


sgx_status_t sgx_free_rsa_key(void *p_rsa_key, sgx_rsa_key_type_t key_type, int mod_size, int exp_size)
{
    (void)(key_type);
    (void)(mod_size);
    (void)(exp_size);
    if (p_rsa_key != NULL)
    {
        EVP_PKEY_free((EVP_PKEY*)p_rsa_key);
    }
    return SGX_SUCCESS;
}

/* SHA Hashing functions
* Parameters:
*   Return: sgx_status_t  - SGX_SUCCESS or failure as defined sgx_error.h
*   Inputs: uint8_t *p_src - Pointer to input stream to be hashed
*           uint32_t src_len - Length of input stream to be hashed
*   Output: sgx_sha256_hash_t *p_hash - Resultant hash from operation */
sgx_status_t sgx_sha256_msg(const uint8_t *p_src, uint32_t src_len, sgx_sha256_hash_t *p_hash)
{
    if ((p_src == NULL) || (p_hash == NULL))
    {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t retval = SGX_ERROR_UNEXPECTED;

    do {
        /* generates digest of p_src */
        if (SHA256((const unsigned char *)p_src, src_len, (unsigned char *)p_hash) == NULL) {
        break;
        }

        retval = SGX_SUCCESS;
    } while(0);


    return retval;
}

IppStatus sgx_ipp_newBN(const Ipp32u *p_data, int size_in_bytes, IppsBigNumState **p_new_BN)
{
    IppsBigNumState *pBN = 0;
    int bn_size = 0;

    if (p_new_BN == NULL || (size_in_bytes <= 0) || ((size_in_bytes % sizeof(Ipp32u)) != 0))
        return ippStsBadArgErr;

    // Get the size of the IppsBigNumState context in bytes
    IppStatus error_code = ippsBigNumGetSize(size_in_bytes/(int)sizeof(Ipp32u), &bn_size);
    if (error_code != ippStsNoErr)
    {
        *p_new_BN = 0;
        return error_code;
    }
    pBN = (IppsBigNumState *)malloc(bn_size);
    if (!pBN)
    {
        error_code = ippStsMemAllocErr;
        *p_new_BN = 0;
        return error_code;
    }
    // Initialize context and partition allocated buffer
    error_code = ippsBigNumInit(size_in_bytes/(int)sizeof(Ipp32u), pBN);
    if (error_code != ippStsNoErr)
    {
        free(pBN);
        *p_new_BN = 0;
        return error_code;
    }
    if (p_data)
    {
        error_code = ippsSet_BN(IppsBigNumPOS, size_in_bytes/(int)sizeof(Ipp32u), p_data, pBN);
        if (error_code != ippStsNoErr)
        {
            *p_new_BN = 0;
            free(pBN);
            return error_code;
        }
    }


    *p_new_BN = pBN;
    return error_code;
}

void sgx_ipp_secure_free_BN(IppsBigNumState *pBN, int size_in_bytes)
{
    if (pBN == NULL || size_in_bytes <= 0 || ((size_in_bytes % sizeof(Ipp32u)) != 0))
    {
        if (pBN)
        {
            free(pBN);
        }
        return;
    }
    int bn_size = 0;

    // Get the size of the IppsBigNumState context in bytes
    // Since we have checked the size_in_bytes before and the &bn_size is not NULL, ippsBigNumGetSize never returns failure
    IppStatus error_code = ippsBigNumGetSize(size_in_bytes/(int)sizeof(Ipp32u), &bn_size);
    if (error_code != ippStsNoErr)
    {
        free(pBN);
        return;
    }
    // Clear the buffer before free.
    //TODO:Implement MEMSET
   // memset_s(pBN, bn_size, 0, bn_size);
    free(pBN);
    return;
}

void secure_free_rsa_pub_key(int n_byte_size, int e_byte_size, IppsRSAPublicKeyState *pub_key)
{
    if (n_byte_size <= 0 || e_byte_size <= 0 || pub_key == NULL) {
        if (pub_key)
            free(pub_key);
        return;
    }
    int rsa_size = 0;
    if (ippsRSA_GetSizePublicKey(n_byte_size * 8, e_byte_size * 8, &rsa_size) != ippStsNoErr) {
        free(pub_key);
        return;
    }
    /* Clear the buffer before free. */
    //TODO:Implement Memset
   // memset_s(pub_key, rsa_size, 0, rsa_size);
    free(pub_key);
    return;
}