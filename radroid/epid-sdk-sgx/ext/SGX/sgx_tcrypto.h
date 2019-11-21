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


#ifndef RADROIDALPHA_SGX_TCRYPTO_H
#define RADROIDALPHA_SGX_TCRYPTO_H
/**
* File: sgx_tcrypto.h
* Description:
*     Interface for generic crypto library APIs required in SDK implementation.
*/

#include "sgx.h"
#include "sgx_defs.h"
#include "stdlib.h"

#define SGX_SHA1_HASH_SIZE              20
#define SGX_SHA256_HASH_SIZE            32
#define SGX_ECP256_KEY_SIZE             32
#define SGX_NISTP_ECP256_KEY_SIZE       (SGX_ECP256_KEY_SIZE/sizeof(uint32_t))
#define SGX_AESGCM_IV_SIZE              12
#define SGX_AESGCM_KEY_SIZE             16
#define SGX_AESGCM_MAC_SIZE             16
#define SGX_HMAC256_KEY_SIZE            32
#define SGX_HMAC256_MAC_SIZE            32
#define SGX_CMAC_KEY_SIZE               16
#define SGX_CMAC_MAC_SIZE               16
#define SGX_AESCTR_KEY_SIZE             16
#define SGX_RSA3072_KEY_SIZE            384
#define SGX_RSA3072_PRI_EXP_SIZE        384
#define SGX_RSA3072_PUB_EXP_SIZE        4

typedef struct _sgx_ec256_dh_shared_t
{
    uint8_t s[SGX_ECP256_KEY_SIZE];
} sgx_ec256_dh_shared_t;

typedef struct _sgx_ec256_private_t
{
    uint8_t r[SGX_ECP256_KEY_SIZE];
} sgx_ec256_private_t;

typedef struct _sgx_ec256_public_t
{
    uint8_t gx[SGX_ECP256_KEY_SIZE];
    uint8_t gy[SGX_ECP256_KEY_SIZE];
} sgx_ec256_public_t;

typedef struct _sgx_ec256_signature_t
{
    uint32_t x[SGX_NISTP_ECP256_KEY_SIZE];
    uint32_t y[SGX_NISTP_ECP256_KEY_SIZE];
} sgx_ec256_signature_t;

typedef struct _sgx_rsa3072_public_key_t
{
    uint8_t mod[SGX_RSA3072_KEY_SIZE];
    uint8_t exp[SGX_RSA3072_PUB_EXP_SIZE];
} sgx_rsa3072_public_key_t;

typedef struct _sgx_rsa3072_key_t
{
    uint8_t mod[SGX_RSA3072_KEY_SIZE];
    uint8_t d[SGX_RSA3072_PRI_EXP_SIZE];
    uint8_t e[SGX_RSA3072_PUB_EXP_SIZE];
} sgx_rsa3072_key_t;

typedef uint8_t sgx_rsa3072_signature_t[SGX_RSA3072_KEY_SIZE];

typedef void* sgx_sha_state_handle_t;
typedef void* sgx_hmac_state_handle_t;
typedef void* sgx_cmac_state_handle_t;
typedef void* sgx_ecc_state_handle_t;
typedef void* sgx_aes_state_handle_t;

typedef uint8_t sgx_sha1_hash_t[SGX_SHA1_HASH_SIZE];
typedef uint8_t sgx_sha256_hash_t[SGX_SHA256_HASH_SIZE];

typedef uint8_t sgx_aes_gcm_128bit_key_t[SGX_AESGCM_KEY_SIZE];
typedef uint8_t sgx_aes_gcm_128bit_tag_t[SGX_AESGCM_MAC_SIZE];
typedef uint8_t sgx_hmac_256bit_key_t[SGX_HMAC256_KEY_SIZE];
typedef uint8_t sgx_hmac_256bit_tag_t[SGX_HMAC256_MAC_SIZE];
typedef uint8_t sgx_cmac_128bit_key_t[SGX_CMAC_KEY_SIZE];
typedef uint8_t sgx_cmac_128bit_tag_t[SGX_CMAC_MAC_SIZE];
typedef uint8_t sgx_aes_ctr_128bit_key_t[SGX_AESCTR_KEY_SIZE];

typedef enum {
    SGX_EC_VALID,               /* validation pass successfully     */

    SGX_EC_COMPOSITE_BASE,      /* field based on composite         */
    SGX_EC_COMPLICATED_BASE,    /* number of non-zero terms in the polynomial (> PRIME_ARR_MAX) */
    SGX_EC_IS_ZERO_DISCRIMINANT,/* zero discriminant */
    SGX_EC_COMPOSITE_ORDER,     /* composite order of base point    */
    SGX_EC_INVALID_ORDER,       /* invalid base point order         */
    SGX_EC_IS_WEAK_MOV,         /* weak Meneze-Okamoto-Vanstone  reduction attack */
    SGX_EC_IS_WEAK_SSA,         /* weak Semaev-Smart,Satoh-Araki reduction attack */
    SGX_EC_IS_SUPER_SINGULAR,   /* supersingular curve */

    SGX_EC_INVALID_PRIVATE_KEY, /* !(0 < Private < order) */
    SGX_EC_INVALID_PUBLIC_KEY,  /* (order*PublicKey != Infinity)    */
    SGX_EC_INVALID_KEY_PAIR,    /* (Private*BasePoint != PublicKey) */

    SGX_EC_POINT_OUT_OF_GROUP,  /* out of group (order*P != Infinity)  */
    SGX_EC_POINT_IS_AT_INFINITY,/* point (P=(Px,Py)) at Infinity  */
    SGX_EC_POINT_IS_NOT_VALID,  /* point (P=(Px,Py)) out-of EC    */

    SGX_EC_POINT_IS_EQUAL,      /* compared points are equal     */
    SGX_EC_POINT_IS_NOT_EQUAL,  /* compared points are different  */

    SGX_EC_INVALID_SIGNATURE    /* invalid signature */
} sgx_generic_ecresult_t;


typedef enum {
    SGX_RSA_VALID,               /* validation pass successfully     */

    SGX_RSA_INVALID_SIGNATURE    /* invalid signature */
} sgx_rsa_result_t;

typedef enum {
    SGX_RSA_PRIVATE_KEY,               /* RSA private key state     */

    SGX_RSA_PUBLIC_KEY    /* RSA public key state */
} sgx_rsa_key_type_t;

#define N_SIZE_IN_BYTES    384
#define E_SIZE_IN_BYTES    4
#define D_SIZE_IN_BYTES    384
#define P_SIZE_IN_BYTES    192
#define Q_SIZE_IN_BYTES    192
#define DMP1_SIZE_IN_BYTES 192
#define DMQ1_SIZE_IN_BYTES 192
#define IQMP_SIZE_IN_BYTES 192

#define N_SIZE_IN_UINT     (N_SIZE_IN_BYTES/sizeof(unsigned int))
#define E_SIZE_IN_UINT     (E_SIZE_IN_BYTES/sizeof(unsigned int))
#define D_SIZE_IN_UINT     (D_SIZE_IN_BYTES/sizeof(unsigned int))
#define P_SIZE_IN_UINT     (P_SIZE_IN_BYTES/sizeof(unsigned int))
#define Q_SIZE_IN_UINT     (Q_SIZE_IN_BYTES/sizeof(unsigned int))
#define DMP1_SIZE_IN_UINT  (DMP1_SIZE_IN_BYTES/sizeof(unsigned int))
#define DMQ1_SIZE_IN_UINT  (DMQ1_SIZE_IN_BYTES/sizeof(unsigned int))
#define IQMP_SIZE_IN_UINT  (IQMP_SIZE_IN_BYTES/sizeof(unsigned int))

typedef struct _rsa_params_t {
    unsigned int n[N_SIZE_IN_UINT];
    unsigned int e[E_SIZE_IN_UINT];
    unsigned int d[D_SIZE_IN_UINT];
    unsigned int p[P_SIZE_IN_UINT];
    unsigned int q[Q_SIZE_IN_UINT];
    unsigned int dmp1[DMP1_SIZE_IN_UINT];
    unsigned int dmq1[DMQ1_SIZE_IN_UINT];
    unsigned int iqmp[IQMP_SIZE_IN_UINT];
}rsa_params_t;

#endif //RADROIDALPHA_SGX_TCRYPTO_H
