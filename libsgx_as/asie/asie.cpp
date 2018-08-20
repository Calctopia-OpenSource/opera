/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
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


// #ifndef __linux__
// #include "targetver.h"
// #endif
// Exclude rarely-used stuff from Windows headers
//#define WIN32_LEAN_AND_MEAN
// Windows Header Files:
//#include <windows.h>

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
// #include "se_types.h"
// #include "sgx_quote.h"
// #include "aeerror.h"
// #include "sgx_tseal.h"
// #include "sgx_lfence.h"
// #include "epid_pve_type.h"
#include "sgx_utils.h"
#include "ipp_wrapper.h"
// #include "epid/common/errors.h"
// #include "sgx_tcrypto.h"
#include "pve_qe_common.h"
#include "provision_msg.h"
#include "cipher.h"
// #include "byte_order.h"
#include "util.h"
#include "string.h"


#include "epid/common/stdtypes.h"
#include "epid/member/api.h"
#include "epid/verifier/api.h"
#include "asie_t.c"
#include "issuer.h"
#include "as_util.h"


#include "sgx_tae_service.h"
#include "sgx_tseal.h"

uint8_t asae_target_info_bin[512] = {0xc9,0xef,0xe9,0xc4,0x5c,0x46,0xfd,0xac,0xd1,0xb8,0xe6,0x1f,0xfb,0x98,0xfd,0x49,0x6f,0xfa,0x5e,0xbe,0x18,0x5c,0x45,0xb8,0x23,0x39,0x7f,0x3d,0xb2,0x81,0x8c,0xdb,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
sgx_target_info_t *asae_target_info = (sgx_target_info_t*)asae_target_info_bin;
/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }
#define PRINT_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    printf("%s\n", EpidStatusToString(ret));\
  }
#define RETURN_ON_IPP_ERROR(ipp_status) \
  if(ippStsNoErr != ipp_status){ \
        return false;            \
  }
#define BREAK_ON_SGX_ERROR(ret) \
  if (SGX_SUCCESS != (ret)) {     \
    break;                       \
  }


typedef struct IssuerData
{
    GroupPubKey         pub_key;
    IPrivKey            ipriv_key;
    sgx_sha256_hash_t   priv_rl_hash;
    sgx_sha256_hash_t   sig_rl_hash;    
} IssuerData;

typedef struct _replay_protected_pay_load
{
    sgx_mc_uuid_t       mc;
    uint32_t            mc_value;
    IssuerData         issuer_data;
} replay_protected_pay_load;

IssuerCtx *g_issuer = NULL;
IssuerData *g_issuer_data = NULL;
GroupVerifCert *g_grp_verif_cert = NULL;

static sgx_status_t verify_mc(replay_protected_pay_load* data2verify)
{
    sgx_status_t ret = SGX_SUCCESS;
    uint32_t mc_value;
    ret = sgx_read_monotonic_counter(&data2verify->mc,&mc_value);
    if(ret != SGX_SUCCESS)
    {
        switch(ret)
        {
        case SGX_ERROR_SERVICE_UNAVAILABLE:
            /* Architecture Enclave Service Manager is not installed or not
            working properly.*/
                break;
        case SGX_ERROR_SERVICE_TIMEOUT:
            /* retry the operation later*/
                break;
        case SGX_ERROR_BUSY:
            /* retry the operation later*/
                break;
        case SGX_ERROR_MC_NOT_FOUND:
            /* the the Monotonic Counter ID is invalid.*/
                break;
        default:
            /*other errors*/
            break;
        }
    }
    else if(mc_value!=data2verify->mc_value)
    {
        ret = SGX_ERROR_UNEXPECTED;
    }
    return ret;
}

static sgx_status_t verify_sealed_data(
    const sgx_sealed_data_t* data2unseal,
    replay_protected_pay_load* data_unsealed)
{
    sgx_status_t ret = SGX_SUCCESS;    
    replay_protected_pay_load temp_unseal;
    uint32_t unseal_length = sizeof(replay_protected_pay_load);

    ret = sgx_unseal_data_cur_cpusvn_only(data2unseal, NULL, 0,
        (uint8_t*)&temp_unseal, &unseal_length);
    if(ret != SGX_SUCCESS)
    {
        switch(ret)
        {
        case SGX_ERROR_MAC_MISMATCH:
            /* MAC of the sealed data is incorrect.
            The sealed data has been tampered.*/
            break;
        case SGX_ERROR_INVALID_ATTRIBUTE:
            /*Indicates attribute field of the sealed data is incorrect.*/
            break;
        case SGX_ERROR_INVALID_ISVSVN:
            /* Indicates isv_svn field of the sealed data is greater than
            the enclave's ISVSVN. This is a downgraded enclave.*/
            break;
        case SGX_ERROR_INVALID_CPUSVN:
            /* Indicates cpu_svn field of the sealed data is greater than
            the platform's cpu_svn. enclave is  on a downgraded platform.*/
            break;
        case SGX_ERROR_INVALID_KEYNAME:
            /*Indicates key_name field of the sealed data is incorrect.*/
            break;
        default:
            /*other errors*/
            break;
        }
        return ret;
    }
    ret = verify_mc(&temp_unseal);
    if (ret == SGX_SUCCESS)
        memcpy(data_unsealed,&temp_unseal,sizeof(replay_protected_pay_load));
    /* remember to clear secret data after been used by memset_s */
    memset_s(&temp_unseal, sizeof(replay_protected_pay_load), 0,
        sizeof(replay_protected_pay_load));
    return ret;
}

sgx_status_t create_sealed_policy(uint8_t* sealed_data, uint32_t sealed_data_size )
{
    sgx_status_t ret = SGX_SUCCESS;
    int busy_retry_times = 2;
    replay_protected_pay_load data2seal;
    memset(&data2seal, 0, sizeof(data2seal));
    uint32_t size = sgx_calc_sealed_data_size(0,
        sizeof(replay_protected_pay_load));
    if(sealed_data_size != size) 
        return SGX_ERROR_INVALID_PARAMETER;
    do{
        ret = sgx_create_pse_session();
    }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
    if (ret != SGX_SUCCESS)
        return ret;
    do
    {
        ret = sgx_create_monotonic_counter(&data2seal.mc,&data2seal.mc_value);
        if(ret != SGX_SUCCESS)
        {
            switch(ret)
            {
            case SGX_ERROR_SERVICE_UNAVAILABLE:
                /* Architecture Enclave Service Manager is not installed or not
                working properly.*/
                break;
            case SGX_ERROR_SERVICE_TIMEOUT:
                /* retry the operation later*/
                break;
            case SGX_ERROR_BUSY:
                /* retry the operation later*/
                break;
            case SGX_ERROR_MC_OVER_QUOTA:
                /* SGX Platform Service enforces a quota scheme on the Monotonic
                Counters a SGX app can maintain. the enclave has reached the
                quota.*/
                break;
            case SGX_ERROR_MC_USED_UP:
                /* the Monotonic Counter has been used up and cannot create
                Monotonic Counter anymore.*/
                break;
            default:
                /*other errors*/
                break;
            }
            break;
        }

        /* secret should be provisioned into enclave after the enclave attests to
        the secret owner.
        For example, the server that delivers the encrypted DRM content.
        In this sample code, a random number is used to represent the secret */ 
        // ret = sgx_read_rand(data2seal.secret, REPLAY_PROTECTED_SECRET_SIZE);
        // if(ret != SGX_SUCCESS)
        //     break;
        // data2seal.log.release_version = 0;
        // /* the secret can be updated for 5 times */
        // data2seal.log.max_release_version = 
            // REPLAY_PROTECTED_PAY_LOAD_MAX_RELEASE_VERSION;
        memcpy(&data2seal.issuer_data, g_issuer_data, sizeof(IssuerData));
        /*sealing the plaintext to ciphertext. The ciphertext can be delivered
        outside of enclave.*/
        ret = sgx_seal_data(0, NULL,sizeof(data2seal),(uint8_t*)&data2seal,
            sealed_data_size, (sgx_sealed_data_t*)sealed_data);
    } while (0);
    
    /* remember to clear secret data after been used by memset_s */
    memset_s(&data2seal, sizeof(replay_protected_pay_load), 0,
        sizeof(replay_protected_pay_load));
    sgx_close_pse_session();
    return ret;
}

sgx_status_t perform_sealed_policy(const uint8_t* sealed_data,
                               uint32_t sealed_data_size)
{
    sgx_status_t ret = SGX_SUCCESS;
    int busy_retry_times = 2;
    replay_protected_pay_load data_unsealed;
    if(sealed_data_size != sgx_calc_sealed_data_size(0,
        sizeof(replay_protected_pay_load))) 
        return SGX_ERROR_INVALID_PARAMETER;
    do{
        ret = sgx_create_pse_session();
    }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
    if (ret != SGX_SUCCESS)
        return ret;
    ret = verify_sealed_data((const sgx_sealed_data_t*) sealed_data,
        &data_unsealed);
    if (SGX_SUCCESS == ret)
    {
      /* release the secret to perform the requested functions,
      for example, decrypt the DRM content*/
        memcpy(g_issuer_data, &data_unsealed.issuer_data, sizeof(IssuerData));
    }
    else
    {
      /* activity log update fail to verify activity log,
      refuse to release the secret */
    }
    sgx_close_pse_session();

    /* remember to clear secret data after been used by memset_s */
    memset_s(&data_unsealed, sizeof(data_unsealed),
        0, sizeof(replay_protected_pay_load) );
    return ret;

}

sgx_status_t update_sealed_policy(uint8_t* sealed_data, uint32_t sealed_data_size)
{
    sgx_status_t ret = SGX_SUCCESS;
    int busy_retry_times = 2;
    replay_protected_pay_load data_unsealed;
    replay_protected_pay_load data2seal;
    if(sealed_data_size != sgx_calc_sealed_data_size(0,
        sizeof(replay_protected_pay_load))) 
        return SGX_ERROR_INVALID_PARAMETER;
    do{
        ret = sgx_create_pse_session();
    }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
    if (ret != SGX_SUCCESS)
        return ret;
    do
    {
        ret = verify_sealed_data((sgx_sealed_data_t*) sealed_data,
            &data_unsealed);
        if(ret != SGX_SUCCESS)
            break;

        memcpy(&data2seal,&data_unsealed, sizeof(replay_protected_pay_load));

        ret = sgx_increment_monotonic_counter(&data2seal.mc,
            &data2seal.mc_value);
        if(ret != SGX_SUCCESS)
        {
            switch(ret)
            {
            case SGX_ERROR_SERVICE_UNAVAILABLE:
                /* Architecture Enclave Service Manager is not installed or not
                working properly.*/
                break;
            case SGX_ERROR_SERVICE_TIMEOUT:
                /* retry the operation*/
                break;
            case SGX_ERROR_BUSY:
                /* retry the operation later*/
                break;
            case SGX_ERROR_MC_NOT_FOUND:
                /* The Monotonic Counter was deleted or invalidated.
                This might happen under certain conditions.
                For example, the Monotonic Counter has been deleted, the SGX
                Platform Service lost its data or the system is under attack. */
                break;
            case SGX_ERROR_MC_NO_ACCESS_RIGHT:
                /* The Monotonic Counter is not accessible by this enclave.
                This might happen under certain conditions.
                For example, the SGX Platform Service lost its data or the
                system is under attack. */
                break;
            default:
                /*other errors*/
                break;
            }
            break;
        }

        /* If the counter value returns doesn't match the expected value,
        some other entity has updated the counter, for example, another instance
        of this enclave. The system might be under attack */
        if(data2seal.mc_value!= data_unsealed.mc_value+1)
        {
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        memcpy(&data2seal.issuer_data, g_issuer_data, sizeof(IssuerData));

        /* seal the new log */
        ret = sgx_seal_data(0, NULL, sizeof(data2seal), (uint8_t*)&data2seal,
            sealed_data_size, (sgx_sealed_data_t*)sealed_data);
    } while (0);
    
    /* remember to clear secret data after been used by memset_s */
    memset_s(&data_unsealed, sizeof(replay_protected_pay_load), 0,
        sizeof(replay_protected_pay_load));

    /* remember to clear secret data after been used by memset_s */
    memset_s(&data2seal, sizeof(replay_protected_pay_load), 0,
        sizeof(replay_protected_pay_load));
    sgx_close_pse_session();
    return ret;
}

sgx_status_t delete_sealed_policy(const uint8_t* sealed_data,
                              uint32_t sealed_data_size)
{
    sgx_status_t ret = SGX_SUCCESS;
    int busy_retry_times = 2;
    replay_protected_pay_load data_unsealed;
    if(sealed_data_size != sgx_calc_sealed_data_size(0,
        sizeof(replay_protected_pay_load))) 
        return SGX_ERROR_INVALID_PARAMETER;
    do{
        ret = sgx_create_pse_session();
    }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
    if (ret != SGX_SUCCESS)
        return ret;
    do
    {
        ret = verify_sealed_data((const sgx_sealed_data_t*) sealed_data,
            &data_unsealed);
        if(ret != SGX_SUCCESS)
            break;
        ret = sgx_destroy_monotonic_counter(&data_unsealed.mc);
        if(ret != SGX_SUCCESS)
        {
            switch(ret)
            {
            case SGX_ERROR_SERVICE_UNAVAILABLE:
                /* Architecture Enclave Service Manager is not installed or not
                working properly.*/
                break;
            case SGX_ERROR_SERVICE_TIMEOUT:
                /* retry the operation later*/
                break;
            case SGX_ERROR_BUSY:
                /* retry the operation later*/
                break;
            case SGX_ERROR_MC_NOT_FOUND:
                /* the the Monotonic Counter ID is invalid.*/
                break;
            case SGX_ERROR_MC_NO_ACCESS_RIGHT:
                /* the Monotonic Counter is not accessible by this enclave.
                This might happen under certain conditions.
                For example, the SGX Platform Service lost its data or
                the system is under attack. */
                break;
            default:
                /*other errors*/
                break;
            }
        }
    } while (0);
    /* remember to clear secret data after been used by memset_s */
    memset_s(&data_unsealed, sizeof(replay_protected_pay_load), 0,
        sizeof(replay_protected_pay_load));
    sgx_close_pse_session();
    return ret;
}


uint32_t asie_create_issuer(
    uint8_t *p_sealed_blob,
    uint32_t sealed_blob_size)
{
    // printf("sizeof GroupVerifCert %d\n", sizeof(GroupVerifCert));
    // printf("sizeof ASQuote %d\n", sizeof(ASQuote));
    // printf("sizeof sealed_blob_size %d\n", sgx_calc_sealed_data_size(0,
    //         sizeof(replay_protected_pay_load)));
    // return 1;
    EpidStatus res = kEpidNoErr;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    do {
        if (!p_sealed_blob || sealed_blob_size != sgx_calc_sealed_data_size(0,
            sizeof(replay_protected_pay_load)))
        {
            res = kEpidBadArgErr;
            break;
        }

        EpidIssuerDelete(&g_issuer);
        BREAK_ON_EPID_ERROR(res);
        if (!g_issuer_data) {
            g_issuer_data = (IssuerData*) malloc(sizeof(IssuerData));
        }
        res = EpidIssuerCreate(epid_random_func, NULL, &g_issuer);
        BREAK_ON_EPID_ERROR(res);
        res = ExportGroupPubKey(&g_issuer_data->pub_key, g_issuer);
        BREAK_ON_EPID_ERROR(res);
        res = ExportIPrivKey(&g_issuer_data->ipriv_key, g_issuer);
        BREAK_ON_EPID_ERROR(res);

        ret = sgx_sha256_msg(reinterpret_cast<const uint8_t*>(g_issuer->priv_rl),
                             uint64_to_uint32(GetPrivRlSize(g_issuer->priv_rl)),
                             &g_issuer_data->priv_rl_hash);
        BREAK_ON_SGX_ERROR(ret);
        ret = sgx_sha256_msg(reinterpret_cast<const uint8_t*>(g_issuer->sig_rl),
                             uint64_to_uint32(GetSigRlSize(g_issuer->sig_rl)),
                             &g_issuer_data->sig_rl_hash);
        BREAK_ON_SGX_ERROR(ret);

        ret = create_sealed_policy(p_sealed_blob, sealed_blob_size);
        BREAK_ON_SGX_ERROR(ret);
    } while(0);
    if (res != kEpidNoErr || ret != SGX_SUCCESS) {
        EpidIssuerDelete(&g_issuer);
    }

    return res != kEpidNoErr || ret != SGX_SUCCESS;
}

uint32_t asie_load_issuer(
    const uint8_t *p_sealed_blob,
    uint32_t sealed_blob_size,
    const uint8_t *p_priv_rl,
    size_t priv_rl_size,
    const uint8_t *p_sig_rl,
    size_t sig_rl_size)
{
    EpidStatus res = kEpidNoErr;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    do {
        if (!p_sealed_blob || sealed_blob_size != sgx_calc_sealed_data_size(0,
            sizeof(replay_protected_pay_load)) ||
            !p_priv_rl || priv_rl_size == 0 ||
            !p_sig_rl || sig_rl_size == 0)
        {
            res = kEpidBadArgErr;
            break;
        }
        EpidIssuerDelete(&g_issuer);
        BREAK_ON_EPID_ERROR(res);
        if (!g_issuer_data) {
            g_issuer_data = (IssuerData*) malloc(sizeof(IssuerData));
        }
        ret = perform_sealed_policy(p_sealed_blob, sealed_blob_size);
        BREAK_ON_SGX_ERROR(ret);
        res = EpidIssuerImport(&g_issuer_data->pub_key, &g_issuer_data->ipriv_key,
                               epid_random_func, NULL, &g_issuer);
        BREAK_ON_EPID_ERROR(res);


        sgx_sha256_hash_t priv_rl_hash;
        sgx_sha256_hash_t sig_rl_hash;
        ret = sgx_sha256_msg(reinterpret_cast<const uint8_t*>(p_priv_rl),
                             uint64_to_uint32(priv_rl_size),
                             &priv_rl_hash);
        BREAK_ON_SGX_ERROR(ret);
        ret = sgx_sha256_msg(reinterpret_cast<const uint8_t*>(p_sig_rl),
                             uint64_to_uint32(sig_rl_size),
                             &sig_rl_hash);
        BREAK_ON_SGX_ERROR(ret);
        if (0 != memcmp(&g_issuer_data->priv_rl_hash, &priv_rl_hash, sizeof(sgx_sha256_hash_t)) ||
            0 != memcmp(&g_issuer_data->sig_rl_hash, &sig_rl_hash, sizeof(sgx_sha256_hash_t)))
        {
            res = kEpidBadArgErr;
            break;
        }
        g_issuer->priv_rl = (PrivRl *) malloc(priv_rl_size);
        memcpy(g_issuer->priv_rl, p_priv_rl, priv_rl_size);
        g_issuer->sig_rl = (SigRl *) malloc(sig_rl_size);
        memcpy(g_issuer->sig_rl, p_sig_rl, sig_rl_size);

    } while(0);
    if (res != kEpidNoErr || ret != SGX_SUCCESS) {
        PRINT_ON_EPID_ERROR(res);
        EpidIssuerDelete(&g_issuer);
    }
    return res != kEpidNoErr || ret != SGX_SUCCESS;
}

uint32_t asie_delete_issuer(
    const uint8_t *p_sealed_blob,
    uint32_t sealed_blob_size)
{
    EpidStatus res = kEpidNoErr;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    do {
        if (!p_sealed_blob || sealed_blob_size != sgx_calc_sealed_data_size(0,
            sizeof(replay_protected_pay_load)))
        {
            res = kEpidBadArgErr;
            break;
        }
        ret = delete_sealed_policy(p_sealed_blob, sealed_blob_size);
        BREAK_ON_SGX_ERROR(ret);
    } while(0);
    return res != kEpidNoErr || ret != SGX_SUCCESS;
}

uint32_t asie_request_grp_verif_cert(
    const uint8_t *p_curr_ts,
    uint32_t ts_size,
    sgx_target_info_t *p_target_info,
    sgx_report_t *p_report,
    uint8_t *p_pseManifest)
{
    EpidStatus res = kEpidNoErr;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    do {
        if (!p_curr_ts || ts_size != AS_TS_SIZE ||
            !p_target_info || !p_report){
            res = kEpidBadArgErr;
            break;
        }
        if (!g_issuer) {
            res = kEpidNotImpl;
            break;
        }
        if (!g_grp_verif_cert) {
            g_grp_verif_cert = reinterpret_cast<GroupVerifCert *>(malloc(sizeof(GroupVerifCert)));
            if (!g_grp_verif_cert) {
                res = kEpidMemAllocErr;
                break;
            }
            memset(g_grp_verif_cert, 0, sizeof(GroupVerifCert));
            memcpy(&g_grp_verif_cert->pub_key, &g_issuer_data->pub_key, sizeof(GroupPubKey));
        }
        memcpy(&g_grp_verif_cert->priv_rl_hash, &g_issuer_data->priv_rl_hash, sizeof(sgx_sha256_hash_t));
        memcpy(&g_grp_verif_cert->sig_rl_hash, &g_issuer_data->sig_rl_hash, sizeof(sgx_sha256_hash_t));

        // res = ExportGroupPubKey(&g_grp_verif_cert->pub_key, g_issuer);
        // BREAK_ON_EPID_ERROR(res);
        // ret = sgx_sha256_msg(reinterpret_cast<const uint8_t*>(g_issuer->priv_rl),
        //                      uint64_to_uint32(GetPrivRlSize(g_issuer->priv_rl)),
        //                      &g_grp_verif_cert->priv_rl_hash);
        // BREAK_ON_SGX_ERROR(ret);
        // ret = sgx_sha256_msg(reinterpret_cast<const uint8_t*>(g_issuer->sig_rl),
        //                      uint64_to_uint32(GetSigRlSize(g_issuer->sig_rl)),
        //                      &g_grp_verif_cert->sig_rl_hash);
        // BREAK_ON_SGX_ERROR(ret);
        memcpy(g_grp_verif_cert->asie_ts, p_curr_ts, AS_TS_SIZE);
        if(0 != g_issuer->rnd_func((unsigned int *)g_grp_verif_cert->nonce, GVC_NONCE_SIZE * 8, NULL)) {
            res = kEpidNotImpl;
            break;
        }
        // gen report for group verification certificate
        sgx_report_data_t report_data = {{0}};
        ret = sgx_sha256_msg(reinterpret_cast<const uint8_t*>(g_grp_verif_cert),
                             sizeof(GroupVerifCert),
                             reinterpret_cast<uint8_t (*)[32]>(&report_data));
        BREAK_ON_SGX_ERROR(ret);
        ret = sgx_create_report(p_target_info, &report_data, p_report);
        BREAK_ON_SGX_ERROR(ret);

        int busy_retry_times = 2;
        do{
            ret = sgx_create_pse_session();
        }while (ret == SGX_ERROR_BUSY && busy_retry_times--);
        BREAK_ON_SGX_ERROR(ret);
        ret = sgx_get_ps_sec_prop((sgx_ps_sec_prop_desc_t*)p_pseManifest);
        // for (size_t i = 0; i < sizeof(sgx_ps_sec_prop_desc_t); i++) printf("%02x ", pseManifest.sgx_ps_sec_prop_desc[i]); printf("\n");
        sgx_close_pse_session();
        BREAK_ON_SGX_ERROR(ret);

    } while(0);
    return res != kEpidNoErr || ret != SGX_SUCCESS;

}

uint32_t asie_produce_grp_verif_cert(
    uint8_t *p_grp_verif_cert,
    uint32_t grp_verif_cert_size,
    uint8_t *p_ias_res,
    uint32_t ias_res_size,
    uint8_t *p_ias_sig,
    uint32_t ias_sig_size,
    uint8_t *p_ias_crt,
    uint32_t ias_crt_size)
{
    EpidStatus res = kEpidNoErr;
    // sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    do {
        if (!p_grp_verif_cert || grp_verif_cert_size < sizeof(GroupVerifCert)) {
            res = kEpidBadArgErr;
            break;
        }

        if (!g_issuer || !g_grp_verif_cert) {
            res = kEpidNotImpl;
            break;
        }

        // update priv_rl and sig_rl hash

        memcpy(&g_grp_verif_cert->priv_rl_hash, &g_issuer_data->priv_rl_hash, sizeof(sgx_sha256_hash_t));
        memcpy(&g_grp_verif_cert->sig_rl_hash, &g_issuer_data->sig_rl_hash, sizeof(sgx_sha256_hash_t));
        // ret = sgx_sha256_msg(reinterpret_cast<const uint8_t*>(g_issuer->priv_rl),
        //                      uint64_to_uint32(GetPrivRlSize(g_issuer->priv_rl)),
        //                      &g_grp_verif_cert->priv_rl_hash);
        // BREAK_ON_SGX_ERROR(ret);
        // ret = sgx_sha256_msg(reinterpret_cast<const uint8_t*>(g_issuer->sig_rl),
        //                      uint64_to_uint32(GetSigRlSize(g_issuer->sig_rl)),
        //                      &g_grp_verif_cert->sig_rl_hash);
        // BREAK_ON_SGX_ERROR(ret);

        // check ias report
        if (!verify_ias_report(reinterpret_cast<uint8_t*>(g_grp_verif_cert),
                                sizeof(GroupVerifCert),
                                p_ias_res, ias_res_size,
                                p_ias_sig, ias_sig_size,
                                p_ias_crt, ias_crt_size) ||
            !is_pse_status_ok(p_ias_res))
        {
            return -1;
        }
        // check ts
        uint8_t ts[AS_TS_SIZE];
        parse_ias_report_ts(p_ias_res, ts);
        if (0 != memcmp(g_grp_verif_cert->asie_ts, ts, AS_TS_SIZE)) {
            res = kEpidErr;
            break;
        }

        memcpy(p_grp_verif_cert, reinterpret_cast<uint8_t*>(g_grp_verif_cert),
            sizeof(GroupVerifCert));
        res = kEpidNoErr;
    } while(0);
    // printf(EpidStatusMsg(res));
    return res != kEpidNoErr;
}

uint32_t asie_calc_rl_sizes(
    size_t *p_priv_rl_size,
    size_t *p_sig_rl_size)
{
    if (!g_issuer) {
        return kEpidNotImpl;
    }
    *p_priv_rl_size = GetPrivRlSize(g_issuer->priv_rl);
    *p_sig_rl_size = GetSigRlSize(g_issuer->sig_rl);
    return 0;
}

uint32_t asie_produce_rls(
    uint8_t *p_priv_rl,
    size_t priv_rl_size,
    uint8_t *p_sig_rl,
    size_t sig_rl_size)
{
    EpidStatus res = kEpidNoErr;
    do {
        if (!g_issuer) {
            res = kEpidNotImpl;
            break;
        }
        if (!p_priv_rl || priv_rl_size < GetPrivRlSize(g_issuer->priv_rl) ||
            !p_sig_rl || sig_rl_size < GetSigRlSize(g_issuer->sig_rl)) {
            res = kEpidBadArgErr;
            break;
        }
        memcpy(p_priv_rl, g_issuer->priv_rl, GetPrivRlSize(g_issuer->priv_rl));
        memcpy(p_sig_rl, g_issuer->sig_rl, GetSigRlSize(g_issuer->sig_rl));

    } while(0);
    return res != kEpidNoErr;
}


uint32_t asie_gen_nonce(
    uint8_t *p_nonce,
    uint32_t nonce_size)
{
    EpidStatus res = kEpidNoErr;
    do {
        if (!p_nonce || nonce_size < sizeof(IssuerNonce)) {
            res = kEpidBadArgErr;
            break;
        }
        if (!g_issuer) {
            res = kEpidNotImpl;
            break;
        }
        IssuerNonce ni = {0};
        res = GenerateNonce(&ni, g_issuer);
        BREAK_ON_EPID_ERROR(res);
        memcpy(p_nonce, &ni, sizeof(IssuerNonce));
    } while(0);
    PRINT_ON_EPID_ERROR(res)
    return res != kEpidNoErr;
}

uint32_t asie_certify_member(
    uint8_t *p_join_request,
    uint32_t join_request_size,
    uint8_t *p_member_cred,
    uint32_t member_cred_size,
    uint8_t *p_ias_res,
    uint32_t ias_res_size,
    uint8_t *p_ias_sig,
    uint32_t ias_sig_size,
    uint8_t *p_ias_crt,
    uint32_t ias_crt_size)
{
    if (!verify_ias_report(p_join_request, join_request_size,
                           p_ias_res, ias_res_size,
                           p_ias_sig, ias_sig_size,
                           p_ias_crt, ias_crt_size))
    {
        return -1;
    }
    EpidStatus res = kEpidNoErr;
    do {
        if (!p_join_request || join_request_size < sizeof(JoinRequest) ||
            !p_member_cred || member_cred_size < sizeof(MembershipCredential)) {
            res = kEpidBadArgErr;
            break;
        }
        if (!g_issuer) {
            res = kEpidNotImpl;
            break;
        }
        
        // check asie identity
        sgx_quote_t ias_quote;
        parse_ias_report(p_ias_res, &ias_quote);
        if (0 != memcmp(&asae_target_info->mr_enclave, &ias_quote.report_body.mr_enclave, sizeof(sgx_measurement_t)) ||
            0 != memcmp(&asae_target_info->attributes, &ias_quote.report_body.attributes, sizeof(sgx_attributes_t)) ||
            0 != memcmp(&asae_target_info->misc_select, &ias_quote.report_body.misc_select, sizeof(sgx_misc_select_t)))
        {
            break;
        }

        MembershipCredential tmp_member_cred;
        res = CertifyMembership(reinterpret_cast<const JoinRequest *>(p_join_request),
                                &g_issuer->ni, g_issuer, &tmp_member_cred);
        BREAK_ON_EPID_ERROR(res);
        memcpy(p_member_cred, &tmp_member_cred, sizeof(MembershipCredential));
    } while(0);
    return res != kEpidNoErr;
}

uint32_t asie_revoke_priv(
    uint8_t *p_sealed_blob,
    uint32_t sealed_blob_size,
    uint8_t *p_f,
    uint32_t f_size)
{
    EpidStatus res = kEpidNoErr;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    do {
        if (!p_f || f_size != sizeof(FpElemStr)) {
            res = kEpidBadArgErr;
            break;
        }
        if (!g_issuer) {
            res = kEpidNotImpl;
            break;
        }
        res = RevokePriv(reinterpret_cast<FpElemStr *>(p_f), g_issuer);
        BREAK_ON_EPID_ERROR(res);


        ret = sgx_sha256_msg(reinterpret_cast<const uint8_t*>(g_issuer->priv_rl),
                             uint64_to_uint32(GetPrivRlSize(g_issuer->priv_rl)),
                             &g_issuer_data->priv_rl_hash);
        BREAK_ON_SGX_ERROR(ret);

        ret = update_sealed_policy(p_sealed_blob, sealed_blob_size);
        BREAK_ON_SGX_ERROR(ret);

    } while(0);
    return res != kEpidNoErr || ret != SGX_SUCCESS;
}

#define OCTSTR32_LOAD(oct, u32)      \
    do {                              \
      oct.data[0] = (unsigned char)((((uint32_t)(u32)) & 0xFF000000) >> 24);   \
      oct.data[1] = (unsigned char)((((uint32_t)(u32)) & 0xFF0000) >> 16);   \
      oct.data[2] = (unsigned char)((((uint32_t)(u32)) & 0xFF00) >> 8);   \
      oct.data[3] = (unsigned char)((((uint32_t)(u32)) & 0xFF));   \
    } while(0);


uint32_t asie_revoke_sig(
    uint8_t *p_sealed_blob,
    uint32_t sealed_blob_size,
    uint8_t *p_sig,
    uint32_t sig_size)
{
    UNUSED(p_sealed_blob);
    UNUSED(sealed_blob_size);
    EpidStatus res = kEpidNoErr;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    do {
        if (!p_sig || sig_size < sizeof(BasicSignature)) {
            res = kEpidBadArgErr;
            break;
        }
        if (!g_issuer) {
            res = kEpidNotImpl;
            break;
        }
        res = RevokeSig(reinterpret_cast<EpidSignature *>(p_sig), g_issuer);
        BREAK_ON_EPID_ERROR(res);


        ret = sgx_sha256_msg(reinterpret_cast<const uint8_t*>(g_issuer->sig_rl),
                             uint64_to_uint32(GetSigRlSize(g_issuer->sig_rl)),
                             &g_issuer_data->sig_rl_hash);
        BREAK_ON_SGX_ERROR(ret);

        ret = update_sealed_policy(p_sealed_blob, sealed_blob_size);
        BREAK_ON_SGX_ERROR(ret);

    } while(0);
    PRINT_ON_EPID_ERROR(res);
    return res != kEpidNoErr || ret != SGX_SUCCESS;
}