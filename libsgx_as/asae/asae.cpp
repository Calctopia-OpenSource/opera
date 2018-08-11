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
#include "sgx_quote.h"
#include "sgx_tcrypto.h"
// #include "aeerror.h"
// #include "sgx_tseal.h"
// #include "sgx_lfence.h"
// #include "epid_pve_type.h"
#include "sgx_utils.h"
// #include "ipp_wrapper.h"
// #include "epid/common/errors.h"
// #include "sgx_tcrypto.h"
#include "pve_qe_common.h"
#include "provision_msg.h"
#include "cipher.h"
// #include "byte_order.h"
#include "util.h"


#include "epid/common/stdtypes.h"
#include "epid/member/api.h"
#include "epid/verifier/api.h"
#include "asae_t.c"

#include "as_util.h"


#include "sgx_tae_service.h"
#include "sgx_tseal.h"

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
/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }
#define PRINT_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    printf("%s\n", EpidStatusToString(ret));\
  }
#define BREAK_ON_SGX_ERROR(ret) \
  if (SGX_SUCCESS != (ret)) {     \
    break;                       \
  }

MemberCtx *g_member = NULL;
GroupPubKey g_pub_key;
PrivKey g_priv_key;
FpElemStr g_f;
#define ASAE_TS_NONCE_SIZE 32
uint8_t asae_ts_nonce[ASAE_TS_NONCE_SIZE];
uint8_t asae_ts[AS_TS_SIZE];
uint8_t pse_status;

typedef struct MemberData
{
    GroupPubKey         pub_key;
    PrivKey             priv_key;  
} MemberData;

uint32_t asae_join_request(
	uint8_t *p_pub_key,
    uint32_t pub_key_size,
    uint8_t *p_nonce,
    uint32_t nonce_size,
    uint8_t *p_join_request,
    uint32_t join_request_size,
    sgx_target_info_t *p_target_info,
    sgx_report_t *p_report)
{
	EpidStatus res = kEpidErr;
    do {
		if (!p_pub_key || pub_key_size < sizeof(GroupPubKey) ||
			!p_nonce || nonce_size < sizeof(IssuerNonce) ||
			!p_join_request || join_request_size < sizeof(JoinRequest) ||
            !p_target_info || !p_report) {
			res = kEpidBadArgErr;
			break;
		}

        FpElemStr *f = &g_f;
        memset(f, 0, sizeof(FpElemStr));
        pve_status_t pve_ret = PVEC_SUCCESS;
        if(PVEC_SUCCESS != (pve_ret=gen_epid_priv_f(f))){
            res = kEpidErr;
            break;
        }

		memcpy(&g_pub_key, p_pub_key, sizeof(GroupPubKey));

        JoinRequest temp_join_r;
        JoinRequest *join_r = &temp_join_r;
        memset(join_r, 0, sizeof(JoinRequest));

        // IssuerNonce ni = {0};

        res = EpidRequestJoin(
            &g_pub_key,
            reinterpret_cast<const IssuerNonce *>(p_nonce),
            f, epid_random_func,
            NULL, kSha512, join_r);
        BREAK_ON_EPID_ERROR(res);
        memcpy(p_join_request, join_r, sizeof(JoinRequest));

        // gen report for join request
        sgx_status_t ret = SGX_ERROR_UNEXPECTED;
        sgx_report_data_t report_data = {{0}};
        ret = sgx_sha256_msg(reinterpret_cast<const uint8_t*>(join_r),
                             sizeof(JoinRequest),
                             reinterpret_cast<uint8_t (*)[32]>(&report_data));
        BREAK_ON_SGX_ERROR(ret);

        ret = sgx_create_report(p_target_info, &report_data, p_report);
        BREAK_ON_SGX_ERROR(ret);

        res = kEpidNoErr;
    } while(0);
    return res != kEpidNoErr;
}

uint32_t asae_create_member(
	uint8_t *p_member_cred,
    uint32_t member_cred_size)
{   
    // printf("\n\n%d\n\n", sgx_calc_sealed_data_size(0,
    //         sizeof(MemberData)));
	EpidStatus res = kEpidNoErr;
    do {
		if (!p_member_cred || member_cred_size < sizeof(MembershipCredential)) {
			res = kEpidBadArgErr;
			break;
		}
        if (g_member) {
            EpidMemberDelete(&g_member);
            g_member = NULL;
        }

		MembershipCredential *member_cred = 
						reinterpret_cast<MembershipCredential *>(p_member_cred);
        memcpy(&g_priv_key.gid, &member_cred->gid, sizeof(GroupId));
        memcpy(&g_priv_key.A, &member_cred->A, sizeof(g_priv_key.A));
        memcpy(&g_priv_key.x, &member_cred->x, sizeof(g_priv_key.x));
        memcpy(&g_priv_key.f, &g_f, sizeof(g_priv_key.f));

        res = EpidMemberCreate(&g_pub_key, &g_priv_key, NULL, epid_random_func, NULL, &g_member);
        BREAK_ON_EPID_ERROR(res);
        
    } while(0);
    return res != kEpidNoErr;
}

uint32_t asae_seal_member(
    uint8_t *p_sealed_blob,
    uint32_t sealed_blob_size)
{
    EpidStatus res = kEpidNoErr;
    sgx_status_t ret = SGX_SUCCESS;
    do {
        if (!p_sealed_blob || sealed_blob_size != sgx_calc_sealed_data_size(0,
            sizeof(MemberData))) {
            res =  kEpidBadArgErr;
            break;
        }
        if (!g_member) {
            res = kEpidNotImpl;
            break;
        }

        MemberData data2seal;
        memcpy(&data2seal.pub_key, &g_pub_key, sizeof(GroupPubKey));
        memcpy(&data2seal.priv_key, &g_priv_key, sizeof(PrivKey));
        ret = sgx_seal_data(0, NULL, sizeof(data2seal),(uint8_t*)&data2seal,
                sealed_blob_size, (sgx_sealed_data_t*)p_sealed_blob);
        BREAK_ON_SGX_ERROR(ret)

    } while(0);
    PRINT_ON_EPID_ERROR(res)
    return res != kEpidNoErr || ret != SGX_SUCCESS;
}

uint32_t asae_unseal_member(
    const uint8_t *p_sealed_blob,
    uint32_t sealed_blob_size)
{

    EpidStatus res = kEpidNoErr;
    sgx_status_t ret = SGX_SUCCESS;
    do {
        if (!p_sealed_blob || sealed_blob_size != sgx_calc_sealed_data_size(0,
            sizeof(MemberData))) {
            res =  kEpidBadArgErr;
            break;
        }

        MemberData data_unseal;
        uint32_t unseal_length = sizeof(data_unseal);
        ret = sgx_unseal_data_cur_cpusvn_only((const sgx_sealed_data_t*)p_sealed_blob,
                                        NULL, 0, (uint8_t*)&data_unseal, &unseal_length);
        BREAK_ON_SGX_ERROR(ret)
        
        if (g_member) {
            EpidMemberDelete(&g_member);
            g_member = NULL;
        }

        memcpy(&g_pub_key, &data_unseal.pub_key, sizeof(GroupPubKey));
        memcpy(&g_priv_key, &data_unseal.priv_key, sizeof(PrivKey));

        res = EpidMemberCreate(&g_pub_key, &g_priv_key, NULL, epid_random_func, NULL, &g_member);
        BREAK_ON_EPID_ERROR(res);
        
    } while(0);
    PRINT_ON_EPID_ERROR(res)
    return res != kEpidNoErr || ret != SGX_SUCCESS;
}



uint32_t asae_update_ts_reqest(
    sgx_target_info_t *p_target_info,
    sgx_report_t *p_report,
    uint8_t *p_pseManifest)
{
    EpidStatus res = kEpidNoErr;
    do {
        if (!p_target_info || !p_report || !p_pseManifest){
            res = kEpidBadArgErr;
            break;
        }
        if (!g_member) {
            res = kEpidNotImpl;
            break;
        }

        // if(0 != g_member->rnd_func((unsigned int *)asae_ts_nonce, ASAE_TS_NONCE_SIZE * 8, NULL)) {
        //     res = kEpidNotImpl;
        //     break;
        // }
        // gen report for group verification certificate
        sgx_status_t ret = SGX_ERROR_UNEXPECTED;
        sgx_report_data_t report_data = {{0}};
        ret = sgx_sha256_msg(asae_ts_nonce,
                             ASAE_TS_NONCE_SIZE,
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
    return res != kEpidNoErr;

}

uint32_t asae_update_ts_response(
    uint8_t *p_ias_res,
    uint32_t ias_res_size,
    uint8_t *p_ias_sig,
    uint32_t ias_sig_size,
    uint8_t *p_ias_crt,
    uint32_t ias_crt_size)
{
    // UNUSED(p_ias_res);
    // UNUSED(ias_res_size);
    // UNUSED(p_ias_sig);
    // UNUSED(ias_sig_size);
    // UNUSED(p_ias_crt);
    // UNUSED(ias_crt_size);
    if (!verify_ias_report(asae_ts_nonce,
                            ASAE_TS_NONCE_SIZE,
                            p_ias_res, ias_res_size,
                            p_ias_sig, ias_sig_size,
                            p_ias_crt, ias_crt_size))
    {
        return -1;
    }
    EpidStatus res = kEpidNoErr;
    do {
        if (!g_member) {
            res = kEpidNotImpl;
            break;
        }
        parse_ias_report_ts(p_ias_res, asae_ts);
        pse_status = (is_pse_status_ok(p_ias_res) ? 0 : 1);
        res = kEpidNoErr;
    } while(0);

    PRINT_ON_EPID_ERROR(res)
    return res != kEpidNoErr;
}

uint32_t asae_calc_quote_size(
    size_t *p_quote_size,
    const uint8_t *p_sig_rl, 
    uint32_t sig_rl_size)
{
    if (!p_quote_size ||
        (!p_sig_rl && sig_rl_size > 0) ||
        (p_sig_rl && sig_rl_size < sizeof(SigRl) - sizeof(SigRlEntry))) {
        return -1;
    }
    SigRl *sig_rl = const_cast<SigRl*>(reinterpret_cast<SigRl const*>(p_sig_rl));
    *p_quote_size = EpidGetSigSize(sig_rl) + sizeof(ASQuote);
    return 0;
}

uint32_t asae_get_quote(
	const sgx_report_t *p_report,
    const uint8_t *p_sig_rl, // SigRL is relatively big, so we cannot copy it into EPC
    uint32_t sig_rl_size,
	uint8_t *p_quote, // Quote is also big, we should output it in piece meal.
    uint32_t quote_size)
{
    // UNUSED(p_quote);
    // UNUSED(quote_size);
	EpidStatus res = kEpidNoErr;
    do {
        if (!p_report || SGX_SUCCESS != sgx_verify_report(p_report) ||
        (!p_sig_rl && sig_rl_size > 0) ||
        (p_sig_rl && sig_rl_size < sizeof(SigRl) - sizeof(SigRlEntry))) {
			res = kEpidBadArgErr;
			break;
		}
		
        SigRl *sig_rl = const_cast<SigRl*>(reinterpret_cast<SigRl const*>(p_sig_rl));
        if (sig_rl && sig_rl_size != GetSigRlSize(sig_rl)) {
            res = kEpidBadArgErr;
            break;
        }

        if (!g_member) {
            res = kEpidNotImpl;
            break;
        }
        // prepare as_quote
        size_t sig_len = EpidGetSigSize(sig_rl);
        if (sig_len + sizeof(ASQuote) != quote_size) {
            res = kEpidBadArgErr;
            break;            
        }
        uint8_t *tmp_as_quote = (uint8_t *) malloc(sig_len + sizeof(ASQuote));
        if (!tmp_as_quote) {
            res = kEpidMemAllocErr;
            break;
        }
        ASQuote *as_quote = reinterpret_cast<ASQuote *>(tmp_as_quote);
        memcpy(&as_quote->isv_report, &p_report->body, sizeof(as_quote->isv_report));
        memcpy(as_quote->asae_ts, asae_ts, AS_TS_SIZE);
        as_quote->pse_status = pse_status;
        as_quote->signature_len = sig_len;

        // register basename
        uint32_t basename_size = 32;
        uint8_t basename[32] = {0};
        memcpy(basename, &p_report->body.mr_signer, basename_size);
        res = EpidRegisterBaseName(g_member, basename, basename_size);
        if (res != kEpidDuplicateErr) {
            BREAK_ON_EPID_ERROR(res);
        }

        // EpidSignature sig;
        res = EpidSign(g_member, as_quote, sizeof(ASQuote), basename, basename_size, sig_rl, sig_rl_size, reinterpret_cast<EpidSignature *>(as_quote->signature), sig_len);
        BREAK_ON_EPID_ERROR(res);

        memcpy(p_quote, as_quote, sig_len + sizeof(ASQuote));

        // VerifierCtx* verifier = NULL;
        // res = EpidVerifierCreate(&g_pub_key, NULL, &verifier);
        // BREAK_ON_EPID_ERROR(res);

        // res = EpidVerify(verifier, reinterpret_cast<EpidSignature const*>(as_quote->signature), sig_len, as_quote, sizeof(ASQuote));
        // BREAK_ON_EPID_ERROR(res);

    } while(0);
    PRINT_ON_EPID_ERROR(res)
    return res != kEpidNoErr;
}
