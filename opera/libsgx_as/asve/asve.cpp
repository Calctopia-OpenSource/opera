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
#include "sgx_quote.h"
#include "sgx_tcrypto.h"
#include "sgx_utils.h"
#include "pve_qe_common.h"
#include "provision_msg.h"
#include "cipher.h"
#include "util.h"


#include "epid/common/stdtypes.h"
#include "epid/common/errors.h"
// #include "epid/member/api.h"


#ifdef __cplusplus
extern "C" {
#endif
#include "epid/common/src/memory.h"
#include "epid/verifier/api.h"
#ifdef __cplusplus
}
#endif

#include "asve_t.c"
#include "as_util.h"

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

VerifierCtx* g_verifier = NULL;
PrivRl *g_priv_rl = NULL;
SigRl *g_sig_rl = NULL;

uint32_t asve_verify_quote(
    uint32_t *p_is_valid,
    const uint8_t *p_grp_verif_cert,
    uint32_t cert_size,
    uint8_t *p_ias_res,
    uint32_t ias_res_size,
    uint8_t *p_ias_sig,
    uint32_t ias_sig_size,
    uint8_t *p_ias_crt,
    uint32_t ias_crt_size,
    sgx_target_info_t *p_asie_target_info,
    sgx_target_info_t *p_isve_target_info,
    const uint8_t *p_curr_ts,
    uint32_t ts_size,
    const uint8_t *p_priv_rl,
    uint32_t priv_rl_size,
    const uint8_t *p_sig_rl,
    uint32_t sig_rl_size,
    const uint8_t *p_quote,
    uint32_t quote_size)
{
    EpidStatus res = kEpidErr;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    do {
        // check group verification cert
        if (!p_grp_verif_cert || cert_size != sizeof(GroupVerifCert) ||
            !p_asie_target_info || !p_isve_target_info ||
            !p_curr_ts || ts_size != AS_TS_SIZE ||
            !verify_ias_report( const_cast<uint8_t*>(p_grp_verif_cert),
                                cert_size,
                                p_ias_res, ias_res_size,
                                p_ias_sig, ias_sig_size,
                                p_ias_crt, ias_crt_size) ||
            !is_pse_status_ok(p_ias_res)) 
        {
            res = kEpidBadArgErr;
            break;
        }
        GroupVerifCert *grp_verif_cert =
                const_cast<GroupVerifCert*>(
                    reinterpret_cast<GroupVerifCert const*>(p_grp_verif_cert));
        
        // check asie identity
        sgx_quote_t ias_quote;
        parse_ias_report(p_ias_res, &ias_quote);
        if (0 != memcmp(&p_asie_target_info->mr_enclave, &ias_quote.report_body.mr_enclave, sizeof(sgx_measurement_t)) ||
            0 != memcmp(&p_asie_target_info->attributes, &ias_quote.report_body.attributes, sizeof(sgx_attributes_t)) ||
            0 != memcmp(&p_asie_target_info->misc_select, &ias_quote.report_body.misc_select, sizeof(sgx_misc_select_t)))
        {
            res = kEpidBadArgErr;
            break;
        }

        if (!p_is_valid ||
            !p_priv_rl || priv_rl_size < sizeof(PrivRl) - sizeof(FpElemStr) ||
            !p_sig_rl || sig_rl_size < sizeof(SigRl) - sizeof(SigRlEntry) ||
            !p_quote || quote_size < sizeof(ASQuote) + sizeof(EpidSignature) - sizeof(NrProof))
        {
            res = kEpidBadArgErr;
            break;
        }
        
        PrivRl *priv_rl = const_cast<PrivRl*>(reinterpret_cast<PrivRl const*>(p_priv_rl));
        SigRl *sig_rl = const_cast<SigRl*>(reinterpret_cast<SigRl const*>(p_sig_rl));
        ASQuote *as_quote = const_cast<ASQuote*>(reinterpret_cast<ASQuote const*>(p_quote));
        EpidSignature *sig = reinterpret_cast<EpidSignature *>(as_quote->signature);

        if (priv_rl_size != GetPrivRlSize(priv_rl) ||
            sig_rl_size != GetSigRlSize(sig_rl) ||
            quote_size != GetASQuoteSize(as_quote) ||
            as_quote->signature_len != GetEpidSigSize(sig)) {
            printf("input size errors\n");
            printf("priv_rl_size: %d %d\n", priv_rl_size, GetPrivRlSize(priv_rl));
            printf("sig_rl_size: %d %d\n", sig_rl_size, GetSigRlSize(sig_rl));
            printf("quote_size: %d %d\n", quote_size, GetASQuoteSize(as_quote));
            printf("signature_len: %d %d\n", as_quote->signature_len, GetEpidSigSize(sig));
            res = kEpidBadArgErr;
            break;
        }

        // check priv_rl and sig_rl hash
        sgx_sha256_hash_t priv_rl_hash = {0};
        sgx_sha256_hash_t sig_rl_hash = {0};
        ret = sgx_sha256_msg(p_priv_rl,
                             priv_rl_size,
                             &priv_rl_hash);
        BREAK_ON_SGX_ERROR(ret);
        ret = sgx_sha256_msg(p_sig_rl,
                             sig_rl_size,
                             &sig_rl_hash);
        BREAK_ON_SGX_ERROR(ret);
        if (0 != memcmp(priv_rl_hash, grp_verif_cert->priv_rl_hash, sizeof(sgx_sha256_hash_t)) ||
            0 != memcmp(sig_rl_hash, grp_verif_cert->sig_rl_hash, sizeof(sgx_sha256_hash_t)))
        {
            res = kEpidBadArgErr;
            break;
        }

        // check timestamps are up-to-date
        uint8_t tmp_ts[AS_TS_SIZE];
        parse_ias_report_ts(p_ias_res, tmp_ts);
        if (0 != memcmp(p_curr_ts, tmp_ts, AS_TS_SIZE) ||
            0 != memcmp(p_curr_ts, grp_verif_cert->asie_ts, AS_TS_SIZE) ||
            0 != memcmp(p_curr_ts, as_quote->asae_ts, AS_TS_SIZE))
        {
            res = kEpidBadArgErr;
            break;
        }

        // TODO: check pse status if using pse
        if (as_quote->pse_status != 0) {
            res = kEpidBadArgErr;
            break;
        }

        if (g_verifier == NULL) 
        {
            res = EpidVerifierCreate(reinterpret_cast<GroupPubKey const*>(p_grp_verif_cert),
                                    NULL, &g_verifier);
            BREAK_ON_EPID_ERROR(res);

            // TODO: check basename
            // uint32_t basename_size = 32;
            // uint8_t basename[32] = {0};
            // res = EpidVerifierSetBasename(g_verifier, basename, basename_size);
            // BREAK_ON_EPID_ERROR(res);

            res = EpidVerifierSetHashAlg(g_verifier, kSha256);
            BREAK_ON_EPID_ERROR(res);
            if (priv_rl) {
                SAFE_FREE(g_priv_rl);
                g_priv_rl = (PrivRl*)SAFE_ALLOC(priv_rl_size);
                memcpy(g_priv_rl, priv_rl, priv_rl_size);
                res = EpidVerifierSetPrivRl(g_verifier, g_priv_rl, priv_rl_size);
                BREAK_ON_EPID_ERROR(res);
            }
            if (sig_rl) {
                SAFE_FREE(g_sig_rl);
                g_sig_rl = (SigRl*)SAFE_ALLOC(sig_rl_size);
                memcpy(g_sig_rl, sig_rl, sig_rl_size);
                res = EpidVerifierSetSigRl(g_verifier, g_sig_rl, sig_rl_size);
                BREAK_ON_EPID_ERROR(res);
            }

        }


        res = EpidVerify(g_verifier, sig, as_quote->signature_len, as_quote, sizeof(ASQuote));
        BREAK_ON_EPID_ERROR(res);
        if (res != kEpidSigValid) {
            break;
        }

        // TODO: check report data
        // check isve identity
        // if (0 != memcmp(&p_isve_target_info->mr_enclave, &as_quote->isv_report.mr_enclave, sizeof(sgx_measurement_t)) ||
        //     0 != memcmp(&p_isve_target_info->attributes, &as_quote->isv_report.attributes, sizeof(sgx_attributes_t)) ||
        //     0 != memcmp(&p_isve_target_info->misc_select, &as_quote->isv_report.misc_select, sizeof(sgx_misc_select_t)))
        // {
        //     break;
        // }


        *p_is_valid = true;
        res = kEpidNoErr;
    } while(0);
    // EpidVerifierDelete(&g_verifier);
    PRINT_ON_EPID_ERROR(res)
    return res != kEpidNoErr;
}