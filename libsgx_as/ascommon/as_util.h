#ifndef SGX_AS_UTIL_H
#define SGX_AS_UTIL_H

#include "sgx_utils.h"
#include "sgx_tcrypto.h"
#include "sgx_quote.h"
#include "sgx_tseal.h"

#include <stddef.h>
#include "epid/common/errors.h"
#include "epid/common/types.h"
#include "epid/common/src/grouppubkey.h"
#include "epid/common/src/memory.h"
#include "epid/common/src/epid2params.h"
#include "epid/common/math/src/ecgroup-internal.h"
#include "epid/common/math/src/finitefield-internal.h"
#include "epid/common/src/endian_convert.h"
#include "epid/common/src/sigrlvalid.h"

#define AS_TS_SIZE 10
#define GVC_NONCE_SIZE 32

typedef struct GroupVerifCert {
    GroupPubKey 		pub_key;
    sgx_sha256_hash_t 	priv_rl_hash;
    sgx_sha256_hash_t 	sig_rl_hash;
    uint8_t 			asie_ts[AS_TS_SIZE];
    uint8_t 			nonce[GVC_NONCE_SIZE];
} GroupVerifCert;

typedef struct ASQuote {
	sgx_report_body_t 	isv_report;
	uint8_t 			asae_ts[AS_TS_SIZE];
    uint8_t             pse_status;
    size_t				signature_len;
    uint8_t             signature[];
} ASQuote;

uint32_t base64_decode(const unsigned char* aSrc, uint32_t srcLen, unsigned char* result);
void array_reverse_order(uint8_t *array, uint32_t array_size);

bool is_ias_report_valid(
    uint8_t *p_ias_res,
    uint32_t ias_res_size,
    uint8_t *p_ias_sig,
    uint32_t ias_sig_size,
    uint8_t *p_ias_crt,
    uint32_t ias_crt_size);


void parse_ias_report(
    uint8_t *p_ias_res,
    // uint32_t ias_res_size,
    sgx_quote_t *p_quote);

void parse_ias_report_ts(
    uint8_t *p_ias_res,
    // uint32_t ias_res_size,
    uint8_t *p_ts);

bool is_quote_status_ok(
    uint8_t *p_ias_res);

bool is_pse_status_ok(
    uint8_t *p_ias_res);

bool verify_ias_report(
    uint8_t *p_msg,
    uint32_t msg_size,
    uint8_t *p_ias_res,
    uint32_t ias_res_size,
    uint8_t *p_ias_sig,
    uint32_t ias_sig_size,
    uint8_t *p_ias_crt,
    uint32_t ias_crt_size);

size_t GetPrivRlSize(PrivRl* priv_rl);
size_t GetSigRlSize(SigRl* sig_rl);
size_t GetEpidSigSize(EpidSignature* sig);
size_t GetASQuoteSize(ASQuote* as_quote);

uint32_t uint64_to_uint32 (uint64_t u64);
sgx_status_t sgx_unseal_data_cur_cpusvn_only(const sgx_sealed_data_t *p_sealed_data,
        uint8_t *p_additional_MACtext,
        uint32_t *p_additional_MACtext_length,
        uint8_t *p_decrypted_text,
        uint32_t *p_decrypted_text_length);
// char const* EpidStatusToString(EpidStatus e);
#endif