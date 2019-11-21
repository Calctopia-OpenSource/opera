#ifndef EXAMPLE_IASVERIFYUTILS_SRC_IASVERIFYUTILS_H_
#define EXAMPLE_IASVERIFYUTILS_SRC_IASVERIFYUTILS_H_

#include <stddef.h>
#include <android/log.h>
#include <string.h>
#include "ext/ipp-crypto/include/ippcp.h"
#include "ext/Opera/opera_types.h"

#define RSA_EXP_OFFSET 22
#define RSA_OID 0x01010df78648862a
#define IASDEBUG "IASVerifier"
#define IAS_SIG_SIZE 256
#define CERT_BEGIN "-----BEGIN CERTIFICATE-----\n"
#define CERT_END   "\n-----END CERTIFICATE-----"
#define TIMESTAMP_ATTRIB "timestamp"
#define QUOTE_BODY_ATTRIB "isvEnclaveQuoteBody"
#define RSA_3072_KEY_BITS         3072
#define RSA_3072_KEY_BYTES        (RSA_3072_KEY_BITS/8)
#define JSON_SEP "\":\""
#define JSON_TERM "\""
#define IASERR "IASVERIF ERROR"

static unsigned char index_64[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

/*Functions*/
uint32_t base64_decode(const void* src, uint32_t src_len, void* result);
int verify_root_ias_rsa_pubKey(char *ias_cert, unsigned char* root_ca_e, unsigned char* root_ca_n);
int parse_and_verify_ias_pubKey(char *ias_cert, char *ias_res, int res_size, char *ias_sig, int sig_size, unsigned char* root_ca_e);
void parse_ias_report(const char *p_ias_res, sgx_quote_t *quote);
void parse_ias_report_ts(const char *ias_response, uint8_t *timestamp);
int verify_enclave(sgx_report_body_t* e, sgx_target_info_t* t);
int verify_revoc_list_hashes(epid_group_certificate_t* gv_cert, uint8_t* prl, int prl_size,
        uint8_t* srl, int srl_size);
void get_current_gmt_time(char *ts, size_t len);

#endif // EXAMPLE_IASVERIFYUTILS_SRC_IASVERIFYUTILS_H_