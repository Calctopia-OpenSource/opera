#include "as_util.h"
#include "ipp_wrapper.h"
#include "sgx_utils.h"
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <stdlib.h>      /* vsnprintf */
#include "pve_qe_common.h"
#include "provision_msg.h"
#include "cipher.h"
// #include "byte_order.h"
#include "util.h"
#include "string.h"
#include "sgx_quote.h"
#include "epid/common/stdtypes.h"
#include "epid/member/api.h"
#include "epid/verifier/api.h"
#include "ipp_wrapper.h"

#define     CHECK_RETRUN(value)     {if(0 == (value)) return 0;}

#define BREAK_ON_IPP_ERROR(ipp_status) \
  if(ippStsNoErr != ipp_status){ \
        break;            \
  }

// extern void printf(const char *fmt, ...);

uint32_t base64_decode(const unsigned char* aSrc, uint32_t srcLen, unsigned char* result)
{ //two reasons will cause the function return 0: 1- The input parameters are wrong, 2- srcLen<4
    static char   index_64[256]   =   {
        64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,
        64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,
        64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   62,   64,   64,   64,   63,
        52,   53,   54,   55,   56,   57,   58,   59,   60,   61,   64,   64,   64,   64,   64,   64,
        64,   0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    10,   11,   12,   13,   14,
        15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   64,   64,   64,   64,   64,
        64,   26,   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,   37,   38,   39,   40,
        41,   42,   43,   44,   45,   46,   47,   48,   49,   50,   51,   64,   64,   64,   64,   64,
        64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,
        64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,
        64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,
        64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,
        64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,
        64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,
        64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,
        64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64,   64
    };

    CHECK_RETRUN(aSrc);
    CHECK_RETRUN(srcLen);
    CHECK_RETRUN(result);


    unsigned char ch1 = 0, ch2 = 0, ch3 = 0, ch4 = 0;
    unsigned char *ptr = result;

    for (unsigned int i = 0; i < srcLen; ++i)
    {
        ch1 = index_64[aSrc[i]];
        if(ch1 == 64)
            continue;
        ch2 = index_64[aSrc[++i]];
        if(ch2 == 64)
            continue;
        *(ptr++) = (unsigned char)(ch1<<2 | ch2>>4);
        ch3 = index_64[aSrc[++i]];
        if(aSrc[i] == '=' || ch3 == 64)
            continue;
        *(ptr++) = (unsigned char)(ch2<<4 | ch3>>2);
        ch4 = index_64[aSrc[++i]];
        if(aSrc[i] == '=' || ch4 == 64)
            continue;
        *(ptr++) = (unsigned char)(ch3<<6 | ch4);
    }
    return (int)(ptr - result);
}

void array_reverse_order(uint8_t *array, uint32_t array_size)
{
    uint32_t i = 0, j = array_size - 1;
    while (i < j) {
        uint8_t tmp = array[i];
        array[i] = array[j];
        array[j] = tmp;
        i++;
        j--;
    }
}


uint8_t ias_root_ca_n[384] = {
    0x1b,0x5d,0x42,0x22,0x06,0x6f,0xff,0x5a,0xd5,0xc0,0xc2,0xad,0x79,0x62,0x25,0x4d,
    0xc7,0x3d,0xdd,0xfb,0x12,0x80,0x5f,0x9a,0x83,0x46,0x8c,0xd1,0x16,0x04,0x5c,0xf2,
    0x54,0x8e,0x1a,0x82,0xc9,0xe8,0xee,0xfc,0xb7,0xcd,0xa6,0x0d,0x9f,0x08,0x9c,0xf8,
    0x06,0x4a,0xf7,0x84,0xf3,0xd0,0xd3,0xf2,0xc1,0x7f,0xf4,0xaa,0x53,0xc4,0x44,0xbd,
    0xa4,0xa1,0x73,0x76,0xd9,0xd2,0x3b,0x0b,0xb1,0xea,0xdf,0x62,0x73,0x25,0xfd,0x9c,
    0x7f,0x58,0x14,0xb3,0x98,0xfb,0xc2,0x93,0x07,0x17,0xe6,0x06,0xb6,0x40,0xff,0xd6,
    0x7d,0x84,0xb4,0x5b,0x23,0x9b,0x69,0xf2,0x6e,0x88,0x14,0x99,0xff,0xe0,0x25,0x1a,
    0xea,0x69,0xc4,0x0e,0xdc,0xb1,0x78,0x95,0xfb,0x69,0x47,0xfe,0xc0,0x11,0xc7,0x4f,
    0x40,0x7f,0xab,0xc9,0xb5,0x42,0x10,0x7d,0x20,0xc1,0x6c,0x22,0xed,0x33,0xde,0x69,
    0xde,0x96,0x1b,0x53,0x99,0x6a,0xf5,0x7d,0x03,0x5d,0x80,0xc5,0x90,0x57,0x12,0x9b,
    0x93,0x60,0xe0,0x9f,0xdd,0xd9,0x90,0xa7,0x28,0x6f,0x90,0x08,0x38,0xaf,0xc2,0x1f,
    0x1e,0x63,0xfe,0xd5,0xaf,0xf5,0xe8,0xdf,0xa2,0x54,0x97,0x40,0x74,0x50,0x82,0xaa,
    0x99,0x37,0x62,0x15,0xb3,0x36,0x4e,0x40,0x31,0x75,0x40,0x3e,0x19,0x03,0x08,0xa8,
    0xe2,0xa5,0xd6,0x92,0x38,0x68,0x52,0x09,0x91,0x36,0x9e,0x21,0x80,0x85,0xa9,0x68,
    0x0a,0x06,0xeb,0x10,0xfb,0x7f,0x5a,0x54,0x47,0xb4,0x07,0x71,0x2d,0x9c,0xf3,0x0e,
    0x24,0x71,0xcb,0xbe,0x6a,0x24,0x29,0xbf,0x8f,0xd7,0x2e,0xf9,0xb3,0x27,0x05,0x99,
    0xcd,0x34,0x99,0x21,0x27,0xdf,0x9d,0xc0,0xf4,0x2f,0xd3,0x55,0xbe,0x14,0x39,0x57,
    0x4b,0x75,0x9e,0x97,0x1b,0x54,0x78,0x54,0x6c,0x69,0xe9,0xa2,0xc5,0x3b,0x09,0x9c,
    0xf5,0x9d,0x67,0x87,0x3d,0xb4,0xad,0x45,0xc6,0xac,0xc6,0xec,0xc8,0x7a,0x5d,0xa1,
    0xa5,0x45,0x9f,0x48,0x6c,0x47,0x48,0x49,0x00,0xae,0xa1,0x47,0x9c,0xe2,0x07,0x1a,
    0x9c,0x77,0xb0,0x37,0x87,0xc9,0x0c,0xd1,0x9d,0x52,0x25,0x63,0x2f,0x6a,0x9d,0x14,
    0xd4,0xeb,0xdd,0xd2,0xcc,0x86,0x47,0x5e,0x6a,0x6a,0x46,0x77,0x09,0x37,0x77,0x31,
    0xd5,0x10,0xb9,0x1d,0x82,0xe6,0x99,0x91,0x64,0x2e,0xde,0x9e,0xfa,0xa0,0x55,0xbb,
    0x5e,0x41,0xd7,0xc0,0x32,0x27,0x2d,0x51,0xbb,0x3c,0x77,0xb5,0x7e,0x64,0x3c,0x9f};
uint8_t ias_root_ca_e[4] = {0x01,0x00,0x01,0x00};

void search_for_rsa_n_e(
    uint8_t *cert, uint32_t cert_size,
    uint8_t **rsa_n, uint32_t &rsa_n_size)
{
    *rsa_n = NULL;
    uint64_t rsa_oid = 0x01010df78648862a;
    for (uint32_t i = 0; i < cert_size - 8; i++) {
        if (*((uint64_t*)(&cert[i])) == rsa_oid && cert[i + 8] == 0x01) {
            uint32_t e_offset = i + 22;
            rsa_n_size = (cert[e_offset] << 8) + cert[e_offset + 1] - 1;
            *rsa_n = &cert[e_offset + 3];
            break;
        }
    }
}

bool verif_ias_cert(
    uint8_t *p_ias_crt,
    IppsRSAPublicKeyState **cert_rsa_pub_key)
{
    if (*cert_rsa_pub_key) free(*cert_rsa_pub_key);
    uint8_t *cert_buffer = NULL;
    IppStatus ipp_status = ippStsNoErr;
    IppsRSAPublicKeyState *root_ca_rsa_pub_key = NULL;
    int is_valid = false;
    Ipp8u *buffer = NULL;
    do
    {
        char *cert_begin = strstr((const char *)p_ias_crt, "-----BEGIN CERTIFICATE-----");
        char *cert_end = strstr((const char *)p_ias_crt, "-----END CERTIFICATE-----");
        if (!cert_begin || !cert_end || cert_begin + 27 >= cert_end) {
            // printf("invalid cert\n");
            break;
        }
        cert_begin += 27;
        cert_buffer = (uint8_t*) malloc(cert_end - cert_begin);
        if (!cert_buffer) {
            // printf("cert buffer malloc failed\n");
            break;
        }
        // decode cert
        base64_decode((const unsigned char *)cert_begin,
                        (uint32_t)(cert_end - cert_begin),
                        (unsigned char*)cert_buffer);

        uint32_t cert_body_size = (cert_buffer[6] << 8) + cert_buffer[7] + 4;

        // extract signature
        uint8_t *sig_begin = &cert_buffer[cert_body_size + 5];
        if (sig_begin[0] & 0x80) {
            sig_begin += (sig_begin[1] << 8) + sig_begin[2] + 3;
        } else {
            sig_begin += sig_begin[0] + 1;
        }
        sig_begin++;
        uint32_t sig_size;
        if (sig_begin[0] & 0x80) {
            sig_size = (sig_begin[1] << 8) + sig_begin[2];
            sig_begin += 3;
        } else {
            sig_size = sig_begin[0];
            sig_begin += 1;
        }
        sig_begin++; // skip leading 0x00
        sig_size--;
        // for (uint32_t i = 0; i < sig_size; i++) printf("%02x ", sig_begin[i]); printf("sig_size:%d\n",sig_size);

        ipp_status = sgx_create_rsa_pub_key(RSA_3072_KEY_BYTES,
                           4,
                           reinterpret_cast<const unsigned char*>(ias_root_ca_n),
                           reinterpret_cast<const unsigned char*>(ias_root_ca_e),
                           reinterpret_cast<void**>(&root_ca_rsa_pub_key));
        BREAK_ON_IPP_ERROR(ipp_status)

        int public_key_buffer_size = 0;
        ipp_status = ippsRSA_GetBufferSizePublicKey(&public_key_buffer_size, root_ca_rsa_pub_key);
        BREAK_ON_IPP_ERROR(ipp_status)

        buffer = (Ipp8u *)malloc(public_key_buffer_size);
        if(!buffer){
            return false;
        }
        // verify cert signature;
        ipp_status = ippsRSAVerify_PKCS1v15(&cert_buffer[4], cert_body_size, sig_begin, &is_valid, root_ca_rsa_pub_key, ippHashAlg_SHA256, buffer);
        BREAK_ON_IPP_ERROR(ipp_status)
        if (!is_valid) {
            // printf("ias cert is not valid\n");
            break;
        }

        // uint rsa_oid[10] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x00};
        // char *rsa_n = strstr((const char *)cert_buffer, (const char *)rsa_oid);
        // for (uint32_t i = 0; i < cert_body_size; i++) printf("%02x ", cert_buffer[i]); printf("\n");
        // if (!rsa_n) {
        //     printf("not rsa\n");
        //     break;
        // }

        uint8_t *rsa_n;
        uint32_t rsa_n_size;
        search_for_rsa_n_e(&cert_buffer[4], cert_body_size,
                            &rsa_n, rsa_n_size);
        if (!rsa_n) {
            // printf("not rsa\n");
            break;
        }

        uint8_t *little_endian_rsa_n = (uint8_t*) malloc(rsa_n_size);
        if (!little_endian_rsa_n) {
            break;
        }
        memcpy(little_endian_rsa_n, rsa_n, rsa_n_size);
        array_reverse_order(little_endian_rsa_n, rsa_n_size);
        uint8_t rsa_e[4] = {0x01, 0x00, 0x01, 0x00};
        ipp_status = sgx_create_rsa_pub_key(rsa_n_size,
                           4,
                           reinterpret_cast<const unsigned char*>(little_endian_rsa_n),
                           reinterpret_cast<const unsigned char*>(rsa_e),
                           reinterpret_cast<void**>(cert_rsa_pub_key));
        BREAK_ON_IPP_ERROR(ipp_status)

    } while(0);
    if (cert_buffer) free(cert_buffer);
    if (buffer) free(buffer);
    if (root_ca_rsa_pub_key) secure_free_rsa_pub_key(RSA_3072_KEY_BYTES,
                       4,
                       root_ca_rsa_pub_key);
    return is_valid;
}

void parse_ias_report(
    uint8_t *p_ias_res,
    // uint32_t ias_res_size,
    sgx_quote_t *p_quote)
{
    char *body_start = strstr((const char *)p_ias_res, "isvEnclaveQuoteBody");
    body_start += 22;
    char *body_end = strstr((const char *)body_start, "\"");
    uint64_t body_size_64 = body_end - body_start;
    uint32_t body_size_32;
    memcpy(&body_size_32, &body_size_64, sizeof(body_size_32));
    base64_decode((const unsigned char *)body_start, body_size_32, (unsigned char*)p_quote);
}

void parse_ias_report_ts(
    uint8_t *p_ias_res,
    // uint32_t ias_res_size,
    uint8_t *p_ts)
{

    char *ts_start = strstr((const char *)p_ias_res, "timestamp");
    ts_start += 12;
    memcpy(p_ts, ts_start, AS_TS_SIZE);
}

bool is_quote_status_ok(
    uint8_t *p_ias_res)
{

    char *status_start = strstr((const char *)p_ias_res, "isvEnclaveQuoteStatus");
    return status_start && status_start[24] == 'O' && status_start[25] == 'K';
}

bool is_pse_status_ok(
    uint8_t *p_ias_res)
{
    char *status_start = strstr((const char *)p_ias_res, "pseManifestStatus");
    return status_start && status_start[20] == 'O' && status_start[21] == 'K';
}

bool is_ias_report_valid(
    uint8_t *p_ias_res,
    uint32_t ias_res_size,
    uint8_t *p_ias_sig,
    uint32_t ias_sig_size,
    uint8_t *p_ias_crt,
    uint32_t ias_crt_size)
{
    IppStatus ipp_status = ippStsNoErr;
    IppsRSAPublicKeyState *rsa_pub_key = NULL;
    int is_valid = false;
    Ipp8u *buffer = NULL;
    if (!p_ias_res || ias_res_size == 0 ||
        !p_ias_sig || ias_sig_size == 0 ||
        !p_ias_crt || ias_crt_size == 0) {
        // printf("not valid\n");
        return false;
    }

    uint8_t sig[256];
    if (256 != base64_decode(p_ias_sig, ias_sig_size, sig)) {
        // printf("base64_decode\n");
        return false;
    }

    // verify ias ca usign ias root ca
    if (!verif_ias_cert(p_ias_crt, &rsa_pub_key) || !rsa_pub_key) 
    {
        // printf("ias cert invalid\n");
        return false;
    }

    do
    {
        int public_key_buffer_size = 0;
        ipp_status = ippsRSA_GetBufferSizePublicKey(&public_key_buffer_size, rsa_pub_key);
        BREAK_ON_IPP_ERROR(ipp_status)

        buffer = (Ipp8u *)malloc(public_key_buffer_size);
        if(!buffer){
            return false;
        }

        ipp_status = ippsRSAVerify_PKCS1v15(p_ias_res, ias_res_size, sig, &is_valid, rsa_pub_key, ippHashAlg_SHA256, buffer);
        BREAK_ON_IPP_ERROR(ipp_status)

        if (!is_valid) {
            // printf("verification failed\n");
            // for (uint32_t i = 0; i < ias_res_size; i++) printf("%c", p_ias_res[i]);
            //     printf("\n");
            // for (uint32_t i = 0; i < ias_sig_size; i++) printf("%c", p_ias_sig[i]);
            //     printf("\n");
            // for (uint32_t i = 0; i < ias_crt_size; i++) printf("%c", p_ias_crt[i]);
            //     printf("\n");
        }
    } while(0);
    if (buffer) free(buffer);
    if (rsa_pub_key) secure_free_rsa_pub_key(RSA_2048_KEY_BYTES,
                       4,
                       rsa_pub_key);

    return is_valid;

}

bool verify_ias_report(
    uint8_t *p_msg,
    uint32_t msg_size,
    uint8_t *p_ias_res,
    uint32_t ias_res_size,
    uint8_t *p_ias_sig,
    uint32_t ias_sig_size,
    uint8_t *p_ias_crt,
    uint32_t ias_crt_size)
{
    if (!p_msg || msg_size == 0 ||
        !is_ias_report_valid(
            p_ias_res, ias_res_size,
            p_ias_sig, ias_sig_size,
            p_ias_crt, ias_crt_size))
    {
        // printf("not valid!");
        return false;
    }

    // TODO: check quote status
    // if (!is_quote_status_ok(p_ias_res)) {
    //     return false;
    // }
    sgx_quote_t quote;
    parse_ias_report(p_ias_res, &quote);

    sgx_report_data_t report_data = {{0}};
    if (SGX_SUCCESS != sgx_sha256_msg(reinterpret_cast<const uint8_t*>(p_msg), msg_size,
                         reinterpret_cast<uint8_t (*)[32]>(&report_data))) {
        return false;
    }

    // for (uint32_t i = 0; i < msg_size; i++) {
    //     printf("%02x ", p_msg[i]);
    // }
    // printf("\n");

    // for (uint32_t i = 0; i < 32; i++) {
    //     printf("%02x %02x\n", report_data.d[i], quote.report_body.report_data.d[i]);
    // }

    return 0 == memcmp(&report_data, &quote.report_body.report_data, 32);
}


uint32_t GetPrivRlSize(PrivRl* priv_rl) {
  const uint32_t kMinSize = sizeof(PrivRl) - sizeof(FpElemStr);
  if (!priv_rl) {
    return kMinSize;
  } else {
    if (ntohl(priv_rl->n1) > (SIZE_MAX - kMinSize) / sizeof(FpElemStr)) {
      return kMinSize;
    } else {
      return (uint32_t)(kMinSize + ntohl(priv_rl->n1) * sizeof(FpElemStr));
    }
  }
  // return sizeof(PrivRl) - sizeof(FpElemStr) + (priv_rl? ntohl(priv_rl->n1) : 0) * sizeof(FpElemStr);
}

uint32_t GetSigRlSize(SigRl* sig_rl) {
  const uint32_t kMinSize = sizeof(SigRl) - sizeof(SigRlEntry);
  if (!sig_rl) {
    return kMinSize;
  } else {
    if (ntohl(sig_rl->n2) > (SIZE_MAX - kMinSize) / sizeof(SigRlEntry)) {
      return kMinSize;
    } else {
      return (uint32_t)(kMinSize + ntohl(sig_rl->n2) * sizeof(SigRlEntry));
    }
  }
  // return sizeof(SigRl) - sizeof(SigRlEntry) + (sig_rl? ntohl(sig_rl->n2) : 0) * sizeof(SigRlEntry);
}

uint32_t GetEpidSigSize(EpidSignature* sig) {
  const uint32_t kMinSize = sizeof(EpidSignature) - sizeof(NrProof);
  if (!sig) {
    return kMinSize;
  } else {
    if (ntohl(sig->n2) > (SIZE_MAX - kMinSize) / sizeof(NrProof)) {
      return kMinSize;
    } else {
      return (uint32_t)(kMinSize + ntohl(sig->n2) * sizeof(NrProof));
    }
  }
  // return sizeof(EpidSignature) - sizeof(NrProof) + (sig ? ntohl(sig->n2) : 0) * sizeof(NrProof);
}

uint32_t GetASQuoteSize(ASQuote* as_quote) {
  if (sizeof(ASQuote) + as_quote->signature_len >= SIZE_MAX) {
    return sizeof(ASQuote);
  } else {
    return (uint32_t)(sizeof(ASQuote) + as_quote->signature_len);
  }
  // return sizeof(ASQuote) + as_quote->signature_len;
}

// uint32_t uint64_to_uint32 (uint64_t u64) {
//     return (uint32_t)u64;
//     uint32_t *u32_ptr = const_cast<uint32_t *>(reinterpret_cast<uint32_t const *>(&u64));
//     return *u32_ptr;
// }

// struct ErrorTextEntry {
//   /// error code
//   EpidStatus value;
//   /// string associated with error code
//   char const* text;
// };

// /// Mapping of status codes to strings
// static const struct ErrorTextEntry kEnumToText[] = {
//     {kEpidNoErr, "no error"},
//     {kEpidErr, "unspecified error"},
//     {kEpidSigInvalid, "invalid signature"},
//     {kEpidSigRevokedInGroupRl, "signature revoked in GroupRl"},
//     {kEpidSigRevokedInPrivRl, "signature revoked in PrivRl"},
//     {kEpidSigRevokedInSigRl, "signature revoked in SigRl"},
//     {kEpidSigRevokedInVerifierRl, "signature revoked in VerifierRl"},
//     {kEpidNotImpl, "not implemented"},
//     {kEpidBadArgErr, "bad arguments"},
//     {kEpidNoMemErr, "could not allocate memory"},
//     {kEpidMemAllocErr, "insufficient memory provided"},
//     {kEpidMathErr, "internal math error"},
//     {kEpidDivByZeroErr, "attempt to divide by zero"},
//     {kEpidUnderflowErr, "underflow"},
//     {kEpidHashAlgorithmNotSupported, "unsupported hash algorithm type"},
//     {kEpidRandMaxIterErr, "reached max iteration for random number generation"},
//     {kEpidDuplicateErr, "argument would add duplicate entry"},
//     {kEpidInconsistentBasenameSetErr,
//      "the set basename is inconsistent with supplied parameters"}};

// char const* EpidStatusToString(EpidStatus e) {
//   uint32_t i = 0;
//   const uint32_t num_entries = sizeof(kEnumToText) / sizeof(kEnumToText[0]);
//   for (i = 0; i < num_entries; i++) {
//     if (e == kEnumToText[i].value) {
//       return kEnumToText[i].text;
//     }
//   }
//   return "unknown error";
// }

sgx_status_t sgx_unseal_data_cur_cpusvn_only(const sgx_sealed_data_t *p_sealed_data,
        uint8_t *p_additional_MACtext,
        uint32_t *p_additional_MACtext_length,
        uint8_t *p_decrypted_text,
        uint32_t *p_decrypted_text_length)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_report_t report;

    ret = sgx_create_report(NULL, NULL, &report);
    if (ret != SGX_SUCCESS)
    {
        return ret;
    }

    if (0 != memcmp(&report.body.cpu_svn, &p_sealed_data->key_request.cpu_svn, sizeof(sgx_cpu_svn_t))) {
        return SGX_ERROR_UNEXPECTED;
    }
    return sgx_unseal_data(p_sealed_data,
                        p_additional_MACtext,
                        p_additional_MACtext_length,
                        p_decrypted_text,
                        p_decrypted_text_length);
}