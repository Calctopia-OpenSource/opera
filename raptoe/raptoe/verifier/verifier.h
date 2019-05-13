#ifndef VERIFIER_H
#define VERIFIER_H

#include <string.h>
#include <errno.h>

#include "ipp_wrapper.h"
#include "cipher.h"

#ifdef __cplusplus
extern "C" {
#endif
#include "epid/common/src/endian_convert.h"
#include "epid/common/src/memory.h"
#include "epid/verifier/api.h"
#ifdef __cplusplus
}
#endif

#include "opera_types.h"
#include "debug_util.h"
#include "ias_cert.h"

#define AS_TS_SIZE 10
#define GVC_NONCE_SIZE 32

#define JSON_SEP "\":\""
#define JSON_TERM "\""
#define TIMESTAMP_ATTRIB "timestamp"
#define QUOTE_STATUS_ATTRIB "isvEnclaveQuoteStatus"
#define PSE_MAN_STATUS_ATTRIB "pseManifestStatus"
#define QUOTE_BODY_ATTRIB "isvEnclaveQuoteBody"
#define STATUS_OK "OK"

#define IAS_SIGNATURE_SIZE 256
#define CERT_BEGIN "-----BEGIN CERTIFICATE-----\n"
#define CERT_END   "\n-----END CERTIFICATE-----"
#define RSA_EXP_OFFSET 22
#define RSA_OID 0x01010df78648862a

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

#endif
