#ifndef OPERA_TYPES_H
#define OPERA_TYPES_H

#include "sgx_tcrypto.h"
#include "sgx_quote.h"

#include "epid/common/src/grouppubkey.h"
#include "epid/common/types.h"

#define AS_TS_SIZE      10  /* Attestation Service GMT timestamp length */
#define GVC_NONCE_SIZE  32

typedef struct _group_verif_cert {
    GroupPubKey         pub_key;        /* EPID group public key */
    sgx_sha256_hash_t   priv_rl_hash;   /* Private key revocation list hash */
    sgx_sha256_hash_t   sig_rl_hash;    /* Signature based revocation list
                                           hash */
    uint8_t		        asie_ts[AS_TS_SIZE];   /* IssueE timestamp */
    uint8_t             nonce[GVC_NONCE_SIZE];  /* IssueE generated nonce */
} epid_group_certificate_t;

typedef struct _opera_quote {
    sgx_report_body_t   isv_report;     /* Report generated by ISV Enclave */
    uint8_t             asae_ts[AS_TS_SIZE];    /* AttestE timestamp */
    uint8_t             pse_status;     /* SGX trusted platform service status */
    uint32_t			signature_len;  /* Length of EPID signature */
    EpidSignature       signature;    /* EPID signature */
} opera_quote_t;

typedef struct _private_key_revocation_list {
    PrivRl*     revoc_list;     /* Private key revocation list */
    uint32_t    size;           /* Size of revocation list */
} priv_rl_t;

typedef struct _signature_revocation_list {
    SigRl*      revoc_list;     /* Signature revocation list */
    uint32_t    size;           /* Size of revocation list */
} sig_rl_t;

typedef struct _ias_report_str {
    char*       str;
    uint32_t    size;
} ias_report_str_t;

typedef struct as_report_t {
    opera_quote_t*              quote;              /* OPERA Quote */
    uint32_t                    quote_size;         /* Size of OPERA quote */
    epid_group_certificate_t*   gv_cert;            /* EPID group certificate */
    ias_report_str_t            ias_response;       /* Response from IAS (Intel
                                                       attestation service)  */
    ias_report_str_t            ias_signature;      /* IAS report signature */
    ias_report_str_t            ias_certificate;    /* IAS report certificate */
    priv_rl_t                   priv_rl;            /* EPID private key based
                                                       revocation list */
    sig_rl_t                    sig_rl;             /* EPID signature based
                                                       revocation list */
} as_report_t;

#endif /* OPERA_TYPES_H */
