# API / DOCUMENTATION

## Enclave Tools

#### `generate_report`
```c
uint32_t generate_report(const uint8_t *msg, uint32_t msg_len, 
        sgx_target_info_t *target_info, sgx_report_t *report)
```
Takes a supplied challenge message (`msg`) and creates an SGX report, destined 
for the enclave whose target info matches the supplied target info, from the 
enclave using the hashed message as the report data. On success the function
returns `SGX_SUCCESS` and the generated report is returned as `report`.

The supplied target info (`target_info`) will typically be the target info for
the OPERA Attestation Enclave that will verify the report and generate an OPERA
quote.

## Enclave Support App Tools

### Tools using inet sockets 

#### `start_remote_attest_server`
```c
int32_t start_remote_attest_server(const char* asae_socket, uint16_t port,
        sgx_report_generator report_gen);
```
Takes a port value to listen on (`port`), the unix socket that the OPERA 
Attestation Enclave is listening on (`asae_socket`) and a function pointer to a
wrapper around the enclave report generation function (`report_gen`). The 
function should only return if an error occurs, in which case it will return 
a non-zero number.

Once started, the remote attest server will wait for a connection from a remote 
attester that will connect using an inet socket to the listening port using the
[`accept_remote_attestation`](#accept_remote_attestation) function.

#### `sgx_report_generator`
```c
typedef sgx_report_t* (*sgx_report_generator)(const uint8_t* msg,
        uint32_t msglen);
```
A function pointer that takes a challenge message (`msg`) and its length 
(`msglen`) and returns an SGX report of that message. 

This function pointer is to be to a wrapper function within the supporting app
that makes an ecall to the enclave to generate the report. An example of how to
do this can be seen in `SampleISV`. This wrapper can be used in tandem with the
[`generate_report`](#generate_report) enclave function.

#### `accept_remote_attestation`
```c
int32_t accept_remote_attestation(const char* asae_socket, int listening_socket,
        sgx_report_generator report_gen);
```
Takes an open inet socket to listen on (`listening_socket`), the unix socket 
that the OPERA Attestation Enclave is listening on (`asae_socket`) and a 
function pointer to a wrapper around the enclave report generation function 
(`report_gen`). The function returns 0 after a successful connection. A non-zero
value is returned on an error.

The function will block and wait for a connection on the socket from a remote
attester. On a connection it will read a challenge message sent over the socket
and then use the `report_gen` function pointer to create a SGX report from that
message. This report is then sent to the asae where it is verified and turned
into an attestation report (an extension of an OPERA quote) which is sent back
and then sent to the remote attester.

#### `as_send_report`
```c
int32_t as_send_report(int fd, as_report_t* report);
```
Sends an attestation report (`report`) over a file descriptor (such as a socket)
(`fd`). Returns 0 on success.

#### `as_read_report`
```c
as_report_t* as_read_report(int fd);
```
Reads an attestation report from a file descriptor (`fd`) and returns it. The
user of this function is expected to free the report. This can be done using
[`free_as_report`](#free_as_report) function. Returns a pointer to the read
report, or null on a failure.

### Non inet tools

#### `free_as_report`
```c
void free_as_report(as_report_t *report);
```
Safely frees the memory used by an attestation report (`report`).

#### `get_current_gmt_time`
```c
void get_current_gmt_time(char *ts, size_t len);
```
Gets a formated gmt timestamp that is the same that is used by OPERA.

## Verifier Tools

#### `verify_quote`
```c
int verify_quote(as_report_t* rep, const char *curr_ts,
        uint32_t ts_size, sgx_target_info_t* asie_target_info,
        sgx_target_info_t* isve_target_info);
```
Takes a generated attestation report (`rep`), the current timestamp (`curr_ts`),
the size of the timestamp (`ts_size`), the target information for the OPERA
Issuing enclave (`asie_target_info`), and the target information for the enclave
being attested (`isve_target_info`). If the report is valid it returns 0.

## OPERA types

#### `as_report_t`
```c
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
```
Represents a report sent by the OPERA Attestation Enclave.

#### `epid_group_certificate_t`
```c
typedef struct _group_verif_cert {
    GroupPubKey         pub_key;                /* EPID group public key */
    sgx_sha256_hash_t   priv_rl_hash;           /* Private key revocation list 
                                                   hash */
    sgx_sha256_hash_t   sig_rl_hash;            /* Signature based revocation 
                                                   list hash */
    uint8_t             asie_ts[AS_TS_SIZE];    /* IssueE timestamp */
    uint8_t             nonce[GVC_NONCE_SIZE];  /* IssueE generated nonce */
} epid_group_certificate_t;
```
Represents the EPID group verification certificate generated by the OPERA 
Issuing Enclave.

#### `opera_quote_t`
```c
typedef struct _opera_quote {
    sgx_report_body_t   isv_report;             /* Report generated by ISV 
                                                   Enclave */
    uint8_t             asae_ts[AS_TS_SIZE];    /* AttestE timestamp */
    uint8_t             pse_status;             /* SGX trusted platform service
                                                   status */
    uint32_t            signature_len;          /* Length of EPID signature */
    EpidSignature       signature;              /* EPID signature */
} opera_quote_t;
```
Represents the opera quote that is generated by the OPERA Attestation Enclave
once it has validated the attested enclaves SGX report.

#### `priv_rl_t`
```c
typedef struct _private_key_revocation_list {
    PrivRl*     revoc_list;     /* Private key revocation list */
    uint32_t    size;           /* Size of revocation list */
} priv_rl_t;
```
Represents a pair of a private key relocation list and the list's size.

#### `sig_rl_t`
```c
typedef struct _signature_revocation_list {
    SigRl*      revoc_list;     /* Signature revocation list */
    uint32_t    size;           /* Size of revocation list */
} sig_rl_t;
```
Represents a pair of a signature key relocation list and the list's size.

#### `ias_report_str_t`
```c
typedef struct _ias_report_str {
    char*       str;
    uint32_t    size;
} ias_report_str_t;
```
Represents a pair of an IAS report string and the size of the string.

