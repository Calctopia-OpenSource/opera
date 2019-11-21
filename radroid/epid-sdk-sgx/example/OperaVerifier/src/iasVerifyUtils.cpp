extern "C" {
#include <android/log.h>
#include <stdlib.h>
#include "src/iasVerifyUtils.h"
#include "src/cryptoRsa.h"
#include "ext/Opera/ias_cert.h"
}

#include <string>

void get_current_gmt_time(char *ts, size_t len)
{
    struct tm *gtime;
    time_t now;

    /* Read the current system time */
    time(&now);

    /* Convert the system time to GMT (now UTC) */
    gtime = gmtime(&now);

    snprintf(ts, len, "%4d-%02d-%02dT%2d:%02d:%02d\n", gtime->tm_year + 1900,
            gtime->tm_mon + 1, gtime->tm_mday, gtime->tm_hour,
            gtime->tm_min, gtime->tm_sec);
}

void array_reverse_order(unsigned char *array, int array_size)
{
    int i = 0, j = array_size - 1;
    unsigned char tmp;
    while (i < j) {
        tmp = array[i];
        array[i++] = array[j];
        array[j--] = tmp;
    }
}

static size_t get_json_value(const char *str, const char *attrib,
        const char** value)
{
    if (str == NULL || attrib == NULL || value == NULL) {
        return 0;
    }

    /* Find attrib in str */
    size_t attrib_len = strlen(attrib);
    char *search_str = (char*)strstr(str, attrib);
    if (search_str == NULL) {
        return 0;
    }

    /* Verify the JSON separator is after attrib */
    search_str += attrib_len;
    char *sep_str = (char*)strstr(search_str, JSON_SEP);
    if (sep_str == NULL || sep_str - search_str > 0) {
        return 0;
    }

    /* Extract value fro JSON, making sure to adjust for null terminator */
    *value = sep_str + sizeof(JSON_SEP) - 1;
    char *end_str = (char*)strstr(*value, JSON_TERM);
    if (end_str == NULL) {
        return 0;
    }
    return (size_t)(end_str - *value);
}

void parse_ias_report(const char *p_ias_res, sgx_quote_t *quote)
{
    const char *body = NULL;
    size_t body_size = get_json_value(p_ias_res, QUOTE_BODY_ATTRIB, &body);
    base64_decode(body, (uint32_t)body_size, (char*)quote);
}

void parse_ias_report_ts(const char *ias_response, uint8_t *timestamp)
{
    const char *ts = NULL;
    if (get_json_value(ias_response, TIMESTAMP_ATTRIB, &ts) > AS_TS_SIZE) {
        memcpy(timestamp, ts, AS_TS_SIZE);
    }
}

unsigned char * search_for_rsa_n_e(const unsigned char *cert, int cert_size,
        int* rsa_n_size)
{
    if (!cert || !rsa_n_size) {
        return NULL;
    }

    uint64_t p = RSA_OID;
    for (int i = 0; i < cert_size - 8; i++) {
        if (!memcmp(cert + i, &p, sizeof(RSA_OID)) && cert[i + 8] == 0x01) {
            int e_offset = i + RSA_EXP_OFFSET;
            *rsa_n_size = (cert[e_offset] << 8) + cert[e_offset + 1] - 1;
            return (unsigned char *)(cert + e_offset + 3);
        }
    }
    return NULL;
}

uint32_t base64_decode(const void* src, uint32_t src_len, void* result)
{
    if (src == NULL || src_len == 0 || result == NULL) {
        return 0;
    }

    unsigned char* p = (unsigned char *)src;
    unsigned char ch1 = 0, ch2 = 0, ch3 = 0, ch4 = 0;
    unsigned char *ptr = (unsigned char*)result;

    for (unsigned int i = 0; i < src_len; ++i)
    {
        if ((ch1 = index_64[p[i]]) == 64) {
            continue;
        }
        if ((ch2 = index_64[p[++i]]) == 64) {
            continue;
        }
        *(ptr++) = (unsigned char)(ch1<<2 | ch2>>4);
        if (p[i] == '=' || (ch3 = index_64[p[++i]]) == 64) {
            continue;
        }
        *(ptr++) = (unsigned char)(ch2<<4 | ch3>>2);
        if (p[i] == '=' || (ch4 = index_64[p[++i]]) == 64) {
            continue;
        }
        *(ptr++) = (unsigned char)(ch3<<6 | ch4);
    }
    return (uint32_t)(ptr - (unsigned char *)result);
}

int verify_root_ias_rsa_pubKey(char *ias_cert, unsigned char* root_ca_e, unsigned char* root_ca_n)
{
    IppsRSAPublicKeyState *root_ca_rsa_pub_key = NULL;
    unsigned char *cert_buffer = NULL, *sig_begin;    
    
    Ipp8u *buffer = NULL;
    int is_valid = 0, public_key_buffer_size = 0, cert_body_size, sig_size,test;
    size_t cert_size;  

    char *cert_begin = (char*)strstr(ias_cert, CERT_BEGIN);
    char *cert_end = (char*)strstr(ias_cert, CERT_END);
    if (!cert_begin || !cert_end ||
            cert_begin + sizeof(CERT_BEGIN) >= cert_end) {
        __android_log_print(ANDROID_LOG_VERBOSE, IASERR, "Invalid IAS certificate\n");
        goto cleanup;
    }

    cert_begin += sizeof(CERT_BEGIN) - 1;
    cert_size = (size_t)(cert_end - cert_begin);
    if(!(cert_buffer = (unsigned char*) malloc(cert_size))) {
         __android_log_print(ANDROID_LOG_VERBOSE, IASERR, "Malloc failure\n");
        goto cleanup;
    }

    base64_decode(cert_begin, (uint32_t)cert_size, cert_buffer);

    cert_body_size = (cert_buffer[6] << 8) + cert_buffer[7] + 4;
    // extract signature
    sig_begin = cert_buffer + cert_body_size + 5;
    if (sig_begin[0] & 0x80) {
        sig_begin += (sig_begin[1] << 8) + sig_begin[2] + 3;
    } else {
        sig_begin += sig_begin[0] + 1;
    }
    sig_begin++;
    if (sig_begin[0] & 0x80) {
        sig_size = (sig_begin[1] << 8) + sig_begin[2];
        sig_begin += 3;
    } else {
        sig_size = sig_begin[0];
        sig_begin += 1;
    }
    sig_begin++; // skip leading 0x00
    sig_size--; 

   if (sgx_create_rsa_pub1_key(RSA_3072_KEY_BYTES, CERT_EXP_SIZE, root_ca_n,
                root_ca_e, (void**)&root_ca_rsa_pub_key) != SGX_SUCCESS) {
        __android_log_print(ANDROID_LOG_VERBOSE, IASERR, "Failed to create rsa public key\n");
        goto cleanup;
    }    

    if (ippsRSA_GetBufferSizePublicKey(&public_key_buffer_size,
                root_ca_rsa_pub_key) != ippStsNoErr) {
        __android_log_print(ANDROID_LOG_VERBOSE, IASERR, "Failed to get public key buffer size\n");
        goto cleanup;  
    }

    if (!(buffer = (Ipp8u *)malloc((size_t)public_key_buffer_size))) {
        __android_log_print(ANDROID_LOG_VERBOSE, IASERR, "Malloc failure\n");
        goto cleanup;
    }

    // verify cert signature;
    if (ippsRSAVerify_PKCS1v15(cert_buffer + 4, cert_body_size, sig_begin,
                &is_valid, root_ca_rsa_pub_key, ippHashAlg_SHA256, buffer)
            != ippStsNoErr || !is_valid) {
        __android_log_print(ANDROID_LOG_VERBOSE, IASERR, "IAS certificate not valid\n");
        goto cleanup;
    }
    
    return 1;
    
cleanup:
    if (cert_buffer) {
        free(cert_buffer);
    }
    if (buffer) {
        free(buffer);
    }

    return 0;
}


/* Return 0 for fail , 1 for success */
int parse_and_verify_ias_pubKey(char *ias_cert, char *ias_res, int res_size, char *ias_sig, int sig_size, unsigned char* root_ca_e){

    unsigned char *cert_buffer = NULL, *rsa_n, *little_endian_rsa_n;
    
    IppsRSAPublicKeyState *rsa_pub_key = NULL;
    Ipp8u sig[IAS_SIG_SIZE];
    Ipp8u *buffer = NULL;
    
    int rsa_n_size, cert_body_size, is_valid = 0, public_key_buffer_size = 0;

    size_t cert_size;  

    char *cert_begin = (char*)strstr(ias_cert, CERT_BEGIN);
    char *cert_end = (char*)strstr(ias_cert, CERT_END);

    if (!cert_begin || !cert_end ||
            cert_begin + sizeof(CERT_BEGIN) >= cert_end) {
        printf("Invalid IAS certificate\n");
        goto cleanup;
    }

    cert_begin += sizeof(CERT_BEGIN) - 1;
    cert_size = (size_t)(cert_end - cert_begin);
    if(!(cert_buffer = (unsigned char*) malloc(cert_size))) {
        printf("Malloc failure\n");
        goto cleanup;
    }

    base64_decode(cert_begin, (uint32_t)cert_size, cert_buffer);

    cert_body_size = (cert_buffer[6] << 8) + cert_buffer[7] + 4;

    if (!(rsa_n = search_for_rsa_n_e(cert_buffer + 4, cert_body_size,
                    &rsa_n_size))) {
        printf("Not rsa\n");
        goto cleanup;
    }

    if (!(little_endian_rsa_n = (unsigned char*) malloc((size_t)rsa_n_size))) {
        printf("Malloc failure\n");
        goto cleanup;
    }

    /*Copy RSA_N from IAS cert to external array*/
    memcpy(little_endian_rsa_n, rsa_n, (size_t)rsa_n_size);
    array_reverse_order(little_endian_rsa_n, rsa_n_size);

    if (sgx_create_rsa_pub1_key(RSA_3072_KEY_BYTES, CERT_EXP_SIZE, rsa_n,
                root_ca_e, (void**)&rsa_pub_key) != SGX_SUCCESS) {
        __android_log_print(ANDROID_LOG_VERBOSE, IASERR, "Failed to create rsa public key\n");
        goto cleanup;
    }  

    if (ippsRSA_GetBufferSizePublicKey(&public_key_buffer_size, rsa_pub_key)
            != ippStsNoErr) {
        printf("Ipps GetBufferSize error\n");
        goto cleanup;
    }

    if (!(buffer = (Ipp8u *)malloc((size_t)public_key_buffer_size))) {
        printf("Failed to malloc %dx bytes", (size_t)public_key_buffer_size);
        goto cleanup;
    }

    if(base64_decode(ias_sig, sig_size, sig) != IAS_SIG_SIZE){
        goto cleanup; 
    }

    if (ippsRSAVerify_PKCS1v15((Ipp8u*)ias_res, res_size, sig,
            &is_valid, rsa_pub_key, ippHashAlg_SHA256, buffer)
            != ippStsNoErr) {
        printf("Ipps RSA verification error\n");
        goto cleanup;
    }

    return 1;

    cleanup:
        if (cert_buffer) {
            free(cert_buffer);
        }
      
    return 0;
}

int verify_enclave(sgx_report_body_t* e, sgx_target_info_t* t)
{
    /* Verify the enclave (e) against it's target (t) info */
    if (!e || !t) {
        return 0;
    }

    return !memcmp(&t->attributes, &e->attributes, sizeof(sgx_attributes_t))
        || !memcmp(&t->mr_enclave, &e->mr_enclave, sizeof(sgx_measurement_t))
        || !memcmp(&t->misc_select, &e->misc_select, sizeof(sgx_misc_select_t));
}

/* Return 0 for fail , return 1 for success */
int verify_revoc_list_hashes(epid_group_certificate_t* gv_cert, uint8_t* prl, int prl_size,
        uint8_t* srl, int srl_size)
{
    sgx_sha256_hash_t prl_hash = {0}, srl_hash = {0};
    sgx_status_t prl_ret, srl_ret;

    prl_ret = sgx_sha256_msg(prl, prl_size, &prl_hash);
    srl_ret = sgx_sha256_msg(srl, srl_size, &srl_hash);

    if (prl_ret != SGX_SUCCESS || srl_ret != SGX_SUCCESS) {
        __android_log_print(ANDROID_LOG_VERBOSE, IASERR, "SGX SHA256 hash failure\n");
        return 0;
    }

    if (memcmp(prl_hash, gv_cert->priv_rl_hash, sizeof(sgx_sha256_hash_t)) ||
            memcmp(srl_hash, gv_cert->sig_rl_hash, sizeof(sgx_sha256_hash_t))) {
        __android_log_print(ANDROID_LOG_VERBOSE, IASERR, "Incorrect revocation list hashes\n");
        return 0;
    }

    return 1;
}