#include "verifier.h"

VerifierCtx* g_verifier = NULL;
PrivRl *g_priv_rl = NULL;
SigRl *g_sig_rl = NULL;

static int is_valid_report_string(ias_report_str_t* rep_str)
{
    return (rep_str != NULL) && (rep_str->str != NULL) && (rep_str->size > 0);
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

int verify_ias_cert(char *ias_cert, IppsRSAPublicKeyState **cert_rsa_pub_key)
{
    unsigned char *cert_buffer = NULL, *sig_begin, *rsa_n, *little_endian_rsa_n;
    IppsRSAPublicKeyState *root_ca_rsa_pub_key = NULL;
    Ipp8u *buffer = NULL;
    int is_valid = 0, public_key_buffer_size, cert_body_size, sig_size,
        rsa_n_size;
    size_t cert_size;

    if (*cert_rsa_pub_key) {
        free(*cert_rsa_pub_key);
    }

    char *cert_begin = (char*)strstr(ias_cert, CERT_BEGIN);
    char *cert_end = (char*)strstr(ias_cert, CERT_END);
    if (!cert_begin || !cert_end ||
            cert_begin + sizeof(CERT_BEGIN) >= cert_end) {
        ERROR("Invalid IAS certificate\n");
        goto cleanup;
    }

    cert_begin += sizeof(CERT_BEGIN) - 1;
    cert_size = (size_t)(cert_end - cert_begin);
    if(!(cert_buffer = (unsigned char*) malloc(cert_size))) {
        ERROR("Malloc failure\n");
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

    if (sgx_create_rsa_pub1_key(RSA_3072_KEY_BYTES, CERT_EXP_SIZE, ias_root_ca_n,
                ias_root_ca_e, (void**)&root_ca_rsa_pub_key) != SGX_SUCCESS) {
        ERROR("Failed to create rsa public key");
        goto cleanup;
    }

    if (ippsRSA_GetBufferSizePublicKey(&public_key_buffer_size,
                root_ca_rsa_pub_key) != ippStsNoErr) {
        ERROR("Failed to get public key buffer size\n");
        goto cleanup;
    }

    if (!(buffer = (Ipp8u *)malloc((size_t)public_key_buffer_size))) {
        ERROR("Malloc failure\n");
        goto cleanup;
    }

    // verify cert signature;
    if (ippsRSAVerify_PKCS1v15(cert_buffer + 4, cert_body_size, sig_begin,
                &is_valid, root_ca_rsa_pub_key, ippHashAlg_SHA256, buffer)
            != ippStsNoErr || !is_valid) {
        ERROR("IAS certificate not valid\n");
        goto cleanup;
    }

    if (!(rsa_n = search_for_rsa_n_e(cert_buffer + 4, cert_body_size,
                    &rsa_n_size))) {
        ERROR("Not rsa\n");
        goto cleanup;
    }

    if (!(little_endian_rsa_n = (unsigned char*) malloc((size_t)rsa_n_size))) {
        ERROR("Malloc failure\n");
        goto cleanup;
    }

    memcpy(little_endian_rsa_n, rsa_n, (size_t)rsa_n_size);
    array_reverse_order(little_endian_rsa_n, rsa_n_size);
    /* RSA e is same as IAS e */
    if (sgx_create_rsa_pub1_key(rsa_n_size, CERT_EXP_SIZE, little_endian_rsa_n,
            ias_root_ca_e, (void**)cert_rsa_pub_key) != SGX_SUCCESS) {
        ERROR("Failure creating rsa public key\n");
        goto cleanup;
    }

    is_valid = 1;
cleanup:
    if (cert_buffer) {
        free(cert_buffer);
    }
    if (buffer) {
        free(buffer);
    }
    if (root_ca_rsa_pub_key) {
        secure_free_rsa_pub_key(RSA_3072_KEY_BYTES, CERT_EXP_SIZE,
                root_ca_rsa_pub_key);
    }
    return is_valid;
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

int check_status_ok(const char *ias_response, const char *status)
{
    const char *is_ok = NULL;
    if (get_json_value(ias_response, status, &is_ok) > 0) {
        return (strncmp(is_ok, STATUS_OK, sizeof(STATUS_OK) - 1) == 0);
    }
    return 1;
}

int is_ias_report_valid(ias_report_str_t* response, ias_report_str_t* ias_sig,
        ias_report_str_t* ias_cert)
{
    IppsRSAPublicKeyState *rsa_pub_key = NULL;
    Ipp8u *buffer = NULL;
    Ipp8u sig[IAS_SIGNATURE_SIZE];
    int public_key_buffer_size = 0;
    int is_valid = 0;

    if (!is_valid_report_string(response) || !is_valid_report_string(ias_sig)
            || !is_valid_report_string(ias_cert)) {
        ERROR("Invalid report string given\n");
        return 0;
    }

    if (base64_decode(ias_sig->str, ias_sig->size, sig) != IAS_SIGNATURE_SIZE) {
        ERROR("Bad encoded signature\n");
        return 0;
    }

    if (!verify_ias_cert(ias_cert->str, &rsa_pub_key) || !rsa_pub_key)
    {
        ERROR("IAS certificate invalid\n");
        goto cleanup;
    }

    if (ippsRSA_GetBufferSizePublicKey(&public_key_buffer_size, rsa_pub_key)
            != ippStsNoErr) {
        ERROR("Ipps GetBufferSize error\n");
        goto cleanup;
    }

    if (!(buffer = (Ipp8u *)malloc((size_t)public_key_buffer_size))) {
        ERROR("Failed to malloc %lx bytes", (size_t)public_key_buffer_size);
        goto cleanup;
    }

    if (ippsRSAVerify_PKCS1v15((Ipp8u*)response->str, (int)response->size, sig,
                &is_valid, rsa_pub_key, ippHashAlg_SHA256, buffer)
            != ippStsNoErr) {
        ERROR("Ipps RSA verification error\n");
        goto cleanup;
    }

    is_valid = 1;

cleanup:
    if (buffer) {
        free(buffer);
    }
    if (rsa_pub_key) {
        secure_free_rsa_pub_key(RSA_2048_KEY_BYTES, CERT_EXP_SIZE, rsa_pub_key);
    }
    return is_valid;
}

int verify_ias_report(epid_group_certificate_t *msg,
        ias_report_str_t* response, ias_report_str_t* ias_sig,
        ias_report_str_t* ias_cert)
{
    sgx_quote_t quote;
    sgx_report_data_t report_data = {{0}};

    if (!msg) {
        ERROR("Bad message\n");
        return false;
    }

    if (!is_ias_report_valid(response, ias_sig, ias_cert)) {
        ERROR("IAS Report invalid\n");
        return false;
    }

    // TODO: check quote status
    // if (!is_quote_status_ok(p_ias_res)) {
    //     return false;
    // }
    parse_ias_report(response->str, &quote);

    if (sgx_sha256_msg((uint8_t*)msg, sizeof(epid_group_certificate_t),
                (sgx_sha256_hash_t*)&report_data) != SGX_SUCCESS) {
        return false;
    }

    return (memcmp(&report_data, &quote.report_body.report_data, 32) == 0);
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


int verify_revoc_list_hashes(epid_group_certificate_t* gv_cert, priv_rl_t* prl,
        sig_rl_t* srl)
{
    sgx_sha256_hash_t prl_hash = {0}, srl_hash = {0};
    sgx_status_t prl_ret, srl_ret;

    prl_ret = sgx_sha256_msg((uint8_t*)prl->revoc_list, prl->size, &prl_hash);
    srl_ret = sgx_sha256_msg((uint8_t*)srl->revoc_list, srl->size, &srl_hash);

    if (prl_ret != SGX_SUCCESS || srl_ret != SGX_SUCCESS) {
        ERROR("SGX SHA256 hash failure\n");
        return 0;
    }

    if (memcmp(prl_hash, gv_cert->priv_rl_hash, sizeof(sgx_sha256_hash_t)) ||
            memcmp(srl_hash, gv_cert->sig_rl_hash, sizeof(sgx_sha256_hash_t))) {
        ERROR("Incorrect revocation list hashes\n");
        return 0;
    }

    return 1;
}

int enable_verifier(GroupPubKey *pub_key, priv_rl_t *prl, sig_rl_t *srl) {
    if (EpidVerifierCreate(pub_key, NULL, &g_verifier) != kEpidNoErr) {
        return 0;
    }

    if (EpidVerifierSetHashAlg(g_verifier, kSha256) != kEpidNoErr) {
        return 0;
    }

    if (g_priv_rl) {
        free(g_priv_rl);
    }
    g_priv_rl = (PrivRl*)malloc(prl->size);
    memcpy(g_priv_rl, prl->revoc_list, prl->size);
    if (EpidVerifierSetPrivRl(g_verifier, g_priv_rl, prl->size) != kEpidNoErr) {
        return 0;
    }

    if (g_sig_rl) {
        free(g_sig_rl);
    }
    g_sig_rl = (SigRl*)malloc(srl->size);
    memcpy(g_sig_rl, srl->revoc_list, srl->size);
    if (EpidVerifierSetSigRl(g_verifier, g_sig_rl, srl->size) != kEpidNoErr) {
        return 0;
    }

    return 1;
}

uint64_t get_priv_rl_size(PrivRl* priv_rl) {
    const uint64_t min = sizeof(PrivRl) - sizeof(FpElemStr);
    return (!priv_rl) ? min : min + ntohl(priv_rl->n1) * sizeof(FpElemStr);
}

uint64_t get_sig_rl_size(SigRl* sig_rl) {
    const uint64_t min = sizeof(SigRl) - sizeof(SigRlEntry);
    return (!sig_rl) ? min : min + ntohl(sig_rl->n2) * sizeof(SigRlEntry);
}

uint64_t get_epid_sig_size(EpidSignature* sig) {
    const uint64_t min = sizeof(EpidSignature) - sizeof(NrProof);
    return (!sig) ? min : min + ntohl(sig->n2) * sizeof(NrProof);
}

uint64_t get_quote_size(opera_quote_t* as_quote) {
    const uint64_t min = sizeof(opera_quote_t) - sizeof(EpidSignature);
    return (min + as_quote->signature_len >= SIZE_MAX)
        ? min : min + as_quote->signature_len;
}

int verify_quote(as_report_t* rep, const char *curr_ts,
        uint32_t ts_size, sgx_target_info_t* asie_target_info,
        sgx_target_info_t* isve_target_info)
{
    sgx_quote_t ias_quote;
    opera_quote_t* quote;
    uint8_t tmp_ts[AS_TS_SIZE];
    uint32_t prl_size, srl_size, epid_sig_size, quote_size;

    if (!asie_target_info || !isve_target_info || !curr_ts || !rep ||
            !rep->quote || !rep->gv_cert || !rep->ias_response.str ||
            !rep->ias_signature.str || !rep->ias_certificate.str ||
            !rep->priv_rl.revoc_list || !rep->sig_rl.revoc_list) {
        ERROR("Invalid report pointer values\n");
        return EFAULT;
    }

    quote = rep->quote;
    prl_size = (uint32_t)get_priv_rl_size(rep->priv_rl.revoc_list);
    srl_size = (uint32_t)get_sig_rl_size(rep->sig_rl.revoc_list);
    epid_sig_size = (uint32_t)get_epid_sig_size(&(quote->signature));
    quote_size = (uint32_t)get_quote_size(quote);

    if (rep->priv_rl.size != prl_size || rep->sig_rl.size != srl_size ||
            quote->signature_len != epid_sig_size ||
            rep->quote_size != quote_size || ts_size != AS_TS_SIZE) {
        ERROR("Bad report sizes\n");
        return EINVAL;
    }

    if (!check_status_ok(rep->ias_response.str, PSE_MAN_STATUS_ATTRIB)) {
        ERROR("Bad PSE Manifest status\n");
        return EINVAL;
    }

    if (!verify_ias_report(rep->gv_cert, &rep->ias_response,
                &rep->ias_signature, &rep->ias_certificate)) {
        ERROR("Bad IAS report\n");
        return EINVAL;
    }

    parse_ias_report(rep->ias_response.str, &ias_quote);
    if (!verify_enclave(&ias_quote.report_body, asie_target_info)) {
        ERROR("ASIE Identity invalid\n");
        return EINVAL;
    }

    if (!verify_revoc_list_hashes(rep->gv_cert, &rep->priv_rl, &rep->sig_rl)) {
        ERROR("Incorrect revocation list hashes\n");
        return EINVAL;
    }

    parse_ias_report_ts(rep->ias_response.str, tmp_ts);
    if (0 != memcmp(curr_ts, tmp_ts, AS_TS_SIZE) ||
            0 != memcmp(curr_ts, rep->gv_cert->asie_ts, AS_TS_SIZE) ||
            0 != memcmp(curr_ts, rep->quote->asae_ts, AS_TS_SIZE)) {
        ERROR("Timestamps not up-to-date\n");
        return EINVAL;
    }

    if (rep->quote->pse_status != 0) {
        ERROR("Bad trusted platform service status\n");
        return EINVAL;
    }

    if (g_verifier == NULL) {
        if(!enable_verifier(&rep->gv_cert->pub_key, &rep->priv_rl,
                    &rep->sig_rl)) {
            ERROR("Failed to enable verifier");
            return EINVAL;
        }
    }

    if (EpidVerify(g_verifier, &quote->signature, quote->signature_len, quote,
                quote_size - quote->signature_len) != kEpidNoErr) {
        ERROR("Quote epid verification failure\n");
        return EINVAL;
    }

    if (!verify_enclave(&quote->isv_report, isve_target_info)) {
        ERROR("ISVE Identity invalid\n");
        return EINVAL;
    }

    return 0;
}

