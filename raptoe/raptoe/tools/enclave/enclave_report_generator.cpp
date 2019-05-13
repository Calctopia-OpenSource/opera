#include "sgx_trts.h"
#include "sgx_tseal.h"
#include "sgx_quote.h"
#include "sgx_report.h"
#include "sgx_utils.h"
#include "string.h"

uint32_t generate_report(const uint8_t *msg, uint32_t msg_len,
        sgx_target_info_t *target_info, sgx_report_t *report)
{
    sgx_report_data_t report_data = {0};
    sgx_sha256_hash_t sha_hash = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    if (msg == NULL || target_info == NULL || report == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    ret = sgx_sha256_msg(msg, msg_len, &sha_hash);
    if (ret != SGX_SUCCESS) {
        return ret;
    }

    memcpy(&(report_data.d), sha_hash, sizeof(sgx_sha256_hash_t));
    ret = sgx_create_report(target_info, &report_data, report);
    if (ret != SGX_SUCCESS) {
        return ret;
    }

    return SGX_SUCCESS;
}

