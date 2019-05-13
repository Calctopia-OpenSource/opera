#ifndef RAPTOE_ENCLAVE_TOOLS_API_H
#define RAPTOE_ENCLAVE_TOOLS_API_H

#include "sgx_utils.h"

uint32_t generate_report(const uint8_t *msg, uint32_t msg_len,
        sgx_target_info_t *target_info, sgx_report_t *report);

#endif
