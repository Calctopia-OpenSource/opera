#include "enclave_tools_api.h"
#include "enclave_t.h"

uint32_t isve_gen_report(const uint8_t* msg, uint32_t msglen,
        sgx_target_info_t *p_target_info, sgx_report_t *p_report)
{
    return generate_report(msg, msglen, p_target_info, p_report);
}

