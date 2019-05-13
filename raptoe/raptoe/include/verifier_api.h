#ifndef RAPTOE_VERIFIER_API_H
#define RAPTOE_VERIFIER_API_H

#include "opera_types.h"
#include "sgx_report.h"

int verify_quote(as_report_t* rep, const char *curr_ts,
        uint32_t ts_size, sgx_target_info_t* asie_target_info,
        sgx_target_info_t* isve_target_info);

#endif
