#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "array_util.h"
#include "opera_types.h"
#include "debug_util.h"
#include "common_tools_api.h"

#define READ_OR_GOTO(fd, p_array, size) \
    if ((res = read_array(fd, (void**)&(p_array), &(size))) != 0) {     \
        ERROR("%i = read_array(%i, %s, %s)", res, fd, #p_array, #size); \
        goto CLEANUP;                                                   \
    }

as_report_t* as_read_report(int fd)
{
    uint32_t size = 0;
    int32_t res = 0;
    as_report_t *report = (as_report_t*)calloc(1, sizeof(as_report_t));

    READ_OR_GOTO(fd, report->quote, report->quote_size);
    READ_OR_GOTO(fd, report->gv_cert, size);
    if (size != sizeof(epid_group_certificate_t)) {
        WARN("Received unexpected size for gv_cert. Got 0x%x, expected 0x%lx",
                size, sizeof(epid_group_certificate_t));
    }

    READ_OR_GOTO(fd, report->ias_response.str, report->ias_response.size);
    READ_OR_GOTO(fd, report->ias_signature.str, report->ias_signature.size);
    READ_OR_GOTO(fd, report->ias_certificate.str, report->ias_certificate.size);
    READ_OR_GOTO(fd, report->priv_rl.revoc_list, report->priv_rl.size);
    READ_OR_GOTO(fd, report->sig_rl.revoc_list, report->sig_rl.size);
    return report;

CLEANUP:
    free_as_report(report);
    return NULL;
}

int32_t as_send_report(int fd, as_report_t* report)
{
    WRITE_ARRAY(fd, report->quote, report->quote_size);
    WRITE_ARRAY(fd, report->gv_cert, sizeof(epid_group_certificate_t));
    WRITE_ARRAY(fd, report->ias_response.str, report->ias_response.size);
    WRITE_ARRAY(fd, report->ias_signature.str, report->ias_signature.size);
    WRITE_ARRAY(fd, report->ias_certificate.str, report->ias_certificate.size);
    WRITE_ARRAY(fd, report->priv_rl.revoc_list, report->priv_rl.size);
    WRITE_ARRAY(fd, report->sig_rl.revoc_list, report->sig_rl.size);
    return 0;
}
