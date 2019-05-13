#include <stdlib.h>
#include "opera_types.h"

#define SAFE_FREE(x) if (x) { free(x); };

void free_as_report(as_report_t *report)
{
    if (report == NULL) {
        return;
    }
    SAFE_FREE(report->quote);
    SAFE_FREE(report->gv_cert);
    SAFE_FREE(report->ias_response.str);
    SAFE_FREE(report->ias_signature.str);
    SAFE_FREE(report->ias_certificate.str);
    SAFE_FREE(report->priv_rl.revoc_list);
    SAFE_FREE(report->sig_rl.revoc_list);
    SAFE_FREE(report);
}
