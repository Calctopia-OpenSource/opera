#ifndef RAPTOE_COMMON_TOOLS_API_H
#define RAPTOE_COMMON_TOOLS_API_H

#include "opera_types.h"

void free_as_report(as_report_t *report);

void get_current_gmt_time(char *ts, size_t len);

#endif
