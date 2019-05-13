#include <stdio.h>
#include <string.h>
#include <time.h>

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
