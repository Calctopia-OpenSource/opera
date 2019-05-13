#ifndef DEBUG_UTIL_H
#define DEBUG_UTIL_H

#ifndef DEBUG_UTIL_PRINTER
#include <stdio.h>
#define DEBUG_UTIL_PRINTER printf
#endif //DEBUG_UTIL_PRINTER

#ifdef DEBUG
#define DEBUG_PRINT(...) DEBUG_UTIL_PRINTER(__VA_ARGS__)
#define WARN(fmt, args...) DEBUG_UTIL_PRINTER("WARN: " fmt, ##args)
#define ERROR(fmt, args...) DEBUG_UTIL_PRINTER("ERROR(%s, %i): " fmt, \
        __FILE__, __LINE__, ##args)
#else
#define DEBUG_PRINT(...)
#define WARN(...)
#define ERROR(...)
#endif //DEBUG

#endif //DEBUG_UTIL_H
