#ifndef RAPTOE_TOOLS_ARRAY_UTIL_H
#define RAPTOE_TOOLS_ARRAY_UTIL_H

#define WRITE_ARRAY(fd, p_array, array_size)                                  \
    do {                                                                      \
        int32_t res;                                                          \
        if ((res = write_array(fd, (void*)p_array, (uint32_t)array_size))) {  \
            close(fd);                                                        \
            return res;                                                       \
        }                                                                     \
    } while(0);

int32_t write_array(int fd, void *p_array, uint32_t array_size);
int32_t read_array(int fd, void **p_array, uint32_t *array_size);

#endif
