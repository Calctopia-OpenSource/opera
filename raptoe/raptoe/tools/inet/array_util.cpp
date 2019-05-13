#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include "debug_util.h"

static int print_errno(void)
{
    DEBUG_PRINT("Errno set to %i: \"%s\"\n", errno, strerror(errno));
    return errno;
}

int32_t read_array(int fd, void **p_array, uint32_t *array_size)
{
    if (p_array == NULL) {
        return EINVAL;
    }

    *array_size = 0;
    if (read(fd, array_size, sizeof(uint32_t)) == -1) {
        ERROR("Error reading array size from fd: %i\n", fd);
        return print_errno();
    }

    if (*p_array) {
        free(*p_array);
    }

    if (!(*p_array = malloc(*array_size))) {
        ERROR("Failed to malloc array of size %x\n", *array_size);
        return ENOMEM;
    }
    DEBUG_PRINT("Array of size 0x%x malloced at %p\n", *array_size, *p_array);

    if (read(fd, *p_array, *array_size) == -1) {
        ERROR("Error reading array size from fd: %i\n", fd);
        return print_errno();
    }
    return 0;
}

int32_t write_array(int fd, void *p_array, uint32_t array_size)
{
    if (send(fd, &array_size, sizeof(uint32_t), 0) == -1) {
        ERROR("Error writing size of p_array 0x%x to fd: %i\n",
                array_size, fd);
        return print_errno();
    }

    if (send(fd, p_array, array_size, 0) == -1) {
        ERROR("Error writing size of p_array 0x%x to fd: %i\n",
                array_size, fd);
        return print_errno();
    }

    return 0;
}

