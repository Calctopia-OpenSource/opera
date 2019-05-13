#include <arpa/inet.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include "debug_util.h"

#define BACKLOG_SIZE 5

int listen_on_inet_socket(uint16_t port)
{
    int sockfd = -1;
    struct sockaddr_in local_addr;

    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        ERROR("Failed to create socket\n");
        return -1;
    }

    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(port);
    local_addr.sin_addr.s_addr = 0;
    memset(&(local_addr.sin_zero), '\0', 8);

    if (bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr)) == -1) {
        ERROR("Failed to bind to socket.. errno = %x\n", errno);
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, BACKLOG_SIZE) == -1) {
        ERROR("Failed to listen on socket\n");
        close(sockfd);
        return -1;
    }

    return sockfd;
}


int connect_unix_socket(const char* service_domain)
{
    int client_sockfd = -1;
    struct sockaddr_un server_addr;

    client_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_sockfd == -1) {
        ERROR("Failed to create socket\n");
        return -1;
    }

    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, service_domain,
            sizeof(server_addr.sun_path) - 1);
    if (connect(client_sockfd, (struct sockaddr*)&server_addr,
                sizeof(server_addr)) == -1) {
        ERROR("Failed to connect to server\n");
        close(client_sockfd);
        return -1;
    }

    return client_sockfd;
}
