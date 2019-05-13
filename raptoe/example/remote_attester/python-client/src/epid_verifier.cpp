#include "epid_verifier.h"

uint32_t verify_sent_quote(int sockfd)
{
    as_report_t *report = (as_report_t*)calloc(1, sizeof(as_report_t));
    char cur_ts[AS_TS_SIZE + 1];

    if ((report = as_read_report(sockfd)) == NULL) {
        ERROR("AS read report failure\n");
        return -1;
    }

    get_current_gmt_time(cur_ts, AS_TS_SIZE + 1);
    if (verify_quote(report, cur_ts, AS_TS_SIZE,
                (sgx_target_info_t*)asie_target_info,
                (sgx_target_info_t*)isve_target_info) != 0) {
        printf("Quote is not valid\n");
        return 1;
    } else {
        printf("Quote is valid\n");
    }

    return 0;
}


uint32_t start_server(uint16_t port)
{
    int sockfd = -1, client_sockfd = -1;
    struct sockaddr_in client_addr;

    if ((sockfd = listen_on_inet_socket(port)) == -1) {
        ERROR("Failed to acquire inet socket\n");
        return -1;
    }

    while(1) {
        uint16_t verif_res;
        DEBUG_PRINT("Waiting for connection\n");

        socklen_t addrlen = sizeof(struct sockaddr_in);
        if((client_sockfd = accept(sockfd, (struct sockaddr*)&client_addr,
                        &addrlen)) == -1) {
            printf("Failed to accept connection\n");
            close(sockfd);
            return -1;
        }
        DEBUG_PRINT("Connection established\n");

        verif_res = htons(verify_sent_quote(client_sockfd) == 0);
        DEBUG_PRINT("Sending response: %x\n", verif_res);
        send(client_sockfd, &verif_res, sizeof(verif_res), 0);
        DEBUG_PRINT("Closing connection\n");
        close(client_sockfd);
    }
    close(sockfd);

    return 0;
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("please specify hosting port\n");
        return -1;
    }

    long int port = 0;
    char * p_end;
    port = strtol(argv[1], &p_end, 10);
    if (*p_end != '\0' || strlen(argv[1]) == 0) {
        ERROR("Invalid port number: %s\n", argv[1]);
        return -1;
    }

    start_server((uint16_t)port);

    return 0;
}
