#include "remote_attester.h"

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


uint32_t start_attestation(uint16_t port, char *ip, char *challenge)
{
    int sockfd = -1;
    struct sockaddr_in dest_addr;
    struct in_addr addr;
    size_t msglen;
    uint16_t verif_res;

    if (!challenge) {
        return -1;
    }

    if (!ip || !inet_aton(ip, &addr)) {
        ERROR("Bad ip\n");
        return -1;
    }

    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        ERROR("Failed to create socket\n");
        return -1;
    }

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr = addr;
    memset(&(dest_addr.sin_zero), '\0', 8);

    if (connect(sockfd, (struct sockaddr*)&dest_addr, sizeof(dest_addr))) {
        ERROR("Connection failed");
        close(sockfd);
    }

    DEBUG_PRINT("Sending challenge message\n");
    msglen = strlen(challenge);
    WRITE_ARRAY(sockfd, challenge, msglen);

    verif_res = htons(verify_sent_quote(sockfd) == 0);
    DEBUG_PRINT("Quote validity: %x\n", verif_res);
    DEBUG_PRINT("Closing connection\n");
    close(sockfd);

    return 0;
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    if (argc < 4) {
        printf("USAGE: %s <port> <ip> <challenge>\n", argv[0]);
        return -1;
    }

    long int port = 0;
    char * p_end;
    port = strtol(argv[1], &p_end, 10);
    if (*p_end != '\0' || strlen(argv[1]) == 0) {
        ERROR("Invalid port number: %s\n", argv[1]);
        return -1;
    }

    start_attestation((uint16_t)port, argv[2], argv[3]);

    return 0;
}
