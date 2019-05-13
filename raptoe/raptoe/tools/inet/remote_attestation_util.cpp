#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "sgx_report.h"
#include "array_util.h"
#include "inet_tools_api.h"
#include "debug_util.h"
#include "opera_types.h"
#include "common_tools_api.h"

as_report_t* as_get_report(sgx_report_t* report, const char* service_domain)
{
    int as_socket;
    as_report_t* as_report = NULL;
    uint8_t option = 3;

    if (!report || !service_domain) {
        ERROR("Invalid parameters\n");
        return NULL;
    }

    if ((as_socket = connect_unix_socket(service_domain)) == -1) {
        return NULL;
    }

    DEBUG_PRINT("Connection established to asae at '%s'\n", service_domain);
    if (write(as_socket, &option, 1) == -1) {
        ERROR("Failed to send option to asae\n");
        return NULL;
    }

    if (write(as_socket, report, sizeof(sgx_report_t)) == -1) {
        ERROR("Failed to send sgx report to asae\n");
        return NULL;
    }

    if ((as_report = as_read_report(as_socket)) == NULL) {
        ERROR("AS read report failure\n");
        return NULL;
    }

    close(as_socket);
    return as_report;
}

int32_t remote_attestation(const char* service_domain, int attester_socket,
        sgx_report_generator report_gen)
{
    sgx_report_t* isve_report = NULL;
    as_report_t *as_report = NULL;
    int32_t res = -1;
    uint8_t *msg = NULL;
    uint32_t msglen = 0;

    if (!report_gen || !service_domain) {
        ERROR("Invalid parameters\n");
        goto EXIT;
    }

    if (read_array(attester_socket, (void**)&msg, &msglen) != 0) {
        ERROR("Failed to read msg from attester");
        goto EXIT;
    }

    isve_report = report_gen(msg, msglen);
    if (isve_report == NULL) {
        ERROR("Failed to generate sgx report\n");
        goto EXIT;
    }

    if ((as_report = as_get_report(isve_report, service_domain)) == NULL) {
        ERROR("Failed to get as report\n");
        goto EXIT;
    }

    if (as_send_report(attester_socket, as_report) != 0) {
        ERROR("Failed to send report\n");
        goto EXIT;
    }
    res = 0;

EXIT:
    if (msg) {
        free(msg);
    }

    if (isve_report) {
        free(isve_report);
    }

    free_as_report(as_report);
    return res;
}

int32_t accept_remote_attestation(const char* asae_socket, int listening_socket,
        sgx_report_generator report_gen)
{
    int attest_socket;

    struct sockaddr_in attester_addr;
    socklen_t sin_size = sizeof(struct sockaddr_in);

    if ((attest_socket = accept(listening_socket,
                    (struct sockaddr*)&attester_addr, &sin_size)) == -1) {
        ERROR("Failed to accept connection\n");
        return -1;
    }

    DEBUG_PRINT("Connection established with remote attester at '%s:%i'\n",
            inet_ntoa(attester_addr.sin_addr), attester_addr.sin_port);
    if (remote_attestation(asae_socket, attest_socket, report_gen) != 0) {
        ERROR("Remote attestation failure\n");
        return -1;
    }

    close(attest_socket);
    return 0;
}

int32_t start_remote_attest_server(const char* asae_socket, uint16_t port,
        sgx_report_generator report_gen)
{
    int sockfd;

    if((sockfd = listen_on_inet_socket(port)) == -1) {
        ERROR("Failed to acquire inet socket\n");
        return -1;
    }

    while(1) {
        DEBUG_PRINT("Waiting for remote attestation\n");
        if (accept_remote_attestation(asae_socket, sockfd, report_gen) < 0) {
            ERROR("Failure during remote attestation\n");
            close(sockfd);
            return -1;
        }
    }

    close(sockfd);
    return 0;
}
