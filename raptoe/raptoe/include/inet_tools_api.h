#ifndef RAPTOE_INET_TOOLS_API_H
#define RAPTOE_INET_TOOLS_API_H

#include "opera_types.h"
#include <unistd.h>
#include "sgx_report.h"

typedef sgx_report_t* (*sgx_report_generator)(const uint8_t* msg,
        uint32_t msglen);

int32_t as_send_report(int fd, as_report_t* report);

as_report_t* as_read_report(int fd);

int connect_unix_socket(const char *service_domain);

int listen_on_inet_socket(uint16_t port);

int32_t start_remote_attest_server(const char* asae_socket, uint16_t port,
        sgx_report_generator report_gen);

int32_t accept_remote_attestation(const char* asae_socket, int listening_socket,
        sgx_report_generator report_gen);

#endif
