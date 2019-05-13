/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include <sys/socket.h>
#include <netinet/in.h>

#include "sgx_urts.h"
#include "App.h"

#include <stdlib.h>
#include <stdint.h>
#ifdef _MSC_VER
#include <intrin.h>
#pragma optimize("gt",on)
#else
#include <x86intrin.h>
#endif

#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sched.h> 
#include <fcntl.h>
#include <assert.h>
#include <time.h>

#include "sgx_uae_service.h"
#include "../../WebService/WebService.h"
#include "../../GeneralSettings.h"


WebService *g_ws;

uint8_t *ias_res = NULL, *ias_sig = NULL, *ias_crt = NULL;
uint32_t ias_res_size, ias_sig_size, ias_crt_size;

sgx_quote_t *qe_quote;
uint32_t qe_quote_size = 0;

#define BREAK_ON_ECALL(ret, func_name, enclave_ret)             \
  if (SGX_SUCCESS != ret) {                                     \
    printf("Failed to %s %x\n", func_name, ret);                \
    break;                                                      \
  } else {                                                      \
    printf("%s successfully\n", func_name);                     \
  }                                                             \
  if (enclave_ret != 0) {                                       \
    printf("error %d\n", enclave_ret);                          \
    break;                                                      \
  }


#define RETURN_ON_SOCKET_ERROR(ret, func_name)           \
  if (ret == -1) {                                       \
    perror(func_name);                 \
    close(server_sockfd);                                \
    return;                                              \
  }

#define READ_QUOTE(fd, quote, quote_size)           \
    read(fd, &quote_size, sizeof(quote_size));      \
    if (quote) free(quote);                         \
    quote = (sgx_quote_t *) malloc(quote_size);     \
    if (!quote) {                                   \
        printf("failed to malloc\n");               \
        break;                                      \
    }                                               \
    read(fd, quote, quote_size);

#define READ_ARRAY(fd, array, array_size)           \
    read(fd, &array_size, sizeof(array_size));      \
    if (array) free(array);                         \
    array = (uint8_t *) malloc(array_size);         \
    if (!array) {                                   \
        printf("failed to malloc\n");               \
        break;                                      \
    }                                               \
    read(fd, array, array_size);

#define WRITE_ARRAY(fd, array, array_size)          \
    write(fd, &array_size, sizeof(array_size));     \
    write(fd, array, array_size);

void fe_init() {
    g_ws = WebService::getInstance();
    g_ws->init();

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    do
    {
        //preparation
        ret = sgx_calc_quote_size(NULL, 0, &qe_quote_size);
        BREAK_ON_ECALL(ret, "sgx_calc_quote_size", 0)

        qe_quote = (sgx_quote_t*)malloc(qe_quote_size);
        if (!qe_quote) {
            printf("failed to malloc qe_quote\n");
            break;
        }
    } while(0);
}

sgx_status_t get_ias_report(
    uint8_t *p_pse_manifest = NULL)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;
    do
    {  
        if(ias_res) free(ias_res);
        ias_res_size = 0;
        if(ias_sig) free(ias_sig);
        ias_sig_size = 0;
        if(ias_crt) free(ias_crt);
        ias_crt_size = 0;

        vector<pair<string, string>> ias_result;
        g_ws->verifyQuote((uint8_t*) qe_quote, p_pse_manifest, NULL, &ias_result);
        ias_res_size = ias_result[0].second.size();
        ias_res = (uint8_t *)malloc(ias_res_size + 1);
        memcpy(ias_res, ias_result[0].second.c_str(), ias_res_size);
        ias_res[ias_res_size] = 0;
        ias_sig_size = ias_result[1].second.size();
        ias_sig = (uint8_t *)malloc(ias_sig_size + 1);
        memcpy(ias_sig, ias_result[1].second.c_str(), ias_sig_size);
        ias_sig[ias_sig_size] = 0;
        ias_crt_size = ias_result[2].second.size();
        ias_crt = (uint8_t *)malloc(ias_crt_size + 1);
        memcpy(ias_crt, ias_result[2].second.c_str(), ias_crt_size);
        ias_crt[ias_crt_size] = 0;

        ret = SGX_SUCCESS;
    } while(0);
    return ret;
}

void feservice() {
    
    int server_sockfd = -1;
    int client_sockfd = -1;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;

    server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sockfd == -1) {
        printf("failed to create socket\n");
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(Settings::fe_port);
    RETURN_ON_SOCKET_ERROR(bind(server_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)), "bind")

    RETURN_ON_SOCKET_ERROR(listen(server_sockfd, 1), "listen")
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;
    while(1) {
        socklen_t client_len = sizeof(client_addr);
        printf("FEServer waiting\n");

        client_sockfd = accept(server_sockfd, (struct sockaddr*)&client_addr, &client_len);
        RETURN_ON_SOCKET_ERROR(client_sockfd, "accept")

        uint8_t option = 0;
        read(client_sockfd, &option, 1);
        do
        {
            if (option == 1) {
                uint8_t pse_manifest[256] = {0}, has_pse_manifest;
                READ_QUOTE(client_sockfd, qe_quote, qe_quote_size);
                read(client_sockfd, &has_pse_manifest, 1);
                if (has_pse_manifest) {
                    read(client_sockfd, pse_manifest, 256);
                    get_ias_report(pse_manifest);
                } else {
                    get_ias_report();
                }
                WRITE_ARRAY(client_sockfd, ias_res, ias_res_size);
                WRITE_ARRAY(client_sockfd, ias_sig, ias_sig_size);
                WRITE_ARRAY(client_sockfd, ias_crt, ias_crt_size);
            } else {
                printf("unkown option %d\n", option);
            }
        } while(0);

        close(client_sockfd);
    }

    close(server_sockfd);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    fe_init();

    feservice();

    return 0;
}
