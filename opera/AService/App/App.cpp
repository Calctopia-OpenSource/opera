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
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

#include "../../libsgx_as/asae/asae_u.h"

#include "sgx_uae_service.h"
#include "../../GeneralSettings.h"

#define ASAE_ENCLAVE_FILENAME "asae.signed.so"


/* Global EID shared by multiple threads */
sgx_enclave_id_t asae_eid = 0;

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

#define PUB_KEY_SIZE 260
#define NONCE_SIZE 32
#define JOIN_REQUEST_SIZE 128
#define MEMBER_CRED_SIZE 100
#define GRP_VERIF_CERT_HEADER_SIZE 366
#define AS_QUOTE_HEADER_SIZE 408
#define AS_TS_SIZE 10
#define SEALED_ISSUER_DATA_SIZE 940
#define SEALED_MEMBER_DATA_SIZE 952


sgx_target_info_t asae_target_info;
sgx_target_info_t asie_target_info;

sgx_target_info_t qe_target_info;
sgx_spid_t spid = {{0x3C,0xA0,0x93,0x5F,0x1B,0x30,0xE8,0x73,
                    0xEA,0x3B,0xE7,0x3C,0xC9,0xA5,0xE1,0x38}};
sgx_quote_nonce_t qe_quote_nonce;
sgx_quote_t *qe_quote;

uint8_t sealed_issuer_data[SEALED_ISSUER_DATA_SIZE];
uint8_t sealed_member_data[SEALED_MEMBER_DATA_SIZE];
uint8_t *grp_verif_cert = NULL;
uint32_t g_cert_size = 0;
uint32_t qe_quote_size = 0;

uint8_t *ias_res = NULL, *ias_sig = NULL, *ias_crt = NULL;
uint32_t ias_res_size, ias_sig_size, ias_crt_size;

uint8_t *gvc_ias_res = NULL, *gvc_ias_sig = NULL, *gvc_ias_crt = NULL;
uint32_t gvc_ias_res_size, gvc_ias_sig_size, gvc_ias_crt_size;
uint8_t *priv_rl = NULL, *sig_rl = NULL;
uint32_t priv_rl_size, sig_rl_size;

uint8_t cur_ts[AS_TS_SIZE + 1];

uint8_t *as_quote = NULL;
uint32_t as_quote_size = 0;

void print_array(uint8_t* array, uint32_t array_size, bool debug = false) {
    if (!debug) return;
    for (int i = 0; i < array_size; i++) {
        printf("0x%02x,", array[i]);
    }
    printf("\n");
}

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
    unlink(server_domain);                              \
    return;                                              \
  }

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

void sgx_quote_prepare() {

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;
    do
    {
        //preparation
        sgx_epid_group_id_t gid = {0};
        ret = sgx_init_quote(&qe_target_info, &gid);
        BREAK_ON_ECALL(ret, "sgx_init_quote", 0)

        ret = sgx_calc_quote_size(NULL, 0, &qe_quote_size);
        BREAK_ON_ECALL(ret, "sgx_calc_quote_size", 0)

        free(qe_quote);
        qe_quote = (sgx_quote_t*)malloc(qe_quote_size);
        if (!qe_quote) {
            printf("failed to malloc qe_quote\n");
            break;
        }
    } while(0);
}

bool asae_backup(sgx_enclave_id_t &asae_eid) {

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;
    bool res = false;
    do
    {
        ret = asae_seal_member(asae_eid, &enclave_ret,
                               sealed_member_data, SEALED_MEMBER_DATA_SIZE);
        BREAK_ON_ECALL(ret, "asae_seal_member", enclave_ret)
        res = true;
    } while(0);
    return res;
}

bool asae_restore(sgx_enclave_id_t &asae_eid) {

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;
    bool res = false;
    do
    {
        ret = asae_unseal_member(asae_eid, &enclave_ret,
                               sealed_member_data, SEALED_MEMBER_DATA_SIZE);
        BREAK_ON_ECALL(ret, "asae_unseal_member", enclave_ret)
        res = true;
    } while(0);
    return res;
}

uint32_t asp_get_cert()
{
    
    int client_sockfd = -1;
    struct sockaddr_in server_addr;

    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sockfd == -1) {
        printf("failed to create socket\n");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(Settings::as_host);
    server_addr.sin_port = htons(Settings::as_port);

    if (connect(client_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        printf("failed to connect to server\n");
        close(client_sockfd);
        return -1;
    }

    uint8_t option = 1;
    write(client_sockfd, &option, 1);
    do {
        READ_ARRAY(client_sockfd, grp_verif_cert, g_cert_size);

        READ_ARRAY(client_sockfd, gvc_ias_res, gvc_ias_res_size);
        READ_ARRAY(client_sockfd, gvc_ias_sig, gvc_ias_sig_size);
        READ_ARRAY(client_sockfd, gvc_ias_crt, gvc_ias_crt_size);

        READ_ARRAY(client_sockfd, priv_rl, priv_rl_size);
        READ_ARRAY(client_sockfd, sig_rl, sig_rl_size);
        // print_array(priv_rl, priv_rl_size, true);
        // print_array(sig_rl, sig_rl_size, true);

        // read(client_sockfd, &asie_target_info, sizeof(asie_target_info));
    } while (0);
    close(client_sockfd);
    return 0;
}



uint32_t asp_provisioning()
{
    
    int client_sockfd = -1;
    struct sockaddr_in server_addr;

    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sockfd == -1) {
        printf("failed to create socket\n");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(Settings::as_host);
    server_addr.sin_port = htons(Settings::as_port);

    if (connect(client_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        printf("failed to connect to server\n");
        close(client_sockfd);
        return -1;
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;

    uint8_t option = 2;
    write(client_sockfd, &option, 1);
    do {
        //asae get nonce
        uint8_t nonce[NONCE_SIZE] = {0};
        read(client_sockfd, nonce, NONCE_SIZE);

        //asae init member
        ret = asae_init_member(asae_eid, &enclave_ret);
        BREAK_ON_ECALL(ret, "asae_init_member", enclave_ret)

        //asae gen join req
        sgx_quote_prepare();

        sgx_report_t report;
        uint8_t join_request[JOIN_REQUEST_SIZE] = {0};
        ret = asae_join_request(asae_eid, &enclave_ret,
                                grp_verif_cert, PUB_KEY_SIZE,
                                nonce, NONCE_SIZE,
                                join_request, JOIN_REQUEST_SIZE,
                                &qe_target_info, &report);
        BREAK_ON_ECALL(ret, "asae_join_request", enclave_ret)

        memset(&asae_target_info, 0, sizeof(asae_target_info));
        memcpy(&asae_target_info.mr_enclave, &report.body.mr_enclave, sizeof(sgx_measurement_t));
        memcpy(&asae_target_info.attributes, &report.body.attributes, sizeof(sgx_attributes_t));
        memcpy(&asae_target_info.misc_select, &report.body.misc_select, sizeof(sgx_misc_select_t));
        printf("asae_target_info:\n");
        print_array((uint8_t*)&asae_target_info, sizeof(asae_target_info), true);

        // write(client_sockfd, &asae_target_info, sizeof(asae_target_info));
        write(client_sockfd, join_request, JOIN_REQUEST_SIZE);

        sgx_report_t qe_report;
        ret = sgx_get_quote(&report,
                           SGX_UNLINKABLE_SIGNATURE,
                           &spid,
                           &qe_quote_nonce,
                           NULL,
                           0,
                           &qe_report,
                           qe_quote,
                           qe_quote_size);
        BREAK_ON_ECALL(ret, "sgx_get_quote", 0)
        WRITE_ARRAY(client_sockfd, qe_quote, qe_quote_size);

        uint8_t member_cred[MEMBER_CRED_SIZE] = {0};
        read(client_sockfd, member_cred, MEMBER_CRED_SIZE);

        // asae provision member
        ret = asae_provision_member(asae_eid, &enclave_ret,
                                member_cred, MEMBER_CRED_SIZE);
        BREAK_ON_ECALL(ret, "asae_provision_member", enclave_ret)

        // asae set sig_rl
        ret = asae_set_sig_rl(asae_eid, &enclave_ret,
                                sig_rl, sig_rl_size);
        BREAK_ON_ECALL(ret, "asae_set_sig_rl", enclave_ret)
    } while (0);
    close(client_sockfd);
    return 0;
}


uint32_t asp_update()
{
    
    int client_sockfd = -1;
    struct sockaddr_in server_addr;

    client_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_sockfd == -1) {
        printf("failed to create socket\n");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(Settings::fe_host);
    server_addr.sin_port = htons(Settings::fe_port);

    if (connect(client_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        printf("failed to connect to server\n");
        close(client_sockfd);
        return -1;
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;

    uint8_t option = 1;
    write(client_sockfd, &option, 1);
    do {

        sgx_report_t report;
        uint8_t pse_manifest[256] = {0};
        ret = asae_update_ts_reqest(asae_eid, &enclave_ret,
                                &qe_target_info, &report, pse_manifest);
        BREAK_ON_ECALL(ret, "asae_update_ts_reqest", enclave_ret)

        sgx_report_t qe_report;
        ret = sgx_get_quote(&report,
                           SGX_UNLINKABLE_SIGNATURE,
                           &spid,
                           &qe_quote_nonce,
                           NULL,
                           0,
                           &qe_report,
                           qe_quote,
                           qe_quote_size);
        BREAK_ON_ECALL(ret, "sgx_get_quote", 0)
        WRITE_ARRAY(client_sockfd, qe_quote, qe_quote_size);
        uint8_t has_pse_manifest = 1;
        write(client_sockfd, &has_pse_manifest, 1);
        write(client_sockfd, pse_manifest, 256);

        READ_ARRAY(client_sockfd, ias_res, ias_res_size);
        READ_ARRAY(client_sockfd, ias_sig, ias_sig_size);
        READ_ARRAY(client_sockfd, ias_crt, ias_crt_size);

        ret = asae_update_ts_response(asae_eid, &enclave_ret,
                                    ias_res, ias_res_size,
                                    ias_sig, ias_sig_size,
                                    ias_crt, ias_crt_size);
        BREAK_ON_ECALL(ret, "asae_update_ts_reqest", enclave_ret)
        ret = asae_calc_quote_size(asae_eid, &enclave_ret, &as_quote_size);
        BREAK_ON_ECALL(ret, "asae_calc_quote_size", enclave_ret)
    } while (0);
    close(client_sockfd);
    return 0;
}



void aservice(const char* server_domain) {
    
    int server_sockfd = -1;
    int client_sockfd = -1;
    struct sockaddr_un server_addr;
    struct sockaddr_un client_addr;

    server_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_sockfd == -1) {
        printf("failed to create socket\n");
        return;
    }

    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, server_domain, sizeof(server_addr.sun_path) - 1);
    RETURN_ON_SOCKET_ERROR(bind(server_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)), "bind")

    RETURN_ON_SOCKET_ERROR(listen(server_sockfd, 5), "listen")

    printf("AServer running\n");
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;
    while(1) {
        socklen_t client_len = sizeof(client_addr);
        // printf("AServer waiting\n");

        client_sockfd = accept(server_sockfd, (struct sockaddr*)&client_addr, &client_len);
        RETURN_ON_SOCKET_ERROR(client_sockfd, "accept")

        uint8_t option = 0;
        read(client_sockfd, &option, 1);
        // printf("handling option %02x\n", option);

        if (option == 1) {
            // write(client_sockfd, &asae_target_info, sizeof(asae_target_info));
            // write(client_sockfd, &asie_target_info, sizeof(asie_target_info));
            // write();
        } else if (option == 2) {
            // write(client_sockfd, &as_quote_size, sizeof(as_quote_size));
            // write();
        } else if (option == 3) {
            sgx_report_t report;
            read(client_sockfd, &report, sizeof(report));

            free(as_quote);
            as_quote = (uint8_t*) malloc(as_quote_size);
            if (!as_quote) {
                printf("failed to malloc as_quote\n");
                break;
            }
            memset(as_quote, 0, as_quote_size);

            ret = asae_get_quote(asae_eid, &enclave_ret,
                        &report, as_quote, as_quote_size);
            if (ret != SGX_SUCCESS || enclave_ret != 0) {
                printf("asae_get_quote error\n");
                break;
            }
            // BREAK_ON_ECALL(ret, "asae_get_quote", enclave_ret)
            WRITE_ARRAY(client_sockfd, as_quote, as_quote_size);

        // } else if (option == 4) {
            WRITE_ARRAY(client_sockfd, grp_verif_cert, g_cert_size);

            WRITE_ARRAY(client_sockfd, gvc_ias_res, gvc_ias_res_size);
            WRITE_ARRAY(client_sockfd, gvc_ias_sig, gvc_ias_sig_size);
            WRITE_ARRAY(client_sockfd, gvc_ias_crt, gvc_ias_crt_size);

            WRITE_ARRAY(client_sockfd, priv_rl, priv_rl_size);
            WRITE_ARRAY(client_sockfd, sig_rl, sig_rl_size);

            // print_array(grp_verif_cert, g_cert_size, true);
            // printf("%s\n%s\n%s\n", ias_res, ias_sig, ias_crt);
            // print_array(priv_rl, priv_rl_size, true);
            // print_array(sig_rl, sig_rl_size, true);

            // read();
        }
        // printf("option: %02x %d\n", option, client_sockfd);

        close(client_sockfd);

        if (option == 0xff) break;
    }

    close(server_sockfd);
    unlink(server_domain);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    if (argc < 2) {
        printf("please specify socket domain\n");
        return -1;
    }
    
    sgx_launch_token_t asae_token = {0};
    int asae_updated = 0;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_create_enclave(ASAE_ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &asae_token, &asae_updated, &asae_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("failed creating asae %x\n", ret);
        return -1;
    }
    printf("create asae successfully\n");

    asp_get_cert();
    asp_provisioning();
    asp_update();
    // do {
    //         sgx_report_t report;

    //         uint32_t enclave_ret = -1;
    //         free(as_quote);
    //         as_quote = (uint8_t*) malloc(as_quote_size);
    //         if (!as_quote) {
    //             printf("failed to malloc as_quote\n");
    //             break;
    //         }
    //         memset(as_quote, 0, as_quote_size);

    //         ret = asae_get_quote(asae_eid, &enclave_ret,
    //                     &report, as_quote, as_quote_size);
    //         if (ret != SGX_SUCCESS || enclave_ret != 0) {
    //             printf("asae_get_quote error\n");
    //             break;
    //         }
    // } while (0);
    aservice(argv[1]);

    sgx_destroy_enclave(asae_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");
    return 0;
}
