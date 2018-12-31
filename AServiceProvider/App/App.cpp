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

#include "../../libsgx_as/asie/asie_u.h"

#include "sgx_uae_service.h"
#include "../../WebService/WebService.h"
#include "../../GeneralSettings.h"

#define ASIE_ENCLAVE_FILENAME "asie.signed.so"

/* Global EID shared by multiple threads */
sgx_enclave_id_t asie_eid = 0;

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


// WebService *g_ws;

sgx_target_info_t asae_target_info;
sgx_target_info_t asie_target_info;
sgx_target_info_t qe_target_info;
sgx_spid_t spid = {{0x83,0xD1,0xAE,0xED,0xDA,0x65,0xBD,0x35,
                    0xFA,0x48,0x09,0x12,0x8D,0x84,0xAC,0x2F}};
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

void as_init() {
    // g_ws = WebService::getInstance();
    // g_ws->init();

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

        qe_quote = (sgx_quote_t*)malloc(qe_quote_size);
        if (!qe_quote) {
            printf("failed to malloc qe_quote\n");
            break;
        }

        g_cert_size = GRP_VERIF_CERT_HEADER_SIZE;
        grp_verif_cert = (uint8_t*) malloc(g_cert_size);
    } while(0);
}

uint32_t verify_ias_quote(
    uint8_t *p_qe_quote,
    uint8_t *p_pse_manifest = NULL)
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

    uint8_t option = 1;
    write(client_sockfd, &option, 1);
    do {
        if (option == 1) {

            WRITE_ARRAY(client_sockfd, p_qe_quote, qe_quote_size);
            uint8_t has_pse_manifest;
            if (p_pse_manifest == NULL) {
                has_pse_manifest = 0;
                write(client_sockfd, &has_pse_manifest, 1);
            } else {
                has_pse_manifest = 1;
                write(client_sockfd, &has_pse_manifest, 1);
                write(client_sockfd, p_pse_manifest, 256);
            }

            READ_ARRAY(client_sockfd, ias_res, ias_res_size);
            READ_ARRAY(client_sockfd, ias_sig, ias_sig_size);
            READ_ARRAY(client_sockfd, ias_crt, ias_crt_size);
        }
    } while (0);
    close(client_sockfd);
    return 0;
}

sgx_status_t get_ias_quote(
    sgx_report_t *p_report,
    uint8_t *p_pse_manifest)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;
    do
    {

        sgx_report_t qe_report;
        ret = sgx_get_quote(p_report,
                           SGX_UNLINKABLE_SIGNATURE,
                           &spid,
                           &qe_quote_nonce,
                           NULL,
                           0,
                           &qe_report,
                           qe_quote,
                           qe_quote_size);
        BREAK_ON_ECALL(ret, "sgx_get_quote", 0)

        verify_ias_quote((uint8_t*) qe_quote, p_pse_manifest);

        ret = SGX_SUCCESS;
    } while(0);
    return ret;
}

sgx_status_t get_ias_report(
    uint8_t *p_pse_manifest = NULL)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;
    do
    {
        verify_ias_quote((uint8_t*) qe_quote, p_pse_manifest);

        ret = SGX_SUCCESS;
    } while(0);
    return ret;
}


bool asie_update(sgx_enclave_id_t &asie_eid)
{

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;
    bool res = false;
    do
    {
        //asie req group verification certificate
        sgx_report_t report;
        uint8_t pse_manifest[256] = {0};
        GetCurrentTimeGMTTime((char*)cur_ts, AS_TS_SIZE + 1);
        ret = asie_request_grp_verif_cert(asie_eid, &enclave_ret,
                                        cur_ts, AS_TS_SIZE,
                                        &qe_target_info, &report, pse_manifest);
        BREAK_ON_ECALL(ret, "asie_request_grp_verif_cert", enclave_ret)
        memset(&asie_target_info, 0, sizeof(asie_target_info));
        memcpy(&asie_target_info.mr_enclave, &report.body.mr_enclave, sizeof(sgx_measurement_t));
        memcpy(&asie_target_info.attributes, &report.body.attributes, sizeof(sgx_attributes_t));
        memcpy(&asie_target_info.misc_select, &report.body.misc_select, sizeof(sgx_misc_select_t));
        printf("asie_target_info:\n");
        print_array((uint8_t*)&asie_target_info, sizeof(asie_target_info), true);
        ret = get_ias_quote(&report, pse_manifest);
        BREAK_ON_ECALL(ret, "get_ias_quote", 0)

        ret = asie_produce_grp_verif_cert(asie_eid, &enclave_ret,
                                  grp_verif_cert, g_cert_size,
                                  ias_res, ias_res_size,
                                  ias_sig, ias_sig_size,
                                  ias_crt, ias_crt_size);
        BREAK_ON_ECALL(ret, "asie_produce_grp_verif_cert", enclave_ret)
        // print_array(grp_verif_cert, g_cert_size, 1);
        gvc_ias_res_size = ias_res_size;
        gvc_ias_sig_size = ias_sig_size;
        gvc_ias_crt_size = ias_crt_size;

        if (gvc_ias_res) free(gvc_ias_res);
        if (gvc_ias_sig) free(gvc_ias_sig);
        if (gvc_ias_crt) free(gvc_ias_crt);

        gvc_ias_res = (uint8_t*) malloc(gvc_ias_res_size);
        gvc_ias_sig = (uint8_t*) malloc(gvc_ias_sig_size);
        gvc_ias_crt = (uint8_t*) malloc(gvc_ias_crt_size);

        memcpy(gvc_ias_res, ias_res, gvc_ias_res_size);
        memcpy(gvc_ias_sig, ias_sig, gvc_ias_sig_size);
        memcpy(gvc_ias_crt, ias_crt, gvc_ias_crt_size);

        //asie get priv_rl and sig_rl
        ret = asie_calc_rl_sizes(asie_eid, &enclave_ret,
                                        &priv_rl_size, &sig_rl_size);
        BREAK_ON_ECALL(ret, "asie_calc_rl_sizes", enclave_ret)

        if (priv_rl) free(priv_rl);
        if (sig_rl) free(sig_rl);
        priv_rl = (uint8_t*) malloc(priv_rl_size);
        sig_rl = (uint8_t*) malloc(sig_rl_size);


        ret = asie_produce_rls(asie_eid, &enclave_ret,
                               priv_rl,
                               priv_rl_size,
                               sig_rl,
                               sig_rl_size);
        BREAK_ON_ECALL(ret, "asie_produce_rls", enclave_ret)

        res = true;
    } while(0);
    return res;
}

bool asie_setup(sgx_enclave_id_t &asie_eid) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;
    bool res = false;
    do
    {
        //asie setup
        ret = asie_create_issuer(asie_eid, &enclave_ret, sealed_issuer_data, SEALED_ISSUER_DATA_SIZE);
        BREAK_ON_ECALL(ret, "asie_create_issuer", enclave_ret)

        asie_update(asie_eid);

        // ret = asie_load_issuer(asie_eid, &enclave_ret,
        //                        sealed_issuer_data, SEALED_ISSUER_DATA_SIZE,
        //                        priv_rl, priv_rl_size,
        //                        sig_rl, sig_rl_size);
        // BREAK_ON_ECALL(ret, "asie_load_issuer", enclave_ret)

        // ret = asie_delete_issuer(asie_eid, &enclave_ret, sealed_issuer_data, SEALED_ISSUER_DATA_SIZE);
        // BREAK_ON_ECALL(ret, "asie_delete_issuer", enclave_ret)

        res = true;
    } while(0);
    return res;
}

bool asie_delete(sgx_enclave_id_t &asie_eid) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;
    bool res = false;
    do
    {
        //asie delete
        ret = asie_delete_issuer(asie_eid, &enclave_ret, sealed_issuer_data, SEALED_ISSUER_DATA_SIZE);
        BREAK_ON_ECALL(ret, "asie_delete_issuer", enclave_ret)

        res = true;
    } while(0);
    return res;
}

void aserviceprovider() {
    
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
    server_addr.sin_port = htons(Settings::as_port);
    RETURN_ON_SOCKET_ERROR(bind(server_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)), "bind")

    RETURN_ON_SOCKET_ERROR(listen(server_sockfd, 1), "listen")
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;
    while(1) {
        socklen_t client_len = sizeof(client_addr);
        printf("AServer waiting\n");

        client_sockfd = accept(server_sockfd, (struct sockaddr*)&client_addr, &client_len);
        RETURN_ON_SOCKET_ERROR(client_sockfd, "accept")

        uint8_t option = 0;
        read(client_sockfd, &option, 1);
        do
        {
            if (option == 1) {
            // get gvc
                WRITE_ARRAY(client_sockfd, grp_verif_cert, g_cert_size);

                WRITE_ARRAY(client_sockfd, gvc_ias_res, gvc_ias_res_size);
                WRITE_ARRAY(client_sockfd, gvc_ias_sig, gvc_ias_sig_size);
                WRITE_ARRAY(client_sockfd, gvc_ias_crt, gvc_ias_crt_size);

                WRITE_ARRAY(client_sockfd, priv_rl, priv_rl_size);
                WRITE_ARRAY(client_sockfd, sig_rl, sig_rl_size);

            } else if (option == 2) {
            // provisioning protocol
                uint8_t nonce[NONCE_SIZE] = {0};
                ret = asie_gen_nonce(asie_eid, &enclave_ret, nonce, NONCE_SIZE);
                BREAK_ON_ECALL(ret, "asie_gen_nonce", enclave_ret)
                write(client_sockfd, nonce, NONCE_SIZE);

                uint8_t join_request[JOIN_REQUEST_SIZE] = {0};
                printf("read join_request\n");
                read(client_sockfd, join_request, JOIN_REQUEST_SIZE);

                printf("read qe_quote\n");
                READ_QUOTE(client_sockfd, qe_quote, qe_quote_size);
                printf("get_ias_report\n");
                get_ias_report();

                uint8_t member_cred[MEMBER_CRED_SIZE] = {0};
                ret = asie_certify_member(asie_eid, &enclave_ret,
                                          join_request, JOIN_REQUEST_SIZE,
                                          member_cred, MEMBER_CRED_SIZE,
                                          ias_res, ias_res_size,
                                          ias_sig, ias_sig_size,
                                          ias_crt, ias_crt_size);
                BREAK_ON_ECALL(ret, "asie_certify_member", enclave_ret)
                write(client_sockfd, member_cred, MEMBER_CRED_SIZE);

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


    // aserviceprovider();
    // return 0;
    
    sgx_launch_token_t asie_token = {0};
    int asie_updated = 0;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_create_enclave(ASIE_ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &asie_token, &asie_updated, &asie_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("failed creating asie %x\n", ret);
        return -1;
    }
    printf("create asie successfully\n");

    as_init();

    asie_setup(asie_eid);
    asie_delete(asie_eid);


    aserviceprovider();

    sgx_destroy_enclave(asie_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");
    return 0;
}
