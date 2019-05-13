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

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

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

#include "../../libsgx_as/asve/asve_u.h"

// Needed to query extended epid group id.
// #include "sgx_uae_service.h"
#include "../../GeneralSettings.h"
#include "../../Util/UtilityFunctions.h"

# define ISVE_ENCLAVE_FILENAME "enclave.signed.so"
# define ASVE_ENCLAVE_FILENAME "asve.signed.so"

/* Global EID shared by multiple threads */
sgx_enclave_id_t isve_eid = 0;
sgx_enclave_id_t asve_eid = 0;

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

sgx_target_info_t isve_target_info;

uint8_t *grp_verif_cert = NULL;
uint32_t g_cert_size = 0;
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

#define READ_ARRAY(fd, array, array_size)           \
    read(fd, &array_size, sizeof(array_size));      \
    free(array);                                    \
    array = (uint8_t *) malloc(array_size);         \
    if (!array) {                                   \
        printf("failed to malloc\n");               \
        break;                                      \
    }                                               \
    read(fd, array, array_size);

#define WRITE_ARRAY(fd, array, array_size)          \
    write(fd, &array_size, sizeof(array_size));     \
    write(fd, array, array_size);

uint32_t as_get_quote(
    sgx_report_t &report,
    uint8_t *&p_quote,
    uint32_t &quote_size,
    const char* service_domain)
{
    uint32_t res = -1;
    int client_sockfd = -1;
    struct sockaddr_un server_addr;

    client_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_sockfd == -1) {
        printf("failed to create socket\n");
        return -1;
    }

    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, service_domain, sizeof(server_addr.sun_path) - 1);
    if (connect(client_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        printf("failed to connect to server\n");
        close(client_sockfd);
        return -1;
    }

    uint8_t option = 3;
    write(client_sockfd, &option, 1);
    do
    {
      write(client_sockfd, &report, sizeof(sgx_report_t));
      READ_ARRAY(client_sockfd, p_quote, quote_size);
      READ_ARRAY(client_sockfd, grp_verif_cert, g_cert_size);

      READ_ARRAY(client_sockfd, gvc_ias_res, gvc_ias_res_size);
      READ_ARRAY(client_sockfd, gvc_ias_sig, gvc_ias_sig_size);
      READ_ARRAY(client_sockfd, gvc_ias_crt, gvc_ias_crt_size);

      READ_ARRAY(client_sockfd, priv_rl, priv_rl_size);
      READ_ARRAY(client_sockfd, sig_rl, sig_rl_size);
      res = 0;
    } while(0);
    close(client_sockfd);

    return res;
}


void as_attestation(
  sgx_enclave_id_t &isve_eid,
  const char* service_domain)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    uint32_t enclave_ret = -1;
    uint8_t *as_quote = NULL;
    uint32_t as_quote_size = 0;

    do
    {
        sgx_report_t isve_report;
        //isve gen report
        ret = isve_gen_report(isve_eid, &enclave_ret,
                              (sgx_target_info_t*)Settings::asae_target_info, &isve_report);
        if (ret != SGX_SUCCESS) {
          printf("isve_gen_report error\n");
          break;
        }
        // memset(&isve_target_info, 0, sizeof(isve_target_info));
        // memcpy(&isve_target_info.mr_enclave, &isve_report.body.mr_enclave, sizeof(sgx_measurement_t));
        // memcpy(&isve_target_info.attributes, &isve_report.body.attributes, sizeof(sgx_attributes_t));
        // memcpy(&isve_target_info.misc_select, &isve_report.body.misc_select, sizeof(sgx_misc_select_t));
        // printf("isve_target_info:\n");
        // print_array((uint8_t*)&isve_target_info, sizeof(isve_target_info), true);

        //asae get quote
        uint32_t res = as_get_quote(isve_report, as_quote, as_quote_size, service_domain);
        if (0 != res) {
          printf("as_get_quote error!\n");
          break;
        }
        // print_array(as_quote, as_quote_size, 1);

        //asve verify quote
        uint32_t is_valid = 0;
        GetCurrentTimeGMTTime((char*)cur_ts, AS_TS_SIZE + 1);
        ret = asve_verify_quote(asve_eid, &enclave_ret, &is_valid,
                                grp_verif_cert, g_cert_size,
                                gvc_ias_res, gvc_ias_res_size,
                                gvc_ias_sig, gvc_ias_sig_size,
                                gvc_ias_crt, gvc_ias_crt_size,
                                (sgx_target_info_t*)Settings::asie_target_info,
                                (sgx_target_info_t*)Settings::isve_target_info,
                                cur_ts, AS_TS_SIZE,
                                priv_rl, priv_rl_size,
                                sig_rl, sig_rl_size,
                                as_quote, as_quote_size);
        if (ret != SGX_SUCCESS) {
          printf("asve_verify_quote error\n");
          break;
        }
        if (is_valid == 0) {
          printf("as_quote is not valid\n");
          break;
        } else {
            printf("as_quote is valid\n");
        }
    } while(0);
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
    
    sgx_launch_token_t isve_token = {0};
    sgx_launch_token_t asve_token = {0};
    int isve_updated = 0;
    int asve_updated = 0;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_create_enclave(ISVE_ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &isve_token, &isve_updated, &isve_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("failed creating isve %x\n", ret);
        return -1;
    }
    printf("create isve successfully\n");
    ret = sgx_create_enclave(ASVE_ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &asve_token, &asve_updated, &asve_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("failed creating asve %x\n", ret);
        return -1;
    }
    printf("create asve successfully\n");

    // do {
    //     int numIters = 10;
    //     struct timespec start_stop_watch_u, stop_stop_watch_u;
    //     clock_gettime(CLOCK_REALTIME, &start_stop_watch_u);

    //     for (int i = 0; i < numIters; i++) {
    //       as_attestation(isve_eid, argv[argc - 1]);
    //     }

    //     clock_gettime(CLOCK_REALTIME, &stop_stop_watch_u);
    //     unsigned long nanosec = ((unsigned long)((stop_stop_watch_u.tv_sec - start_stop_watch_u.tv_sec) * 1000000 + (stop_stop_watch_u.tv_nsec - start_stop_watch_u.tv_nsec) / 1000));
    //     double secs = (double) nanosec / 1000000;
    //     printf("%f iters/sec (%d iters in %f sec)\n", numIters / secs, numIters, secs);
    // } while(0);

    as_attestation(isve_eid, argv[argc - 1]);
    as_attestation(isve_eid, argv[argc - 1]);
    as_attestation(isve_eid, argv[argc - 1]);
    as_attestation(isve_eid, argv[argc - 1]);
    as_attestation(isve_eid, argv[argc - 1]);

    sgx_destroy_enclave(isve_eid);
    sgx_destroy_enclave(asve_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");
    return 0;
}
