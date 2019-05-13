#include "sample_app.h"

sgx_enclave_id_t isve_eid = 0;

/* OCall functions for enclave */
void ocall_print_string(const char *str)
{
    printf("%s", str);
}

sgx_report_t* generate_report(const uint8_t* msg, uint32_t msglen)
{
    sgx_report_t *isve_report = NULL;
    uint32_t enclave_ret;

    if ((isve_report = (sgx_report_t*)malloc(sizeof(sgx_report_t))) == NULL) {
        ERROR("Failed to allocated size for isve_report\n");
        return NULL;
    }

    if (isve_gen_report(isve_eid, &enclave_ret, msg, msglen,
                (sgx_target_info_t*)asae_target_info, isve_report)
            != SGX_SUCCESS || enclave_ret != SGX_SUCCESS) {
        ERROR("Failed to generate report\n");
        free(isve_report);
        return NULL;
    }

    return isve_report;
}

int SGX_CDECL main(int argc, char *argv[])
{
    if (argc < 3) {
        printf("USAGE: %s <AS Port> <RemoteAttestListeningPort>\n", argv[0]);
        return -1;
    }

    sgx_launch_token_t isve_token = {0};
    uint32_t ret;
    int isve_updated = 0;
    uint16_t port = 0;
    char * p_end;
    port = (uint16_t)strtol(argv[2], &p_end, 10);
    if (*p_end != '\0' || strlen(argv[2]) == 0) {
        ERROR("Invalid port number: %s\n", argv[2]);
        return -1;
    }

    if ((ret = sgx_create_enclave(ISVE_ENCLAVE_FILENAME, SGX_DEBUG_FLAG,
                &isve_token, &isve_updated, &isve_eid, NULL)) != SGX_SUCCESS) {
        ERROR("Failed creating isve %x\n", ret);
        return -1;
    }
    DEBUG_PRINT("Created %s successfully\n", ISVE_ENCLAVE_FILENAME);

    if(start_remote_attest_server(argv[1], port, generate_report) != 0) {
        ERROR("Failed using remote attest server\n");
    }

    if (sgx_destroy_enclave(isve_eid) == SGX_SUCCESS) {
        DEBUG_PRINT("%s successfully destroyed\n", ISVE_ENCLAVE_FILENAME);
    }
    return 0;
}
