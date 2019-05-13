#ifndef WEBSERVICE_H
#define WEBSERVICE_H

#include <string>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>
#include <curl/curl.h>
#include <jsoncpp/json/json.h>
#include <iostream>

// #include "../Util/LogBase.h"
#include "../Util/UtilityFunctions.h"

using namespace std;

enum IAS {
    sigrl,
    report
};

struct attestation_verification_report_t {
    string report_id;
    string isv_enclave_quote_status;
    string timestamp;
};

struct attestation_evidence_payload_t {
    string isv_enclave_quote;
};

struct ias_response_header_t {
    int response_status;
    int content_length;
    std::string request_id;
    std::string x_iasreport_signature;
    std::string x_iasreport_signing_certificate;
};

struct ias_response_container_t {
    char *p_response;
    size_t size;
};

static int REQUEST_ID_MAX_LEN = 32;
static int X_IASREPORT_SIGNATURE_MAX_LEN = 512;
static int X_IASREPORT_SIGNING_CERTIFICATE_MAX_LEN = 8192;
static vector<pair<string, string>> retrieved_sigrl;

class WebService {

public:
    WebService();
    static WebService* getInstance();
    virtual ~WebService();
    void init();
    bool getSigRL(string gid, string *sigrl);
    bool verifyQuote(uint8_t *quote, uint8_t *pseManifest, uint8_t *nonce, vector<pair<string, string>> *result);

private:
    bool sendToIAS(string url, IAS type, string payload,
                   struct curl_slist *headers,
                   ias_response_container_t *ias_response_container,
                   ias_response_header_t *response_header);

    string createJSONforIAS(uint8_t *quote, uint8_t *pseManifest, uint8_t *nonce);
    vector<pair<string, string>> parseJSONfromIAS(string json);

private:
    static WebService* instance;
    CURL *curl;
};

#endif



