#include "WebService.h"
#include "../GeneralSettings.h"

WebService* WebService::instance = NULL;

WebService::WebService() {}

WebService::~WebService() {
    if (curl)
        curl_easy_cleanup(curl);
}


WebService* WebService::getInstance() {
    if (instance == NULL) {
        instance = new WebService();
    }

    return instance;
}


void WebService::init() {
    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();

    if (curl) {
        printf("Curl initialized successfully\n");
//		curl_easy_setopt( curl, CURLOPT_VERBOSE, 1L );
        curl_easy_setopt( curl, CURLOPT_SSLCERTTYPE, "PEM");
        curl_easy_setopt( curl, CURLOPT_SSLCERT, Settings::ias_crt);
        curl_easy_setopt( curl, CURLOPT_SSLKEY, Settings::ias_key);
        curl_easy_setopt( curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
        curl_easy_setopt( curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
        curl_easy_setopt( curl, CURLOPT_NOPROGRESS, 1L);
    } else
        printf("Curl init error\n");
}


vector<pair<string, string>> WebService::parseJSONfromIAS(string json) {
    Json::Value root;
    Json::Reader reader;
    bool parsingSuccessful = reader.parse(json.c_str(), root);

    if (!parsingSuccessful) {
        printf("Failed to parse JSON string from IAS\n");
        return vector<pair<string, string>>();
    }

    vector<pair<string,string>> values;

    string id = root.get("id", "UTF-8" ).asString();
    string timestamp = root.get("timestamp", "UTF-8" ).asString();
    string epidPseudonym = root.get("epidPseudonym", "UTF-8" ).asString();
    string isvEnclaveQuoteStatus = root.get("isvEnclaveQuoteStatus", "UTF-8" ).asString();

    values.push_back({"id", id});
    values.push_back({"timestamp", timestamp});
    values.push_back({"epidPseudonym", epidPseudonym});
    values.push_back({"isvEnclaveQuoteStatus", isvEnclaveQuoteStatus});

    return values;
}


string WebService::createJSONforIAS(uint8_t *quote, uint8_t *pseManifest, uint8_t *nonce) {
    Json::Value request;

    request["isvEnclaveQuote"] = Base64encodeUint8(quote, 1116);
    if (pseManifest) request["pseManifest"] = Base64encodeUint8(pseManifest, 256);

    Json::FastWriter fastWriter;
    string output = fastWriter.write(request);

    return output;
}


size_t ias_response_header_parser(void *ptr, size_t size, size_t nmemb, void *userdata) {
    int parsed_fields = 0, response_status, content_length, ret = size * nmemb;

    char *x = (char*) calloc(size+1, nmemb);
    assert(x);
    memcpy(x, ptr, size * nmemb);
    // printf("ias response x: [%s]", x);
    parsed_fields = sscanf( x, "HTTP/1.1 %d", &response_status );

    if (parsed_fields == 1) {
        ((ias_response_header_t *) userdata)->response_status = response_status;
        return ret;
    }

    parsed_fields = sscanf( x, "content-length: %d", &content_length );
    if (parsed_fields == 1) {
        ((ias_response_header_t *) userdata)->content_length = content_length;
        return ret;
    }

    char *p_request_id = (char*) calloc(1, REQUEST_ID_MAX_LEN);
    parsed_fields = sscanf(x, "request-id: %s", p_request_id );

    if (parsed_fields == 1) {
        std::string request_id_str( p_request_id );
        ( ( ias_response_header_t * ) userdata )->request_id = request_id_str;
        //if (p_request_id) free(p_request_id);
        return ret;
    }
    //if (p_request_id) free(p_request_id);

    char *p_x_iasreport_signature = (char*) calloc(1, X_IASREPORT_SIGNATURE_MAX_LEN);
    parsed_fields = sscanf(x, "x-iasreport-signature: %s", p_x_iasreport_signature );

    if (parsed_fields == 1) {
        std::string x_iasreport_signature_str( p_x_iasreport_signature );
        ( ( ias_response_header_t * ) userdata )->x_iasreport_signature = x_iasreport_signature_str;
        //if (p_x_iasreport_signature) free(p_x_iasreport_signature);
        return ret;
    }
    //if (p_x_iasreport_signature) free(p_x_iasreport_signature);
        
    char *p_x_iasreport_signing_certificate = (char*) calloc(1, X_IASREPORT_SIGNING_CERTIFICATE_MAX_LEN);
    parsed_fields = sscanf(x, "x-iasreport-signing-certificate: %s", p_x_iasreport_signing_certificate );

    if (parsed_fields == 1) {
        std::string x_iasreport_signing_certificate_str( p_x_iasreport_signing_certificate );
        ( ( ias_response_header_t * ) userdata )->x_iasreport_signing_certificate = x_iasreport_signing_certificate_str;
        //if (p_x_iasreport_signing_certificate) free(p_x_iasreport_signing_certificate);
        return ret;
    }
    //if (p_x_iasreport_signing_certificate) free(p_x_iasreport_signing_certificate);



    return ret;
}


size_t ias_reponse_body_handler( void *ptr, size_t size, size_t nmemb, void *userdata ) {
    size_t realsize = size * nmemb;
    ias_response_container_t *ias_response_container = ( ias_response_container_t * ) userdata;
    ias_response_container->p_response = (char *) realloc(ias_response_container->p_response, ias_response_container->size + realsize + 1);

    if (ias_response_container->p_response == NULL ) {
        printf("Unable to allocate extra memory");
        return 0;
    }
    // printf("RESPONSE[%s]", (char*) ptr);
    memcpy( &( ias_response_container->p_response[ias_response_container->size]), ptr, realsize );
    ias_response_container->size += realsize;
    ias_response_container->p_response[ias_response_container->size] = 0;

    return realsize;
}


bool WebService::sendToIAS(string url,
                           IAS type,
                           string payload,
                           struct curl_slist *headers,
                           ias_response_container_t *ias_response_container,
                           ias_response_header_t *response_header) {

    CURLcode res = CURLE_OK;

    curl_easy_setopt( curl, CURLOPT_URL, url.c_str());

    if (headers) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    }

    ias_response_container->p_response = (char*) malloc(1);
    ias_response_container->size = 0;

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, ias_response_header_parser);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, response_header);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ias_reponse_body_handler);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, ias_response_container);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return false;
    }

    return true;
}


bool WebService::getSigRL(string gid, string *sigrl) {
    printf("Retrieving SigRL from IAS\n");

    //check if the sigrl for the gid has already been retrieved once -> to save time
    for (auto x : retrieved_sigrl) {
        if (x.first == gid) {
            *sigrl = x.second;
            return false;
        }
    }

    ias_response_container_t ias_response_container;
    ias_response_header_t response_header;

    string url = Settings::ias_url + "sigrl/" + gid;

    this->sendToIAS(url, IAS::sigrl, "", NULL, &ias_response_container, &response_header);

    printf("\tResponse status is: %d\n" , response_header.response_status);
    printf("\tContent-Length: %d\n", response_header.content_length);

    if (response_header.response_status == 200) {
        if (response_header.content_length > 0) {
            string response(ias_response_container.p_response);
            *sigrl = Base64decode(response);
        }
        retrieved_sigrl.push_back({gid, *sigrl});
    } else
        return true;

    return false;
}


bool WebService::verifyQuote(uint8_t *quote, uint8_t *pseManifest, uint8_t *nonce, vector<pair<string, string>> *result) {
    string encoded_quote = this->createJSONforIAS(quote, pseManifest, nonce);

    ias_response_container_t ias_response_container;
    ias_response_header_t response_header;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    string payload = encoded_quote;

    string url = Settings::ias_url + "report";
    this->sendToIAS(url, IAS::report, payload, headers, &ias_response_container, &response_header);


    if (response_header.response_status == 200) {
        // printf("Quote attestation successful, new report has been created\n");

        string response(ias_response_container.p_response);
        // printf("IAS response {%s}", response.c_str());

        // auto res = parseJSONfromIAS(response);
        
        (*result).push_back({"raw_res", response});
        (*result).push_back({"ias_sig", response_header.x_iasreport_signature});

        char *decoded = curl_easy_unescape(curl, response_header.x_iasreport_signing_certificate.c_str(), 0, NULL);
        string ias_crt(decoded);
        (*result).push_back({"ias_crt", ias_crt});
        curl_free(decoded);




    } else {
        printf("Quote attestation returned status: %d\n", response_header.response_status);
        return true;
    }

    return false;
}




