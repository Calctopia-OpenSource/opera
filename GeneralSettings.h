#ifndef GENERALSETTINGS_H
#define GENERALSETTINGS_H

#include <string>

using namespace std;

namespace Settings {
	static string spid = "83D1AEEDDA65BD35FA4809128D84AC2F"; //SPID provided by Intel after registration for the IAS service
	static const char *ias_crt = "server.crt"; //location of the certificate send to Intel when registring for the IAS
	static const char *ias_key = "server.key";
	static string ias_url = "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v2/";
}

#endif
