/**
* Author : Brian Batey
*/

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>

extern "C" {
#include "epid/verifier/api.h"
#include "src/verifysig.h"
#include "src/iasVerifyUtils.h"
#include "ext/Opera/opera_types.h"
#include "src/cryptoRsa.h"
}
#define APPNAME "OperaNativeWrapper"

/* Returns 0 on success, any other integer is failure (See documentation)*/
extern "C" JNIEXPORT jint JNICALL
Java_com_example_operaverifierlib_OperaVerifier_epidVerify(
        JNIEnv *env,
        jobject pthis,
        jbyteArray quote,
    	jbyteArray grpVerifCrt,    	
    	jbyteArray privRl,
    	jbyteArray sigRl
	){	

	//Setup Variables
	EpidStatus result = kEpidNoErr;	
	uint8_t *gvc = NULL, *priv_rl = NULL, *sig_rl = NULL, *asquote = NULL;
	int gvc_size, priv_rl_size, sig_rl_size, quote_size = 0, res;
	
	/* Transfer From Java ByteArray to C-Array for Native Operations */

	//GVCert
	gvc_size = env->GetArrayLength(grpVerifCrt);
    gvc = (uint8_t*) (*env).GetByteArrayElements(grpVerifCrt,NULL);	
	
	//PrivRL
	priv_rl_size = (*env).GetArrayLength(privRl);
	priv_rl = (uint8_t*) (*env).GetByteArrayElements(privRl,NULL);	
	
	//SigRL
    sig_rl_size = (*env).GetArrayLength(sigRl);
    sig_rl = (uint8_t*) (*env).GetByteArrayElements(sigRl,NULL);
	
	//Quote
	quote_size = env->GetArrayLength(quote);
    asquote = (uint8_t*) (*env).GetByteArrayElements(quote, NULL); 	
	
	/* Call Verify Function From OPERA verifier library and store result */
	res = Verify(gvc, asquote, sig_rl, sig_rl_size, priv_rl, priv_rl_size);

	/* Release Allocated Arrays */
	env->ReleaseByteArrayElements(grpVerifCrt, (jbyte*)gvc, JNI_ABORT);
	env->ReleaseByteArrayElements(privRl, (jbyte*)priv_rl, JNI_ABORT);
	env->ReleaseByteArrayElements(sigRl, (jbyte*)sig_rl, JNI_ABORT);
	env->ReleaseByteArrayElements(quote, (jbyte*)asquote, JNI_ABORT);

    return res;
}

/*Returns 0 for success , -1 for failure*/
extern "C" JNIEXPORT jint JNICALL
Java_com_example_operaverifierlib_OperaVerifier_checkIasSigSize(
        JNIEnv *env,
        jobject pthis,
        jbyteArray report
	){	

	char* arrayIn = NULL;
	int array_size = 0, ret = 0;	 
	jbyte nativeArray[IAS_SIG_SIZE];

	array_size = env->GetArrayLength(report);
	arrayIn = (char*) (*env).GetByteArrayElements(report, NULL);
	
	/* Decode signature and verify length */
	if(base64_decode(arrayIn, array_size, nativeArray) != IAS_SIG_SIZE){
		ret = -1;
		goto cleanup;
	} 

	/*Cleanup if no errors*/
	goto cleanup;

cleanup:
	/* Release Array */
	env->ReleaseByteArrayElements(report, (jbyte*)arrayIn, JNI_ABORT);	
	return ret;
}

/* Return 0 for success, -1 for failure*/
extern "C" JNIEXPORT jint JNICALL
Java_com_example_operaverifierlib_OperaVerifier_iasRootCACertVerify(
		JNIEnv *env,
		jobject pthis,
		jbyteArray ias_cert,
		jbyteArray root_exp,
		jbyteArray root_mod				
	){

	int output = 0;
	char* ias_arr = (char*) (*env).GetByteArrayElements(ias_cert, NULL);
	unsigned char* root_ca_e = (unsigned char*) (*env).GetByteArrayElements(root_exp,NULL);
	unsigned char* root_ca_n = (unsigned char*) (*env).GetByteArrayElements(root_mod,NULL);

	if(verify_root_ias_rsa_pubKey(ias_arr, root_ca_e, root_ca_n) == 0){	
		output = -1;	
		goto cleanup;
	}	
	
	goto cleanup;

cleanup:
	env->ReleaseByteArrayElements(ias_cert, (jbyte*)ias_arr, JNI_ABORT);
	env->ReleaseByteArrayElements(root_exp, (jbyte*)root_ca_e, JNI_ABORT);
	env->ReleaseByteArrayElements(root_mod, (jbyte*)root_ca_n, JNI_ABORT);
	return output;
}

/*Return 0 for success, -1 for failure*/
extern "C" JNIEXPORT jint JNICALL
Java_com_example_operaverifierlib_OperaVerifier_iasParseAndVerifyRSAPubkey(
		JNIEnv *env,
		jobject pthis,
		jbyteArray ias_cert,
		jbyteArray ias_res,
		jbyteArray ias_sig,
		jbyteArray root_exp			
	){

	int output = 0;

	char* cert = (char*) (*env).GetByteArrayElements(ias_cert, NULL);
	char* res = (char*) (*env).GetByteArrayElements(ias_res, NULL);
	char* sig = (char*) (*env).GetByteArrayElements(ias_sig, NULL);
	unsigned char* root_ca_e = (unsigned char*) (*env).GetByteArrayElements(root_exp,NULL);

	int res_size = env->GetArrayLength(ias_res);
	int sig_size = env->GetArrayLength(ias_sig);
	 
	if(parse_and_verify_ias_pubKey(cert, res, res_size, sig, sig_size, root_ca_e) == 0){
		output = -1;				
		goto cleanup;
	}	
	
	goto cleanup;

cleanup:
	env->ReleaseByteArrayElements(ias_cert, (jbyte*)cert, JNI_ABORT);
	env->ReleaseByteArrayElements(ias_res, (jbyte*)res, JNI_ABORT);
	env->ReleaseByteArrayElements(ias_sig, (jbyte*)sig, JNI_ABORT);	
	env->ReleaseByteArrayElements(root_exp, (jbyte*)root_ca_e, JNI_ABORT);	
	return output;
}


/* Returns 0 on success , -1 on failure */
extern "C" JNIEXPORT jint JNICALL
Java_com_example_operaverifierlib_OperaVerifier_iasParseAndVerifyEnclave(
		JNIEnv *env,
		jobject pthis,
		jbyteArray gv_cert,
		jbyteArray ias_cert,
		jbyteArray as_target_info
	){


	sgx_quote_t quote;
    sgx_report_data_t report_data = {{0}};

	int output = -1;
	uint8_t* msg = (uint8_t*)(*env).GetByteArrayElements(gv_cert, NULL);
	uint8_t* asie_target_info = (uint8_t*)(*env).GetByteArrayElements(as_target_info, NULL);
	char* ias_arr = (char*)(*env).GetByteArrayElements(ias_cert, NULL);

	parse_ias_report(ias_arr, &quote);

	if (sgx_sha256_msg(msg, sizeof(epid_group_certificate_t),
                (sgx_sha256_hash_t*)&report_data) != SGX_SUCCESS) {
       __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "SGX SHA256 HASH FAILED!!!!\n");		
       goto cleanup;
    }

    if(memcmp(&report_data, &quote.report_body.report_data, 32) != 0){
    	__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Quote report data doesn't match SGX report!!\n");
    	goto cleanup;
    }

    if (!verify_enclave(&quote.report_body, (sgx_target_info_t*)asie_target_info)) {
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "ASIE Identity invalid\n");
        goto cleanup;
    }

    output = 0;    
    //__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "IAS PAVE SUCCESS!!!\n"); 
    goto cleanup;

cleanup:
	env->ReleaseByteArrayElements(ias_cert, (jbyte*)ias_arr, JNI_ABORT);
	env->ReleaseByteArrayElements(gv_cert, (jbyte*)msg, JNI_ABORT);
	env->ReleaseByteArrayElements(as_target_info, (jbyte*)asie_target_info, JNI_ABORT);
	return output;
}

/*Returns 0 for success, -1 for failure*/
extern "C" JNIEXPORT jint JNICALL
Java_com_example_operaverifierlib_OperaVerifier_verifyRlHashes(
		JNIEnv *env,
		jobject pthis,
		jbyteArray gv_cert,
		jbyteArray privRl,
		jbyteArray sigRl	
	){

	int output = 0, prl_size = 0, srl_size = 0;
	char* gvc = (char*) (*env).GetByteArrayElements(gv_cert, NULL);

	uint8_t* priv_rl = (uint8_t*) (*env).GetByteArrayElements(privRl, NULL);
	uint8_t* sig_rl = (uint8_t*) (*env).GetByteArrayElements(sigRl, NULL);

	prl_size = env->GetArrayLength(privRl);
	srl_size = env->GetArrayLength(sigRl);
	
	if(verify_revoc_list_hashes((epid_group_certificate_t*) gvc, priv_rl, prl_size,
        sig_rl, srl_size) == 0){
		output = -1;
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "REVOC LIST HASH VERFICATION FAILED!!!\n");		
		goto cleanup;
	}

	goto cleanup;

cleanup:
	env->ReleaseByteArrayElements(gv_cert, (jbyte*)gvc, JNI_ABORT);
	env->ReleaseByteArrayElements(privRl, (jbyte*)priv_rl, JNI_ABORT);
	env->ReleaseByteArrayElements(sigRl, (jbyte*)sig_rl, JNI_ABORT);

	return output;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_example_operaverifierlib_OperaVerifier_parseAndVerifyTS(
		JNIEnv *env,
		jobject pthis,
		jbyteArray gv_cert,
		jbyteArray ias_res,
		jbyteArray quote,
		jbyteArray tsIn	
	){

	int output = 0, prl_size = 0, srl_size = 0;

	char* iasRes = (char*) (*env).GetByteArrayElements(ias_res, NULL);
	
	epid_group_certificate_t* gvc = (epid_group_certificate_t*) (*env).GetByteArrayElements(gv_cert, NULL);
	opera_quote_t* operaQuote = (opera_quote_t*) (*env).GetByteArrayElements(quote, NULL);
	
	uint8_t* curr_ts = (uint8_t*)(*env).GetByteArrayElements(tsIn,NULL);
	uint8_t tmp_ts[AS_TS_SIZE];
	
 	parse_ias_report_ts(iasRes, tmp_ts);
    
    if (0 != memcmp(curr_ts, tmp_ts, AS_TS_SIZE) ||
            0 != memcmp(curr_ts, gvc->asie_ts, AS_TS_SIZE) ||
            0 != memcmp(curr_ts, (opera_quote_t*)operaQuote->asae_ts, AS_TS_SIZE)) {

        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Timestamps not up-to-date\n");
    	output = -1;
        goto cleanup;
    }
		
	goto cleanup;

cleanup:
	env->ReleaseByteArrayElements(gv_cert, (jbyte*)gvc, JNI_ABORT);
	env->ReleaseByteArrayElements(ias_res, (jbyte*)iasRes, JNI_ABORT);
	env->ReleaseByteArrayElements(quote, (jbyte*)operaQuote, JNI_ABORT);
	env->ReleaseByteArrayElements(tsIn, (jbyte*)curr_ts, JNI_ABORT);

	return output;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_example_operaverifierlib_OperaVerifier_getTimeGMT(
		JNIEnv *env,
		jobject pthis
		){

		jbyteArray timeOut = env->NewByteArray(AS_TS_SIZE+1);
		char cur_ts[AS_TS_SIZE+1];

		get_current_gmt_time(cur_ts, AS_TS_SIZE + 1);

		env->SetByteArrayRegion(timeOut, 0, AS_TS_SIZE + 1, (jbyte*)cur_ts);

		return timeOut;
}

/*Returns 0 for success, -1 for failure*/
extern "C" JNIEXPORT jint JNICALL
Java_com_example_operaverifierlib_OperaVerifier_verifyPSEStatus(
		JNIEnv *env,
		jobject pthis,
		jbyteArray quote
		){

		int output = 0;
		opera_quote_t* operaQuote = (opera_quote_t*) (*env).GetByteArrayElements(quote, NULL);

		if (operaQuote->pse_status != 0) {
        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Bad trusted platform service status\n");
        output = -1;
        goto cleanup;
    	}    	

    	goto cleanup;

cleanup:
	env->ReleaseByteArrayElements(quote, (jbyte*)operaQuote, JNI_ABORT);
	return output;
}