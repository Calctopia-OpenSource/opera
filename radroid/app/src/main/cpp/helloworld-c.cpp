//TODO: rework includes during library separations

#include <jni.h>
#include <string>
extern "C" {
#include "../../../include/verifysig.h"
}
#include "helloworld-c.h"
/*#include "epid_endian_convert.h"
#include "epid_memory.cpp"
#include "epid_verifier_api.h"
#include "ipp_wrapper.h"*/

/*
void get_current_gmt_time(char *ts, size_t len)
{
    struct tm *gtime;
    time_t now;

 Read the current system time

    time(&now);

 Convert the system time to GMT (now UTC)

    gtime = gmtime(&now);

    snprintf(ts, len, "%4d-%02d-%02dT%2d:%02d:%02d\n", gtime->tm_year + 1900,
             gtime->tm_mon + 1, gtime->tm_mday, gtime->tm_hour,
             gtime->tm_min, gtime->tm_sec);
}
*/

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_radroidalpha_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject pthis
 ){
    std::string hello = "Hello from C++";
    GroupPubKey pub = {0};
    Verify(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,pub);
    return env->NewStringUTF(hello.c_str());
}
/*

extern "C" JNIEXPORT jint JNICALL
Java_com_example_radroidalpha_MainActivity_verifyQuote(
    JNIEnv *env,
    jobject
this
,
    jbyteArray quote,
    jbyteArray grpVerifCrt,
    jbyteArray iasRes,
    jbyteArray iasSig,
    jbyteArray iasCrt,
    jbyteArray privRl,
    jbyteArray sigRl
    ){
        //Create temp/time variables
        jbyte *quotePtr, *gvCertPtr, *iasResPtr, *iasSigPtr, *iasCrtPtr, *privRLPtr, *sigRlPtr;
        char cur_ts[AS_TS_SIZE + 1];
        as_report_t asReport;

        //Copy byte arrays for native use
        quotePtr = (*env).GetByteArrayElements(quote,0);
        gvCertPtr = (*env).GetByteArrayElements(grpVerifCrt,0);
        iasResPtr = (*env).GetByteArrayElements(iasRes,0);
        iasSigPtr = (*env).GetByteArrayElements(iasSig,0);
        iasCrtPtr = (*env).GetByteArrayElements(iasCrt, 0);
        privRLPtr = (*env).GetByteArrayElements(privRl, 0);
        sigRlPtr = (*env).GetByteArrayElements(sigRl, 0);
        privRLPtr = (*env).GetByteArrayElements(privRl, 0);

        asReport.quote = (opera_quote_t*)quotePtr;
        asReport.gv_cert = (epid_group_certificate_t*)gvCertPtr;
        asReport.ias_response = iasResPtr;

        //Get Timestamp for Verification
        get_current_gmt_time(cur_ts, AS_TS_SIZE + 1);

        //Run Verifier

        //Release Arrays
        (*env).ReleaseByteArrayElements(quote, quotePtr,JNI_ABORT);
        (*env).ReleaseByteArrayElements(grpVerifCrt, gvCertPtr, JNI_ABORT);
        (*env).ReleaseByteArrayElements(iasRes, iasResPtr, JNI_ABORT);
        (*env).ReleaseByteArrayElements(iasSig, iasSigPtr,JNI_ABORT);
        (*env).ReleaseByteArrayElements(iasCrt, iasCrtPtr, JNI_ABORT);
        (*env).ReleaseByteArrayElements(privRl, privRLPtr, JNI_ABORT);
        (*env).ReleaseByteArrayElements(sigRl, sigRlPtr, JNI_ABORT);
        (*env).ReleaseByteArrayElements(privRl, privRLPtr, JNI_ABORT);
        return 0;
    }
*/
//
////Copy byte arrays for native use
//quotePtr = (*env).GetByteArrayElements(quote,0);
//gvCertPtr = (*env).GetByteArrayElements(grpVerifCrt,0);
//iasResPtr = (*env).GetByteArrayElements(iasRes,0);
//iasSigPtr = (*env).GetByteArrayElements(iasSig,0);
//iasCrtPtr = (*env).GetByteArrayElements(iasCrt, 0);
//privRLPtr = (*env).GetByteArrayElements(privRl, 0);
//sigRlPtr = (*env).GetByteArrayElements(sigRl, 0);
//privRLPtr = (*env).GetByteArrayElements(privRl, 0);
//
//asReport.quote = (opera_quote_t*)quotePtr;
//asReport.gv_cert = (epid_group_certificate_t*)gvCertPtr;
//asReport.ias_response.str = (char*)iasResPtr;
//asReport.ias_signature.str = (char*)iasSigPtr;
//asReport.ias_certificate.str = (char*)iasCrtPtr;
//asReport.priv_rl.revoc_list = (PrivRl*)privRLPtr;
//asReport.sig_rl.revoc_list = (SigRl*)sigRlPtr;
//
//
////Get Timestamp for Verification
//get_current_gmt_time(cur_ts, AS_TS_SIZE + 1);
