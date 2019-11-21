/**
 *  Created by: Brian Batey
 */

package com.example.operaverifierlib
import java.nio.charset.Charset

private const val PSE_STATUS_ATTRIB = "pseManifestStatus"
private const val JSON_TERM = "\""
private const val JSON_SEP = "\":\""
private const val JSON_SUCCESS = "OK"

class OperaVerifier{

    init{
        System.loadLibrary("OperaVerifier")
    }

    /* Report Storage */
    private var asReport = AttestationReport()

    /* JNI Imported Functions */
    private external fun epidVerify(quote :ByteArray, grpVerifCrt :ByteArray, privRl :ByteArray, sigRl :ByteArray):Int
    private external fun checkIasSigSize(report :ByteArray):Int
    private external fun iasRootCACertVerify(iasCert :ByteArray, root_exp: ByteArray, root_mod: ByteArray):Int
    private external fun iasParseAndVerifyRSAPubkey(ias_cert: ByteArray, ias_res: ByteArray, ias_sig: ByteArray, root_exp: ByteArray): Int
    private external fun iasParseAndVerifyEnclave(gv_cert:ByteArray, ias_cert:ByteArray, asie_target_info:ByteArray):Int
    private external fun verifyRlHashes(gv_cert: ByteArray, privRl: ByteArray, sigRl: ByteArray):Int
    private external fun parseAndVerifyTS(gv_cert: ByteArray, ias_res: ByteArray, quote: ByteArray, tsIn: ByteArray):Int
    private external fun getTimeGMT():ByteArray
    private external fun verifyPSEStatus(quote :ByteArray):Int

    /* Internal Functions */
    private fun getJsonValue(str: String, attrib: String):Int{
        /* Check "str" for given attribute value with separator attached*/
        if(!str.contains(attrib + JSON_SEP)){
            return -1
        }

        /* Get index values */
        val headIndex = str.indexOf(attrib) + attrib.length + JSON_SEP.length
        val tailIndex = str.indexOf(JSON_TERM, headIndex)

        /* Extract data from JSON*/
        val jsonVal = str.substring(headIndex, tailIndex)
        if(jsonVal!=(JSON_SUCCESS)) {
            return -1
        }
        return 0
    }

    @Suppress("SENSELESS_COMPARISON", "FoldInitializerAndIfToElvis")
    private fun isIasReportValid(asReport: AttestationReport, debug: Boolean = false):Int{
        /* Ensure Ias reports aren't empty */
        if(asReport.getGvcIasResSize() == 0 || asReport.getGvcIasCrtSize() == 0 || asReport.getGvcIasSigSize() == 0){
            if(debug) {
                println("An IAS report is Empty!!!")
            }
            return -1
        }
        if(debug) {
            println("IAS Report State OK!")
        }

        /* Check for Valid IAS signature size after decoding */
        if(checkIasSigSize(asReport.getGvcIasSigData()) != 0) {
            if(debug) {
                println("IAS Signature Size Invalid")
            }
            return -1
        }
        if(debug) {
            println("IAS Sig Size OK!")
        }

        /* Verify with Root CA RSA Public Key */
        if(iasRootCACertVerify(asReport.getGvcIasCrtData(), ias_root_ca_e, ias_root_ca_n) != 0){
            if(debug) {
                println("ROOT CA RSA VERIFICATION FAILED!!!")
            }
            return -1
        }
        if(debug) {
            println("ROOT CA Public Key OK!!!")
        }

        /*Verify using parsed exponent and sig from IAS report*/
        if(iasParseAndVerifyRSAPubkey(asReport.getGvcIasCrtData(), asReport.getGvcIasResData(), asReport.getGvcIasSigData(), ias_root_ca_e) != 0){
            if(debug) {
                print("IAS RSA Public Key ERROR!!!")
            }
            return -1
        }
        if(debug) {
            println("IAS Parsed Public Key OK!!!")
        }
        return 0
    }

    private fun getCurrTime():ByteArray{
        return getTimeGMT()
    }

    /* Public Functions */
    fun verifyEpidSig() :Int{
        return epidVerify(this.asReport.getQuoteData(),this.asReport.getGrpVerifCertData(),this.asReport.getPrivRLData(), this.asReport.getSigRLData())
    }

    fun checkIasResponseStatus(): Int{
        val iasString = this.asReport.getGvcIasResData().toString(Charset.defaultCharset())
        return getJsonValue(iasString, PSE_STATUS_ATTRIB)
    }

    fun verifyIasReport() : Int{
        if (isIasReportValid(this.asReport) != 0) {
            return -1
        }

        if(iasParseAndVerifyEnclave(asReport.getGrpVerifCertData(),asReport.getGvcIasResData(), asie_target_info) != 0){
            return -1
        }
        return 0
    }

    fun verifyRevListHashes(debug: Boolean = false): Int{
        if(verifyRlHashes(this.asReport.getGrpVerifCertData(), this.asReport.getPrivRLData(), this.asReport.getSigRLData()) != 0){
            return -1
        }
        if(debug) {
            println("RL HASHES VERIFIED!!!")
        }
        return 0
    }

    fun getPSEStatus(debug: Boolean = false): Int{
        if(verifyPSEStatus(this.asReport.getQuoteData()) != 0){
            return -1
        }
        if(debug) {
            println("PSE OK!!!")
        }
        return 0
    }

    fun verifyTimeStamps(debug: Boolean = false):Int{
        if(parseAndVerifyTS(this.asReport.getGrpVerifCertData(), this.asReport.getGvcIasResData(), this.asReport.getQuoteData(), this.asReport.getCurrTS()) != 0){
            return -1
        }
        if(debug) {
            println("TIMESTAMPS OK!!!!")
        }
        return 0
    }

    fun getReport() : AttestationReport{
        return this.asReport
    }

    fun setReportTS(){
        this.asReport.setCurrTS(this.getCurrTime())
    }
 }