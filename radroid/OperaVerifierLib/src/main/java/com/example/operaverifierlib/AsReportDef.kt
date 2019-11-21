package com.example.operaverifierlib

data class ReportElement(val name: String){
    var eleData= ByteArray(0)
    var eleSize: Int = 0
}

// Kotlin Version of ASReport

class AttestationReport{

    //AS Report Members
    var quote = ReportElement("opera_quote")
    var grpVerifCert = ReportElement("gv_cert")
    var gvcIasRes = ReportElement("ias_report")
    var gvcIasSig = ReportElement("ias_signature")
    var gvcIasCrt = ReportElement("ias_cert")
    var privRL = ReportElement("priv_key_rev_list")
    var sigRL = ReportElement("sig_rev_list")
    var currTS = ReportElement("currTS")

    //Setters
    fun setQuoteData(qData: ByteArray){
        this.quote.eleData = qData
    }

    fun setQuoteSize(qSize:Int){
        this.quote.eleSize = qSize
    }

    fun setGrpVerifCertData(qData: ByteArray){
        this.grpVerifCert.eleData = qData
    }

    fun setGrpVerifCertSize(qSize:Int){
        this.grpVerifCert.eleSize = qSize
    }

    fun setGvcIasResData(qData: ByteArray){
        this.gvcIasRes.eleData = qData
    }

    fun setGvcIasResSize(qSize:Int){
        this.gvcIasRes.eleSize = qSize
    }

    fun setGvcIasSigData(qData: ByteArray){
        this.gvcIasSig.eleData = qData
    }

    fun setGvcIasSigSize(qSize:Int){
        this.gvcIasSig.eleSize = qSize
    }

    fun setGvcIasCrtData(qData: ByteArray){
        this.gvcIasCrt.eleData = qData
    }

    fun setGvcIasCrtSize(qSize:Int){
        this.gvcIasCrt.eleSize = qSize
    }

    fun setPrivRLData(qData: ByteArray){
        this.privRL.eleData = qData
    }

    fun setPrivRLSize(qSize:Int){
        this.privRL.eleSize = qSize
    }

    fun setSigRLData(qData: ByteArray){
        this.sigRL.eleData = qData
    }

    fun setSigRLSize(qSize:Int){
        this.sigRL.eleSize = qSize
    }

    fun setCurrTS(qData: ByteArray){
        this.currTS.eleData = qData
    }

    fun setCurrTSSize(qSize: Int){
        this.currTS.eleSize = qSize
    }

    //Getters
    fun getQuoteData() : ByteArray{
        return this.quote.eleData
    }

    fun getQuoteSize() : Int{
        return this.quote.eleSize
    }

    fun getGrpVerifCertData() : ByteArray{
        return this.grpVerifCert.eleData
    }

    fun getGrpVerifCertSize() : Int{
        return this.grpVerifCert.eleSize
    }

    fun getGvcIasResData() : ByteArray{
        return this.gvcIasRes.eleData
    }

    fun getGvcIasResSize() : Int{
        return this.gvcIasRes.eleSize
    }

    fun getGvcIasSigData() : ByteArray{
        return this.gvcIasSig.eleData
    }

    fun getGvcIasSigSize() : Int{
        return this.gvcIasSig.eleSize
    }

    fun getGvcIasCrtData() : ByteArray{
        return this.gvcIasCrt.eleData
    }

    fun getGvcIasCrtSize() : Int{
        return this.gvcIasCrt.eleSize
    }

    fun getPrivRLData() : ByteArray{
        return this.privRL.eleData
    }

    fun getPrivRLSize() : Int{
        return this.privRL.eleSize
    }

    fun getSigRLData() : ByteArray{
        return this.sigRL.eleData
    }

    fun getSigRLSize() : Int{
        return this.sigRL.eleSize
    }

    fun getCurrTS():ByteArray{
        return this.currTS.eleData
    }

    fun getCurrTSSize():Int{
       return this.currTS.eleSize
    }
}