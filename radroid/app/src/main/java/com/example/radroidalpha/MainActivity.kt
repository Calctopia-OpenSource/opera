package com.example.radroidalpha
import android.annotation.SuppressLint
import android.os.AsyncTask
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.view.View
import android.widget.Toast
import com.example.operaverifierlib.*
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    private var operaVerifier = OperaVerifier()

    private fun errorToast(){
        Toast.makeText(applicationContext,"Verification Failed!!!", Toast.LENGTH_SHORT).show()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
    }

    @SuppressLint("ShowToast")
    fun getServerInfo(view:View){

        /* Retrieve User Input from EditText entries */
        val isvIpAddr = IPEntry.text.toString()
        val isvPortNum = PortEntry.text.toString()

        /*Create Toaster for UI reporting in external thread*/
        val socketToast = Toast.makeText(applicationContext, "", Toast.LENGTH_SHORT)

        /* Get Current Time Stamp*/
        operaVerifier.setReportTS()

        /* Connect to ISV and Retrieve Attestation Report */
        val isvSocket = OperaSocket(isvIpAddr, isvPortNum, operaVerifier.getReport(), socketToast)
        isvSocket.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR)
    }

    fun verifyOperaQuote(view:View){

        if (operaVerifier.checkIasResponseStatus() != 0){
            println("BAD PSE MANIFEST")
            errorToast()
            return
        }

        if(operaVerifier.verifyIasReport() != 0) {
            println("IAS VERIFICATION FAILED!")
            errorToast()
            return
        }

        if(operaVerifier.verifyRevListHashes() != 0){
            println("REVOCATION LIST HASH VERIFICATION FAILED!!!")
            errorToast()
            return
        }

        if(operaVerifier.getPSEStatus()!=0){
            println("BAD PSE STATUS!!")
            errorToast()
            return
        }

        if(operaVerifier.verifyTimeStamps()!=0){
            println("INVALID TIME STAMP!!!")
            errorToast()
            return
        }

        when(val retCode = operaVerifier.verifyEpidSig()){
            0 -> Toast.makeText(applicationContext,"Verification Success!!!", Toast.LENGTH_SHORT).show()
            else -> {
                println("EPID VERIFICATION FAILED")
                println("ERROR CODE: $retCode")
                errorToast()
                return
            }
        }
    }
}
