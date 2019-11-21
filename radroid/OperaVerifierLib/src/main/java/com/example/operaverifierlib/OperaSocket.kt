/**
 *  Created by: Brian Batey
 */

package com.example.operaverifierlib
import android.os.AsyncTask
import android.widget.Toast
import java.io.*
import java.net.InetAddress
import java.net.Socket
import java.net.SocketException
import java.nio.ByteBuffer
import kotlin.random.Random

private const val INTSIZE = 4  //NOT GUARANTEED FOR ALL SYSTEMS
private const val MSGSIZE = 1028 //Sets Message Length for Challenge Message

/**
 * Socket Connection Class - used to connect to the ISV through TCP/IP.
 *
 *  @param ipaddr] *      A string representing IP address or URL of the client server (ISV)
 *  @param portNum] *     A string representing the port number to use
 *  @param report] *      An empty ASReport object for storing the outgoing report retrieved from the ISV
 */

class OperaSocket(ipaddr:String, portNum: String, report: AttestationReport, toastUI: Toast) : AsyncTask<Void, Void, Int>() {

    private val serverIp = ipaddr
    private val portNumb = portNum
    private var asReport = report
    private val extToast = toastUI

    override fun doInBackground(vararg params: Void?): Int {

        // Create Socket Connection and Setup I/O Streams
        val servIP = InetAddress.getByName(serverIp)
        try {
            val clientConn = Socket(servIP, portNumb.toInt())
            val dStreamIn = DataInputStream(clientConn.getInputStream())
            val dStrmOut = DataOutputStream(clientConn.getOutputStream())

            // Create PseudoRandom Challenge Message
            val cmesg = Random.Default.nextBytes(MSGSIZE)

            //Send Challenge Message using Output Stream
            dStrmOut.write(MSGSIZE)
            dStrmOut.write(cmesg)

            // Receive Quote for Local Verification using Input Stream
            receiveQuote(dStreamIn)

            // Close connection
            clientConn.close()

        }catch(e : SocketException){
            extToast.setText("ISV Get Report Failed!!!")
            extToast.show()
            return -1
        }
        extToast.setText("ISV Get Report Success!!!")
        extToast.show()
        return 0
    }

    private fun receiveElementAndSize(dStrm: DataInputStream): Pair<Int,ByteArray>{

        //Create an Int Sized array
        val elementArray = ByteArray(INTSIZE)
        dStrm.readFully(elementArray)

        // Swap Endianness
        val elementArrayEndSwp = endianChange(elementArray)

        // Convert to an Int for the Size of the Receive Buffer
        val eleSize = ByteBuffer.wrap(elementArrayEndSwp).int

        // Create a ByteArray of the Size Specified by the Sender
        val arrayOut = ByteArray(eleSize)

        //Read "Size" bytes from the dataStream
        dStrm.readFully(arrayOut)
        return Pair(eleSize, arrayOut)
    }

    private fun endianChange(arrayIn: ByteArray): ByteArray {
        val length = arrayIn.size
        val output = ByteArray(length)
        for (i in 0 until length) {
            output[length - i - 1] = arrayIn[i]
        }
        return output
    }

    private fun receiveQuote(dStreamIn: DataInputStream){
        var retPair = receiveElementAndSize(dStreamIn)
        asReport.setQuoteSize(retPair.first)
        asReport.setQuoteData(retPair.second.copyOf())

        retPair = receiveElementAndSize(dStreamIn)
        asReport.setGrpVerifCertSize(retPair.first)
        asReport.setGrpVerifCertData(retPair.second.copyOf())

        retPair = receiveElementAndSize(dStreamIn)
        asReport.setGvcIasResSize(retPair.first)
        asReport.setGvcIasResData(retPair.second.copyOf())

        retPair = receiveElementAndSize(dStreamIn)
        asReport.setGvcIasSigSize(retPair.first)
        asReport.setGvcIasSigData(retPair.second.copyOf())

        retPair = receiveElementAndSize(dStreamIn)
        asReport.setGvcIasCrtSize(retPair.first)
        asReport.setGvcIasCrtData(retPair.second.copyOf())

        retPair = receiveElementAndSize(dStreamIn)
        asReport.setPrivRLSize(retPair.first)
        asReport.setPrivRLData(retPair.second.copyOf())

        retPair = receiveElementAndSize(dStreamIn)
        asReport.setSigRLSize(retPair.first)
        asReport.setSigRLData(retPair.second.copyOf())
    }
}


