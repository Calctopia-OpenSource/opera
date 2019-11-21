### OPERA Socket  

`OperaSocket.kt`

The OPERA socket class is an example socket class that follows the protocols necessary to communicate with an OPERA ISV.

Currently the class is designed as an Android [AsyncTask](https://developer.android.com/reference/kotlin/android/os/AsyncTask). Thus, all operations are executed in a background thread on the Android platform.

The current operation flow upon AsyncTask execution is such: 

1. Connection to ISV client through IP socket is established.
2. Random ByteArray of `MSGSIZE` bytes is created as a Challenge Message for the ISV attestation process.
3. Challenge Message is sent to ISV
4. ISV replies with `AttestationReport`
5. Toaster declaring success or failure is shown.
6. Connection is closed.

#### Constants
`INTSIZE` - Represents uint32 size on target ISV system  
`MSGSIZE` - Represents the size of the random ByteArray for the challenge message

#### Constructor
```kotlin
OperaSocket(ipaddr:String, portNum:String, report: AttestationReport, toastUI: Toast)
```  

`ipaddr` - a Kotlin String representing the IP Address of the target ISV server.  
`portNum` - a Kotlin String representing the Port Number of the target ISV server.  
`report` - an empty `AttestationReport` object for receiving the incoming AsReport.  
`toastUI` - a [Toast](https://developer.android.com/guide/topics/ui/notifiers/toasts) object for displaying messages to the Main UI thread  

...  
Go to [API.md](API.md)
