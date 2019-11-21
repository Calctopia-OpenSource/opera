## OPERA Verifier Class 

`OperaVerifier.kt`  
The OPERA Verifier class contains methods for Intel EPID verification, Intel IPP crypto functions, Intel SGX    verification functions, and OPERA verification.  

### Constructor 
```kotlin
OperaVerifier()
```
-----------------------

### Public Functions

#### checkIasResponseStatus
```kotlin
checkIasResponseStatus() : Int
```  
Ensures stored IAS response contains a valid PSE status attribute tag.

###### Returns
A negative integer on failure, and 0 on success.

-------------------

#### getPSEStatus  
```kotlin
getPSEStatus():Int
```  
Verifies Quote Data has been received from the PSE(Platform Services Enclave).

###### Returns
A negative integer on failure, and 0 on success. 

--------------------

#### getReport  
```kotlin
getReport():AttestationReport
```  
Returns the `AttestationReport` object associated with the calling OPERA Verifier object instance.  

###### Returns
An `AttestationReport` object. 

---------------------------------

#### setReportTS  
```kotlin
setReportTS()
```  
Sets the current TimeStamp for the calling OPERA verifer object instance.  

###### Note* - This function is most commonly used immediately before or after an Opera Socket connection is initiated for Report transfer.

---------------------------------

#### verifyEpidSig
```kotlin
verifyEpidSig():Int
```  
Verifies the validity of the Epid Signature stored in the quote of the calling OPERA Verifier object. 

###### Returns
Integer 0 on for successful EPID verification, a negative integer otherwise.

---------------------------------

#### checkIasResponseStatus
```kotlin
checkIasResponseStatus():Int
```  
Verifies an IAS Response has been stored in the received quote.

###### Returns
Integer 0 on successful verification, a negative integer otherwise.

---------------------------------

#### verifyIasReport
```kotlin
verifyIasReport():Int
```  
Parses and Verifies the stored IAS Report in the calling OPERA verifier object.

###### Returns
Integer 0 on successful verification, a negative integer otherwise.

---------------------------------


#### verifyRevListHashes
```kotlin
verifyRevListHashes():Int
```  
Verifies the PrivRl and SigRL SGX Hashes stored in the calling OPERA verifier object.

###### Returns
Integer 0 on successful verification, a negative integer otherwise.

---------------------------------


#### verifyTimeStamps
```kotlin
verifyTimeStamps():Int
```  
Verifies the timestamp stored in the report received from the ISV with the timestamp stored in the calling OPERA Verifier object.

###### Returns
Integer 0 on successful verification, a negative integer otherwise.

###### *NOTE* - *The timestamp stored in the calling OPERA Verifier object is generated with the 'setReportTS()' function.*

---------------------------------
Go to [API.md](API.md)
