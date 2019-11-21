# Types
## ASReport

A data storage type designed to store the OPERA report received from an OPERA ISV.


```kotlin
class AttestationReport{
 ReportElement  quote         /* OPERA quote */
 ReportElement  grpVerifCert  /* EPID group certificate */
 ReportElement  gvcIasRes     /* Response from IAS      */
 ReportElement  gvcIasSig     /* IAS report signature   */
 ReportElement  gvcIasCrt     /* IAS report certificate */
 ReportElement  privRL        /* EPID private key based revocation list */
 ReportElement  sigRL         /* EPID private key based revocation list */
 ReportElement  currTS        /* System generated TimeStamp */
 
 /* Each element has a corresponding get/set function for data and size */
}
```
## ReportElement
```kotlin
 data class ReportElement(val name:String){
    ByteArray[]     eleData   /* element data */
    Int             eleSize   /* element size */
 }
```
Go to [API.md](API.md)
