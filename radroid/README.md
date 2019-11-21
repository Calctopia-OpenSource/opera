# RADroid
Remote Attestation for Android using OPERA

RADroid is an example Android ARM based application that demonstrates a suite of tools provided by the OPERA Verifier Android module for connecting to an OPERA enabled Intel(R) SGX enclave and verifying the generated OPERA Report on Android devices.

A Pre-built shared library for the OPERA Verifier module is included in the example but it is suggested that the user compiles their own libraries to include in the module if implementing into an external project. Instructions and modified SDKs for generating the libraries are included in the current directory.

## ISV Prerequisites
* OPERA 
* [linux-sgx](https://github.com/intel/linux-sgx)

## RADroid Application Prerequisites
* [OPERA Verifier Android Module](./OperaVerifierLib)(Pre-built Module Included)

## Building

**RADroid App:**
Import the current project directory into Android Studio or Gradle compatible IDE/build system to generate an APK to install on an Android Device.
The project files contain Gradle configurations for building with Gradle. Application has been tested in Android Studio 3.5 with Gradle version 5.6.2

**ISV:** 

To build the ISV, copy the TestISV folder contents to an SGX enabled device.
Run the `make` command inside the RADISV folder.
Once built, update the necessary OPERA components with the ISV target info.
Once OPERA is updated, update the ASIE Target Info found in the [OPERA Verifier Android Module](./OperaVerifierLib).
