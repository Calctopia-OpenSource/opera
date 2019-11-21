# OPERA Verifier Android Module

The OPERA Verifier Module is a drop in module that extends Intel EPID verification, SGX cryptography functions, and OPERA verification functions to an Android application.

Included with this example is a pre-built OPERA Verifier Shared Library.

Instructions for compiling the library and its components follow.

## API/Documentation
See [API.md](API.md) for complete API and further documentation.

## Prerequisites
* Android SDK with NDK Bundle 
* OpenSSL Static Libraries 
* Intel EPID SDK Static Libraries with SGX functions ([link](../epid-sdk-sgx))
* OperaVerifierLib shared library 
* libc++_shared.so - (can be obtained from Android NDK)

## Minimum Android SDK Version
Version 21

## Building
The SDKs provided have been modified to allow errorless compilition in an ARM architecture environment. For information about cross compilation see the Android NDK documentation [here](https://developer.android.com/ndk/guides/other_build_systems).

To compile the OpenSSL libraries follow the instructions at [OpenSSL](https://wiki.openssl.org/index.php/Android), the pre-built library included is OpenSSL v1.1.0k.

Copy the Intel Epid SDK with SGX functions [folder](../epid-sdk-sgx) to a desired directory.

Then copy the compiled OpenSSL static libraries `libcrypto.a` and `libssl.a` to the following directory:

*~pathToFolder*`/epid-sdk-sgx/ext/openssl/lib`

Then copy the include headers to the following directory:

*~pathToFolder*`/epid-sdk-sgx/ext/openssl/include`

Run the configure command in the cross-compile environment:

*~pathToFolder*`/epid-sdk-sgx/./configure`

Then run the make command in the cross-compile environment:

*~pathToFolder*`/epid-sdk-sgx/make`

Once the make command is complete run the install command:
*~pathToFolder*`/epid-sdk-sgx/install`

The shared library for the module will then be found at:
*~pathToFolder/epid-sdk-sgx/example/OperaSharedLib/libOperaVerifier.so*

Copy `libOperaVerifier.so` and 'libc++_shared.so` 
to *./OperaVerifierLib/src/main/jniLibs/*
under the correct abi directory.

Ex. for armeabi-v7a:

*./OperaVerifierLib/src/main/jniLibs/armeabi-v7a/libOperaVerifier.so*

The module now can be added to any project with Gradle support. 

For help on implementing a module into an Android Studio project see [here](https://developer.android.com/studio/projects/add-app-module)
