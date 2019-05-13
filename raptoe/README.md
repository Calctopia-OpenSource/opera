# RAPTOE

Remote Attestation Process Tools for OPERA Enclaves

RAPTOE provides a framework for designing processes to remotely verify the 
integrity of OPERA enabled Intel(R) SGX enclaves and for enabling said enclaves 
to accept remote attestation.

## Prerequisites

* OPERA

* [linux-sgx](https://github.com/intel/linux-sgx)

## Setup 

Build and install the SGX SDK. Once installed set the path variables in 
`buildenv.mk` for the locations of the SGX SDK, the linux-sgx repository,
and the OPERA repository.

## Building

RAPTOE can built by doing the following after the proper setup is complete:
```
make
```

## Example Code

An example of how to use RAPTOE as part of an enclave and supporting app can be
found under `SampleISV`.

An example verifier that was made to work with the `SampleISV` can be found
under `EpidVerifier`.

An example remote attestation client written in python is provided under
`RemoteAttester`.

See [EXAMPLES.md](EXAMPLES.md) for how to run the sample code.

## API/Documentation

See [API.md](API.md) for the documentation and API for using RAPTOE. 
