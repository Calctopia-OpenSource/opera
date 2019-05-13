# Sample Code
Sample code is provided to show how to use and build with RAPTOE. The samples
provided are
 - A sample enclave and hosting app that accepts remote attestation
 - Two different remote attesters. One written with a python client that 
 connects back to a C++ helper, and one written completely in C++

## How to run
The sample code can be executed using the following commands:
First run the sample enclave.
```
$ cd examples/isv/
$ ./sample_app <path to AS socket> <remote attestation port>
```

Next choose which remote attester to use.

#### C++ Remote attester
```
$ cd examples/remote_attester/cpp-client
% ./remote_attester <port of isv> <ip address of isv> <challenge message>
```
The remote attester will output whether or not the quote is valid. 

#### Python Remote attester

First the epid verifier helper must be started.

```
$ cd EpidVerifier
$ ./epid_verifier <epid-verifier-port>
```

Once that is started the python script can be run following the usage 
information supplied.
```
usage: RemoteAttester.py [-h] [-v] [-m MESSAGE] [-r]
                         isve-ip isve-port asve-ip asve-port

A psuedoapp that can perform remote attestation of an OPERA and RAPTOE ISV

positional arguments:
  isve-ip               The ip address of the ISV running the IsvE to be
                        attested
  isve-port             The port of the ISV running the IsvE to be attested
  asve-ip               The ip address of the server running the asve that can
                        verify the IsvE quote
  asve-port             The port of the server running the asve that can
                        verify the opera quote

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose output
  -m MESSAGE, --message MESSAGE
                        The file to read the message sent to the enclave from.
                        If none is specified a default message is used.
  -r, --random-message  Send a random message as the challenge message to the
                        enclave.
```
Both the python script and the epid verifier helper should output whether or not
the quote is valid.


