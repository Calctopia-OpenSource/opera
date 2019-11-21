#!/usr/bin/make -f

#define variables
IPP_API_INCLUDE_DIR = ../ext/ipp-crypto/include
EXAMPLE_INSTALL_DIR = ./
JNIWRAPPER_SRC = ./OperaVerifier/src/OperaJNIWrapper.cpp

OPENSSL_INCLUDE_DIR = ../ext/openssl/include
SGX_INCLUDE_DIR = ../ext/SGX
OPERAVERIF_INCLUDE_DIR = ./OperaVerifier
OPERAVERIF_SRC = $(filter-out $(JNIWRAPPER_SRC), $(wildcard ./OperaVerifier/src/*.cpp))
OPERAVERIF_OBJ = $(sort $(OPERAVERIF_SRC:.cpp=.o))
OPERAVERIF_SO = ./OperaVerifier/src/libOperaVerifier.so
LIB_IPPCP_INCLUDE_DIR = ../ext/ipp-crypto/sources/include

LIB_IPPCP_DIR = ../ext/ipp-crypto/sources/ippcp
LIB_MEMBER_DIR = ../epid/member
LIB_VERIFIER_DIR = ../epid/verifier
LIB_COMMON_DIR = ../epid/common
LIB_OPENSSL_DIR = ../ext/openssl/lib

#set linker flags
LDCRYPTO = -L$(LIB_OPENSSL_DIR) \
	-lssl \
	-lcrypto

LDFLAGS += -L$(LIB_IPPCP_DIR) \
	-L$(LIB_COMMON_DIR) \
	-lcommon \
	-lippcp \
	-llog \
	-lz

#include cluster
INCLUDE_DIRS =-I$(LIB_VERIFIER_DIR)/../.. \
		-I$(IPP_API_INCLUDE_DIR) \
		-I$(OPERAVERIF_INCLUDE_DIR) \
		-I$(OPENSSL_INCLUDE_DIR) \
		-I$(SGX_INCLUDE_DIR) \
		-I$(LIB_IPPCP_DIR) \
		-I$(LIB_IPPCP_INCLUDE_DIR)


$(OPERAVERIF_SO): $(OPERAVERIF_OBJ)
	$(CXX) -shared -o $@ $^ $(JNIWRAPPER_SRC) $(INCLUDE_DIRS) $(LDCRYPTO) -L$(LIB_VERIFIER_DIR) -lverifier $(LDFLAGS)

$(OPERAVERIF_OBJ): %.o: %.cpp
	$(CXX) -o $@ $(INCLUDE_DIRS) -c $^ -fPIC

#target part
build: all install

all: $(OPERAVERIF_SO)

install:
	mkdir -p '$(EXAMPLE_INSTALL_DIR)/OperaSharedLib'
	cp -r ./OperaVerifier/src/libOperaVerifier.so '$(EXAMPLE_INSTALL_DIR)/OperaSharedLib'		

clean:
	rm -f $(OPERAVERIF_OBJ) \
		$(OPERAVERIF_SO)
	rm -rf '$(EXAMPLE_INSTALL_DIR)/OperaSharedLib' 
	
