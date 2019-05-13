#
# Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########

include ../../buildenv.mk
SGX_MODE ?= HW

ifeq ($(ARCH), x86)
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

######## App Settings ########

ifneq ($(SGX_MODE), HW)
    URTS_LIB := sgx_urts_sim
else
    URTS_LIB := sgx_urts
endif

APP_SRC := ./app/sample_app.cpp
APP_INCLUDE := $(INCLUDE) -Iapp -I$(SGX_SDK)/include -I$(EPID_SDK)

APP_CFLAGS := $(CFLAGS)
APP_CXXFLAGS := $(CXXFLAGS)

APP_LDFLAGS := $(LDFLAGS) -L$(SGX_LIBRARY_PATH) -l$(URTS_LIB) -lpthread \
	-L$(RAPTOE)/tools -lraptoe_inet -lraptoe_common

ifneq ($(SGX_MODE), HW)
    APP_LDFLAGS += -lsgx_uae_service_sim
else
    APP_LDFLAGS += -lsgx_uae_service
endif

APP_OBJ := $(APP_SRC:.cpp=.o)

APP_NAME := sample_app

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	TRTS_LIB := sgx_trts_sim
	SERVICE_LIB := sgx_tservice_sim
else
	TRTS_LIB := sgx_trts
	SERVICE_LIB := sgx_tservice
endif
CRYPTO_LIB := sgx_tcrypto

ENCLAVE_SRC := ./enclave/enclave.cpp

ENCLAVE_INCLUDE := $(INCLUDE) -Ienclave -I$(SGX_SDK)/include \
	-I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

ENCLAVE_CFLAGS := $(CFLAGS) -nostdinc -fvisibility=hidden -fpie \
	-ffunction-sections -fdata-sections
ENCLAVE_CXXFLAGS := $(CXXFLAGS) -nostdinc++

ENCLAVE_LDFLAGS :=  -L$(RAPTOE)/tools -lraptoe_enclave \
	-Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(TRTS_LIB) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(CRYPTO_LIB) -l$(SERVICE_LIB) \
	-Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=enclave/enclave.lds \
	$(LDFLAGS)
ENCLAVE_OBJ := $(ENCLAVE_SRC:.cpp=.o)

ENCLAVE_NAME := sample_enclave.so
SIGNED_ENCLAVE_NAME := sample_enclave.signed.so
ENCLAVE_CONFIG_FILE := enclave/enclave.config.xml

.PHONY: all
ifeq ($(SGX_MODE), RELEASE)
all: $(APP_NAME) $(ENCLAVE_NAME)
else
all: $(APP_NAME) $(SIGNED_ENCLAVE_NAME)
endif

######## App Objects ########

app/enclave_u.c: $(SGX_EDGER8R) enclave/enclave.edl
	@cd app && $(SGX_EDGER8R) --untrusted ../enclave/enclave.edl --search-path \
		../enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

app/enclave_u.o: app/enclave_u.c
	@$(CC) -o $@ $(APP_CFLAGS) $(APP_INCLUDE) -c $<
	@echo "CC   <=  $<"

$(APP_OBJ): %.o: %.cpp
	@$(CXX) -o $@ $(APP_CXXFLAGS) $(APP_INCLUDE) -c $<
	@echo "CXX  <=  $<"

$(APP_NAME): app/enclave_u.o $(APP_OBJ)
	@$(CXX) -o $@ $^ $(APP_LDFLAGS)
	@echo "LINK =>  $@"

######## Enclave Objects ########

enclave/enclave_t.c: $(SGX_EDGER8R) enclave/enclave.edl
	@cd enclave && $(SGX_EDGER8R) --trusted ../enclave/enclave.edl \
		--search-path ../enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

enclave/enclave_t.o: enclave/enclave_t.c
	@$(CC) -o $@ $(ENCLAVE_CFLAGS) $(ENCLAVE_INCLUDE) -c $<
	@echo "CC   <=  $<"

$(ENCLAVE_OBJ): %.o: %.cpp
	@$(CXX) -o $@ $(ENCLAVE_CXXFLAGS) $(ENCLAVE_INCLUDE) -c $<
	@echo "CXX  <=  $<"

$(ENCLAVE_NAME): enclave/enclave_t.o $(ENCLAVE_OBJ)
	@$(CXX) -o $@ $^ $(ENCLAVE_LDFLAGS)
	@echo "LINK =>  $@"

$(SIGNED_ENCLAVE_NAME): $(ENCLAVE_NAME)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/enclave_private.pem -enclave \
		$(ENCLAVE_NAME) -out $@ -config $(ENCLAVE_CONFIG_FILE)
	@echo "SIGN =>  $@"

.PHONY: clean

clean:
	@rm -f $(APP_NAME) $(ENCLAVE_NAME) $(SIGNED_ENCLAVE_NAME) $(APP_OBJ) \
		app/enclave_u.* $(ENCLAVE_OBJ) enclave/enclave_t.*
