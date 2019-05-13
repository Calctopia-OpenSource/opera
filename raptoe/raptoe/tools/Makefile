#/usr/bin/make -f

LIB_COMMON = libraptoe_common.a
LIB_COMMON_SRC := $(wildcard ./common/*)

LIB_ENCLAVE = libraptoe_enclave.a
LIB_ENCLAVE_SRC := $(wildcard ./enclave/*)

LIB_INET = libraptoe_inet.a
LIB_INET_SRC := $(wildcard ./inet/*)

ALL_LIBS := $(LIB_COMMON) $(LIB_ENCLAVE) $(LIB_INET)

.PHONY: all
all: $(ALL_LIBS)

$(LIB_COMMON): $(LIB_COMMON_SRC)
	$(MAKE) -C ./common all

$(LIB_ENCLAVE): $(LIB_ENCLAVE_SRC)
	$(MAKE) -C ./enclave all

$(LIB_INET): $(LIB_INET_SRC)
	$(MAKE) -C ./inet all

.PHONY: clean
clean: 
	$(MAKE) -C ./common clean
	$(MAKE) -C ./enclave clean
	$(MAKE) -C ./inet clean
