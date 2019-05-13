#!/usr/bin/make -f

include ../../../buildenv.mk

SRC := $(wildcard ./src/*.cpp)

OBJ := $(SRC:.cpp=.o)

INCLUDE += -Isrc -I$(SGX_SDK)/include \
	-I$(EPID_SDK) -I$(LINUX_SGX)/common/inc -I$(LINUX_SGX)/common/inc/internal \
	-I$(PSW)/ae/pve -I$(PSW)/ae/inc/internal -I$(PSW)/ae/common \
	-I$(PSW)/ae/inc -I$(IPPCP)/inc -I$(RDRAND)

LIBDIRS := -L$(RAPTOE) -L$(RAPTOE)/tools -L$(LINUX_SGX)/sdk/tlibcrypto \
	-L$(EPID_SDK)/epid/common -L$(EPID_SDK)/epid/verifier -L/usr/lib \
	-L$(RDRAND)/src -L$(IPPCP)/lib/linux/intel64

LDFLAGS += $(LIBDIRS) -lraptoe_inet -lraptoe_common -lraptoe_verifier \
		   -lverifier -lcommon -lippcp -lsgx_tcrypto -lssl -lcrypto -lrdrand

LIBRAPTOE := $(RAPTOE)/libraptoe_verifier.a $(RAPTOE)/libraptoe_common.a \
	$(RAPTOE)/libraptoe_inet.a

EXE := ./epid_verifier

all: $(EXE)

$(EXE): $(LIBRAPTOE) $(OBJ)
	@$(CXX) -o $@ $(OBJ) $(LDFLAGS)
	@echo "LD   =>  $@"

$(OBJ): %.o: %.cpp
	@$(CXX) -o $@ $(CXXFLAGS) $(INCLUDE) -c $< 
	@echo "CXX  <=  $<"

$(LIBRAPTOE):
	$(MAKE) -C $(RAPTOE)

.PHONY: clean
clean:
	@rm -f $(OBJ) $(EXE)
