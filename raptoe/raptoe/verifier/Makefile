#!/usr/bin/make -f

include ../../buildenv.mk

SRC := $(wildcard *.cpp)

OBJ := $(SRC:.cpp=.o)

INCLUDE += -I. -I$(SGX_SDK)/include -I$(EPID_SDK) -I$(LINUX_SGX)/common/inc \
	-I$(LINUX_SGX)/common/inc/internal -I$(PSW)/ae/pve -I$(RDRAND) \
	-I$(PSW)/ae/inc/internal -I$(PSW)/ae/common -I$(PSW)/ae/inc -I$(IPPCP)/inc \
	-I$(EPID_SDK)/ext/ipp/include

VERIFIER := ../libraptoe_verifier.a

all: $(VERIFIER)

$(VERIFIER): $(OBJ)
	@$(AR) rcs $@ $^
	@echo "AR   =>  $@"

$(OBJ): %.o: %.cpp
	@$(CXX) -o $@ $(CXXFLAGS) $(INCLUDE) -c $< 
	@echo "CXX  <=  $<"

.PHONY: clean
clean:
	@rm -f $(OBJ) $(VERIFIER)
