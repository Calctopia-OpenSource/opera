#/usr/bin/make -f

include ../../../buildenv.mk

SRC := $(wildcard *.cpp)
OBJ := $(SRC:.cpp=.o)

LIBNAME := enclave
LIB := ../libraptoe_$(LIBNAME).a

all: $(LIB)

$(LIB): $(OBJ)
	@$(AR) rcs $@ $^
	@echo "AR   =>  $@"

$(OBJ): %.o: %.cpp
	@$(CXX) -o $@ $(CXXFLAGS) $(INCLUDE) -c $< 
	@echo "CXX  <=  $<"

.PHONY: clean
clean:
	@rm -f $(OBJ) $(LIB)
