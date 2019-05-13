#/usr/bin/make -f

include ../../../buildenv.mk

SRC := $(wildcard *.cpp)
OBJ := $(SRC:.cpp=.o)
FREE_REPORT_SRC := ../common/free_as_report.cpp
FREE_REPORT_OBJ := $(FREE_REPORT_SRC:.cpp=.o)

LIBNAME := inet
LIB := ../libraptoe_$(LIBNAME).a

all: $(LIB)

$(LIB): $(OBJ) $(FREE_REPORT_OBJ)
	@$(AR) rcs $@ $^
	@echo "AR   =>  $@"

$(OBJ): %.o: %.cpp
	@$(CXX) -o $@ $(CXXFLAGS) $(INCLUDE) -c $< 
	@echo "CXX  <=  $<"

$(FREE_REPORT_OBJ): $(FREE_REPORT_SRC)
	$(MAKE) -C ../common all

.PHONY: clean
clean:
	@rm -f $(OBJ) $(LIB)
