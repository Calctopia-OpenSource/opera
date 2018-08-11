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


ROOT_DIR              := /home/donnod/Research/SGX/linux-sgx
COMMON_DIR            := $(ROOT_DIR)/common
LINUX_EXTERNAL_DIR    := $(ROOT_DIR)/external
LINUX_PSW_DIR         := $(ROOT_DIR)/psw
LINUX_SDK_DIR         := $(ROOT_DIR)/sdk
LINUX_UNITTESTS       := $(ROOT_DIR)/unittests


CP    := /bin/cp -f
MKDIR := mkdir -p
STRIP := strip
OBJCOPY := objcopy

# clean the content of 'INCLUDE' - this variable will be set by vcvars32.bat
# thus it will cause build error when this variable is used by our Makefile,
# when compiling the code under Cygwin tainted by MSVC environment settings.
INCLUDE :=

# turn on stack protector for SDK
CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
    COMMON_FLAGS += -fstack-protector
else
    COMMON_FLAGS += -fstack-protector-strong
endif

ifdef DEBUG
    COMMON_FLAGS += -O0 -ggdb -DDEBUG -UNDEBUG
    COMMON_FLAGS += -DSE_DEBUG_LEVEL=SE_TRACE_DEBUG
else
    COMMON_FLAGS += -O2 -D_FORTIFY_SOURCE=2 -UDEBUG -DNDEBUG
endif

ifdef SE_SIM
    COMMON_FLAGS += -DSE_SIM
endif

COMMON_FLAGS += -ffunction-sections -fdata-sections

# turn on compiler warnings as much as possible
COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
    -Waddress -Wsequence-point -Wformat-security \
    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
    -Wcast-align -Wconversion -Wredundant-decls

# additional warnings flags for C
CFLAGS += -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants

# additional warnings flags for C++
CXXFLAGS += -Wnon-virtual-dtor

CXXFLAGS += -std=c++11

# .DEFAULT_GOAL := all
# # this turns off the RCS / SCCS implicit rules of GNU Make
# % : RCS/%,v
# % : RCS/%
# % : %,v
# % : s.%
# % : SCCS/s.%

# If a rule fails, delete $@.
.DELETE_ON_ERROR:

HOST_FILE_PROGRAM := file

UNAME := $(shell uname -m)
ifneq (,$(findstring 86,$(UNAME)))
    HOST_ARCH := x86
    ifneq (,$(shell $(HOST_FILE_PROGRAM) -L $(SHELL) | grep 'x86[_-]64'))
        HOST_ARCH := x86_64
    endif
else
    $(info Unknown host CPU arhitecture $(UNAME))
    $(error Aborting)
endif

BUILD_DIR := $(ROOT_DIR)/build/linux

ifeq "$(findstring __INTEL_COMPILER, $(shell $(CC) -E -dM -xc /dev/null))" "__INTEL_COMPILER"
  ifeq ($(shell test -f /usr/bin/dpkg; echo $$?), 0)
    ADDED_INC := -I /usr/include/$(shell dpkg-architecture -qDEB_BUILD_MULTIARCH)
  endif
endif

ARCH := $(HOST_ARCH)
ifeq "$(findstring -m32, $(CXXFLAGS))" "-m32"
  ARCH := x86
endif

ifeq ($(ARCH), x86)
COMMON_FLAGS += -DITT_ARCH_IA32
else
COMMON_FLAGS += -DITT_ARCH_IA64
endif

CFLAGS   += $(COMMON_FLAGS)
CXXFLAGS += $(COMMON_FLAGS)

# Enable the security flags
COMMON_LDFLAGS := -Wl,-z,relro,-z,now,-z,noexecstack

# Compiler and linker options for an Enclave
#
# We are using '--export-dynamic' so that `g_global_data_sim' etc.
# will be exported to dynamic symbol table.
#
# When `pie' is enabled, the linker (both BFD and Gold) under Ubuntu 14.04
# will hide all symbols from dynamic symbol table even if they are marked
# as `global' in the LD version script.
ENCLAVE_CFLAGS   = -ffreestanding -nostdinc -fvisibility=hidden -fpie
ENCLAVE_CXXFLAGS = $(ENCLAVE_CFLAGS) -nostdinc++
ENCLAVE_LDFLAGS  = $(COMMON_LDFLAGS) -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
                   -Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
                   -Wl,--defsym,__ImageBase=0


# Choose to use the optimized libraries (IPP/String/Math) by default.
# Users could also use the source code version (SGXSSL/String/Math) by
# explicitly specifying 'USE_OPT_LIBS=0'
USE_OPT_LIBS ?= 1


ifeq ($(ARCH), x86_64)
IPP_SUBDIR = intel64
else
IPP_SUBDIR = ia32
endif

SGX_IPP_DIR     := $(ROOT_DIR)/external/ippcp_internal
SGX_IPP_INC     := $(SGX_IPP_DIR)/inc
IPP_LIBS_DIR    := $(SGX_IPP_DIR)/lib/linux/$(IPP_SUBDIR)
LD_IPP          := -lippcp -lippcore



WORK_DIR := $(shell pwd)
AENAME   := $(notdir $(WORK_DIR))
SONAME  := $(AENAME).so
ifdef DEBUG
CONFIG   := config_debug.xml
else
CONFIG   := config.xml
endif
EDLFILE  := $(wildcard *.edl)

LINUX_EPID := $(LINUX_EXTERNAL_DIR)/epid/lib/linux

EXTERNAL_LIB_NO_CRYPTO = -lsgx_tstdc

URTSLIB := -lsgx_urts
TRTSLIB := -lsgx_trts
EXTERNAL_LIB_NO_CRYPTO += -lsgx_tservice

TCRYPTO_LIBDIR := $(LINUX_SDK_DIR)/tlibcrypto
EXTERNAL_LIB   = $(EXTERNAL_LIB_NO_CRYPTO) -L$(TCRYPTO_LIBDIR) -lsgx_tcrypto

INCLUDE := -I$(LINUX_PSW_DIR)/ae/inc \
           -I$(COMMON_DIR)/inc                         \
           -I$(COMMON_DIR)/inc/tlibc                   \
           -I$(COMMON_DIR)/inc/internal                \
           -I$(LINUX_SDK_DIR)/selib                    \
           -I$(LINUX_SDK_DIR)/trts

SIGNTOOL  := $(ROOT_DIR)/build/linux/sgx_sign
SGXSIGN   := $(ROOT_DIR)/build/linux/sgx_sign

KEYFILE   := $(LINUX_SDK_DIR)/sign_tool/sample_sec.pem
EDGER8R   := $(LINUX_SDK_DIR)/edger8r/linux/_build/Edger8r.native

CXXFLAGS  += $(ENCLAVE_CXXFLAGS)
CFLAGS    += $(ENCLAVE_CFLAGS)

LDTFLAGS  = -L$(BUILD_DIR) -Wl,--whole-archive $(TRTSLIB) -Wl,--no-whole-archive \
            -Wl,--start-group $(EXTERNAL_LIB) -Wl,--end-group                    \
            -Wl,--version-script=$(ROOT_DIR)/build-scripts/enclave.lds $(ENCLAVE_LDFLAGS)

LDTFLAGS_NO_CRYPTO = -L$(BUILD_DIR) -Wl,--whole-archive $(TRTSLIB) -Wl,--no-whole-archive \
            -Wl,--start-group $(EXTERNAL_LIB_NO_CRYPTO) -Wl,--end-group                    \
            -Wl,--version-script=$(ROOT_DIR)/build-scripts/enclave.lds $(ENCLAVE_LDFLAGS)

LDTFLAGS += -fuse-ld=gold -Wl,--rosegment -Wl,-Map=out.map -Wl,--undefined=version -Wl,--gc-sections
LDTFLAGS_NO_CRYPTO += -fuse-ld=gold -Wl,--rosegment -Wl,-Map=out.map -Wl,--undefined=version -Wl,--gc-sections

DEFINES := -D__linux__

vpath %.cpp $(COMMON_DIR)/src:$(LINUX_PSW_DIR)/ae/common

.PHONY : version

version.o: $(LINUX_PSW_DIR)/ae/common/version.cpp
	$(CXX) $(CXXFLAGS) -fno-exceptions -fno-rtti $(INCLUDE) $(DEFINES) -c $(LINUX_PSW_DIR)/ae/common/version.cpp -o $@
