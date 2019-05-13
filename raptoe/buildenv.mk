#!/usr/bin/make -f

# External libraries
SGX_SDK ?= /opt/intel/sgxsdk
LINUX_SGX ?= /home/donnod/Research/SGX/linux-sgx
OPERA ?= #opera 

# Linux SGX Subdirectories
PSW ?= $(LINUX_SGX)/psw
IPPCP ?= $(LINUX_SGX)/external/ippcp_internal
RDRAND ?= $(LINUX_SGX)/external/rdrand
EPID_SDK ?= $(LINUX_SGX)/external/epid-sdk

# Build configuration
DEBUG ?= 1

# RAPTOE root
BUILD_ENV_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
ROOT_DIR := $(patsubst %/,%,$(dir $(BUILD_ENV_PATH)))
RAPTOE := $(ROOT_DIR)/raptoe

# Architecture
ifeq ($(findstring -m32,$(CFLAGS)),-m32)
    ARCH := x86
else ifeq ($(findstring -m64,$(CFLAGS)),-m64)
    ARCH := x86_64
else ifeq ($(findstring -arm,$(CC)),arm-)
    ARCH := arm
else
    ARCH := $(shell uname -m)
endif

# Debug or build flags
ifeq ($(DEBUG),1)
    CFLAGS += -O0 -g -DDEBUG
else
    CFLAGS += -O2 -D_FORTIFY_SOURCE=2 -DNDEBUG
endif

# Enable stack protector based on CC version
CC_STRONG_SP_ENABLED := $(shell expr "`$(CC) -dumpversion`" \>= "4.9")
ifeq ($(CC_STRONG_SP_ENABLED),1)
    CFLAGS += -fstack-protector-strong
else
    CFLAGS += -fstack-protector
endif

# Architecture flags
ifeq ($(ARCH), x86)
    CFLAGS += -m32
    LDFLAGS += -m32
else ifeq ($(ARCH), x86_64)
    CFLAGS += -m64
    LDFLAGS += -m64
endif

# Compiler build flags
CFLAGS += -fPIC

# Compiler warning flags
CFLAGS += -Werror -Wall -Wextra -Wformat -Wformat-security -Winit-self \
		  -Wshadow -Wmissing-include-dirs -Wfloat-equal -Wcast-align -Wundef \
		  -Wconversion -Wpointer-arith -Wreturn-type -Wwrite-strings \
		  -Waggregate-return -Wswitch-default -Wswitch-enum -Wunreachable-code

# Additional warning flags for C++
CXXFLAGS := $(CFLAGS) -Wnon-virtual-dtor -std=c++11

# Additional warning flags for C
CFLAGS += -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants

# Linker flags
LDFLAGS += -fstack-protector -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now

# Include flags
INCLUDE := -I$(ROOT_DIR)/util -I$(RAPTOE)/include -I$(SGX_SDK)/include \
	-I$(EPID_SDK)
