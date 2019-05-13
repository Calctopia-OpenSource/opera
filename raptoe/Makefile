#!/usr/bin/make

include buildenv.mk

.PHONY: all
all: raptoe examples

.PHONY: raptoe
raptoe: 
	$(MAKE) -C ./raptoe all

.PHONY: examples
examples:
	$(MAKE) -C ./example all
	
.PHONY: clean
clean:
	$(MAKE) -C ./raptoe clean
	$(MAKE) -C ./example clean

