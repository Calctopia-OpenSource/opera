#!/usr/bin/make -f

.PHONY: all
all:
	$(MAKE) -C ./isv all
	$(MAKE) -C ./remote_attester/python-client all
	$(MAKE) -C ./remote_attester/cpp-client all

.PHONY: clean
clean:
	$(MAKE) -C ./isv clean
	$(MAKE) -C ./remote_attester/python-client clean
	$(MAKE) -C ./remote_attester/cpp-client clean
