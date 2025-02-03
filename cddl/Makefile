SHELL := /bin/bash

.DEFAULT_GOAL := check

FRAGMENTS += start.cddl
FRAGMENTS += trustworthiness-vector.cddl 
FRAGMENTS += trustworthiness-claim.cddl 
FRAGMENTS += trust-tier.cddl 
FRAGMENTS += verifier-id.cddl 
FRAGMENTS += non-empty.cddl
FRAGMENTS += jc.cddl

CDDLC_FLAGS := -r -x -f -u -2t cddl

ar4si-autogen.cddl: ; $(cddlc) $(CDDLC_FLAGS) $(FRAGMENTS) > $@

CLEANFILES += ar4si-autogen.cddl

.PHONY: clean
clean: ; rm -f $(CLEANFILES)

.PHONY: check-c
check-c: ar4si-autogen.cddl; $(cddl) $< generate 10

.PHONY: check-j
check-j: ar4si-autogen.cddl; $(cddl) $< json-generate 10

.PHONY: check
check: check-c check-j

include tools.mk
