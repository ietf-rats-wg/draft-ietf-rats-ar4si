cddl ?= $(shell command -v cddl)
ifeq ($(strip $(cddl)),)
$(error cddl not found. To install cddl: 'gem install cddl')
endif

cddlc ?= $(shell command -v cddlc)
ifeq ($(strip $(cddlc)),)
$(error cddlc not found. To install cddlc: 'gem install cddlc')
endif


