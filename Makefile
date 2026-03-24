TRIVY_IMAGE ?= aquasec/trivy:0.69.3
CACHE_DIR := .cache
BATS_LIB_PATH := $(CURDIR)/test/test_helper
BATS := $(CURDIR)/test/test_helper/bats-core/bin/bats

BATS_ENV := BATS_LIB_PATH=$(BATS_LIB_PATH) \
	INPUT_CACHE_DIR=$(CACHE_DIR) \
	INPUT_TRIVY_IMAGE=$(TRIVY_IMAGE) \
	TRIVY_DEBUG=true

BATS_FLAGS := --timing --verbose-run

.PHONY: test
test: unit-test integration-test

.PHONY: unit-test
unit-test: submodules
	$(BATS_ENV) $(BATS) $(BATS_FLAGS) test/test_entrypoint.bats

.PHONY: integration-test
integration-test: submodules
	$(BATS_ENV) $(BATS) $(BATS_FLAGS) test/test.bats

.PHONY: update-golden
update-golden: submodules
	UPDATE_GOLDEN=1 $(BATS_ENV) $(BATS) $(BATS_FLAGS) test/test.bats

.PHONY: clean-cache
clean-cache:
	rm -rf $(CACHE_DIR)

.PHONY: submodules
submodules:
	git submodule update --init --recursive
