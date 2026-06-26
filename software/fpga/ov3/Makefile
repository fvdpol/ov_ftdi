PYTHON := python3
PYTHONPATH := ../migen:../misoc
export PYTHONPATH
OVCTL := ../../host/ovctl.py
FPGA_TEST_PREFIX := ../../host/test_fpga_

PY_FILES := $(shell find ovhw ovplatform targets -name '*.py')

MAIN_TARGET := ov3
FPGA_TEST_TARGETS := ftdi_loopback ftdi_txramp
TARGETS := $(MAIN_TARGET) $(FPGA_TEST_TARGETS)

# Arbitrarily chosen minimum slack required to account for PCB traces
MIN_SLACK := 0.3

.DELETE_ON_ERROR:
.PHONY: main all clean test testall testfpga run

main: $(MAIN_TARGET)
all: $(TARGETS)

build_dir = $(if $(filter $1,$(MAIN_TARGET)),build,build_$1)
bitfile   = $(call build_dir,$1)/$1.bit
fwpkgfile = $(call build_dir,$1)/$1.fwpkg

define TARGET_RULES

$(call bitfile,$1): $(PY_FILES)
	$$(PYTHON) build.py --target $1 -d $(call build_dir,$1) -n $1 \
	--min-slack $$(MIN_SLACK)

$(call fwpkgfile,$1): $(call bitfile,$1)
	$(PYTHON) -m zipfile -c $$@ $$< $(call build_dir,$1)/map.txt

.PHONY: $1

# User-facing build target
$1: $(call bitfile,$1)

endef

$(foreach t,$(TARGETS),$(eval $(call TARGET_RULES,$t)))

# For main target, additionally build fwpkg
$(MAIN_TARGET): $(call fwpkgfile,$(MAIN_TARGET))

clean:
	rm -rf $(foreach t,$(TARGETS),$(call build_dir,$t))

# Full test of tests anywhere in source tree, including basic sanity
# tests on per-module basis
testall:
	nosetests3 --all-modules -v

# Just the explicit testsuite
test:
	nosetests3 sim -v

define FPGA_TEST_RULE

.PHONY: runfpga_$1
runfpga_$1: $(call bitfile,$1)
	$(PYTHON) $(FPGA_TEST_PREFIX)$1.py $$<

endef

$(foreach t,$(FPGA_TEST_TARGETS),$(eval $(call FPGA_TEST_RULE,$t)))

# Run test bitstreams on actual FPGA
testfpga: $(addprefix runfpga_,$(FPGA_TEST_TARGETS))

run: $(OVCTL) $(call bitfile,$(MAIN_TARGET))
	$(OVCTL) -C -b $(call bitfile,$(MAIN_TARGET)) none
