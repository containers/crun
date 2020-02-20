RUNTIME := podman
IMAGE := crun-builder
CRUN_SOURCE := $(realpath ../..)

all: build-image build-crun

build-crun:
	@if test "x$(CRUN_SOURCE)" = x; then printf "+--------------------------+\n|Please specify CRUN_SOURCE|\n+--------------------------+\n" >&2; exit 1; fi
	$(RUNTIME) run --rm -v $(CRUN_SOURCE):/crun $(IMAGE)
	@printf -- "----------------------------------------------------\ncrun built in $(CRUN_SOURCE)/static-build\n----------------------------------------------------\n"

build-image:
	$(RUNTIME) $(RUNTIME_OPTS) build $(BUILD_OPTS) -t $(IMAGE) .
