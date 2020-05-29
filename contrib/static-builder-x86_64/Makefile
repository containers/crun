RUNTIME := podman
IMAGE := crun-builder
CRUN_SOURCE := $(realpath ../..)

all: build-image build-crun

build-crun:
	@if test "x$(CRUN_SOURCE)" = x; then printf "+--------------------------+\n|Please specify CRUN_SOURCE|\n+--------------------------+\n" >&2; exit 1; fi
	$(RUNTIME) run --rm -v $(CRUN_SOURCE):/crun -w /crun $(IMAGE) sh -c "nix build -f nix && cp result/bin/crun ."
	@printf -- "----------------------------------------------------\ncrun built in $(CRUN_SOURCE)/crun\n----------------------------------------------------\n"

build-image:
	$(RUNTIME) $(RUNTIME_OPTS) build $(BUILD_OPTS) -f Dockerfile -t $(IMAGE) $(CRUN_SOURCE)
