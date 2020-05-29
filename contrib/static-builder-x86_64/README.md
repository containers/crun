# Build

To build a static crun binary for x86_64, you need first to create the
container image containing all of the dependencies and tools needed to
build a static crun executable.

Use the `build-image` makefile target to build the image, as:

`make -C contrib/static-builder-x86_64 build-image`

You can override the runtime used and the image name generated using
RUNTIME and IMAGE:

`make -C contrib/static-builder-x86_64 build-image RUNTIME=/usr/bin/podman IMAGE=quay.io/giuseppe/crun-builder`

Once the image is ready, you can build crun with:

`make -C contrib/static-builder-x86_64 build-crun CRUN_SOURCE=$(pwd)`

`CRUN_SOURCE` is mandatory.  If you wish, you can also specify a
different `RUNTIME`.
