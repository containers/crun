#!/bin/sh

cd $1

if test "$(id -u)" != 0; then
	echo "run as root"
	exit 1
fi

(cd /crun; git clean -fdx; ./autogen.sh && ./configure && make -j $(nproc))

export OCI_RUNTIME=/crun/crun
export CGROUP_MANAGER=cgroupfs
export STORAGE_OPTIONS="--storage-driver=vfs"

ulimit -u unlimited
export TMPDIR=/var/tmp

# Skip some tests that are not currently supported:
#
# - checkpoint
#  crun doesn't support CRIU.
#
# - search|trust|inspect|logs|generate|import|mounted rw|inherit host devices|privileged CapEff|
#   Flaky or not using the runtime.
#
# - selinux
#   Travis runs on Ubuntu.
#
# - systemd
# - notify_socket
#   must fix NOTIFY_PATH support in crun.  upstream runc doesn't support it as well :-) https://github.com/opencontainers/runc/pull/1807
#
# - podman run exit 12*|podman run exit code on failure to exec|failed to start
#   assumption that "create" must fail if the executable is not found.  We must add lookup for the executable in $PATH to mimic the runc behavior.


ginkgo --focus='.*' --skip='.*(checkpoint|selinux|notify_socket|systemd|podman run exit 12*|podman run exit code on failure to exec|failed to start|search|trust|inspect|logs|generate|import|mounted rw|inherit host devices|privileged CapEff|).*' \
	 -v -tags "seccomp   ostree selinux  varlink exclude_graphdriver_devicemapper" \
	 -timeout=50m -cover -flakeAttempts 3 -progress -trace -noColor test/e2e/.
