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

# Skip some tests that are not currently supported
# checkpoint - crun doesn't support CRIU
# cgroup-parent crunc creates a CGROUP namespace, so these tests fail
# stats - might be related to the cgroup-parent failures, must be investigated
# network|portbindings - fail on Fedora 29, also with runc, must be investigated
# failed to start|podman run exit - assumption that "create" must fail if the executable is not found.  Must be investigated
# podman rmi - must be investigated
# podman images --all flag - must be investigated
# podman logs tail two lines - fails when running in a container on Xenial (not crun related).  Must be investigated

ginkgo --focus='.*'  --skip='.*(checkpoint|stats|net ns|selinux|cgroup-parent|podman run exit|systemd|network|portbindings|failed to start|podman rmi|podman images --all flag|podman logs tail two lines).*' \
	 -v -tags "seccomp   ostree selinux  varlink exclude_graphdriver_devicemapper" \
	 -timeout=50m -cover -flakeAttempts 3 -progress -trace -noColor test/e2e/.
