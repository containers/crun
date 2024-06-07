#!/bin/bash

if test "$(id -u)" != 0; then
	echo "run as root"
	exit 1
fi

set -xeuo pipefail

(
cd /crun
git config --global --add safe.directory /crun
git clean -fdx
./autogen.sh
./configure CFLAGS='-Wall -Wextra -Werror' --prefix=/usr
make -j "$(nproc)"
make install
)

uname -a
cat /proc/self/mountinfo

export OCI_RUNTIME=/usr/bin/crun
export CGROUP_MANAGER=cgroupfs
export STORAGE_OPTIONS="--storage-driver=overlay"
export STORAGE_FS="overlay"

export GO111MODULE=off

ulimit -u unlimited
export TMPDIR=/var/tmp

# Skip some tests that are not currently supported in the testing environment:
#
# - search|pull from docker|trust|inspect|logs|generate|import|mounted rw|inherit host devices|privileged CapEff|prune unused images|podman images filter|image list filter
#   Flaky or not using the runtime.
#
# - selinux
#   Travis runs on Ubuntu.
#
# - systemd
# - notify_socket
#
# - podman run exit 12*|podman run exit code on failure to exec|failed to start
#   device-cgroup-rule|capabilities|network|overlay volume flag|prune removes a pod with a stopped container: not working on github actions
#
# - Podman run with specified static IPv6 has correct IP
#   Does not work inside test environment.

ginkgo --focus='.*' --skip='.*(selinux|notify_socket|systemd|podman run exit 12*|podman run exit code on failure to exec|failed to start|search|trust|inspect|logs|generate|import|mounted rw|inherit host devices|play kube|cgroups=disabled|privileged CapEff|device-cgroup-rule|capabilities|network|pull from docker|--add-host|removes a pod with a container|prune removes a pod with a stopped container|overlay volume flag|prune unused images|podman images filter|image list filter|create --pull|podman ps json format|using journald for container|image tree|--pull|shared layers|child images|cached images|flag with multiple mounts|overlay and used as workdir|image_copy_tmp_dir|Podman run with specified static IPv6 has correct IP|authenticated push|pod create --share-parent|podman kill paused container|login and logout|podman top on privileged container|local registry with authorization|podman update container all options v2|push test|podman pull and run on split imagestore|Podman kube play|uidmapping and gidmapping|push with --add-compression).*' \
	 -vv -tags "seccomp ostree selinux exclude_graphdriver_devicemapper" \
	 -timeout=50m -cover -flake-attempts 3 -progress -trace -no-color test/e2e/.
