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
./configure --enable-embedded-blake3 CFLAGS='-Wall -Wextra -Werror' --prefix=/usr
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

# Skip some tests that are not currently supported in the testing environment.
SKIP_TESTS=(
	# Flaky or not using the runtime.
	'generate'
	'image list filter'
	'import'
	'inherit host devices'
	'inspect'
	'logs'
	'mounted rw'
	'podman images filter'
	'privileged CapEff'
	'prune unused images'
	'pull from docker'
	'search'
	'trust'

	# Selinux not supported on Ubuntu.
	'selinux'

	'notify_socket'
	'systemd'

	# Not working on GitHub Actions.
	'Podman run with specified static IPv6 has correct IP'
	'capabilities'
	'device-cgroup-rule'
	'failed to start'
	'network'
	'overlay volume flag'
	'podman run exit 12'
	'podman run exit code on failure to exec'
	'prune removes a pod with a stopped container'

	'--add-host'
	'--pull'
	'Podman kube play'
	'artifact'
	'authenticated push'
	'cached images'
	'cgroups=disabled'
	'child images'
	'create --pull'
	'enforces DiffID matching'
	'flag with multiple mounts'
	'image tree'
	'image_copy_tmp_dir'
	'local registry with authorization'
	'login and logout'
	'overlay and used as workdir'
	'play kube'
	'pod create --share-parent'
	'podman kill paused container'
	'podman ps json format'
	'podman pull and run on split imagestore'
	'podman top on privileged container'
	'podman update container all options v2'
	'push test'
	'push with --add-compression'
	'push with authorization'
	'removes a pod with a container'
	'shared layers'
	'uidmapping and gidmapping'
	'using journald for container'

	# Does not work inside container as upperdir is overlayfs (issue 1999).
	'podman build and remove basic alpine with TMPDIR as relative'

	# Not related to runtime.
	'--tls-details'
)
SKIP_REGEX=$(IFS='|'; echo "${SKIP_TESTS[*]}")

ginkgo --focus='.*' --skip="$SKIP_REGEX" \
	 -v --show-node-events --trace \
	 -tags "seccomp ostree selinux" \
	 -timeout=50m -cover -flake-attempts 3 -no-color test/e2e/.
