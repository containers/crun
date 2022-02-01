#!/bin/sh

if test "$(id -u)" != 0; then
	echo "run as root"
	exit 1
fi
set -e

(
cd /crun
git clean -fdx
./autogen.sh
./configure CFLAGS='-Wall -Wextra -Werror' --prefix=/usr
make -j "$(nproc)"
make install
)

# make sure runc is not used
rm -f /usr/bin/runc /usr/local/bin/runc
ln /usr/bin/crun /usr/bin/runc

rm -f /usr/bin/journalctl

export CONTAINER_CGROUP_MANAGER=cgroupfs
export RUNTIME_BINARY_PATH=/usr/bin/crun
export CONTAINER_CONMON_CGROUP=pod
export JOBS=2

# adapt tests to cgroupfs
sed -i 's/\.slice//g' test/testdata/*.json
sed -i -e 's|@test "conmon custom cgroup" {|@test "conmon custom cgroup" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "privileged ctr device add" {|@test "privileged ctr device add" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "ctr device add" {|@test "ctr device add" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "privileged ctr -- check for rw mounts" {|@test "privileged ctr -- check for rw mounts" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "kubernetes pod terminationGracePeriod passthru" {|@test "kubernetes pod terminationGracePeriod passthru" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "userns annotation auto should succeed" {|@test "userns annotation auto should succeed" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "userns annotation auto should map host run_as_user" {|@test "userns annotation auto should map host run_as_user" {\nskip\n|g' test/*.bats

# remove useless tests
rm test/image.* test/config* test/reload_config.bats test/crio-wipe.bats test/network_ping.bats

test/test_runner.sh
