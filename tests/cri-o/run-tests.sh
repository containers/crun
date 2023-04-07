#!/bin/sh

if test "$(id -u)" != 0; then
	echo "run as root"
	exit 1
fi
set -e

(
cd /crun
git config --global --add safe.directory /crun
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
sed -i -e 's|@test "checkpoint and restore one container into a new pod using --export" {|@test "checkpoint and restore one container into a new pod using --export" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "ctr device add" {|@test "ctr device add" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "privileged ctr -- check for rw mounts" {|@test "privileged ctr -- check for rw mounts" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "kubernetes pod terminationGracePeriod passthru" {|@test "kubernetes pod terminationGracePeriod passthru" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "userns annotation auto should succeed" {|@test "userns annotation auto should succeed" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "userns annotation auto should map host run_as_user" {|@test "userns annotation auto should map host run_as_user" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "ctr execsync" {|@test "ctr execsync" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "image volume ignore" {|@test "image volume ignore" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "image volume bind" {|@test "image volume bind" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "conmon pod cgroup" {|@test "conmon pod cgroup" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "run NRI CpusetAdjustmentUpdate test" {|@test "run NRI CpusetAdjustmentUpdate test" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "run NRI CpusetAdjustment test" {|@test "run NRI CpusetAdjustment test" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "image volume user mkdir" {|@test "image volume user mkdir" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "crio restore with missing config.json" {|@test "crio restore with missing config.json" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "crio restore upon exiting KUBENSMNT" {|@test "crio restore upon exiting KUBENSMNT" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "seccomp notifier with runtime/default" {|@test "seccomp notifier with runtime/default" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "seccomp notifier with custom profile" {|@test "seccomp notifier with custom profile" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "seccomp notifier with runtime/default but not stop" {|@test "seccomp notifier with runtime/default but not stop" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "test workload pod gets configured to defaults" {|@test "test workload pod gets configured to defaults" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "test workload can override pod defaults" {|@test "test workload can override pod defaults" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "test workload pod should not be set if not defaulted or specified" {|@test "test workload pod should not be set if not defaulted or specified" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "test workload pod should not be set if annotation not specified" {|@test "test workload pod should not be set if annotation not specified" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "test workload pod should override infra_ctr_cpuset option" {|@test "test workload pod should override infra_ctr_cpuset option" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "checkpoint and restore one container into a new pod (drop infra:true)" {|@test "checkpoint and restore one container into a new pod (drop infra:true)" {\nskip\n|g' test/*.bats
sed -i -e 's|@test "checkpoint and restore one container into a new pod (drop infra:false)" {|@test "checkpoint and restore one container into a new pod (drop infra:false)" {\nskip\n|g' test/*.bats
# disable all irqbalance tests
sed -i -e 's|@test \(.*\)$|@test \1\nskip\n|g' test/irqbalance.bats

# remove useless tests
rm test/image.* test/config* test/reload_config.bats test/crio-wipe.bats test/network_ping.bats

test/test_runner.sh
