#!/bin/sh

INIT=${INIT:-init}
OCI_RUNTIME=${OCI_RUNTIME:-/usr/bin/crun}

export INIT
export OCI_RUNTIME

rm -f -- *.trs

COLOR="no"
if [ -t 1 ]; then
    COLOR="yes"
fi

managers="cgroupfs"
if grep -q systemd /proc/1/comm && $OCI_RUNTIME --version | grep -qF +SYSTEMD; then
	managers="$managers systemd"
fi

for cm in cgroupfs systemd; do
    export CGROUP_MANAGER=$cm
    echo "#"
    echo "# CGROUP_MANAGER=$cm"
    echo "#"
    for i in test_*.py; do
	    ./tap-driver.sh --test-name "$i" --log-file "${i}_${cm}.log" --trs-file "${i}_${cm}.trs" --color-tests "${COLOR}" --enable-hard-errors yes --expect-failure no -- /usr/bin/python "$i"
    done
done

if grep FAIL -- *.trs; then
    exit 1
fi
