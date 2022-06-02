#!/bin/sh

INIT=${INIT:-init}
OCI_RUNTIME=${OCI_RUNTIME:-/usr/bin/crun}

export INIT
export OCI_RUNTIME

rm -f *.trs

COLOR=
if [ -t 1 ]; then
    COLOR="--color-tests yes"
fi

for i in test_*.py
do
    ./tap-driver.sh --test-name $i --log-file $i.log --trs-file $i.trs ${COLOR} --enable-hard-errors yes --expect-failure no -- /usr/bin/python $i
done

if grep "FAIL\|ERROR" *.trs; then
    exit 1
fi
