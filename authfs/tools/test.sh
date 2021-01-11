#!/bin/bash

# Run with -u to enter new namespace.
if [[ $1 == "-u" ]]; then
  exec unshare -m -U -r $0
fi

trap "umount /tmp/mnt" EXIT;
mkdir -p /tmp/mnt

echo "Mounting authfs in background ..."
strace -o authfs.strace target/debug/authfs \
  /tmp/mnt \
  --local-verified-file 2:testdata/input.4m:testdata/input.4m.merkle_dump:testdata/input.4m.fsv_sig \
  --local-verified-file 3:testdata/input.4k1:testdata/input.4k1.merkle_dump:testdata/input.4k1.fsv_sig \
  --local-verified-file 4:testdata/input.4k:testdata/input.4k.merkle_dump:testdata/input.4k.fsv_sig \
  --local-unverified-file 5:testdata/input.4k \
  &
sleep 0.1

echo "Accessing files in authfs ..."
echo
md5sum /tmp/mnt/2 testdata/input.4m
echo
md5sum /tmp/mnt/3 testdata/input.4k1
echo
md5sum /tmp/mnt/4 /tmp/mnt/5 testdata/input.4k
echo
dd if=/tmp/mnt/2 bs=1000 skip=100 count=50 status=none |md5sum
dd if=testdata/input.4m bs=1000 skip=100 count=50 status=none |md5sum
echo
tac /tmp/mnt/4 |md5sum
tac /tmp/mnt/5 |md5sum
tac testdata/input.4k |md5sum
echo
test -f /tmp/mnt/2 || echo 'FAIL: an expected file is missing'
test -f /tmp/mnt/0 && echo 'FAIL: unexpected file presents'
test -f /tmp/mnt/1 && echo 'FAIL: unexpected file presents, 1 is root dir'
test -f /tmp/mnt/100 && echo 'FAIL: unexpected file presents'
test -f /tmp/mnt/foo && echo 'FAIL: unexpected file presents'
test -f /tmp/mnt/dir/3 && echo 'FAIL: unexpected file presents'
echo "Done!"
