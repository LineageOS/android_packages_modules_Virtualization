#!/system/bin/sh

# TODO(victorhsieh): Create a standard Android test for continuous integration.
#
# How to run this test:
#
# Setup:
# $ adb push testdata/input.4m* /data/local/tmp
#
# Shell 1:
# $ adb shell 'cd /data/local/tmp && exec 9</system/bin/sh 8<input.4m 7<input.4m.merkle_dump 6<input.4m.fsv_sig 5<input.4m 4<input.4m.merkle_dump.bad 3<input.4m.fsv_sig fd_server --ro-fds 9 --ro-fds 8:7:6 --ro-fds 5:4:3'
#
# Shell 2:
# $ adb push tools/device-test.sh /data/local/tmp/ && adb shell /data/local/tmp/device-test.sh

# Run with -u to enter new namespace.
if [[ $1 == "-u" ]]; then
  exec unshare -mUr $0
fi

cd /data/local/tmp

MOUNTPOINT=/data/local/tmp/authfs
trap "umount ${MOUNTPOINT}" EXIT;
mkdir -p ${MOUNTPOINT}

size=$(du -b /system/bin/sh |awk '{print $1}')
size2=$(du -b input.4m |awk '{print $1}')

echo "Mounting authfs in background ..."

# TODO(170494765): Replace /dev/null (currently not used) with a valid
# certificate.
authfs \
  ${MOUNTPOINT} \
  --local-verified-file 2:input.4m:input.4m.merkle_dump:input.4m.fsv_sig:/dev/null \
  --local-verified-file 3:input.4k1:input.4k1.merkle_dump:input.4k1.fsv_sig:/dev/null \
  --local-verified-file 4:input.4k:input.4k.merkle_dump:input.4k.fsv_sig:/dev/null \
  --local-unverified-file 5:/system/bin/sh \
  --remote-unverified-file 6:9:${size} \
  --remote-verified-file 7:8:${size2}:/dev/null \
  --remote-verified-file 8:5:${size2}:/dev/null \
  &
sleep 0.1

echo "Accessing files in authfs ..."
md5sum ${MOUNTPOINT}/2 input.4m
echo
md5sum ${MOUNTPOINT}/3 input.4k1
echo
md5sum ${MOUNTPOINT}/4 input.4k
echo
md5sum ${MOUNTPOINT}/5 /system/bin/sh
md5sum ${MOUNTPOINT}/6
echo
md5sum ${MOUNTPOINT}/7 input.4m
echo
echo Checking error cases...
cat /data/local/tmp/authfs/8 2>&1 |grep -q ": I/O error" || echo "Failed to catch the problem"
echo "Done!"
