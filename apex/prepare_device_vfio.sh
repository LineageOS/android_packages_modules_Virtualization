#!/bin/bash

# Copyright 2020 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# prepare_device_vfio.sh: prepares a device for VFIO assignment by binding a VFIO driver to it

adb="${ADB:="adb"}" # ADB command to use
vfio_dir="/dev/vfio"
platform_bus="/sys/bus/platform"
vfio_reset_required="/sys/module/vfio_platform/parameters/reset_required"
vfio_noiommu_param="/sys/module/vfio/parameters/enable_unsafe_noiommu_mode"
vfio_unsafe_interrupts_param="/sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts"

function print_help() {
    echo "prepare_device_vfio.sh prepares a device for VFIO assignment"
    echo ""
    echo " Usage:"
    echo "    $0 DEVICE_NAME"
    echo "      Prepare device DEVICE_NAME for VFIO assignment."
    echo ""
    echo "    help - prints this help message"
}

function cmd() {
    $adb shell $@
}

function tcmd() {
    trap "echo \"Error: adb shell command '$@' failed\" ; exit 1" ERR
    $adb shell $@
}

function ensure_root() {
    # Check user id
    if [ $(cmd "id -u") != 0 ]; then
        read -p "Must run as root; restart ADBD? [y/n] " answer
        case $answer in
            [Yy]* )
                $adb root && $adb wait-for-device && sleep 3 || exit 1
                ;;
            * )
                exit 1
        esac
    fi
}

function check_vfio() {
    cmd "[ -c $vfio_dir/vfio ]"
    if [ $? -ne 0 ]; then
        echo "cannot find $vfio_dir/vfio"
        exit 1
    fi

    cmd "[ -d $platform_bus/drivers/vfio-platform ]"
    if [ $? -ne 0 ]; then
        echo "VFIO-platform is not supported"
        exit 1
    fi
}

function check_device() {
    cmd "[ -d $device_sys ]"
    if [ $? -ne 0 ]; then
        echo "no device $device ($device_sys)"
        exit 1
    fi
}

function get_device_iommu_group() {
    local group=$(cmd "basename \$(readlink \"$device_sys/iommu_group\")")
    if [ $? -eq 0 ]; then
        echo $group
    else
        echo ""
    fi
}

function misc_setup() {
    # VFIO NOIOMMU check
    if [ -z "$group" ]; then
        echo "$device_sys does not have an IOMMU group - setting $vfio_noiommu_param"
        tcmd "echo y > \"$vfio_noiommu_param\""
    fi

    # Disable SELinux to allow virtualizationmanager and crosvm to access sysfs
    echo "[*WARN*] setenforce=0: SELinux is disabled"
    tcmd "setenforce 0"

    # Samsung IOMMU does not report interrupt remapping support, so enable unsafe uinterrupts
    if [ -n "$group" ]; then
        local iommu_drv=$(cmd "basename \$(readlink \"$device_sys/iommu/device/driver\")")
        if [ "$iommu_drv" = "samsung-sysmmu-v9" ]; then
            tcmd "echo y > \"$vfio_unsafe_interrupts_param\""
        fi
    fi
}

function bind_vfio_driver() {
    # Check if non-VFIO driver is currently bound, ie unbinding is needed
    cmd "[ -e \"$device_driver\" ] && \
        [ ! \$(basename \$(readlink \"$device_driver\")) = \"vfio-platform\" ]"
            if [ $? -eq 0 ]; then
                # Unbind current driver
                tcmd "echo \"$device\" > \"$device_driver/unbind\""
            fi

    # Bind to VFIO driver
    cmd "[ ! -e \"$device_driver\" ]"
    if [ $? -eq 0 ]; then
        # Bind vfio-platform driver
        tcmd "echo \"vfio-platform\" > \"$device_sys/driver_override\""
        tcmd "echo \"$device\" > \"$platform_bus/drivers_probe\""
        sleep 2
    fi
}

function verify_vfio_driver() {
    # Verify new VFIO file structure
    group=$(get_device_iommu_group)
    if [ -z "$group" ]; then
        echo "cannot setup VFIO-NOIOMMU for $device_sys"
        exit 1
    fi

    cmd "[ ! -c \"$vfio_dir/$group\" ] || \
        [ ! -e \"$device_driver\" ] || \
        [ ! \$(basename \$(readlink \"$device_driver\")) = \"vfio-platform\" ]"
    if [ $? -eq 0 ]; then
        echo "could not bind $device to VFIO platform driver"

        if [ $(cmd "cat $vfio_reset_required") = Y ]; then
            echo "VFIO device reset handler must be registered. Either unset $vfio_reset_required, \
or register a reset handler for $device_sys"
        fi
        exit 1
    fi
}

function prepare_device() {
    device="$1"
    device_sys="/sys/bus/platform/devices/$device"
    device_driver="$device_sys/driver"

    ensure_root
    check_vfio
    check_device
    group=$(get_device_iommu_group)
    misc_setup

    bind_vfio_driver
    verify_vfio_driver

    echo "Device: $device_sys"
    echo "IOMMU group: $group"
    echo "VFIO group file: $vfio_dir/$group"
    echo "Ready!"
}

cmd=$1

case $cmd in
    ""|help) print_help ;;
    *) prepare_device "$cmd" $@ ;;
esac
