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

# vm_shell.sh shows the VMs running in the Android device and connects to it
# Usage:
# vm_shell [cid]
#
#   cid: CID of the VM to connect to. If omitted, the list of CIDs available are shown

function connect_vm() {
    cid=$1
    echo Connecting to CID ${cid}
    adb disconnect localhost:8000
    adb forward tcp:8000 vsock:${cid}:5555
    adb connect localhost:8000
    adb -s localhost:8000 root
    adb -s localhost:8000 wait-for-device
    adb -s localhost:8000 shell
    exit 0
}

selected_cid=$1
available_cids=$(adb shell /apex/com.android.virt/bin/vm list | awk 'BEGIN { FS="[:,]" } /cid/ { print $2; }')

if [ -z "${available_cids}" ]; then
    echo No VM is available
    exit 1
fi

if [ ! -n "${selected_cid}" ]; then
    PS3="Select CID of VM to adb-shell into: "
    select cid in ${available_cids}
    do
        selected_cid=${cid}
        break
    done
fi

if [[ ! " ${available_cids[*]} " =~ " ${selected_cid} " ]]; then
    echo VM of CID $selected_cid does not exist. Available CIDs: ${available_cids}
    exit 1
fi

connect_vm ${selected_cid}
