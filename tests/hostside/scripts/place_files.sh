#!/usr/bin/env bash
##
## Copyright (C) 2020 The Android Open Source Project
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##      http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##

set -euo pipefail

# Wrapper around 'expr' that handles the fact that it returns code 1
# if the result is zero/null. That messes with 'set -e'.
function expr {
	eval 'val=$($(which expr) $@); ret=$?'
	if [ "$ret" != 0 -a "$ret" != 1 ]
	then
		return $ret
	fi
	echo "$val"
}

ARGS=( "$@" )
NUM_ARGS=${#ARGS[@]}

POS_DIVIDER=-1
for i in $(seq 0 $(expr $NUM_ARGS - 1))
do
	if [ "${ARGS[$i]}" == "--" ]
	then
		if [ "$POS_DIVIDER" -eq -1 ]
		then
			POS_DIVIDER=$i
		else
			echo "Multiple dividers in command line inputs" 1>&2
			exit 1
		fi
	fi
done

if [ "$POS_DIVIDER" -eq -1 ]
then
	echo "Divider expected among command line inputs" 1>&2
	exit 1
fi

NUM_INPUT=${POS_DIVIDER}
NUM_OUTPUT=$(expr $NUM_ARGS - $POS_DIVIDER - 1)

if [ "$NUM_INPUT" -ne "$NUM_OUTPUT" ]
then
	echo "Number of inputs does not match number of outputs" 1>&2
	exit 1
fi

for i in $(seq 0 $(expr $NUM_INPUT - 1))
do
	INPUT="${ARGS[$i]}"
	OUTPUT="${ARGS[$NUM_INPUT + $i + 1]}"
	mkdir -p "$(dirname "$OUTPUT")"
	cp "$INPUT" "$OUTPUT"
done
