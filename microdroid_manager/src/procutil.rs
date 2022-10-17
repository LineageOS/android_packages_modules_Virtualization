// Copyright 2022, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::{Context, Result};
use libc::{sysconf, _SC_CLK_TCK};
use regex::Regex;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};

const MILLIS_PER_SEC: i64 = 1000;

pub struct CpuTime {
    pub user: i64,
    pub nice: i64,
    pub sys: i64,
    pub idle: i64,
}

pub struct MemInfo {
    pub total: i64,
    pub free: i64,
    pub available: i64,
    pub buffer: i64,
    pub cached: i64,
}

// Get CPU time information from /proc/stat
//
// /proc/stat example(omitted):
//   cpu  24790952 21104390 10771070 10480973587 1700955 0 410931 0 316532 0
//   cpu0 169636 141307 61153 81785791 9605 0 183524 0 1345 0
//   cpu1 182431 198327 68273 81431817 10445 0 32392 0 2616 0
//   cpu2 183209 174917 68591 81933935 12239 0 10042 0 2415 0
//   cpu3 183413 177758 69908 81927474 13354 0 5853 0 2491 0
//   intr 7913477443 39 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
//   ctxt 10326710014
//   btime 1664123605
//   processes 9225712
//   procs_running 1
//   procs_blocked 0
//   softirq 2683914305 14595298 304837101 1581 327291100 16397051 0 208857783 1024640365 787932 786506094
//
// expected output:
//   user: 24790952
//   nice: 21104390
//   sys: 10771070
//   idle: 10480973587
pub fn get_cpu_time() -> Result<CpuTime> {
    let re = Regex::new(r"^cpu\s+([\d]+)\s([\d]+)\s([\d]+)\s([\d]+)").unwrap();

    let mut proc_stat = BufReader::new(File::open("/proc/stat")?);
    let mut line = String::new();
    proc_stat.read_line(&mut line)?;
    let data_list = re.captures(&line).context("Failed to capture values")?;

    let ticks_per_sec = unsafe { sysconf(_SC_CLK_TCK) } as i64;
    let cpu_time = CpuTime {
        user: data_list.get(1).unwrap().as_str().parse::<i64>()? * MILLIS_PER_SEC / ticks_per_sec,
        nice: data_list.get(2).unwrap().as_str().parse::<i64>()? * MILLIS_PER_SEC / ticks_per_sec,
        sys: data_list.get(3).unwrap().as_str().parse::<i64>()? * MILLIS_PER_SEC / ticks_per_sec,
        idle: data_list.get(4).unwrap().as_str().parse::<i64>()? * MILLIS_PER_SEC / ticks_per_sec,
    };
    Ok(cpu_time)
}

// Get memory information from /proc/meminfo
//
// /proc/meminfo example(omitted):
//   MemTotal:       263742736 kB
//   MemFree:        37144204 kB
//   MemAvailable:   249168700 kB
//   Buffers:        10231296 kB
//   Cached:         189502836 kB
//   SwapCached:       113848 kB
//   Active:         132266424 kB
//   Inactive:       73587504 kB
//   Active(anon):    1455240 kB
//   Inactive(anon):  6993584 kB
//   Active(file):   130811184 kB
//   Inactive(file): 66593920 kB
//   Unevictable:       56436 kB
//   Mlocked:           56436 kB
//   SwapTotal:      255123452 kB
//   SwapFree:       254499068 kB
//   Dirty:               596 kB
//   Writeback:             0 kB
//   AnonPages:       5295864 kB
//   Mapped:          3512608 kB
//
// expected output:
//   total: 263742736
//   free: 37144204
//   available: 249168700
//   buffer: 10231296
//   cached: 189502836
pub fn get_mem_info() -> Result<MemInfo> {
    let re = Regex::new(r"^.*?:\s+([0-9]+)\skB").unwrap();

    let proc_mem_info = fs::read_to_string("/proc/meminfo")?;
    let data_list: Vec<_> = proc_mem_info
        .trim()
        .splitn(6, '\n')
        .map(|s| re.captures(s).context("Failed to capture values").ok()?.get(1))
        .collect();

    let mem_info = MemInfo {
        total: data_list[0].unwrap().as_str().parse::<i64>()?,
        free: data_list[1].unwrap().as_str().parse::<i64>()?,
        available: data_list[2].unwrap().as_str().parse::<i64>()?,
        buffer: data_list[3].unwrap().as_str().parse::<i64>()?,
        cached: data_list[4].unwrap().as_str().parse::<i64>()?,
    };
    Ok(mem_info)
}
