#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# mprotectsnoop Trace mprotect() syscall.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of BCC trace & reformat. See
# examples/hello_world.py for a BCC trace with default output example.
#
# Copyright (c) 2015 Andreas Schnebinger.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 16-Sep-2020   Andreas Schnebinger   Created this.

from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    u64 ts;
};

BPF_PERF_OUTPUT(events);

void syscall__mprotect(void *ctx) {
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.ts = bpf_ktime_get_ns() / 1000;
    events.perf_submit(ctx, &data, sizeof(data));
};
""")
b.attach_kprobe(event=b.get_syscall_fnname("mprotect"),
                fn_name="syscall__mprotect")

# header
print("%-6s %-16s %-18s %s" % ("PID", "CMD", "TIME(s)", "CALL"))

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-6d %-16s %-18.9f mprotect()" % (event.pid, event.comm.decode('utf-8', 'replace'), (float(event.ts) / 1000000)))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
