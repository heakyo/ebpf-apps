#!/usr/bin/env python3

import sys

from bcc import BPF
from bcc.utils import printb

b = BPF(src_file="trace_open.c")

def print_event(cpu, data, size):
    event = b["myevents"].event(data)
    printb(b"%-16s %-6d %-16s" %
            (event.comm, event.pid, event.fname))

def bpf_perf_buffer(b):
    b["myevents"].open_perf_buffer(print_event)
    while 1:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit();

def main():
    b.attach_kprobe(event="do_sys_openat2", fn_name="hello_world")

    print("%-16s %-6s %-16s" % ("COMM", "PID", "FILE"))

    bpf_perf_buffer(b)

if __name__ == "__main__":
    sys.exit(main())
